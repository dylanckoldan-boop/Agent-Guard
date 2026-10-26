"""Admission (Layer 1): signed, least-privilege agent identity.

Nothing runs unattested. Every agent Agent Guard sanctions is registered with a
cryptographic identity and a *scope* — the narrow set of actions, hosts and path
prefixes its job actually requires. The circle authority signs that binding into
a :class:`Credential`. An agent presenting no valid credential, or acting outside
its scope, is the first thing the net catches: an unregistered process that
touches a decoy is an intrusion by definition.

Least privilege is the whole point. An agent that summarizes logs does not need
to delete files, open new network egress, or spawn children — so its scope says
so, and anything beyond it is a policy violation the surrounding system can act
on even when the model itself is confused.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from agent_guard.crypto import Signer


@dataclass(frozen=True)
class Scope:
    """What a sanctioned agent is allowed to do. Empty frozensets mean 'none'."""

    allowed_actions: frozenset[str] = field(default_factory=frozenset)
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    allowed_path_prefixes: frozenset[str] = field(default_factory=frozenset)
    may_spawn: bool = False

    def canonical(self) -> str:
        return json.dumps(
            {
                "actions": sorted(self.allowed_actions),
                "hosts": sorted(self.allowed_hosts),
                "paths": sorted(self.allowed_path_prefixes),
                "spawn": self.may_spawn,
            },
            sort_keys=True,
        )

    def permits_action(self, action: str) -> bool:
        return action in self.allowed_actions

    def permits_host(self, host: str) -> bool:
        return any(host == h or host.endswith("." + h) for h in self.allowed_hosts)

    def permits_path(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.allowed_path_prefixes)


@dataclass(frozen=True)
class Credential:
    agent_id: str
    scope: Scope
    issuer_ref: str
    issued_at: float
    signature: str


@dataclass
class AgentIdentity:
    """A sanctioned agent, as Agent Guard tracks it at runtime."""

    agent_id: str
    label: str
    credential: Credential
    pid: int | None = None
    registered_at: float = field(default_factory=time.time)


class TrustDomain:
    """The circle: issues credentials and holds the signing authority. Sentinels
    receive only :attr:`circle_verifier` (public), so they can check a credential
    or a revocation but never forge one."""

    def __init__(self, signer: Signer) -> None:
        if not signer.can_sign():
            raise ValueError("TrustDomain needs a signing authority, not a verify-only handle")
        self._signer = signer

    @property
    def circle_signer(self) -> Signer:
        return self._signer

    @property
    def circle_verifier(self) -> Signer:
        return self._signer.verifier()

    @staticmethod
    def _message(agent_id: str, scope: Scope, issued_at: float, issuer_ref: str) -> bytes:
        return f"{agent_id}|{scope.canonical()}|{issued_at:.0f}|{issuer_ref}".encode()

    def issue(self, agent_id: str, scope: Scope) -> Credential:
        issued_at = time.time()
        ref = self._signer.public_ref
        sig = self._signer.sign(self._message(agent_id, scope, issued_at, ref))
        return Credential(agent_id, scope, ref, issued_at, sig)

    def verify(self, cred: Credential) -> bool:
        return self.circle_verifier.verify(
            self._message(cred.agent_id, cred.scope, cred.issued_at, cred.issuer_ref),
            cred.signature,
        )


def verify_credential(verifier: Signer, cred: Credential) -> bool:
    """Standalone credential check for a holder of only the public verifier
    (e.g. a sentinel that must not be able to mint credentials)."""
    msg = f"{cred.agent_id}|{cred.scope.canonical()}|{cred.issued_at:.0f}|{cred.issuer_ref}".encode()
    return verifier.verify(msg, cred.signature)
