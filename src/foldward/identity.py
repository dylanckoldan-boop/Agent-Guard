"""Admission (Layer 1): signed, least-privilege agent identity.

Nothing runs unattested. Every agent Foldward sanctions is registered with a
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
import os
import time
from dataclasses import dataclass, field

from foldward.crypto import Signer


def _canonical(payload: dict) -> bytes:
    """Deterministic, type-tagged bytes for a signature. The leading ``type``
    domain-separates credentials from revocations and other signed records, so a
    signature minted for one kind can never be replayed as another, and the
    compact JSON is unambiguous — no field can be shifted across a delimiter the
    way a ``|``-joined string allowed (see AG-F07)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


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
        # A granted prefix permits a path only when the path is that directory or
        # lies *beneath* it — the match must land on a path separator. A bare
        # string prefix let "/home/proj" also admit "/home/proj-secrets", and let
        # "/home/proj/../.ssh" slip through; normalizing and requiring a separator
        # boundary closes both (see AG-F04).
        if not self.allowed_path_prefixes:
            return False
        target = os.path.normcase(os.path.realpath(path))
        for prefix in self.allowed_path_prefixes:
            base = os.path.normcase(os.path.realpath(prefix))
            if target == base or target.startswith(base + os.sep):
                return True
        return False


@dataclass(frozen=True)
class Credential:
    agent_id: str
    scope: Scope
    issuer_ref: str
    issued_at: float
    signature: str


@dataclass
class AgentIdentity:
    """A sanctioned agent, as Foldward tracks it at runtime."""

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
        return _canonical({
            "type": "foldward/credential/v1",
            "agent": agent_id,
            "scope": scope.canonical(),
            "issued_at": round(issued_at),
            "issuer": issuer_ref,
        })

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
    msg = TrustDomain._message(cred.agent_id, cred.scope, cred.issued_at, cred.issuer_ref)
    return verifier.verify(msg, cred.signature)
