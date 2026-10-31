"""The signed, DoS-resistant revocation registry.

When an agent is pacified, its credential is revoked and the revocation is
shared across every sentinel in the mesh, so a swarm lockout propagates. The
registry is the single most abusable component in the whole design, so it is
built defensively around one rule:

**A revocation is accepted only if it carries a valid circle signature.**

That one rule buys two properties at once. An outsider — or a *compromised
sentinel* — cannot forge a revocation, so the registry cannot be weaponized
into a denial-of-service that locks out healthy agents; and it cannot forge an
"all-clear" to quietly un-revoke a contained agent. Verification uses only the
circle's public verifier, so holding the registry grants no power to write to
it. This is the network-realm instantiation of the point raised early on: if a
compromised node could forge a healthy heartbeat or a bogus lockout, the whole
mesh goes blind.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from foldward.crypto import AuditLog, Signer


@dataclass(frozen=True)
class Revocation:
    agent_id: str
    reason: str
    issuer_ref: str
    issued_at: float
    signature: str


class RevocationRegistry:
    def __init__(self, circle_verifier: Signer, audit: AuditLog | None = None, path: Path | None = None) -> None:
        # Only the *public* verifier is held here: the registry can check a
        # revocation's signature but can never produce one itself.
        self._verifier = circle_verifier
        self._audit = audit
        self._revoked: dict[str, Revocation] = {}
        # When a path is given, revocations are durable: a swarm lockout must
        # survive a restart or a contained agent would silently become sanctioned
        # again (AG-A03). With no path the registry is in-memory (unit-test default).
        self._path = path
        if path is not None:
            self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        for item in raw:
            try:
                self._revoked[item["agent_id"]] = Revocation(**item)
            except (KeyError, TypeError):
                continue

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps([asdict(r) for r in self._revoked.values()]), "utf-8")
            tmp.replace(self._path)
        except OSError:
            pass

    @staticmethod
    def _message(agent_id: str, reason: str, issued_at: float, issuer_ref: str) -> bytes:
        # Type-tagged canonical JSON: a revocation can't be forged by replaying a
        # credential's signature, and no field can be shifted across a delimiter
        # (agent_id="a|b", reason="c" is distinct from agent_id="a", reason="b|c").
        return json.dumps({
            "type": "foldward/revocation/v1",
            "agent": agent_id,
            "reason": reason,
            "issued_at": round(issued_at),
            "issuer": issuer_ref,
        }, sort_keys=True, separators=(",", ":")).encode()

    def revoke(self, agent_id: str, reason: str, issuer: Signer) -> bool:
        """Mint and submit a revocation. ``issuer`` must be the circle's
        signing authority (a verify-only handle cannot sign)."""
        if not issuer.can_sign():
            raise ValueError("revoke() needs the circle signing authority")
        issued_at = time.time()
        sig = issuer.sign(self._message(agent_id, reason, issued_at, issuer.public_ref))
        return self.submit(Revocation(agent_id, reason, issuer.public_ref, issued_at, sig))

    def submit(self, rev: Revocation) -> bool:
        """Accept a revocation from anywhere (another sentinel, a shared feed)
        only if its circle signature verifies. Forgeries are rejected and logged."""
        msg = self._message(rev.agent_id, rev.reason, rev.issued_at, rev.issuer_ref)
        if not self._verifier.verify(msg, rev.signature):
            if self._audit is not None:
                self._audit.append("revocation.rejected", {"agent": rev.agent_id, "reason": "bad_signature"})
            return False
        self._revoked[rev.agent_id] = rev
        self._save()
        if self._audit is not None:
            self._audit.append("revocation.accepted", {"agent": rev.agent_id, "reason": rev.reason})
        return True

    def is_revoked(self, agent_id: str) -> bool:
        return agent_id in self._revoked

    def get(self, agent_id: str) -> Revocation | None:
        return self._revoked.get(agent_id)

    def all(self) -> list[Revocation]:
        return list(self._revoked.values())

    def __len__(self) -> int:
        return len(self._revoked)
