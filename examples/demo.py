"""A runnable, self-contained demonstration of Agent Guard's layers.

No live processes and no partners required — it drives the engine directly with
synthetic agents so you can watch the net catch and pacify a rogue agent, and
see the signed registry reject a forged revocation.

    python examples/demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_guard.config import Settings
from agent_guard.core import AgentGuard
from agent_guard.detect import DetectedAgent, ProcessInfo, Reason
from agent_guard.identity import Scope
from agent_guard.registry import Revocation


def rule(title: str) -> None:
    print("\n" + "=" * 68 + f"\n  {title}\n" + "=" * 68)


def main() -> None:
    g = AgentGuard(Settings())
    g.alert_listeners.append(lambda t, x, l: print(f"   · [{l}] {t}: {x}"))

    rule("1. Admission — a sanctioned, least-privilege agent")
    ident = g.register_agent("researcher", Scope(allowed_actions=frozenset({"summarize"}),
                                                 allowed_hosts=frozenset({"api.anthropic.com"})))
    print(f"   registered {ident.agent_id}; credential verifies: {g.trust.verify(ident.credential)}")

    rule("2. The net catches a rogue agent (decoy touch → auto-contain)")
    proc = ProcessInfo(pid=4242, name="python", exe="/tmp/exfil.py", cmdline=["python", "agent.py"],
                       remote_hosts=[f"5.5.0.{i}:443" for i in range(11)])
    rogue = DetectedAgent(4242, "exfil-probe", proc, sanctioned=False, score=100,
                          reasons=[Reason("touched decoy credentials.env", 100, "tripwire")],
                          state="flagged", agent_id="rogue-1")
    g._detections = [rogue]
    g._evaluate(rogue)
    print(f"   rogue state: {rogue.state} | revoked: {g.registry.is_revoked('rogue-1')}")

    rule("3. The registry rejects a forged revocation (no DoS weaponization)")
    forged = Revocation("researcher", "shutdown", "attacker", 0.0, "ed25519:AAAA")
    print(f"   forged revocation accepted? {g.registry.submit(forged)}  (expected False)")
    print(f"   researcher still live?      {not g.registry.is_revoked(ident.agent_id)}")

    rule("4. The audit is tamper-evident and PQ-signed")
    ok, _ = g.audit.verify()
    print(f"   chain intact: {ok} | entries: {len(g.audit)} | scheme: {g.signer.scheme}")
    g.audit._entries[1].data["x"] = "tampered"
    broken, at = g.audit.verify()
    print(f"   after tampering: intact={broken} (broke at #{at})")

    rule("5. Attestation of oversight state")
    g.audit._entries[1].data.pop("x", None)  # undo tamper for a clean attestation
    att = g.attest()
    print(f"   notary: {att['notary']} | signed: {att['signature'] is not None}")
    print("\nStandalone — no partners required. With sentinel-vision installed, the")
    print("binary would be scanned, egress firewalled, and the agent vaulted with rollback.")


if __name__ == "__main__":
    main()
