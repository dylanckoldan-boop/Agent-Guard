"""The AgentGuard facade — wires every layer together for the CLI and GUI.

This is the one object the rest of the app talks to. It builds the trust fabric
(signer, trust domain, signed registry, tamper-evident audit), the net (tripwire,
detector), the pacify ladder (response + containment), and the oversight mesh
(consensus + mix channel); detects partners once at startup; and exposes
high-level operations: register a sanctioned agent, scan the fleet, decide, and
pacify or release.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from agent_guard.config import Settings
from agent_guard.crypto import AuditLog, new_signer
from agent_guard.detect import DetectedAgent, Detector
from agent_guard.identity import AgentIdentity, Scope, TrustDomain
from agent_guard.integrations import cryptomigrate as cm_integ
from agent_guard.integrations import partner_status
from agent_guard.integrations import sentinel_vision as sv_integ
from agent_guard.mesh import Consensus, MeshSnapshot, MixChannel
from agent_guard.quarantine import Quarantine
from agent_guard.registry import RevocationRegistry
from agent_guard.response import Containment, Response, Rung, RUNG_BY_NAME
from agent_guard.tripwire import Tripwire

Alert = Callable[[str, str, str], None]  # (title, text, level)


@dataclass
class GuardSnapshot:
    total_agents: int
    healthy: int
    flagged: int
    contained: int
    revoked: int
    trips: int
    audit_len: int
    audit_ok: bool
    partners: dict
    detections: list = field(default_factory=list)
    mesh: MeshSnapshot | None = None


class AgentGuard:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.load()
        # trust fabric
        self.signer = new_signer(self.settings.signer_scheme)  # the circle authority
        self.audit = AuditLog(self.signer)
        self.trust = TrustDomain(self.signer)
        self.registry = RevocationRegistry(self.signer.verifier(), self.audit)
        # net
        self.tripwire = Tripwire(self.audit)
        self.quarantine = Quarantine()
        self.detector = Detector(self.settings)
        # mesh
        self.consensus = Consensus(threshold=float(self.settings.risk_contain_threshold))
        self.mix = MixChannel(enabled=self.settings.mix_oversight_traffic, min_cover=self.settings.mix_min_cover)
        # partners + pacify ladder
        self.partners = partner_status()
        self.containment: Containment = (
            sv_integ.make_containment(self.quarantine)
            if self.partners.sentinel_vision
            else Containment(self.quarantine)
        )
        self.response = Response(self.registry, self.signer, self.audit, self.containment, escalate=self._escalate)
        # state
        self._sanctioned: dict[str, AgentIdentity] = {}
        self._detections: list[DetectedAgent] = []
        self.alert_listeners: list[Alert] = []
        self._lock = threading.Lock()
        self.audit.append("guard.start", {"scheme": self.signer.scheme, "partners": self.partners.__dict__})

    # ------------------------------------------------------------------ admission
    def register_agent(self, label: str, scope: Scope, pid: int | None = None) -> AgentIdentity:
        agent_id = f"agent-{len(self._sanctioned) + 1}-{int(time.time())}"
        cred = self.trust.issue(agent_id, scope)
        ident = AgentIdentity(agent_id, label, cred, pid)
        self._sanctioned[agent_id] = ident
        self.audit.append("admission.registered", {"agent": agent_id, "label": label, "pid": pid})
        return ident

    def sanctioned(self) -> list[AgentIdentity]:
        return list(self._sanctioned.values())

    def _sanctioned_pids(self) -> dict[int, tuple[str, Scope]]:
        return {
            i.pid: (i.agent_id, i.credential.scope)
            for i in self._sanctioned.values()
            if i.pid is not None and not self.registry.is_revoked(i.agent_id)
        }

    # ------------------------------------------------------------------ the net
    def plant_canaries(self, directories: list[str]) -> list[str]:
        planted = self.tripwire.plant_canaries(directories)
        self.audit.append("tripwire.planted", {"count": len(planted)})
        return planted

    def scan(self, decoy_pids: set[int] | None = None) -> list[DetectedAgent]:
        """Run the detector, update per-agent state through consensus, and emit
        oversight records through the mix channel."""
        with self._lock:
            detections = self.detector.detect(self._sanctioned_pids(), decoy_pids)
            for d in detections:
                self._evaluate(d)
            self._detections = detections
            return detections

    def _evaluate(self, d: DetectedAgent) -> None:
        contrib: dict[str, float] = {}
        decoy = False
        for r in d.reasons:
            contrib[r.kind] = contrib.get(r.kind, 0.0) + r.points
            if r.kind == "tripwire":
                decoy = True
        decision = self.consensus.decide(contrib, decoy=decoy)
        # oversight record goes through the 'many doors' channel (not the agent's traffic)
        self.mix.emit(
            {"kind": "vote", "agent": d.agent_id or f"pid:{d.pid}", "risk": d.score},
            urgent=False,
        )
        if d.score >= self.settings.risk_flag_threshold and d.state != "contained":
            d.state = "flagged"
            self.audit.append("detect.flagged", {"pid": d.pid, "score": d.score, "why": d.why})
            self._alert("Rogue agent flagged", f"{d.label} (pid {d.pid}) — {d.why}", "warning" if d.score < 85 else "danger")
        # auto-contain only on a decoy touch (zero-false-positive signal)
        if decoy and self.settings.auto_contain_on_decoy:
            self.pacify(d, auto=True)
        elif decision.contain and not self.settings.report_only:
            self.pacify(d, auto=True)

    # ------------------------------------------------------------------ pacify
    def pacify(self, d: DetectedAgent, rung: str | None = None, *, auto: bool = False):
        target = RUNG_BY_NAME.get(
            (rung or self.settings.auto_contain_max_rung).lower(), Rung.SUSPEND
        )
        exe = d.proc.exe or None
        results = self.response.pacify(d, target, auto=auto, exe_path=exe)
        d.state = "contained"
        self._alert("Agent pacified", f"{d.label} (pid {d.pid}) contained → {target.name.lower()}", "danger")
        return results

    def release(self, d: DetectedAgent):
        res = self.response.release(d)
        self._alert("Agent released", f"{d.label} (pid {d.pid}) resumed", "info")
        return res

    # ------------------------------------------------------------------ attestation
    def attest(self) -> dict:
        ok, _ = self.audit.verify()
        state = {
            "audit_head": self.audit.head,
            "audit_len": len(self.audit),
            "audit_intact": ok,
            "revocations": len(self.registry),
            "sanctioned": len(self._sanctioned),
            "containments": len(self.response.history),
        }
        return cm_integ.CryptomigrateAdapter().attest(state, self.signer)

    # ------------------------------------------------------------------ snapshot
    def snapshot(self) -> GuardSnapshot:
        dets = self._detections
        healthy = sum(1 for d in dets if d.state == "healthy")
        flagged = sum(1 for d in dets if d.state == "flagged")
        contained = sum(1 for d in dets if d.state == "contained")
        ok, _ = self.audit.verify()
        mesh = MeshSnapshot(
            core_state="containing" if contained else ("deciding" if flagged else "nominal"),
            sentinels=[{"name": s.name, "kind": s.kind, "weight": s.weight} for s in self.consensus.sentinels],
            agents=[{"label": d.label, "state": d.state, "score": d.score} for d in dets],
            mix_enabled=self.mix.enabled,
            mix_cover_ratio=(self.mix.stats.cover_emitted / self.mix.stats.total) if self.mix.stats.total else 0.0,
        )
        return GuardSnapshot(
            total_agents=len(dets),
            healthy=healthy,
            flagged=flagged,
            contained=contained,
            revoked=len(self.registry),
            trips=self.tripwire.trips,
            audit_len=len(self.audit),
            audit_ok=ok,
            partners=self.partners.__dict__,
            detections=dets,
            mesh=mesh,
        )

    # ------------------------------------------------------------------ alerts
    def _alert(self, title: str, text: str, level: str = "info") -> None:
        if self.settings.quiet_mode and level == "info":
            return
        for fn in list(self.alert_listeners):
            try:
                fn(title, text, level)
            except Exception:
                pass

    def _escalate(self, ev: dict) -> None:
        self._alert("Escalated to operator", f"agent {ev.get('agent')} contained ({ev.get('up_to')})", "warning")
