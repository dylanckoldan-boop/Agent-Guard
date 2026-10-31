"""The AgentGuard facade — wires every layer together for the CLI and GUI.

This is the one object the rest of the app talks to. It builds the trust fabric
(signer, trust domain, signed registry, tamper-evident audit), the net (tripwire,
detector), the pacify ladder (response + containment), and the oversight mesh
(consensus + mix channel); detects partners once at startup; and exposes
high-level operations: register a sanctioned agent, scan the fleet, decide, and
pacify or release.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from agent_guard import config
from agent_guard.config import Settings
from agent_guard.crypto import AuditLog, deserialize_signer, new_signer, serialize_signer
from agent_guard.detect import DetectedAgent, Detector, Reason
from agent_guard.identity import AgentIdentity, Credential, Scope, TrustDomain
from agent_guard.integrations import cryptomigrate as cm_integ
from agent_guard.integrations import partner_status
from agent_guard.integrations import sentinel_vision as sv_integ
from agent_guard.mesh import Consensus, MeshSnapshot, MixChannel
from agent_guard.quarantine import Quarantine
from agent_guard.registry import RevocationRegistry
from agent_guard.response import RUNG_BY_NAME, Containment, Response, Rung
from agent_guard.tripwire import Tripwire

try:
    import psutil

    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover
    _HAVE_PSUTIL = False

Alert = Callable[[str, str, str], None]  # (title, text, level)

# Interpreters whose *script argument* is the agent, not the interpreter binary.
# Quarantining the interpreter would neutralize every Python/Node process on the
# box; the artifact to isolate is the script it was told to run (see AG-A05).
_INTERPRETERS = frozenset({
    "python", "pythonw", "py", "node", "nodejs", "deno", "bun",
    "ruby", "perl", "php", "bash", "sh", "zsh", "dash",
})


def _is_interpreter(path: str) -> bool:
    if not path:
        return False
    base = os.path.basename(path).lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base in _INTERPRETERS or base.rstrip("0123456789.") in _INTERPRETERS


def _script_from_cmdline(cmdline: list[str]) -> str | None:
    """The script path an interpreter was told to run: the first positional
    argument after the interpreter. ``-m module`` has no script file to isolate."""
    for arg in cmdline[1:]:
        if arg == "-m":
            return None
        if arg.startswith("-"):
            continue
        return arg
    return None


def _quarantine_target(proc) -> str | None:
    """What to quarantine for a process: the agent's own binary, or — when it is
    run by an interpreter — the script, never the shared interpreter (AG-A05)."""
    exe = getattr(proc, "exe", None) or ""
    cmdline = list(getattr(proc, "cmdline", None) or [])
    if _is_interpreter(exe) or (not exe and cmdline and _is_interpreter(cmdline[0])):
        # The script the interpreter runs, or None for a `-m module` run — NEVER
        # the interpreter itself. Quarantining the shared interpreter would take
        # out every Python/Node process on the box (AG-A05).
        return _script_from_cmdline(cmdline)
    return exe or None


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
        # trust fabric — persisted under the data root so the circle's keypair,
        # the audit chain and the revocation set all survive a restart (AG-A03).
        state = config.sub_dir("state")
        self.signer = self._load_or_create_signer()  # the circle authority
        self.audit = AuditLog(self.signer, path=state / "audit.json")
        self.trust = TrustDomain(self.signer)
        self.registry = RevocationRegistry(self.signer.verifier(), self.audit, path=state / "revocations.json")
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
        # kept for mirroring containment records into sentinel-vision's protected log
        self.sv = sv_integ.SentinelVisionAdapter() if self.partners.sentinel_vision else None
        self.response = Response(self.registry, self.signer, self.audit, self.containment, escalate=self._escalate)
        # state
        self._sanctioned: dict[str, AgentIdentity] = {}
        self._suspended: dict[int, DetectedAgent] = {}  # agents we froze, re-checked each scan (AG-A08)
        self._detections: list[DetectedAgent] = []
        self.alert_listeners: list[Alert] = []
        self._lock = threading.Lock()
        self._load_agents()  # restore sanctioned identities from a previous run
        self.audit.append("guard.start", {"scheme": self.signer.scheme, "partners": self.partners.__dict__})

    # ------------------------------------------------------------------ persistence
    def _load_or_create_signer(self):
        """Load the circle's keypair from the owner-only keystore, or mint and save
        one on first run. Reusing the keypair keeps every prior credential, audit
        signature and revocation verifiable after a restart (AG-A03)."""
        p = config.sub_dir("keys") / "circle.json"
        if p.exists():
            try:
                return deserialize_signer(json.loads(p.read_text("utf-8")))
            except Exception:
                pass  # unreadable/stale keystore: mint a fresh authority below
        signer = new_signer(self.settings.signer_scheme)
        try:
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(serialize_signer(signer)), "utf-8")
            tmp.replace(p)
            if os.name == "posix":
                p.chmod(0o600)
        except OSError:
            pass
        return signer

    def _agents_path(self):
        return config.sub_dir("state") / "agents.json"

    def _load_agents(self) -> None:
        try:
            raw = json.loads(self._agents_path().read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        for a in raw:
            try:
                sc = a["scope"]
                scope = Scope(
                    frozenset(sc["actions"]), frozenset(sc["hosts"]),
                    frozenset(sc["paths"]), bool(sc["spawn"]),
                )
                cred = Credential(a["agent_id"], scope, a["issuer_ref"], a["issued_at"], a["signature"])
                self._sanctioned[a["agent_id"]] = AgentIdentity(
                    a["agent_id"], a["label"], cred, a.get("pid"), a.get("registered_at", time.time())
                )
            except (KeyError, TypeError):
                continue

    def _save_agents(self) -> None:
        data = []
        for i in self._sanctioned.values():
            s = i.credential.scope
            data.append({
                "agent_id": i.agent_id, "label": i.label, "pid": i.pid, "registered_at": i.registered_at,
                "issuer_ref": i.credential.issuer_ref, "issued_at": i.credential.issued_at,
                "signature": i.credential.signature,
                "scope": {
                    "actions": sorted(s.allowed_actions), "hosts": sorted(s.allowed_hosts),
                    "paths": sorted(s.allowed_path_prefixes), "spawn": s.may_spawn,
                },
            })
        try:
            p = self._agents_path()
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), "utf-8")
            tmp.replace(p)
        except OSError:
            pass

    # ------------------------------------------------------------------ admission
    def register_agent(self, label: str, scope: Scope, pid: int | None = None) -> AgentIdentity:
        agent_id = f"agent-{len(self._sanctioned) + 1}-{int(time.time())}"
        cred = self.trust.issue(agent_id, scope)
        ident = AgentIdentity(agent_id, label, cred, pid)
        self._sanctioned[agent_id] = ident
        self._save_agents()
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
            self._recheck_suspended()  # re-freeze anything resumed since the last scan (AG-A08)
            detections = self.detector.detect(self._sanctioned_pids(), decoy_pids)
            for d in detections:
                self._note_canary_contact(d)  # a touched canary is a decoy hit (AG-A02)
                self._evaluate(d)
            self._detections = detections
            return detections

    def _note_canary_contact(self, d: DetectedAgent) -> None:
        if any(r.kind == "tripwire" for r in d.reasons):
            return  # already scored as a decoy hit (e.g. via decoy_pids)
        for path in d.proc.touched_paths:
            decoy_id = self.tripwire.is_canary(path)
            if decoy_id:
                self.tripwire.on_contact(d.agent_id or f"pid:{d.pid}", decoy_id, d.pid, f"touched canary {path}")
                d.score = 100
                d.reasons = [Reason("touched a decoy / honeytoken", 100, "tripwire")]
                d.state = "flagged"
                return

    def _recheck_suspended(self) -> None:
        """Re-freeze any agent we suspended that has since been resumed — by the
        agent itself or a helper it started. The resume is logged and alerted as
        tamper, and the suspension is reasserted (AG-A08)."""
        if not _HAVE_PSUTIL:
            return
        for pid, d in list(self._suspended.items()):
            ct = getattr(d.proc, "create_time", None) or None
            try:
                p = psutil.Process(pid)
                if ct and abs(p.create_time() - ct) > 1.0:
                    del self._suspended[pid]  # PID reused: our agent is gone
                    continue
                if p.status() != psutil.STATUS_STOPPED:
                    self._alert(
                        "Containment tamper detected",
                        f"{d.label} (pid {pid}) was resumed after suspension — re-freezing",
                        "danger",
                    )
                    self.containment.suspend(pid, ct)
                    self.audit.append("containment.retrip", {"agent": d.agent_id or f"pid:{pid}", "pid": pid})
            except Exception:
                self._suspended.pop(pid, None)  # process is gone

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
        exe = _quarantine_target(d.proc)
        results = self.response.pacify(d, target, auto=auto, exe_path=exe)
        d.state = "contained"
        if d.pid is not None:
            if target == Rung.SUSPEND:
                self._suspended[d.pid] = d  # watch for a tamper-resume (AG-A08)
            elif target >= Rung.TERMINATE:
                self._suspended.pop(d.pid, None)
        self._alert("Agent pacified", f"{d.label} (pid {d.pid}) contained → {target.name.lower()}", "danger")
        self._mirror_to_protected_log(
            {
                "event": "pacify",
                "agent": d.agent_id or f"pid:{d.pid}",
                "pid": d.pid,
                "rung": target.name.lower(),
                "auto": auto,
                "audit_head": self.audit.head,
                "audit_signature": self.audit.sign_head(),
            }
        )
        return results

    def _mirror_to_protected_log(self, record: dict) -> None:
        """When sentinel-vision is present, also append the record to its
        tamper-proof, append-only plugin log, so a compromised agent cannot erase
        its own containment record even if it reaches Agent Guard's own store."""
        if self.sv is None:
            return
        try:
            self.sv.plugin_log_append(record)
        except Exception:
            pass

    def release(self, d: DetectedAgent):
        res = self.response.release(d)
        if d.pid is not None:
            self._suspended.pop(d.pid, None)  # cleared: stop watching it for tamper
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
