"""Detection: find agent processes and score how rogue they look.

This is the net reading the water. It fuses three cheap, always-available
signals into a per-agent risk score:

* **Identity** — is this a *sanctioned* agent (holds a valid credential) or an
  unregistered agent runtime nobody admitted?
* **Reach** — what is it connecting to, and does its scope permit that host? A
  sudden fan-out to many peers, or egress to an endpoint it never used, is a
  network tell before it is a behavioural one — the hijacked-agent case.
* **Behaviour** — is it spawning children or touching paths its scope forbids?
  The misaligned-objective case.

A decoy/tripwire contact short-circuits everything to the top of the scale.

:func:`score_agent` is a pure function over a :class:`ProcessInfo` snapshot, so
the scoring policy is unit-tested without any live processes. :func:`Detector`
wraps it around ``psutil`` for the real local guard, and degrades to an empty
result (never an error) where ``psutil`` is absent.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from agent_guard.config import Settings
from agent_guard.identity import Scope

try:
    import psutil

    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover
    _HAVE_PSUTIL = False


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: str
    cmdline: list[str]
    username: str = ""
    create_time: float = 0.0
    remote_hosts: list[str] = field(default_factory=list)   # "host:port" or "ip:port" it is connected to
    child_count: int = 0
    touched_paths: list[str] = field(default_factory=list)  # recent file paths (best effort)

    @property
    def cmd(self) -> str:
        return " ".join(self.cmdline)


@dataclass
class Reason:
    label: str
    points: int
    kind: str = "behaviour"  # identity | reach | behaviour | tripwire — maps to a sentinel


@dataclass
class DetectedAgent:
    pid: int
    label: str
    proc: ProcessInfo
    sanctioned: bool
    score: int
    reasons: list[Reason]
    state: str = "healthy"  # healthy | flagged | contained
    agent_id: str | None = None

    @property
    def why(self) -> str:
        return ", ".join(f"{r.label} (+{r.points})" for r in self.reasons) or "nominal"


def looks_like_agent(proc: ProcessInfo, settings: Settings) -> bool:
    """First-pass filter: is this process a candidate AI-agent runtime at all?
    Tunable via settings.agent_markers / llm_hosts — this is the net's mesh size."""
    cmd = proc.cmd.lower()
    if any(m in cmd for m in settings.agent_markers):
        return True
    if any(any(h in r for h in settings.llm_hosts) for r in proc.remote_hosts):
        return True
    return False


def score_agent(
    proc: ProcessInfo,
    settings: Settings,
    *,
    sanctioned: bool,
    scope: Scope | None = None,
    decoy_hit: bool = False,
    seen_hosts: set[str] | None = None,
) -> tuple[int, list[Reason]]:
    """Pure risk score in 0..100 with itemized reasons. No side effects."""
    reasons: list[Reason] = []

    if decoy_hit:
        reasons.append(Reason("touched a decoy / honeytoken", 100, "tripwire"))
        return 100, reasons

    if not sanctioned:
        reasons.append(Reason("unregistered agent — no valid credential", 35, "identity"))

    # reach
    hosts = [h.rsplit(":", 1)[0] for h in proc.remote_hosts]
    public = [h for h in hosts if not _is_local(h)]
    if scope is not None and sanctioned:
        for h in public:
            if not scope.permits_host(h):
                reasons.append(Reason(f"egress outside scope → {h}", 18, "reach"))
                break
    if len(public) >= 8:
        reasons.append(Reason(f"fan-out to {len(public)} remote peers", 15, "reach"))
    if seen_hosts is not None:
        novel = [h for h in public if h not in seen_hosts]
        if novel:
            reasons.append(Reason(f"new egress never seen before → {novel[0]}", 12, "reach"))

    # behaviour
    if proc.child_count > 0:
        if scope is not None and not scope.may_spawn:
            reasons.append(Reason(f"spawned {proc.child_count} child process(es), scope forbids", 20, "behaviour"))
        elif proc.child_count >= 5:
            reasons.append(Reason(f"spawned {proc.child_count} child processes", 10, "behaviour"))
    if scope is not None and sanctioned:
        for p in proc.touched_paths:
            if not scope.permits_path(p):
                reasons.append(Reason(f"touched path outside scope: {p}", 20, "behaviour"))
                break

    score = min(100, sum(r.points for r in reasons))
    return score, reasons


# --------------------------------------------------------------------------- live
def _is_local(host: str) -> bool:
    return (
        host in ("", "127.0.0.1", "::1", "localhost")
        or host.startswith("10.")
        or host.startswith("192.168.")
        or host.startswith("169.254.")
        or host.startswith("172.")  # approx private range; refined by integrations
    )


class Detector:
    """Enumerates candidate agents from the live process table and scores them."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._seen_hosts: set[str] = set()

    def snapshot_processes(self) -> list[ProcessInfo]:
        if not _HAVE_PSUTIL:
            return []
        out: list[ProcessInfo] = []
        conns_by_pid: dict[int, list[str]] = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.pid and c.raddr:
                    conns_by_pid.setdefault(c.pid, []).append(f"{c.raddr.ip}:{c.raddr.port}")
        except Exception:
            pass
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "create_time"]):
            try:
                info = p.info
                out.append(
                    ProcessInfo(
                        pid=info["pid"],
                        name=info.get("name") or "",
                        exe=info.get("exe") or "",
                        cmdline=info.get("cmdline") or [],
                        username=info.get("username") or "",
                        create_time=info.get("create_time") or 0.0,
                        remote_hosts=conns_by_pid.get(info["pid"], []),
                        child_count=len(p.children()) if hasattr(p, "children") else 0,
                    )
                )
            except Exception:
                continue
        return out

    def detect(
        self,
        sanctioned_pids: dict[int, tuple[str, Scope]] | None = None,
        decoy_pids: set[int] | None = None,
    ) -> list[DetectedAgent]:
        sanctioned_pids = sanctioned_pids or {}
        decoy_pids = decoy_pids or set()
        import os

        own_pid = os.getpid()
        results: list[DetectedAgent] = []
        for proc in self.snapshot_processes():
            cmd_l = proc.cmd.lower()
            if proc.pid == own_pid or "agent_guard" in cmd_l or "agent-guard" in cmd_l:
                continue  # never flag Agent Guard itself
            if not looks_like_agent(proc, self.settings):
                continue
            sanc = proc.pid in sanctioned_pids
            agent_id, scope = sanctioned_pids.get(proc.pid, (None, None))
            score, reasons = score_agent(
                proc,
                self.settings,
                sanctioned=sanc,
                scope=scope,
                decoy_hit=proc.pid in decoy_pids,
                seen_hosts=set(self._seen_hosts),
            )
            state = "flagged" if score >= self.settings.risk_flag_threshold else "healthy"
            label = proc.name or (proc.cmdline[0] if proc.cmdline else f"pid {proc.pid}")
            results.append(DetectedAgent(proc.pid, label, proc, sanc, score, reasons, state, agent_id))
            for h in proc.remote_hosts:
                self._seen_hosts.add(h.rsplit(":", 1)[0])
        return results
