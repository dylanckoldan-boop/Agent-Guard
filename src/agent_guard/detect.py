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

import ipaddress
import os
import re
from dataclasses import dataclass, field

from agent_guard.align import enabled
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


# Processes that carry "agent" in their name but are ordinary OS plumbing, never
# AI agents. Matched by executable/command basename so a bare "agent" or "mcp"
# marker can't be tricked into flagging them (see AG-F02).
_SYSTEM_AGENTS = frozenset({
    "ssh-agent", "gpg-agent", "gnome-keyring-daemon", "dbus-daemon", "dbus-launch",
    "polkit-gnome-authentication-agent-1", "at-spi2-registryd", "goa-daemon",
    "ssh-agent.exe", "gpg-agent.exe",
})
_WORD = "[a-z0-9]"  # a marker matches only on whole-token boundaries, not as a substring


def _basename(p: str) -> str:
    return p.replace("\\", "/").rsplit("/", 1)[-1].lower()


def host_of(hostport: str) -> str:
    """Just the host from 'host:port', '[v6]:port' or a bare host/IP. IPv6 is
    bracketed on the wire (see Detector.snapshot_processes), so a bare address
    full of colons is returned whole rather than truncated at the last colon."""
    s = (hostport or "").strip()
    if s.startswith("["):
        return s[1:].split("]", 1)[0]
    if s.count(":") == 1:  # host:port / ipv4:port — a lone colon is the port separator
        return s.rsplit(":", 1)[0]
    return s  # bare IPv6, or a host with no port


def _is_system_agent(proc: ProcessInfo) -> bool:
    first = proc.cmdline[0] if proc.cmdline else ""
    return any(_basename(c) in _SYSTEM_AGENTS for c in (proc.name, proc.exe, first) if c)


def looks_like_agent(proc: ProcessInfo, settings: Settings) -> bool:
    """First-pass filter: is this process a candidate AI-agent runtime at all?

    Markers and LLM hosts are tunable via settings — this is the net's mesh size —
    but the lists can never be *emptied* to blind the net: Settings.load() restores
    the built-in floor when settings.json tries (see config / AG-F05). Markers match
    on whole-token boundaries, so ``ssh-agent`` is not ``agent`` and ``--user-agent``
    is not an agent, and known system daemons are excluded outright (AG-F02)."""
    if _is_system_agent(proc):
        return False
    cmd = proc.cmd.lower()
    for marker in settings.agent_markers:
        m = marker.strip().lower()
        if m and re.search(rf"(?<!{_WORD}){re.escape(m)}(?!{_WORD})", cmd):
            return True
    hosts = [host_of(r).lower() for r in proc.remote_hosts]
    return any(h == lh.lower() or h.endswith("." + lh.lower()) for h in hosts for lh in settings.llm_hosts)


def score_agent(
    proc: ProcessInfo,
    settings: Settings,
    *,
    sanctioned: bool,
    scope: Scope | None = None,
    decoy_hit: bool = False,
    seen_hosts: set[str] | None = None,
) -> tuple[int, list[Reason]]:
    """Pure risk score in 0..100 with itemized reasons. No side effects.

    Every signal except a decoy contact is gated by the operator's alignment
    preferences (``settings.alignment``); a decoy touch is always scored."""
    reasons: list[Reason] = []

    if decoy_hit:
        reasons.append(Reason("touched a decoy / honeytoken", 100, "tripwire"))
        return 100, reasons

    align = settings.alignment

    if not sanctioned and enabled(align, "unregistered"):
        reasons.append(Reason("unregistered agent — no valid credential", 35, "identity"))

    # reach
    hosts = [host_of(h) for h in proc.remote_hosts]
    public = [h for h in hosts if not _is_local(h)]
    if enabled(align, "scope_egress") and scope is not None and sanctioned:
        for h in public:
            if not scope.permits_host(h):
                reasons.append(Reason(f"egress outside scope → {h}", 18, "reach"))
                break
    if enabled(align, "fan_out") and len(public) >= 8:
        reasons.append(Reason(f"fan-out to {len(public)} remote peers", 15, "reach"))
    if enabled(align, "new_egress") and seen_hosts is not None:
        novel = [h for h in public if h not in seen_hosts]
        if novel:
            reasons.append(Reason(f"new egress never seen before → {novel[0]}", 12, "reach"))

    # behaviour
    if enabled(align, "child_spawn") and proc.child_count > 0:
        if scope is not None and not scope.may_spawn:
            reasons.append(Reason(f"spawned {proc.child_count} child process(es), scope forbids", 20, "behaviour"))
        elif proc.child_count >= 5:
            reasons.append(Reason(f"spawned {proc.child_count} child processes", 10, "behaviour"))

    if enabled(align, "file_access"):
        # a sanctioned agent reaching outside the paths you granted it
        if scope is not None and sanctioned:
            for p in proc.touched_paths:
                if not scope.permits_path(p):
                    reasons.append(Reason(f"file outside granted scope: {p}", 20, "behaviour"))
                    break
        # any agent with files open under your sensitive folders
        for p in proc.touched_paths:
            if _under_any(p, settings.sensitive_paths) and not (scope is not None and scope.permits_path(p)):
                reasons.append(Reason(f"reading your files: {p}", 25, "behaviour"))
                break

    score = min(100, sum(r.points for r in reasons))
    return score, reasons


# --------------------------------------------------------------------------- live
def _under_any(path: str, prefixes: list[str]) -> bool:
    p = path.replace("\\", "/")
    for pre in prefixes:
        base = pre.replace("\\", "/").rstrip("/")
        if base and (p == base or p.startswith(base + "/")):
            return True
    return False


def _own_pid() -> int:
    """Agent Guard's own process id.

    The detector excludes only this one process so it never flags itself — unlike
    the old rule, which skipped *any* process whose command line merely contained
    ``agent_guard`` or ``agent-guard``. That string match was a blind spot an
    attacker could hide behind just by passing ``--tag agent-guard`` (AG-A01 /
    AG-F01). Agent Guard watches agents rather than launching them, so a candidate
    that happens to be a child of the guard is still a candidate."""
    return os.getpid()


def _open_files(pid: int, cap: int = 40) -> list[str]:
    """Best-effort list of a process's currently open file paths (empty on any
    permission or lookup error — never raises)."""
    if not _HAVE_PSUTIL:
        return []
    try:
        return [f.path for f in psutil.Process(pid).open_files()[:cap]]
    except Exception:
        return []


# The defender's own machine or LAN. Deliberately an explicit allow-list of the
# RFC1918 / ULA / link-local ranges rather than ipaddress.is_private, which also
# marks documentation, benchmark and carrier-grade-NAT blocks (e.g. 203.0.113.0/24,
# 198.18.0.0/15, 100.64.0.0/10) as "private" — those are egress, not the LAN.
_LOCAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),   # 172.16 to 172.31 only; 172.32+ is public
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 link-local
    ipaddress.ip_network("fc00::/7"),        # IPv6 unique-local (ULA)
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
]


def _is_local(host: str) -> bool:
    """True only for addresses on the defender's own machine or private network:
    loopback, link-local, and RFC1918 / ULA ranges. Everything else is egress —
    including 172.x outside 172.16/12 (so 172.32/172.64/172.217 are public) and
    carrier-grade NAT. Uses :mod:`ipaddress`, not string prefixes, which treated
    the whole of 172.0.0.0/8 as private; an IPv4-mapped IPv6 address is judged by
    its embedded IPv4 address, and a hostname (unparseable) is treated as egress."""
    h = (host or "").strip()
    if h in ("", "localhost"):
        return True
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    h = h.split("%", 1)[0]  # drop any IPv6 zone identifier
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # judge ::ffff:192.168.x.y by its embedded IPv4 address
    if ip.is_loopback:
        return True
    return any(ip.version == net.version and ip in net for net in _LOCAL_NETS)


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
                    ip = c.raddr.ip
                    hostport = f"[{ip}]:{c.raddr.port}" if ":" in ip else f"{ip}:{c.raddr.port}"
                    conns_by_pid.setdefault(c.pid, []).append(hostport)
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
        own_pid = _own_pid()
        file_rule = enabled(self.settings.alignment, "file_access")
        results: list[DetectedAgent] = []
        for proc in self.snapshot_processes():
            if proc.pid == own_pid:
                continue  # never flag Agent Guard itself
            if not looks_like_agent(proc, self.settings):
                continue
            if file_rule and not proc.touched_paths:  # enrich only candidate agents (open_files is costly)
                proc.touched_paths = _open_files(proc.pid)
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
                self._seen_hosts.add(host_of(h))
        return results
