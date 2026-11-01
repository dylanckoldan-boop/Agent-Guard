"""The Foldward facade — wires every layer together for the CLI and GUI.

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

from foldward import config
from foldward.config import Settings
from foldward.crypto import (
    AuditLog,
    deserialize_signer,
    new_signer,
    post_quantum_available,
    serialize_signer,
)
from foldward.detect import DetectedAgent, Detector, Reason
from foldward.identity import AgentIdentity, Credential, Scope, TrustDomain
from foldward.integrations import cryptomigrate as cm_integ
from foldward.integrations import partner_status
from foldward.integrations import sentinel_vision as sv_integ
from foldward.mesh import Consensus, MeshSnapshot, MixChannel
from foldward.osutil import write_private
from foldward.pending import PendingCopies
from foldward.quarantine import Quarantine
from foldward.registry import RevocationRegistry
from foldward.response import RUNG_BY_NAME, Containment, Response, Rung
from foldward.tripwire import Tripwire

try:
    import psutil

    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover
    _HAVE_PSUTIL = False

Alert = Callable[[str, str, str], None]  # (title, text, level)

# Runtimes whose *script argument* is the agent, not the runtime binary. Quarantining
# the runtime would neutralize every program that uses it (every Python, Node or Java
# program on the machine), so the artifact to isolate is the script it was told to
# run, or nothing (AG-A05). For each runtime: the options that mean "no script file"
# (code given inline, a module or class name), the options that take a separate
# value, and subcommands that come before the script.
_RUNTIMES: dict[str, tuple[frozenset[str], frozenset[str], frozenset[str]]] = {}


def _runtime(names: str, no_script: str = "", takes_value: str = "", subcommands: str = "") -> None:
    rule = (frozenset(no_script.split()), frozenset(takes_value.split()), frozenset(subcommands.split()))
    for n in names.split():
        _RUNTIMES[n] = rule


_runtime("python pythonw py", "-m -c", "-W -X --check-hash-based-pycs")
_runtime("node nodejs", "-e --eval -p --print", "-r --require --import --loader --experimental-loader -C --conditions")
_runtime("deno", "eval", "--config -c --import-map --location --cert --seed --v8-flags", "run test bench serve")
_runtime("bun", "-e --eval -p --print", "-r --preload --cwd --env-file", "run x")
_runtime("ruby", "-e", "-r -I -C -E")
_runtime("perl", "-e -E", "-I -M -m")
_runtime("php", "-r -a", "-c -d -z")
_runtime("bash sh zsh dash ksh fish tcsh csh", "-c", "-o -O --rcfile --init-file")
_runtime("java javaw", "-m --module", "-cp -classpath --class-path -p --module-path --add-modules")
_runtime("dotnet mono", "", "", "exec")
_runtime("cscript wscript", "", "")
_runtime("osascript", "-e", "-l -s")
_runtime("rscript", "-e --expr", "")
_runtime("julia", "-e --eval -E --print", "-L --load -J --sysimage")
_runtime("lua luajit", "-e", "-l")
_runtime("tclsh wish", "", "")
# PowerShell and cmd: only an explicit script file counts (-File); a command line
# given inline has no file to isolate.
_POWERSHELL = frozenset({"powershell", "pwsh"})
_NO_SCRIPT_EVER = frozenset({"cmd"})
# Launchers start the real runtime as a child; the launcher binary is shared tooling.
_LAUNCHERS = frozenset({
    "uv", "uvx", "npx", "npm", "pnpm", "yarn", "pipx", "poetry", "pdm", "hatch", "conda", "mamba", "bunx",
})


def _runtime_name(path: str) -> str:
    base = os.path.basename(path.replace("\\", "/")).lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base.rstrip("0123456789.-") or base


def _is_interpreter(path: str) -> bool:
    if not path:
        return False
    name = _runtime_name(path)
    return name in _RUNTIMES or name in _POWERSHELL or name in _NO_SCRIPT_EVER or name in _LAUNCHERS


def _script_from_cmdline(cmdline: list[str], runtime: str = "python") -> str | None:
    """The script file a runtime was told to run, or None when there is none (code
    given inline, a module or class name, a launcher)."""
    if runtime in _LAUNCHERS or runtime in _NO_SCRIPT_EVER:
        return None
    args = list(cmdline[1:])
    if runtime in _POWERSHELL:
        for i, a in enumerate(args):
            if a.lower() in ("-file", "-f") and i + 1 < len(args):
                return args[i + 1]
        return None
    no_script, takes_value, subcommands = _RUNTIMES.get(runtime, _RUNTIMES["python"])
    skip_next = False
    seen_positional = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in no_script:
            return None
        if runtime in ("java", "javaw") and a == "-jar":
            continue  # the next argument is the jar: the agent's own file
        if a in takes_value:
            skip_next = True
            continue
        if a.startswith("//") and runtime in ("cscript", "wscript"):
            continue
        if a.startswith("-"):
            continue
        if not seen_positional and a.lower() in subcommands:
            seen_positional = True
            continue
        return a
    return None


def _quarantine_target(proc) -> str | None:
    """What to quarantine for a process: the agent's own binary, or — when it is run
    by a shared runtime — the script, never the runtime itself (AG-A05). A relative
    script path is resolved against the *agent's* working directory; without it
    nothing is returned, so Foldward never acts on a same-named file in its own
    folder (AG-N02)."""
    exe = getattr(proc, "exe", None) or ""
    cmdline = list(getattr(proc, "cmdline", None) or [])
    runtime_path = exe or (cmdline[0] if cmdline else "")
    if _is_interpreter(runtime_path):
        script = _script_from_cmdline(cmdline, _runtime_name(runtime_path))
        if not script:
            return None
        if os.path.isabs(script):
            return script
        cwd = getattr(proc, "cwd", "") or ""
        return os.path.normpath(os.path.join(cwd, script)) if cwd and os.path.isabs(cwd) else None
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
    warnings: list = field(default_factory=list)


class Foldward:
    # Time allowed per scan for checking whether programs that are not agent
    # candidates hold a canary open (AG-A02); the sweep resumes where it stopped.
    SWEEP_BUDGET_S = 0.5
    # After a failed copy to Sentinel Vision's protected log, wait this long before trying again (INT-05, INT-N02).
    MIRROR_RETRY_S = 60.0
    # How often to ask Sentinel Vision how full the protected log is, and the share that is reported (INT-N01).
    LOG_ROOM_CHECK_S = 6 * 3600.0
    LOG_ROOM_WARN_SHARE = 0.8
    # A full protected log is reported at most this often (INT-N01).
    LOG_FULL_REPORT_S = 3600.0

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.load()
        # Problems found at start-up that the operator should see: shown by `status`,
        # on the Overview page, and in the audit (AG-A09, AG-N04, AG-N05).
        self.warnings: list[str] = []
        # trust fabric — persisted under the data root so the circle's keypair,
        # the audit chain and the revocation set all survive a restart (AG-A03).
        state = config.sub_dir("state")
        self.signer = self._load_or_create_signer()  # the circle authority
        self.audit = AuditLog(self.signer, path=state / "audit.json")
        self.trust = TrustDomain(self.signer)
        self.registry = RevocationRegistry(self.signer.verifier(), self.audit, path=state / "revocations.json")
        # net
        self.tripwire = Tripwire(self.audit, path=state / "canaries.json")
        self.quarantine = Quarantine()
        self.detector = Detector(self.settings)
        # mesh
        self.consensus = Consensus(threshold=float(self.settings.risk_contain_threshold))
        self.mix = MixChannel(enabled=self.settings.mix_oversight_traffic, min_cover=self.settings.mix_min_cover)
        # partners + pacify ladder
        self.partners = partner_status()
        self.sv = sv_integ.SentinelVisionAdapter() if self.partners.sentinel_vision else None
        self.containment: Containment = (
            sv_integ.make_containment(self.quarantine, self.sv)
            if self.sv is not None
            else Containment(self.quarantine)
        )
        self.response = Response(self.registry, self.signer, self.audit, self.containment, escalate=self._escalate)
        # state
        self._sanctioned: dict[str, AgentIdentity] = {}
        self._suspended: dict[int, DetectedAgent] = {}  # agents we froze, re-checked each scan (AG-A08)
        self._detections: list[DetectedAgent] = []
        self._observed: set[tuple[int, str]] = set()  # (pid, canary) contacts already reported
        self._stale_reported: set[tuple[str, int]] = set()
        self._sweep_cursor = 0
        # protected-log records still to be copied, saved so they survive a restart (INT-05, INT-N02)
        self._pending = PendingCopies(state / "protected-log-queue.json")
        self._next_mirror_try = 0.0  # time.monotonic() before which a failed copy isn't retried
        self._next_room_check = 0.0  # time.monotonic() of the next check of the protected log's room
        self._full_reported = float("-inf")  # time.monotonic() a full protected log was last reported
        self.alert_listeners: list[Alert] = []
        self._lock = threading.Lock()
        self._load_agents()  # restore sanctioned identities from a previous run
        self._startup_checks()
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
                self.warnings.append(
                    "The saved signing key couldn't be read, so a new one was made. Agents registered "
                    "before need to be registered again."
                )
        signer = new_signer(self.settings.signer_scheme)
        try:
            write_private(p, json.dumps(serialize_signer(signer)).encode())  # owner-only from the start
        except OSError:
            pass
        return signer

    def _startup_checks(self) -> None:
        if self.audit.load_problem:
            kept = f" It was kept as {self.audit.kept_as}." if self.audit.kept_as else ""
            self.warnings.append(f"The audit log was damaged: {self.audit.load_problem}.{kept}")
            self.audit.append("audit.recovered", {"problem": self.audit.load_problem, "kept_as": self.audit.kept_as})
        else:
            ok, at = self.audit.verify()
            if not ok:
                self.warnings.append(f"The audit log's hash chain is broken at entry {at}: it was changed outside Foldward.")
        if self.registry.rejected_on_load:
            self.warnings.append(
                f"{self.registry.rejected_on_load} saved revocation(s) had no valid signature and were ignored."
            )
        if self._pending.load_problem:
            kept = f" It was kept as {self._pending.kept_as}." if self._pending.kept_as else ""
            self.warnings.append(
                "The list of containment records waiting for Sentinel Vision's protected log was damaged: "
                f"{self._pending.load_problem}.{kept} The records themselves are in Foldward's own audit."
            )
        elif len(self._pending):
            n = len(self._pending)
            where = "Foldward copies them when it can" if self.sv is not None else "Sentinel Vision isn't available now"
            self.warnings.append(
                f"{n} containment record(s) from an earlier run are still waiting to be copied to Sentinel Vision's "
                f"protected log; {where}. They are in Foldward's own audit meanwhile."
            )
        if "ML-DSA" not in self.signer.scheme:
            if post_quantum_available():
                self.warnings.append(
                    f"This install's signing key is {self.signer.scheme}, made without ML-DSA. Post-quantum signing "
                    "is off until a new key is made (see SECURITY.md, 'Signing keys')."
                )
            else:
                self.warnings.append(
                    f"Post-quantum signing is unavailable: this Python's `cryptography` package has no ML-DSA, so "
                    f"Foldward signs with {self.signer.scheme} only. Install cryptography 47 or newer."
                )
        for w in self.warnings:
            self.audit.append("guard.warning", {"text": w})

    def _agents_path(self):
        return config.sub_dir("state") / "agents.json"

    def _load_agents(self) -> None:
        try:
            raw = json.loads(self._agents_path().read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        rejected = 0
        for a in raw:
            try:
                sc = a["scope"]
                scope = Scope(
                    frozenset(sc["actions"]), frozenset(sc["hosts"]),
                    frozenset(sc["paths"]), bool(sc["spawn"]),
                )
                cred = Credential(a["agent_id"], scope, a["issuer_ref"], a["issued_at"], a["signature"])
                ct = a.get("pid_create_time")
                ct = float(ct) if isinstance(ct, (int, float)) and not isinstance(ct, bool) else None
            except (KeyError, TypeError, ValueError):
                rejected += 1
                continue
            # The saved file is only as trustworthy as the folder it sits in, so every
            # credential is verified again before it can sanction anything (AG-N04).
            try:
                valid = self.trust.verify(cred)
            except Exception:
                valid = False
            if not valid:
                rejected += 1
                self.audit.append("admission.rejected", {"agent": a.get("agent_id"), "reason": "bad_signature_on_disk"})
                continue
            self._sanctioned[a["agent_id"]] = AgentIdentity(
                a["agent_id"], a.get("label", ""), cred, a.get("pid"), a.get("registered_at", time.time()), ct
            )
        if rejected:
            self.warnings.append(
                f"{rejected} saved agent registration(s) had no valid signature and were ignored. If you didn't "
                "change state/agents.json yourself, another program did."
            )

    def _save_agents(self) -> None:
        data = []
        for i in self._sanctioned.values():
            s = i.credential.scope
            data.append({
                "agent_id": i.agent_id, "label": i.label, "pid": i.pid, "registered_at": i.registered_at,
                "pid_create_time": i.pid_create_time,
                "issuer_ref": i.credential.issuer_ref, "issued_at": i.credential.issued_at,
                "signature": i.credential.signature,
                "scope": {
                    "actions": sorted(s.allowed_actions), "hosts": sorted(s.allowed_hosts),
                    "paths": sorted(s.allowed_path_prefixes), "spawn": s.may_spawn,
                },
            })
        try:
            write_private(self._agents_path(), json.dumps(data).encode())
        except OSError:
            pass

    # ------------------------------------------------------------------ admission
    def register_agent(
        self, label: str, scope: Scope, pid: int | None = None, *, create_time: float | None = None
    ) -> AgentIdentity:
        """Sanction an agent. With ``pid``, the identity is bound to that running
        process: its start time is recorded, and a later process that reuses the PID
        is not sanctioned (AG-N04). ``create_time`` may be given when the caller
        already knows it; otherwise it is read from the live process."""
        if pid is not None and create_time is None:
            if not _HAVE_PSUTIL:
                raise ValueError("binding a registration to a PID needs psutil")
            try:
                create_time = psutil.Process(pid).create_time()
            except Exception as exc:
                raise ValueError(f"no running process with pid {pid}") from exc
        agent_id = f"agent-{len(self._sanctioned) + 1}-{int(time.time())}"
        cred = self.trust.issue(agent_id, scope)
        ident = AgentIdentity(agent_id, label, cred, pid, pid_create_time=create_time)
        self._sanctioned[agent_id] = ident
        self._save_agents()
        self.audit.append("admission.registered", {"agent": agent_id, "label": label, "pid": pid})
        return ident

    def sanctioned(self) -> list[AgentIdentity]:
        return list(self._sanctioned.values())

    def _sanctioned_pids(self) -> dict[int, tuple[str, Scope, float | None]]:
        return {
            i.pid: (i.agent_id, i.credential.scope, i.pid_create_time)
            for i in self._sanctioned.values()
            if i.pid is not None and i.pid_create_time is not None and not self.registry.is_revoked(i.agent_id)
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
            self._retry_mirrors()
            self._check_protected_log_room()
            sanctioned = self._sanctioned_pids()
            detections = self.detector.detect(sanctioned, decoy_pids)
            self._report_stale_pids(detections, sanctioned)
            for d in detections:
                self._note_canary_contact(d)  # a touched canary is a decoy hit (AG-A02)
                self._evaluate(d)
            self._sweep_canaries({d.pid for d in detections})
            self._check_canaries()
            self._detections = detections
            return detections

    def _report_stale_pids(self, detections: list[DetectedAgent], sanctioned: dict) -> None:
        """A registered PID now held by a different process is not sanctioned; say so
        once, so the operator knows why a registered agent shows as unregistered."""
        for d in detections:
            entry = sanctioned.get(d.pid)
            if entry is None or d.sanctioned:
                continue
            key = (entry[0], d.pid)
            if key in self._stale_reported:
                continue
            self._stale_reported.add(key)
            self.audit.append("admission.stale_pid", {"agent": entry[0], "pid": d.pid})
            self._alert(
                "Registration doesn't match this process",
                f"PID {d.pid} was registered for {entry[0]}, but it now belongs to a process that started later. "
                "It is treated as unregistered; register the agent again if it was restarted.",
                "warning",
            )

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

    def _check_canaries(self) -> None:
        """Report a canary that was deleted, replaced or changed. Reading one changes
        none of that, so a change means something touched the bait (AG-N07)."""
        for _decoy_id, path, change in self.tripwire.check_integrity():
            self._alert(
                "A canary was tampered with",
                f"{path} was {change}. Something handled the bait; check which programs ran, then delete "
                "the file and plant the canaries again if the change was yours.",
                "danger",
            )

    def _sweep_canaries(self, candidates: set[int]) -> None:
        """Report canary contact by programs that are not agent candidates — an
        antivirus, an indexer or a backup tool. They are shown, never contained
        (AG-A02). Bounded by SWEEP_BUDGET_S per scan; it resumes where it stopped."""
        if not _HAVE_PSUTIL or not self.tripwire.has_canaries:
            return
        own = os.getpid()
        try:
            pids = sorted(p for p in psutil.pids() if p not in candidates and p != own)
        except Exception:
            return
        if not pids:
            return
        start = next((i for i, p in enumerate(pids) if p > self._sweep_cursor), 0)
        order = pids[start:] + pids[:start]
        deadline = time.monotonic() + self.SWEEP_BUDGET_S
        for pid in order:
            if time.monotonic() > deadline:
                break
            self._sweep_cursor = pid
            try:
                proc = psutil.Process(pid)
                files = proc.open_files()
                name = proc.name()
            except Exception:
                continue
            for f in files:
                decoy_id = self.tripwire.is_canary(f.path)
                if decoy_id and (pid, decoy_id) not in self._observed:
                    self._observed.add((pid, decoy_id))
                    self.tripwire.on_observed(decoy_id, pid, f"{name} opened {f.path}")
                    self._alert(
                        "Canary opened by a program that isn't an agent",
                        f"{name} (pid {pid}) opened {f.path}. Reported only: Foldward never contains programs "
                        "that aren't agents.",
                        "warning",
                    )
        else:
            self._sweep_cursor = 0  # full pass done: start over next scan

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
        if decoy and self.settings.auto_contain_on_decoy:
            if d.sanctioned:
                # A sanctioned agent is never contained automatically on a canary hit:
                # another program can put bait where a legitimate agent works, which
                # would turn the tripwire against it (AG-N03). The operator decides.
                self.audit.append("detect.decoy_sanctioned", {"agent": d.agent_id, "pid": d.pid})
                self._alert(
                    "Sanctioned agent opened a canary",
                    f"{d.label} (pid {d.pid}, {d.agent_id}) opened a canary. It was not contained automatically "
                    "because it is registered; check it and contain it from The Net if needed.",
                    "danger",
                )
            else:
                # auto-contain only an unregistered agent on a decoy touch
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
        its own containment record even if it reaches Foldward's own store.

        The record is queued, in an owner-only file, before it is sent, so a copy
        that fails survives a restart (INT-N02); copies go oldest first. A failed
        copy is reported and retried (INT-05), and a full log is reported as
        possible tampering, since any program running as the user can fill it
        (INT-N01)."""
        if self.sv is None:
            return
        saved = self._pending.add(record)
        ok, detail, full = self._flush_pending(first=record)
        if ok:
            return
        self.audit.append("mirror.failed", {"detail": detail, "pending": len(self._pending), "saved": saved})
        if full and self._report_full_log(detail):
            return
        kept = (
            "Foldward keeps it, also across restarts, and retries every minute"
            if saved
            else "Foldward retries every minute, but couldn't save it to disk, so it is lost if Foldward closes first"
        )
        self._alert(
            "Containment record not yet protected",
            f"It couldn't be copied to Sentinel Vision's protected log ({detail}). {kept}; "
            "the record is in Foldward's own audit meanwhile.",
            "warning",
        )

    def _try_mirror(self, record: dict) -> tuple[bool, str, bool]:
        """(copied, what went wrong, whether the log refused it because it is full)."""
        try:
            res = self.sv.plugin_log_append(record)
        except Exception as exc:
            return False, str(exc), False
        return (
            bool(getattr(res, "ok", False)),
            str(getattr(res, "detail", res)),
            getattr(res, "full", False) is True,
        )

    def _flush_pending(self, first: dict | None = None) -> tuple[bool, str, bool]:
        """Copy the waiting records, oldest first, and stop at the first that fails, so the
        protected log keeps their order. Returns (all copied, what went wrong, log full).
        ``first`` is a record queued just now: copying it isn't a retry."""
        detail, full, copied = "", False, 0
        while len(self._pending):
            record = self._pending.oldest()
            ok, detail, full = self._try_mirror(record)
            if not ok:
                break
            self._pending.drop_oldest()
            copied += 1
            if record is not first:
                self.audit.append("mirror.retried", {"agent": record.get("agent")})
        if copied:
            self._pending.save()
        if len(self._pending):
            self._next_mirror_try = time.monotonic() + self.MIRROR_RETRY_S
            return False, detail, full
        return True, "", False

    def _retry_mirrors(self) -> None:
        """At each scan, retry waiting copies, at most once a minute while they fail."""
        if self.sv is None or not len(self._pending) or time.monotonic() < self._next_mirror_try:
            return
        ok, detail, full = self._flush_pending()
        if not ok and full:
            self._report_full_log(detail)  # waiting records stay queued either way

    def _report_full_log(self, detail: str) -> bool:
        """A full protected log keeps every later containment record out of it (INT-N01).
        Reported as possible tampering, at most once an hour; returns whether it was reported now."""
        now = time.monotonic()
        if now - self._full_reported < self.LOG_FULL_REPORT_S:
            return False
        self._full_reported = now
        self.audit.append("mirror.log_full", {"detail": detail, "pending": len(self._pending)})
        self._alert(
            "Sentinel Vision's protected log is full",
            f"Containment records can't be added to Foldward's protected log in Sentinel Vision ({detail}). "
            f"Foldward keeps them ({len(self._pending)} waiting) and they are in its own signed audit. Any program "
            "running as you can add records to that log, so it may have been filled on purpose to keep them out. "
            "See what filled it with `sentinel-vision-cli plugin-log read foldward`; Sentinel Vision's "
            "docs/PLUGINS.md says how an administrator makes room.",
            "danger",
        )
        return True

    def _check_protected_log_room(self) -> None:
        """Every few hours, ask Sentinel Vision (0.5.3 or newer) how full Foldward's
        protected log is and warn from 80%, before a full log keeps records out (INT-N01)."""
        if self.sv is None or time.monotonic() < self._next_room_check:
            return
        self._next_room_check = time.monotonic() + self.LOG_ROOM_CHECK_S
        try:
            room = self.sv.plugin_log_room()
        except Exception:
            room = None  # an older Sentinel Vision, or a stand-in without the call
        if not isinstance(room, dict):
            return
        used, limit = room.get("bytes"), room.get("limit")
        if not (isinstance(used, int) and isinstance(limit, int) and limit > 0):
            return
        if used < self.LOG_ROOM_WARN_SHARE * limit:
            return
        self.audit.append("mirror.log_filling", {"bytes": used, "limit": limit})
        self._alert(
            "Sentinel Vision's protected log is filling up",
            f"Foldward's protected log in Sentinel Vision is {min(100, round(100 * used / limit))}% full. Any "
            "program running as you can add records to it, so it may be being filled on purpose to keep "
            "containment records out. See what filled it with `sentinel-vision-cli plugin-log read foldward`.",
            "warning",
        )

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
            warnings=list(self.warnings),
        )

    # ------------------------------------------------------------------ alerts
    def _alert(self, title: str, text: str, level: str = "info") -> None:
        if self.settings.quiet_mode and level == "info":
            return
        for fn in list(self.alert_listeners):
            try:
                fn(title, text, level)
            except Exception:
                continue

    def _escalate(self, ev: dict) -> None:
        self._alert("Escalated to operator", f"agent {ev.get('agent')} contained ({ev.get('up_to')})", "warning")
