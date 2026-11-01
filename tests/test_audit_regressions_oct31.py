"""Regression tests for the 31 October 2026 audit (AG-N01 to AG-N05, and the AG-A02, AG-A05, AG-A09
items it reopened). Integration findings (INT-01 to INT-05) are tested in test_integrations.py and
test_sentinel_vision_contract.py; website findings in test_site.py.

Several tests start real, harmless child processes and freeze them, exactly as an attack would be
handled; every child is killed on teardown."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

from foldward import config, detect
from foldward.config import DEFAULT_AGENT_MARKERS, Settings
from foldward.core import Foldward, _quarantine_target
from foldward.detect import DetectedAgent, ProcessInfo, Reason
from foldward.identity import Scope
from foldward.quarantine import Quarantine, QuarantineRefused
from foldward.response import Response, Rung
from foldward.tripwire import _CANARY_MARKER, Tripwire

psutil = pytest.importorskip("psutil")
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX argv[0], FIFO and signal semantics")


def _holder(path) -> str:
    """A tiny program that keeps ``path`` open, as an agent reading a secret would."""
    return f"import time\nf = open({str(path)!r}, 'rb')\ntime.sleep(60)\n"


def _wait_open(pid: int, path, timeout: float = 15.0) -> None:
    want = os.path.realpath(str(path))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if any(os.path.realpath(f.path) == want for f in psutil.Process(pid).open_files()):
                return
        except psutil.Error:
            pass
        time.sleep(0.05)
    pytest.fail(f"pid {pid} never opened {path}")


def _status(pid: int) -> str:
    try:
        return psutil.Process(pid).status()
    except psutil.NoSuchProcess:
        return "gone"


@pytest.fixture
def spawn():
    procs: list[subprocess.Popen] = []

    def _spawn(argv, script=None, text=None, cwd=None):
        if script is not None and text is not None:
            Path(script).write_text(text)
        p = subprocess.Popen(argv, executable=sys.executable, cwd=cwd,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
        return p

    yield _spawn
    for p in procs:
        p.kill()  # SIGKILL also ends a SIGSTOPped process
        p.wait(timeout=10)


@pytest.fixture
def canary(tmp_path):
    """A guard with one planted canary."""
    g = Foldward(Settings())
    bait = tmp_path / "bait"
    bait.mkdir()
    return g, g.plant_canaries([str(bait)])[0]


# ------------------------------------------------------------------ AG-N01: names never exempt
@pytest.mark.parametrize(
    ("name", "exe", "argv0"),
    [
        ("ssh-agent", "/home/user/bin/ssh-agent", "ssh-agent"),  # a renamed copy of the interpreter
        ("python3", "/usr/bin/python3", "ssh-agent"),  # only argv[0] changed
        ("gpg-agent", "/tmp/gpg-agent", "gpg-agent"),
    ],
)
def test_a_process_named_like_a_system_daemon_is_still_a_candidate(name, exe, argv0):
    proc = ProcessInfo(1234, name, exe, [argv0, "agent.py", "--framework", "crewai"])

    assert detect.looks_like_agent(proc, Settings())


@posix_only
def test_the_operating_systems_own_daemon_stays_exempt():
    real = shutil.which("ssh-agent", path="/usr/bin:/bin")
    if not real:
        pytest.skip("no ssh-agent in /usr/bin")
    st = os.stat(os.path.realpath(real))
    if st.st_uid != 0 or st.st_mode & 0o022:
        pytest.skip("ssh-agent here isn't root-owned")
    settings = Settings(agent_markers=[*DEFAULT_AGENT_MARKERS, "ssh-agent"])  # a marker that would match it

    assert not detect.looks_like_agent(ProcessInfo(1, "ssh-agent", real, ["ssh-agent", "-s"]), settings)


@posix_only
def test_a_rogue_agent_launched_as_ssh_agent_is_still_contained(tmp_path, spawn, canary):
    g, bait = canary
    script = tmp_path / "rogue.py"
    p = spawn(["ssh-agent", str(script), "--framework", "crewai"], script, _holder(bait))
    _wait_open(p.pid, bait)

    [d] = [x for x in g.scan() if x.pid == p.pid]

    assert d.state == "contained"
    assert _status(p.pid) == psutil.STATUS_STOPPED


# ------------------------------------------------------------------ AG-N02: containment can't be stalled
def test_the_ladder_freezes_the_agent_before_anything_slow():
    assert Response.plan(Rung.SUSPEND)[0] is Rung.SUSPEND
    assert Response.plan(Rung.TERMINATE)[0] is Rung.SUSPEND
    assert Response.plan(Rung.TERMINATE)[-1] is Rung.TERMINATE
    assert Response.plan(Rung.QUARANTINE) == [Rung.THROTTLE, Rung.QUARANTINE]  # no suspend asked for: none added


@posix_only
def test_quarantine_refuses_a_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "agent.py"
    os.mkfifo(fifo)
    started = time.monotonic()

    with pytest.raises(QuarantineRefused):
        Quarantine(tmp_path / "vault").add(str(fifo), "agent-1", "pacified")

    assert time.monotonic() - started < 2.0


@posix_only
def test_quarantine_refuses_a_device(tmp_path):
    with pytest.raises(QuarantineRefused):
        Quarantine(tmp_path / "vault").add("/dev/zero", "agent-1", "pacified")


def test_quarantine_refuses_a_relative_path(tmp_path):
    with pytest.raises(QuarantineRefused):
        Quarantine(tmp_path / "vault").add("agent.py", "agent-1", "pacified")


def test_a_relative_script_is_resolved_against_the_agents_own_folder(tmp_path):
    folder = tmp_path / "agent-home"
    proc = ProcessInfo(1, "python3", "/usr/bin/python3", ["python3", "agent.py"], cwd=str(folder))

    assert _quarantine_target(proc) == str(folder / "agent.py")
    assert _quarantine_target(ProcessInfo(1, "python3", "/usr/bin/python3", ["python3", "agent.py"])) is None


def test_a_file_that_cant_be_removed_is_not_reported_as_quarantined(tmp_path, monkeypatch):
    f = tmp_path / "agent.bin"
    f.write_bytes(b"\x7fELF")
    vault = Quarantine(tmp_path / "vault")

    real_unlink = os.unlink

    def refuse(path, *args, **kwargs):
        if os.fspath(path) == str(f):
            raise PermissionError("read-only")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", refuse)
    with pytest.raises(ValueError, match="nothing was quarantined"):
        vault.add(str(f), "agent-1", "pacified")
    monkeypatch.undo()

    assert len(vault) == 0
    assert f.exists()


@posix_only
def test_an_agent_running_from_a_fifo_is_frozen_without_delay(tmp_path, spawn, canary):
    g, bait = canary
    fifo = tmp_path / "fifo_agent.py"
    os.mkfifo(fifo)
    threading.Thread(target=lambda: fifo.write_text(_holder(bait)), daemon=True).start()
    p = spawn([sys.executable, str(fifo), "--framework", "crewai"])
    _wait_open(p.pid, bait)
    done: dict = {}

    t = threading.Thread(target=lambda: done.setdefault("dets", g.scan()), daemon=True)
    t.start()
    t.join(15)

    assert not t.is_alive(), "the scan hung on the agent's FIFO"
    assert _status(p.pid) == psutil.STATUS_STOPPED


@posix_only
def test_a_relative_script_never_moves_a_same_named_file_in_foldwards_folder(tmp_path, spawn, canary, monkeypatch):
    g, bait = canary
    agent_dir, guard_dir = tmp_path / "agent", tmp_path / "guard"
    agent_dir.mkdir()
    guard_dir.mkdir()
    (agent_dir / "agent.py").write_text(_holder(bait))
    innocent = guard_dir / "agent.py"
    innocent.write_text("# someone else's file\n")
    p = spawn([sys.executable, "agent.py", "--framework", "crewai"], cwd=agent_dir)
    _wait_open(p.pid, bait)
    monkeypatch.chdir(guard_dir)

    g.scan()

    assert innocent.exists()
    assert not (agent_dir / "agent.py").exists()  # the agent's own script was the one quarantined
    assert [i.original_path for i in g.quarantine.list()] == [str(agent_dir / "agent.py")]


# ------------------------------------------------------------------ AG-A05: shared runtimes are never taken
@pytest.mark.parametrize(
    ("exe", "argv", "expected"),
    [
        ("/usr/bin/java", ["java", "-jar", "/opt/a/agent.jar"], "/opt/a/agent.jar"),
        ("/usr/bin/java", ["java", "-cp", "/opt/a/lib.jar", "com.example.Main"], None),
        ("/usr/bin/pwsh", ["pwsh", "-NoProfile", "-File", "/opt/a/agent.ps1"], "/opt/a/agent.ps1"),
        ("/usr/bin/pwsh", ["pwsh", "-Command", "Get-Process"], None),
        ("/usr/bin/dotnet", ["dotnet", "/opt/a/agent.dll"], "/opt/a/agent.dll"),
        ("/usr/local/bin/uv", ["uv", "run", "/opt/a/agent.py"], None),
        ("/usr/bin/node", ["node", "-e", "require('x')"], None),
        ("/usr/bin/bash", ["bash", "-c", "curl example.com"], None),
        ("/usr/bin/python3.12", ["python3.12", "-X", "dev", "/opt/a/agent.py"], "/opt/a/agent.py"),
        ("/usr/bin/deno", ["deno", "run", "--allow-net", "/opt/a/agent.ts"], "/opt/a/agent.ts"),
    ],
)
def test_a_shared_runtime_is_never_the_quarantine_target(exe, argv, expected):
    assert _quarantine_target(ProcessInfo(1, os.path.basename(exe), exe, argv)) == expected


def test_quarantine_from_the_gui_always_asks_first():
    pytest.importorskip("PySide6")
    from foldward.gui.pages.net import NetPage

    page = types.SimpleNamespace(guard=types.SimpleNamespace(settings=Settings(report_only=False)))
    question = NetPage.confirmation(page, "quarantine", types.SimpleNamespace(label="rogue", pid=7))

    assert question and "moved into the encrypted quarantine" in question


# ------------------------------------------------------------------ AG-N03 / AG-A02: canaries
def test_a_marker_copied_into_another_file_is_not_a_canary(tmp_path):
    f = tmp_path / "run.log"
    f.write_bytes(_CANARY_MARKER + b"x" * 100)

    assert Tripwire().is_canary(str(f)) is None


def test_a_replaced_canary_is_no_longer_recognised(tmp_path):
    tw = Tripwire()
    bait = tmp_path / "bait"
    bait.mkdir()
    planted = tw.plant_canaries([str(bait)])[0]
    os.unlink(planted)
    Path(planted).write_bytes(b"someone else's file")  # same path, different file

    assert tw.is_canary(planted) is None


def test_canaries_planted_by_one_run_are_recognised_by_the_next(tmp_path):
    bait = tmp_path / "bait"
    bait.mkdir()
    planted = Foldward(Settings()).plant_canaries([str(bait)])

    assert all(Foldward(Settings()).tripwire.is_canary(p) for p in planted)


def test_a_canary_left_by_an_earlier_version_is_adopted_when_planting_again(tmp_path):
    bait = tmp_path / "bait"
    bait.mkdir()
    old = bait / "credentials.env"
    old.write_bytes(_CANARY_MARKER)  # how canaries looked before the planted list existed
    tw = Tripwire()

    tw.plant_canaries([str(bait)])

    assert tw.is_canary(str(old))
    assert old.read_bytes() == _CANARY_MARKER  # never overwritten


def test_a_sanctioned_agent_on_a_canary_is_flagged_not_contained(guard):
    alerts: list[str] = []
    guard.alert_listeners.append(lambda title, text, level: alerts.append(title))
    d = DetectedAgent(999999, "helper", ProcessInfo(999999, "helper", "", []), True, 100,
                      [Reason("touched a decoy / honeytoken", 100, "tripwire")], "flagged", "agent-1")

    guard._evaluate(d)

    assert d.state == "flagged"
    assert "Sanctioned agent opened a canary" in alerts
    assert not guard.registry.is_revoked("agent-1")


@posix_only
def test_a_forged_marker_cant_turn_containment_on_a_sanctioned_agent(tmp_path, spawn, canary):
    g, _bait = canary
    log = tmp_path / "run.log"
    log.write_bytes(b"x" * 200)
    script = tmp_path / "helper.py"
    p = spawn([sys.executable, str(script), "--framework", "crewai"], script, _holder(log))
    _wait_open(p.pid, log)
    g.register_agent("helper", Scope(allowed_path_prefixes=frozenset({str(tmp_path)})), pid=p.pid)
    with open(log, "r+b") as fh:
        fh.write(_CANARY_MARKER)  # another program plants the marker where the helper works

    [d] = [x for x in g.scan() if x.pid == p.pid]

    assert d.state != "contained"
    assert script.exists()
    assert _status(p.pid) != psutil.STATUS_STOPPED


@posix_only
def test_a_program_that_isnt_an_agent_is_reported_not_contained(tmp_path, spawn, canary):
    g, bait = canary
    script = tmp_path / "indexer.py"
    p = spawn([sys.executable, str(script)], script, _holder(bait))  # no agent markers at all
    _wait_open(p.pid, bait)
    alerts: list[str] = []
    g.alert_listeners.append(lambda title, text, level: alerts.append(title))
    g.SWEEP_BUDGET_S = 10.0

    g.scan()

    assert "Canary opened by a program that isn't an agent" in alerts
    assert g.audit.events("tripwire.observed")
    assert _status(p.pid) != psutil.STATUS_STOPPED


# ------------------------------------------------------------------ AG-N04: saved state is checked
def _state() -> Path:
    return config.sub_dir("state")


def test_a_forged_registration_on_disk_is_rejected_with_a_warning():
    Foldward(Settings())  # creates the keys
    (_state() / "agents.json").write_text(json.dumps([{
        "agent_id": "agent-forged", "label": "forged", "pid": os.getpid(), "registered_at": 0,
        "pid_create_time": psutil.Process().create_time(), "issuer_ref": "nobody", "issued_at": 0,
        "signature": "AAAA", "scope": {"actions": ["*"], "hosts": ["*"], "paths": ["/"], "spawn": True},
    }]))

    g = Foldward(Settings())

    assert g.sanctioned() == []
    assert any("no valid signature" in w for w in g.warnings)
    assert g.audit.events("admission.rejected")


def test_a_forged_revocation_on_disk_is_ignored_with_a_warning():
    Foldward(Settings())
    (_state() / "revocations.json").write_text(json.dumps([
        {"agent_id": "agent-1", "reason": "x", "issuer_ref": "nobody", "issued_at": 0, "signature": "AAAA"}
    ]))

    g = Foldward(Settings())

    assert not g.registry.is_revoked("agent-1")
    assert any("revocation" in w for w in g.warnings)


def test_a_reused_pid_is_not_sanctioned(guard, monkeypatch):
    ident = guard.register_agent("worker", Scope(), pid=4242, create_time=1000.0)
    later = ProcessInfo(4242, "worker", "", ["python", "langchain_worker.py"], create_time=2000.0)
    monkeypatch.setattr(guard.detector, "snapshot_processes", lambda: [later])
    alerts: list[str] = []
    guard.alert_listeners.append(lambda title, text, level: alerts.append(title))

    [d] = guard.scan()

    assert d.sanctioned is False and d.agent_id is None
    assert "Registration doesn't match this process" in alerts
    assert guard.audit.events("admission.stale_pid")[0].data == {"agent": ident.agent_id, "pid": 4242}


def test_registering_a_pid_that_isnt_running_is_refused(guard):
    pid = 3_000_000
    while psutil.pid_exists(pid):
        pid += 1

    with pytest.raises(ValueError, match="no running process"):
        guard.register_agent("ghost", Scope(), pid=pid)


@posix_only
def test_keys_and_state_are_owner_only_from_the_start():
    g = Foldward(Settings())
    g.register_agent("x", Scope())
    root = config.data_root()
    for rel in ("keys/circle.json", "state/agents.json", "state/audit.json", "quarantine/quarantine.key"):
        mode = stat.S_IMODE(os.stat(root / rel).st_mode)
        assert mode == 0o600, f"{rel} is {oct(mode)}"


# ------------------------------------------------------------------ AG-N05: a damaged audit isn't erased
def test_a_damaged_audit_is_kept_aside_and_reported():
    Foldward(Settings())
    (_state() / "audit.json").write_text('[{"seq": 0}]')  # an entry missing its fields

    g = Foldward(Settings())

    assert any("audit log was damaged" in w for w in g.warnings)
    assert list(_state().glob("audit.corrupt-*.json"))
    assert g.audit.events("audit.recovered")


# ------------------------------------------------------------------ AG-A09: no silent fall-back
def test_a_signing_key_without_ml_dsa_is_reported():
    g = Foldward(Settings(signer_scheme="ed25519"))

    assert any("Post-quantum signing" in w for w in g.warnings)
    assert g.audit.events("guard.warning")
