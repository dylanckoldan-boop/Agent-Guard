"""Detection and risk scoring. The scoring policy is a pure function, so no live processes are needed."""

from __future__ import annotations

import os
import types

import pytest

from agent_guard import detect as detect_module
from agent_guard.config import Settings
from agent_guard.detect import (
    DetectedAgent,
    Detector,
    ProcessInfo,
    Reason,
    looks_like_agent,
    score_agent,
)
from agent_guard.identity import Scope
from agent_guard.mesh import DEFAULT_SENTINELS


def make_proc(**overrides) -> ProcessInfo:
    fields = {"pid": 4321, "name": "python", "exe": "/usr/bin/python3", "cmdline": ["python", "worker.py"]}
    fields.update(overrides)
    return ProcessInfo(**fields)


def public_hosts(n: int) -> list[str]:
    """n public peers (TEST-NET-3 addresses, which the scorer does not treat as local)."""
    return [f"203.0.113.{i}:443" for i in range(1, n + 1)]


def kinds(reasons) -> list[str]:
    return [r.kind for r in reasons]


# ---------------------------------------------------------------------- tripwire
def test_decoy_contact_scores_the_maximum_with_a_tripwire_reason():
    score, reasons = score_agent(make_proc(), Settings(), sanctioned=False, decoy_hit=True)

    assert score == 100
    assert kinds(reasons) == ["tripwire"]
    assert reasons[0].points == 100


def test_decoy_contact_short_circuits_every_other_signal():
    noisy = make_proc(remote_hosts=public_hosts(10), child_count=9, touched_paths=["/etc/shadow"])

    score, reasons = score_agent(noisy, Settings(), sanctioned=True, scope=Scope(), decoy_hit=True)

    assert (score, kinds(reasons)) == (100, ["tripwire"])


# ---------------------------------------------------------------------- identity
def test_unregistered_agent_gets_an_identity_reason():
    score, reasons = score_agent(make_proc(), Settings(), sanctioned=False)

    assert score >= 35
    assert kinds(reasons) == ["identity"]


def test_identity_alone_is_not_enough_to_surface_a_detection():
    score, _ = score_agent(make_proc(), Settings(), sanctioned=False)

    assert score < Settings().risk_flag_threshold


def test_sanctioned_agent_acting_within_scope_scores_zero():
    scope = Scope(allowed_hosts=frozenset({"api.example.com"}), allowed_path_prefixes=frozenset({"/work/"}))
    proc = make_proc(remote_hosts=["api.example.com:443"], touched_paths=["/work/out.txt"])

    assert score_agent(proc, Settings(), sanctioned=True, scope=scope) == (0, [])


# ------------------------------------------------------------------------- reach
def test_fan_out_to_many_public_peers_adds_a_reach_reason():
    proc = make_proc(remote_hosts=public_hosts(10))

    score, reasons = score_agent(proc, Settings(), sanctioned=True)

    [fan_out] = [r for r in reasons if "fan-out" in r.label]
    assert fan_out.kind == "reach"
    assert "10" in fan_out.label
    assert score == fan_out.points


def test_fan_out_stacks_with_the_identity_reason_for_an_unregistered_agent():
    score, reasons = score_agent(make_proc(remote_hosts=public_hosts(10)), Settings(), sanctioned=False)

    assert sorted(kinds(reasons)) == ["identity", "reach"]
    assert score == sum(r.points for r in reasons)


@pytest.mark.parametrize(("peers", "flagged"), [(7, False), (8, True)])
def test_fan_out_threshold_boundary(peers, flagged):
    _, reasons = score_agent(make_proc(remote_hosts=public_hosts(peers)), Settings(), sanctioned=True)

    assert any("fan-out" in r.label for r in reasons) is flagged


def test_local_and_private_peers_do_not_count_toward_fan_out():
    hosts = [f"10.0.0.{i}:80" for i in range(1, 11)] + ["192.168.1.5:22", "127.0.0.1:8080", "localhost:5000"]

    assert score_agent(make_proc(remote_hosts=hosts), Settings(), sanctioned=True) == (0, [])


def test_egress_outside_scope_is_a_reach_reason():
    scope = Scope(allowed_hosts=frozenset({"api.example.com"}))
    proc = make_proc(remote_hosts=["api.example.com:443", "203.0.113.9:443"])

    _, reasons = score_agent(proc, Settings(), sanctioned=True, scope=scope)

    assert kinds(reasons) == ["reach"]
    assert "203.0.113.9" in reasons[0].label


def test_scope_checks_apply_only_to_sanctioned_agents():
    proc = make_proc(remote_hosts=["203.0.113.9:443"], touched_paths=["/etc/shadow"])

    _, reasons = score_agent(proc, Settings(), sanctioned=False, scope=Scope())

    assert kinds(reasons) == ["identity"]


def test_novel_egress_is_a_reach_reason():
    proc = make_proc(remote_hosts=["203.0.113.1:443", "203.0.113.2:443"])

    _, reasons = score_agent(proc, Settings(), sanctioned=True, seen_hosts={"203.0.113.1"})
    [novel] = reasons
    assert novel.kind == "reach"
    assert "203.0.113.2" in novel.label

    # once every peer has been seen nothing is novel, and with no history novelty is not assessed
    seen_all = {"203.0.113.1", "203.0.113.2"}
    assert score_agent(proc, Settings(), sanctioned=True, seen_hosts=seen_all) == (0, [])
    assert score_agent(proc, Settings(), sanctioned=True) == (0, [])


# --------------------------------------------------------------------- behaviour
def test_children_are_a_behaviour_reason_only_when_the_scope_forbids_spawning():
    proc = make_proc(child_count=2)

    _, forbidden = score_agent(proc, Settings(), sanctioned=True, scope=Scope(may_spawn=False))
    _, permitted = score_agent(proc, Settings(), sanctioned=True, scope=Scope(may_spawn=True))

    assert kinds(forbidden) == ["behaviour"]
    assert permitted == []


@pytest.mark.parametrize(("children", "flagged"), [(4, False), (5, True)])
def test_large_child_fleets_are_flagged_even_without_a_scope(children, flagged):
    _, reasons = score_agent(make_proc(child_count=children), Settings(), sanctioned=True)

    assert kinds(reasons) == (["behaviour"] if flagged else [])


def test_touching_a_path_outside_scope_is_a_behaviour_reason():
    scope = Scope(allowed_path_prefixes=frozenset({"/work/"}))
    proc = make_proc(touched_paths=["/work/a.txt", "/etc/passwd"])

    _, reasons = score_agent(proc, Settings(), sanctioned=True, scope=scope)

    assert kinds(reasons) == ["behaviour"]
    assert "/etc/passwd" in reasons[0].label


def test_score_is_the_capped_sum_of_reason_points():
    proc = make_proc(remote_hosts=public_hosts(10), child_count=3, touched_paths=["/etc/passwd"])

    score, reasons = score_agent(proc, Settings(), sanctioned=True, scope=Scope(), seen_hosts=set())

    assert {r.kind for r in reasons} == {"reach", "behaviour"}
    assert score == min(100, sum(r.points for r in reasons))
    assert 0 < score <= 100


def test_every_reason_kind_is_voted_on_by_a_default_sentinel():
    busy = make_proc(remote_hosts=public_hosts(10), child_count=6, touched_paths=["/etc/passwd"])
    produced = []
    produced += score_agent(busy, Settings(), sanctioned=False)[1]
    produced += score_agent(busy, Settings(), sanctioned=True, scope=Scope(), seen_hosts=set())[1]
    produced += score_agent(busy, Settings(), sanctioned=False, decoy_hit=True)[1]

    assert {r.kind for r in produced} == {"identity", "reach", "behaviour", "tripwire"}
    assert {r.kind for r in produced} <= {s.kind for s in DEFAULT_SENTINELS}


# --------------------------------------------------------------- looks_like_agent
def test_framework_command_lines_look_like_agents():
    proc = make_proc(cmdline=["python", "langchain_agent.py"])

    assert looks_like_agent(proc, Settings()) is True


def test_a_plain_shell_does_not_look_like_an_agent():
    proc = make_proc(name="bash", exe="/bin/bash", cmdline=["bash"])

    assert looks_like_agent(proc, Settings()) is False


def test_marker_matching_is_case_insensitive():
    assert looks_like_agent(make_proc(cmdline=["python", "AutoGen_Runner.py"]), Settings()) is True


def test_talking_to_an_llm_endpoint_makes_any_process_a_candidate():
    proc = make_proc(cmdline=["node", "server.js"], remote_hosts=["api.anthropic.com:443"])

    assert looks_like_agent(proc, Settings()) is True


def test_the_net_is_tunable_through_settings():
    custom = Settings(agent_markers=["mybot"], llm_hosts=[])

    assert looks_like_agent(make_proc(cmdline=["python", "mybot.py"]), custom)
    assert not looks_like_agent(make_proc(cmdline=["python", "langchain_agent.py"]), custom)


# ------------------------------------------------------------------ data classes
def test_process_cmd_joins_the_command_line():
    assert make_proc(cmdline=["python", "-m", "worker"]).cmd == "python -m worker"


def test_detected_agent_why_lists_reasons_or_says_nominal():
    proc = make_proc()
    quiet = DetectedAgent(1, "quiet", proc, True, 0, [])
    noisy = DetectedAgent(2, "noisy", proc, False, 50, [Reason("a", 35, "identity"), Reason("b", 15, "reach")])

    assert quiet.why == "nominal"
    assert noisy.why == "a (+35), b (+15)"


# ----------------------------------------------------- Detector (fake process table)
@pytest.fixture
def detector_for(monkeypatch):
    """Build a Detector whose process table is the given list (no psutil, no live processes)."""

    def build(*procs, settings=None):
        det = Detector(settings or Settings())
        monkeypatch.setattr(det, "snapshot_processes", lambda: list(procs))
        return det

    return build


def test_detector_ignores_processes_that_are_not_agents(detector_for):
    agent = make_proc(pid=11, cmdline=["python", "langchain_agent.py"])
    shell = make_proc(pid=12, name="bash", cmdline=["bash"])

    found = detector_for(agent, shell).detect()

    assert [d.pid for d in found] == [11]


def test_detector_never_flags_agent_guard_itself(detector_for):
    me = make_proc(pid=os.getpid(), cmdline=["python", "langchain_agent.py"])
    module = make_proc(pid=11, cmdline=["python", "-m", "agent_guard", "watch"])
    script = make_proc(pid=12, cmdline=["agent-guard", "scan"])

    assert detector_for(me, module, script).detect() == []


def test_detections_surface_at_the_flag_threshold(detector_for):
    quiet = make_proc(pid=11, cmdline=["python", "langchain_agent.py"])
    noisy = make_proc(pid=12, cmdline=["python", "crewai_runner.py"], remote_hosts=public_hosts(10))

    by_pid = {d.pid: d for d in detector_for(quiet, noisy).detect()}

    assert by_pid[11].state == "healthy"
    assert by_pid[12].state == "flagged"
    assert by_pid[12].score >= Settings().risk_flag_threshold


@pytest.mark.parametrize(
    ("margin", "state"),
    [pytest.param(0, "flagged", id="at-threshold"), pytest.param(1, "healthy", id="below-threshold")],
)
def test_the_flag_threshold_is_inclusive(detector_for, margin, state):
    proc = make_proc(pid=11, cmdline=["python", "langchain_agent.py"])  # unregistered, nothing else
    score, _ = score_agent(proc, Settings(), sanctioned=False)

    [found] = detector_for(proc, settings=Settings(risk_flag_threshold=score + margin)).detect()

    assert found.score == score
    assert found.state == state


def test_sanctioned_pids_carry_their_identity_and_scope(detector_for):
    proc = make_proc(pid=11, cmdline=["python", "langchain_agent.py"], child_count=2)
    det = detector_for(proc)

    [allowed] = det.detect({11: ("agent-1", Scope(may_spawn=True))})
    [forbidden] = det.detect({11: ("agent-1", Scope(may_spawn=False))})

    assert allowed.sanctioned is True
    assert allowed.agent_id == "agent-1"
    assert allowed.score == 0
    assert kinds(forbidden.reasons) == ["behaviour"]


def test_decoy_pids_are_scored_as_a_tripwire_contact(detector_for):
    proc = make_proc(pid=11, cmdline=["python", "langchain_agent.py"])

    [hit] = detector_for(proc).detect(decoy_pids={11})

    assert hit.score == 100
    assert kinds(hit.reasons) == ["tripwire"]
    assert hit.state == "flagged"  # the detector flags; containing is the guard's decision


def test_detector_remembers_which_peers_it_has_seen(detector_for):
    proc = make_proc(pid=11, cmdline=["python", "langchain_agent.py"], remote_hosts=["203.0.113.5:443"])
    det = detector_for(proc)

    [first] = det.detect()
    [second] = det.detect()

    assert any("new egress" in r.label for r in first.reasons)
    assert not any("new egress" in r.label for r in second.reasons)


def test_label_falls_back_through_name_command_line_and_pid(detector_for):
    via_llm = {"remote_hosts": ["api.openai.com:443"]}  # keeps the nameless processes in the candidate set
    named = make_proc(pid=11, name="worker", cmdline=["python", "x"], **via_llm)
    unnamed = make_proc(pid=12, name="", cmdline=["python", "x"], **via_llm)
    bare = make_proc(pid=13, name="", cmdline=[], **via_llm)

    labels = {d.pid: d.label for d in detector_for(named, unnamed, bare).detect()}

    assert labels == {11: "worker", 12: "python", 13: "pid 13"}


def test_without_psutil_the_detector_degrades_to_an_empty_result(monkeypatch):
    monkeypatch.setattr(detect_module, "_HAVE_PSUTIL", False)
    det = Detector(Settings())

    assert det.snapshot_processes() == []
    assert det.detect() == []


class FakeProcess:
    """Just enough of ``psutil.Process`` for Detector.snapshot_processes."""

    def __init__(self, info, children=0):
        self._info = info
        self._children = children

    @property
    def info(self):
        if isinstance(self._info, Exception):
            raise self._info
        return self._info

    def children(self):
        return [object()] * self._children


def conn(pid, ip=None, port=None):
    return types.SimpleNamespace(pid=pid, raddr=types.SimpleNamespace(ip=ip, port=port) if ip else ())


def install_fake_psutil(monkeypatch, procs, connections):
    def net_connections(kind="inet"):
        if isinstance(connections, Exception):
            raise connections
        return connections

    fake = types.SimpleNamespace(net_connections=net_connections, process_iter=lambda attrs: procs)
    monkeypatch.setattr(detect_module, "psutil", fake, raising=False)
    monkeypatch.setattr(detect_module, "_HAVE_PSUTIL", True)


def test_snapshot_assembles_connections_and_children_from_psutil(monkeypatch):
    worker = {"pid": 11, "name": "worker", "exe": "/usr/bin/python3", "cmdline": ["python", "x.py"],
              "username": "alice", "create_time": 1700000000.0}
    unreadable = {"pid": 12, "name": None, "exe": None, "cmdline": None, "username": None, "create_time": None}
    connections = [conn(11, "203.0.113.5", 443), conn(11, "203.0.113.6", 80), conn(12), conn(None, "203.0.113.7", 22)]
    install_fake_psutil(monkeypatch, [FakeProcess(worker, children=2), FakeProcess(unreadable)], connections)

    snapshot = {p.pid: p for p in Detector(Settings()).snapshot_processes()}

    assert snapshot[11].remote_hosts == ["203.0.113.5:443", "203.0.113.6:80"]
    assert snapshot[11].child_count == 2
    assert (snapshot[11].name, snapshot[11].exe, snapshot[11].username) == ("worker", "/usr/bin/python3", "alice")
    # what psutil cannot read comes back as None; the snapshot normalises it to empty values
    assert (snapshot[12].name, snapshot[12].exe, snapshot[12].cmdline) == ("", "", [])
    assert snapshot[12].remote_hosts == []  # a listening socket has no remote address


def test_snapshot_survives_unreadable_processes_and_connection_tables(monkeypatch):
    readable = {"pid": 21, "name": "ok", "exe": "", "cmdline": ["ok"], "username": "", "create_time": 0.0}
    procs = [FakeProcess(RuntimeError("access denied")), FakeProcess(readable)]
    install_fake_psutil(monkeypatch, procs, PermissionError("no connection table"))

    snapshot = Detector(Settings()).snapshot_processes()

    assert [p.pid for p in snapshot] == [21]
    assert snapshot[0].remote_hosts == []


def test_live_snapshot_includes_this_process():
    pytest.importorskip("psutil")

    procs = Detector(Settings()).snapshot_processes()

    [me] = [p for p in procs if p.pid == os.getpid()]
    assert isinstance(me, ProcessInfo)
