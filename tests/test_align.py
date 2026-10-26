"""Alignment preferences gate every discretionary signal; safety signals stay on."""

from __future__ import annotations

from agent_guard.align import ALIGNMENT_RULES, DEFAULT_ALIGNMENT, RULE_KEYS, enabled
from agent_guard.config import Settings
from agent_guard.detect import ProcessInfo, score_agent


def _proc(**kw) -> ProcessInfo:
    base = {"pid": 4242, "name": "python", "exe": "/x/agent.py", "cmdline": ["python", "langchain_agent.py"]}
    base.update(kw)
    return ProcessInfo(**base)


def test_rule_registry_is_sane():
    assert ALIGNMENT_RULES
    assert set(DEFAULT_ALIGNMENT) == set(RULE_KEYS)
    assert all(DEFAULT_ALIGNMENT.values())
    assert enabled({}, "a_future_rule") is True        # unknown/new rules default on
    assert enabled({"fan_out": False}, "fan_out") is False


def test_default_alignment_scores_unregistered_fanout():
    proc = _proc(remote_hosts=[f"5.5.5.{i}:443" for i in range(10)])

    score, reasons = score_agent(proc, Settings(), sanctioned=False, seen_hosts=set())

    kinds = {r.kind for r in reasons}
    assert score >= 60
    assert {"identity", "reach"} <= kinds


def test_disabling_fanout_removes_only_that_signal():
    proc = _proc(remote_hosts=[f"5.5.5.{i}:443" for i in range(10)])
    s = Settings()
    s.alignment["fan_out"] = False
    s.alignment["new_egress"] = False

    _, reasons = score_agent(proc, s, sanctioned=False, seen_hosts=set())

    labels = " ".join(r.label for r in reasons)
    assert "fan-out" not in labels
    assert "unregistered" in labels  # identity still applies


def test_disabling_unregistered_lets_a_bare_agent_pass():
    proc = _proc(remote_hosts=[])
    s = Settings()
    s.alignment["unregistered"] = False

    score, reasons = score_agent(proc, s, sanctioned=False, seen_hosts=set())

    assert score == 0
    assert reasons == []


def test_file_access_flags_reading_sensitive_folders():
    s = Settings()
    s.sensitive_paths = ["/home/me/Documents"]
    proc = _proc(touched_paths=["/home/me/Documents/taxes.pdf"])

    _, reasons = score_agent(proc, s, sanctioned=False, seen_hosts=set())
    assert any("reading your files" in r.label for r in reasons)

    s.alignment["file_access"] = False
    _, reasons_off = score_agent(proc, s, sanctioned=False, seen_hosts=set())
    assert not any("reading your files" in r.label for r in reasons_off)


def test_decoy_always_fires_even_with_every_rule_off():
    s = Settings()
    s.alignment = dict.fromkeys(RULE_KEYS, False)
    proc = _proc()

    score, reasons = score_agent(proc, s, sanctioned=False, decoy_hit=True, seen_hosts=set())

    assert score == 100
    assert reasons[0].kind == "tripwire"


def test_settings_round_trip_alignment_and_paths():
    s = Settings()
    s.alignment["child_spawn"] = False
    s.sensitive_paths = ["/tmp/secret"]
    s.save()

    loaded = Settings.load()

    assert loaded.alignment["child_spawn"] is False
    assert loaded.sensitive_paths == ["/tmp/secret"]
