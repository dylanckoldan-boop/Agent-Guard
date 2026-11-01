"""Containment records that can't reach Sentinel Vision's protected log right away (INT-05, INT-N01, INT-N02).

A failed copy is saved owner-only and survives a restart (INT-N02); copies go oldest first and are retried at most once
a minute; a full log, which any program running as the user can cause, is reported as possible tampering, and a log
filling up is reported from 80% (INT-N01).
"""

from __future__ import annotations

import stat
import sys
import types

import pytest

from foldward import config
from foldward.config import Settings
from foldward.core import Foldward
from foldward.integrations.sentinel_vision import LogResult

FULL = "plugin-log append failed (exit 2): error: log is full (50 MB); nothing was written"


def _agent(name: str = "rogue-1"):
    return types.SimpleNamespace(
        pid=None, agent_id=name, state="flagged", label=name, proc=types.SimpleNamespace(exe=None)
    )


class StandInSentinelVision:
    """A Sentinel Vision whose protected log takes records while ``up`` and not ``full``."""

    def __init__(self, up: bool = True, full: bool = False) -> None:
        self.up, self.full = up, full
        self.log: list[dict] = []
        self.tries = 0
        self.room: dict | None = None

    def plugin_log_append(self, record: dict) -> LogResult:
        self.tries += 1
        if self.full:
            return LogResult(False, FULL, True)
        if not self.up:
            return LogResult(False, "plugin-log append failed (exit 2): error: service not reachable")
        self.log.append(record)
        return LogResult(True, "appended to sentinel-vision protected log")

    def plugin_log_room(self) -> dict | None:
        return self.room


@pytest.fixture
def alerts(guard):
    seen: list[tuple[str, str, str]] = []
    guard.alert_listeners.append(lambda title, text, level: seen.append((title, text, level)))
    return seen


@pytest.fixture(autouse=True)
def _no_processes(monkeypatch):
    """Scans see no processes, so only the protected-log work runs."""
    from foldward.detect import Detector

    monkeypatch.setattr(Detector, "snapshot_processes", lambda self: [])


def _queue_file():
    return config.sub_dir("state") / "protected-log-queue.json"


def test_a_failed_copy_is_saved_owner_only_and_survives_a_restart(guard, alerts):
    guard.sv = StandInSentinelVision(up=False)

    guard.pacify(_agent(), "revoke", auto=True)

    assert _queue_file().exists()
    if sys.platform != "win32":
        assert stat.S_IMODE(_queue_file().stat().st_mode) == 0o600
    [(_title, text, level)] = [a for a in alerts if a[0] == "Containment record not yet protected"]
    assert "also across restarts" in text and level == "warning"

    restarted = Foldward(Settings())  # closed before Sentinel Vision came back
    assert len(restarted._pending) == 1
    assert any("still waiting to be copied" in w for w in restarted.warnings)
    restarted.sv = StandInSentinelVision(up=True)
    restarted.scan()

    assert [r["agent"] for r in restarted.sv.log] == ["rogue-1"]
    assert restarted.audit.events("mirror.retried") and len(restarted._pending) == 0
    assert not _queue_file().exists()


def test_copies_go_oldest_first_and_stop_at_the_first_failure(guard):
    sv = StandInSentinelVision(up=False)
    guard.sv = sv
    for name in ("a", "b", "c"):
        guard.pacify(_agent(name), "revoke", auto=True)
    assert len(guard._pending) == 3
    assert sv.tries == 3  # each new record tried the oldest once and stopped there

    sv.up = True
    guard._next_mirror_try = 0.0
    guard.scan()

    assert [r["agent"] for r in sv.log] == ["a", "b", "c"]
    assert len(guard.audit.events("mirror.retried")) == 3


def test_a_failed_copy_is_retried_at_most_once_a_minute(guard):
    sv = StandInSentinelVision(up=False)
    guard.sv = sv
    guard.pacify(_agent(), "revoke", auto=True)
    assert sv.tries == 1

    guard.scan()
    guard.scan()
    assert sv.tries == 1  # nothing within the minute

    guard._next_mirror_try -= Foldward.MIRROR_RETRY_S  # a minute later
    guard.scan()
    assert sv.tries == 2


def test_a_copy_that_succeeds_at_once_leaves_nothing_behind(guard, alerts):
    sv = StandInSentinelVision(up=True)
    guard.sv = sv

    guard.pacify(_agent(), "revoke", auto=True)

    assert len(sv.log) == 1 and len(guard._pending) == 0 and not _queue_file().exists()
    assert not guard.audit.events("mirror.failed") and not guard.audit.events("mirror.retried")
    assert not [a for a in alerts if "protected" in a[0]]


def test_a_full_protected_log_is_reported_as_possible_tampering(guard, alerts):
    sv = StandInSentinelVision(full=True)
    guard.sv = sv

    guard.pacify(_agent("a"), "revoke", auto=True)

    [(_title, text, level)] = [a for a in alerts if a[0] == "Sentinel Vision's protected log is full"]
    assert level == "danger" and "on purpose" in text and "plugin-log read foldward" in text
    assert guard.audit.events("mirror.log_full")

    guard.pacify(_agent("b"), "revoke", auto=True)  # within the hour: the record is still reported, not the log
    assert len([a for a in alerts if a[0] == "Sentinel Vision's protected log is full"]) == 1
    assert [a[0] for a in alerts].count("Containment record not yet protected") == 1
    assert len(guard._pending) == 2  # both kept until there is room

    sv.full = False  # an administrator made room
    guard._next_mirror_try = 0.0
    guard.scan()
    assert [r["agent"] for r in sv.log] == ["a", "b"] and len(guard._pending) == 0


def test_a_damaged_queue_is_kept_aside_and_reported(guard):
    _queue_file().write_text("{not json")

    restarted = Foldward(Settings())

    assert len(restarted._pending) == 0 and not _queue_file().exists()
    [warning] = [w for w in restarted.warnings if "waiting for Sentinel Vision's protected log was damaged" in w]
    kept = restarted._pending.kept_as
    assert kept and kept in warning
    assert (_queue_file().parent / kept).read_text() == "{not json"


def test_a_protected_log_filling_up_is_reported_from_80_percent(guard, alerts):
    sv = StandInSentinelVision()
    guard.sv = sv

    def filling():
        return [a for a in alerts if a[0] == "Sentinel Vision's protected log is filling up"]

    sv.room = {"bytes": 10, "limit": 100}
    guard.scan()
    assert filling() == []

    sv.room = {"bytes": 85, "limit": 100}
    guard.scan()
    assert filling() == []  # asked at most every few hours

    guard._next_room_check = 0.0
    guard.scan()
    [(_title, text, level)] = filling()
    assert level == "warning" and "85% full" in text and "on purpose" in text
    assert guard.audit.events("mirror.log_filling")

    sv.room = None  # an older Sentinel Vision doesn't say
    guard._next_room_check = 0.0
    guard.scan()
    assert len(filling()) == 1
