"""The net: canary files, decoy contact, and asymmetric legibility."""

from __future__ import annotations

from pathlib import Path

import pytest

from foldward.tripwire import CANARY_NAMES, Decoy, Tripwire


@pytest.fixture
def tripwire(audit):
    return Tripwire(audit)


@pytest.fixture
def bait_dir(tmp_path):
    d = tmp_path / "bait"
    d.mkdir()
    return d


# ---------------------------------------------------------------------- canaries
def test_plant_canaries_writes_decoy_files(tripwire, bait_dir):
    planted = tripwire.plant_canaries([str(bait_dir)])

    assert sorted(Path(p).name for p in planted) == sorted(CANARY_NAMES)
    for p in planted:
        assert Path(p).parent == bait_dir
        assert Path(p).is_file()
        assert b"foldward-canary" in Path(p).read_bytes()
    assert len(tripwire.decoys()) == len(planted)
    assert {d.kind for d in tripwire.decoys()} == {"file"}


def test_is_canary_recognises_planted_files_and_nothing_else(tripwire, bait_dir):
    planted = tripwire.plant_canaries([str(bait_dir)])
    (bait_dir / "notes.txt").write_text("ordinary file")

    decoy_ids = {d.decoy_id for d in tripwire.decoys()}
    found = [tripwire.is_canary(p) for p in planted]
    assert all(found)
    assert set(found) == decoy_ids
    assert tripwire.is_canary(str(bait_dir / "notes.txt")) is None
    assert tripwire.is_canary("/definitely/not/a/canary") is None


def test_plant_canaries_never_overwrites_an_existing_file(tripwire, bait_dir):
    existing = bait_dir / "credentials.env"
    existing.write_text("REAL_SECRET=1")

    planted = tripwire.plant_canaries([str(bait_dir)])

    assert existing.read_text() == "REAL_SECRET=1"
    assert str(existing) not in planted
    assert tripwire.is_canary(str(existing)) is None
    assert len(planted) == len(CANARY_NAMES) - 1


def test_plant_canaries_skips_directories_that_do_not_exist(tripwire, tmp_path):
    assert tripwire.plant_canaries([str(tmp_path / "missing")]) == []
    assert tripwire.decoys() == []


def test_plant_canaries_can_target_several_directories(tripwire, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()

    planted = tripwire.plant_canaries([str(a), str(b)])

    assert len(planted) == 2 * len(CANARY_NAMES)
    assert {Path(p).parent for p in planted} == {a, b}


# ----------------------------------------------------------------------- contact
def test_on_contact_counts_the_trip_and_audits_it(tripwire, audit):
    assert tripwire.trips == 0

    ev = tripwire.on_contact("agent-7", "canary:/x", pid=4242, detail="read credentials.env")

    assert tripwire.trips == 1
    assert tripwire.events == [ev]
    assert (ev.decoy_id, ev.agent_id, ev.pid, ev.detail) == ("canary:/x", "agent-7", 4242, "read credentials.env")
    [fired] = audit.events("tripwire.fired")
    assert fired.data == {"decoy": "canary:/x", "agent": "agent-7", "pid": 4242, "detail": "read credentials.env"}

    tripwire.on_contact("agent-7", "canary:/y")
    assert tripwire.trips == 2
    assert len(audit.events("tripwire.fired")) == 2
    assert audit.verify() == (True, 2)


def test_on_contact_without_an_audit_log_still_counts():
    tripwire = Tripwire()

    tripwire.on_contact("agent-7", "canary:/x")

    assert tripwire.trips == 1


# ------------------------------------------------------- asymmetric legibility
def test_agent_and_human_views_of_a_decoy_differ(tripwire):
    decoy = Decoy(
        "act-export",
        "action",
        "export_all_secrets",
        human_note="HONEYPOT: any call to this is an intrusion",
        agent_note="Exports every credential in one call",
    )
    tripwire.register(decoy)

    assert decoy in tripwire.decoys()
    assert tripwire.agent_view(decoy) != tripwire.human_view(decoy)
    assert tripwire.human_view(decoy) == decoy.human_note  # a reviewer is always told the truth
    assert tripwire.agent_view(decoy) == decoy.agent_note
    assert tripwire.is_canary("export_all_secrets") is None  # only file decoys are canary paths


def test_planted_canaries_are_asymmetrically_legible(tripwire, bait_dir):
    tripwire.plant_canaries([str(bait_dir)])

    for decoy in tripwire.decoys():
        assert tripwire.agent_view(decoy) != tripwire.human_view(decoy)
        assert decoy.locator in tripwire.human_view(decoy)
