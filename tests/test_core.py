"""The Foldward facade: wiring, admission, containment policy, snapshot and attestation."""

from __future__ import annotations

import json

import pytest

from foldward.config import Settings
from foldward.core import Foldward, GuardSnapshot, _quarantine_target
from foldward.detect import DetectedAgent, ProcessInfo, Reason
from foldward.identity import Scope
from foldward.integrations import partner_status
from foldward.mesh import MeshSnapshot
from foldward.response import Containment

DECOY_REASON = Reason("touched a decoy / honeytoken", 100, "tripwire")


def detection(reasons, agent_id="rogue-1") -> DetectedAgent:
    """A detection with no live process behind it (pid=None), so containment is pure bookkeeping."""
    proc = ProcessInfo(pid=12345, name="rogue", exe="", cmdline=["rogue"])
    score = min(100, sum(r.points for r in reasons))
    return DetectedAgent(None, "rogue", proc, False, score, list(reasons), agent_id=agent_id)


def attestation_payload(att: dict) -> bytes:
    body = {k: att[k] for k in ("format", "issued_at", "notary", "state")}
    return json.dumps(body, sort_keys=True).encode()


# --------------------------------------------------------------------------- build
def test_guard_builds_with_default_settings(guard):
    assert guard.signer.can_sign()
    assert guard.audit.verify() == (True, 1)
    [start] = guard.audit.events("guard.start")
    assert start.data["scheme"] == guard.signer.scheme
    assert type(guard.containment) is Containment  # standalone ladder: no sentinel-vision to swap in


def test_guard_state_is_confined_to_the_isolated_data_root(guard, tmp_path):
    assert (tmp_path / "Foldward" / "quarantine" / "quarantine.key").is_file()


def test_a_guard_built_without_settings_loads_and_saves_them_in_the_isolated_root(tmp_path):
    Foldward()

    assert (tmp_path / "Foldward" / "settings.json").is_file()


def test_default_settings_are_conservative():
    s = Settings()

    assert s.report_only is True
    assert s.auto_contain_on_decoy is True
    assert s.auto_contain_max_rung == "suspend"  # nothing as final as terminate happens unattended
    assert s.risk_flag_threshold < s.risk_contain_threshold


def test_settings_round_trip_through_the_isolated_file(tmp_path):
    Settings(report_only=False, scan_interval_s=9.0).save()

    assert (tmp_path / "Foldward" / "settings.json").is_file()
    loaded = Settings.load()
    assert loaded.report_only is False
    assert loaded.scan_interval_s == 9.0


def test_settings_loading_ignores_unknown_keys(tmp_path):
    saved = {"report_only": False, "added_by_a_future_version": 1}
    (tmp_path / "Foldward" / "settings.json").write_text(json.dumps(saved), "utf-8")

    assert Settings.load().report_only is False


def test_settings_loading_survives_a_corrupt_file(tmp_path):
    (tmp_path / "Foldward" / "settings.json").write_text("{not json", "utf-8")

    assert Settings.load() == Settings()


def test_standalone_install_reports_no_partners(guard):
    status = partner_status()

    assert status.sentinel_vision is False
    assert status.cryptomigrate is False
    assert guard.partners == status


# ----------------------------------------------------------------------- admission
def test_register_agent_issues_a_valid_credential(guard):
    ident = guard.register_agent("x", Scope())

    assert guard.trust.verify(ident.credential)
    assert ident.label == "x"
    assert ident.credential.agent_id == ident.agent_id
    assert ident in guard.sanctioned()
    assert guard.audit.events("admission.registered")[-1].data["agent"] == ident.agent_id


def test_each_registered_agent_gets_its_own_id(guard):
    a = guard.register_agent("a", Scope())
    b = guard.register_agent("b", Scope())

    assert a.agent_id != b.agent_id
    assert len(guard.sanctioned()) == 2


# ----------------------------------------------------------------------------- net
def test_plant_canaries_is_audited_and_registered(guard, tmp_path):
    bait = tmp_path / "bait"
    bait.mkdir()

    planted = guard.plant_canaries([str(bait)])

    assert planted
    assert guard.audit.events("tripwire.planted")[-1].data == {"count": len(planted)}
    assert guard.tripwire.is_canary(planted[0])


# --------------------------------------------------------------- containment policy
def test_decoy_touch_auto_contains_and_revokes(guard):
    d = detection([DECOY_REASON])

    guard._evaluate(d)

    assert d.state == "contained"
    assert guard.registry.is_revoked("rogue-1")
    begin = guard.audit.events("pacify.begin")[-1].data
    assert begin["auto"] is True
    assert begin["up_to"] == "SUSPEND"  # the configured ceiling: never terminate unattended


def test_auto_containment_alerts_the_operator(guard):
    alerts = []
    guard.alert_listeners.append(lambda title, text, level: alerts.append((title, level)))

    guard._evaluate(detection([DECOY_REASON]))

    titles = [title for title, _ in alerts]
    assert "Rogue agent flagged" in titles
    assert "Escalated to operator" in titles
    assert "Agent pacified" in titles


def test_every_evaluation_emits_a_mixed_oversight_record(guard):
    guard._evaluate(detection([DECOY_REASON]))

    assert guard.mix.stats.real_emitted == 1
    assert guard.mix.stats.cover_emitted == guard.settings.mix_min_cover


def test_decoy_touch_is_only_flagged_when_auto_containment_is_off():
    g = Foldward(Settings(auto_contain_on_decoy=False))  # report_only stays on
    d = detection([DECOY_REASON])

    g._evaluate(d)

    assert d.state == "flagged"
    assert not g.registry.is_revoked("rogue-1")


def test_consensus_containment_acts_only_when_report_only_is_off():
    reasons = [Reason("no credential", 100, "identity"), Reason("fan-out", 100, "reach"),
               Reason("spawn", 100, "behaviour")]
    watching, acting = Foldward(Settings()), Foldward(Settings(report_only=False))
    quiet, active = detection(reasons, "quiet-1"), detection(reasons, "active-1")

    watching._evaluate(quiet)
    acting._evaluate(active)

    assert quiet.state == "flagged"  # surfaced for the operator to act on
    assert not watching.registry.is_revoked("quiet-1")
    assert active.state == "contained"
    assert acting.registry.is_revoked("active-1")


def test_one_noisy_sentinel_cannot_force_containment_even_when_acting():
    g = Foldward(Settings(report_only=False))
    d = detection([Reason("fan-out", 100, "reach")])

    g._evaluate(d)

    assert d.state == "flagged"
    assert not g.registry.is_revoked("rogue-1")


@pytest.mark.parametrize(
    ("margin", "state"),
    [pytest.param(0, "flagged", id="at-threshold"), pytest.param(1, "healthy", id="below-threshold")],
)
def test_the_flag_threshold_is_inclusive(margin, state):
    g = Foldward(Settings(risk_flag_threshold=35 + margin))
    d = detection([Reason("unregistered agent", 35, "identity")])

    g._evaluate(d)

    assert d.state == state


@pytest.mark.parametrize(("contain_threshold", "state"), [(85, "flagged"), (40, "contained")])
def test_the_contain_threshold_setting_gates_consensus_containment(contain_threshold, state):
    # three sentinels agree, but their weighted risk (about 47) only clears the lower threshold
    reasons = [
        Reason("no credential", 35, "identity"),
        Reason("fan-out", 15, "reach"),
        Reason("spawn", 20, "behaviour"),
    ]
    g = Foldward(Settings(report_only=False, risk_contain_threshold=contain_threshold))
    d = detection(reasons)

    g._evaluate(d)

    assert d.state == state


@pytest.mark.parametrize(
    ("requested", "reached"),
    [
        ("throttle", "THROTTLE"),
        ("quarantine", "QUARANTINE"),
        ("revoke", "REVOKE"),
        ("suspend", "SUSPEND"),
        ("terminate", "TERMINATE"),
        ("SUSPEND", "SUSPEND"),
        ("bogus", "SUSPEND"),  # an unknown rung falls back to the safe, reversible one
        (None, "SUSPEND"),  # no rung asked for: the configured auto-contain ceiling
    ],
)
def test_pacify_climbs_to_the_requested_rung(guard, requested, reached):
    d = detection([DECOY_REASON])

    guard.pacify(d, requested)

    assert guard.response.history[-1]["up_to"] == reached
    assert d.state == "contained"


@pytest.mark.parametrize(
    ("exe", "cmdline", "expected"),
    [
        # a script run under an interpreter: quarantine the script
        ("/usr/bin/python3", ["/usr/bin/python3", "/home/x/agent.py"], "/home/x/agent.py"),
        ("", ["python", "langchain_agent.py"], "langchain_agent.py"),
        # a `-m module` run: NOTHING safe to isolate — never the interpreter (AG-A05)
        ("/usr/bin/python3", ["python", "-m", "crewai", "run"], None),
        ("/usr/local/bin/node", ["node"], None),
        # a native binary: quarantine the binary itself
        ("/opt/rogue/rogue.bin", ["/opt/rogue/rogue.bin", "--go"], "/opt/rogue/rogue.bin"),
    ],
)
def test_quarantine_target_never_picks_the_interpreter(exe, cmdline, expected):
    proc = ProcessInfo(pid=1, name="p", exe=exe, cmdline=cmdline)
    assert _quarantine_target(proc) == expected


def test_a_low_risk_detection_is_neither_flagged_nor_contained(guard):
    d = detection([Reason("unregistered agent", 35, "identity")])

    guard._evaluate(d)

    assert d.state == "healthy"
    assert guard.audit.events("detect.flagged") == []


def test_a_failing_alert_listener_does_not_break_containment(guard):
    seen = []

    def broken(*_args):
        raise RuntimeError("listener bug")

    guard.alert_listeners.extend([broken, lambda title, text, level: seen.append(title)])
    d = detection([DECOY_REASON])

    guard._evaluate(d)

    assert d.state == "contained"
    assert "Agent pacified" in seen


def test_quiet_mode_suppresses_info_alerts_only():
    g = Foldward(Settings(quiet_mode=True))
    levels = []
    g.alert_listeners.append(lambda title, text, level: levels.append(level))

    g.release(detection([DECOY_REASON]))  # an "info" alert
    g._evaluate(detection([DECOY_REASON], "rogue-2"))  # "danger" / "warning" alerts

    assert "info" not in levels
    assert "danger" in levels


# ------------------------------------------------------------------------ scanning
def test_scan_scores_detections_and_the_snapshot_counts_them(guard, monkeypatch):
    proc = ProcessInfo(pid=424242, name="crew", exe="", cmdline=["python", "crewai_runner.py"])
    monkeypatch.setattr(guard.detector, "snapshot_processes", lambda: [proc])

    detections = guard.scan()

    assert [d.pid for d in detections] == [424242]
    assert detections[0].state == "healthy"  # unregistered alone is below the flag threshold
    snap = guard.snapshot()
    assert (snap.total_agents, snap.healthy, snap.flagged, snap.contained) == (1, 1, 0, 0)


def test_revoking_a_credential_makes_the_agent_unsanctioned_again(guard, monkeypatch):
    ident = guard.register_agent("worker", Scope(), pid=424242)
    proc = ProcessInfo(pid=424242, name="worker", exe="", cmdline=["python", "langchain_worker.py"])
    monkeypatch.setattr(guard.detector, "snapshot_processes", lambda: [proc])

    [before] = guard.scan()
    guard.registry.revoke(ident.agent_id, "operator revoked", guard.signer)
    [after] = guard.scan()

    assert (before.sanctioned, before.agent_id, before.score) == (True, ident.agent_id, 0)
    assert after.sanctioned is False
    assert after.score >= 35


def test_decoy_contact_pacifies_a_real_process_end_to_end(guard, sleeper, monkeypatch):
    proc = ProcessInfo(pid=sleeper.pid, name="rogue", exe="", cmdline=["python", "langchain_agent.py"])
    monkeypatch.setattr(guard.detector, "snapshot_processes", lambda: [proc])
    alerts = []
    guard.alert_listeners.append(lambda title, text, level: alerts.append(title))

    [d] = guard.scan(decoy_pids={sleeper.pid})

    assert (d.score, d.state) == (100, "contained")
    assert guard.registry.is_revoked(f"pid:{sleeper.pid}")
    assert "Agent pacified" in alerts
    snap = guard.snapshot()
    assert (snap.total_agents, snap.contained, snap.revoked) == (1, 1, 1)
    assert snap.audit_len == len(guard.audit)
    assert snap.mesh.core_state == "containing"
    assert snap.mesh.agents == [{"label": "rogue", "state": "contained", "score": 100}]

    # containment is reversible: releasing the agent thaws it and clears the state
    assert guard.release(d).ok
    assert d.state == "healthy"


# ---------------------------------------------------------------------- snapshot
def test_snapshot_of_a_fresh_guard_is_nominal(guard):
    snap = guard.snapshot()

    assert isinstance(snap, GuardSnapshot)
    assert snap.audit_ok is True
    assert isinstance(snap.mesh, MeshSnapshot)
    assert snap.mesh.core_state == "nominal"
    assert [s["kind"] for s in snap.mesh.sentinels] == ["identity", "reach", "behaviour", "tripwire"]
    assert snap.mesh.mix_enabled is guard.settings.mix_oversight_traffic
    assert snap.partners == guard.partners.__dict__
    assert (snap.total_agents, snap.flagged, snap.contained, snap.revoked, snap.trips) == (0, 0, 0, 0, 0)


def test_snapshot_reports_the_mix_cover_ratio(guard):
    cover = guard.settings.mix_min_cover
    assert guard.snapshot().mesh.mix_cover_ratio == 0.0

    guard._evaluate(detection([DECOY_REASON]))  # one real oversight record, padded with `cover` cover records

    assert guard.snapshot().mesh.mix_cover_ratio == pytest.approx(cover / (cover + 1))


def test_snapshot_reports_a_broken_audit_chain(guard):
    guard.audit._entries[0].data["scheme"] = "forged"

    assert guard.snapshot().audit_ok is False


# --------------------------------------------------------------------- attestation
def test_attest_returns_a_signed_foldward_attestation(guard):
    att = guard.attest()

    assert att["notary"] == "foldward"
    assert att["signature"] is not None
    assert att["format"] == "foldward-attestation/1"
    assert att["signer_ref"] == guard.signer.public_ref
    assert att["state"]["audit_intact"] is True


def test_attestation_signature_verifies_and_binds_the_reported_state(guard):
    att = guard.attest()
    verifier = guard.signer.verifier()

    assert verifier.verify(attestation_payload(att), att["signature"])

    att["state"] = {**att["state"], "revocations": 99}
    assert not verifier.verify(attestation_payload(att), att["signature"])


def test_attestation_reflects_what_the_guard_has_done(guard):
    guard.register_agent("x", Scope())
    guard._evaluate(detection([DECOY_REASON]))

    state = guard.attest()["state"]

    assert state["sanctioned"] == 1
    assert state["revocations"] == 1
    assert state["containments"] == 1
    assert state["audit_len"] == len(guard.audit)  # attesting is read-only: it appends nothing
    assert state["audit_head"] == guard.audit.head


@pytest.mark.parametrize("scheme", ["auto", "ed25519", "hmac"])
def test_guard_runs_on_every_signer_scheme(scheme):
    g = Foldward(Settings(signer_scheme=scheme))
    ident = g.register_agent("x", Scope())

    assert g.trust.verify(ident.credential)
    assert g.snapshot().audit_ok is True
    assert g.attest()["signature"] is not None
