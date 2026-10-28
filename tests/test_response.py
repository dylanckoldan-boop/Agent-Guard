"""The pacify ladder. OS-level effects vary by platform; the audit/registry/state bookkeeping does not."""

from __future__ import annotations

import types

import pytest

from agent_guard import response as response_module
from agent_guard.quarantine import Quarantine
from agent_guard.registry import RevocationRegistry
from agent_guard.response import RUNG_BY_NAME, ActionResult, Containment, Response, Rung


@pytest.fixture
def registry(signer, audit):
    return RevocationRegistry(signer.verifier(), audit)


@pytest.fixture
def response(registry, signer, audit):
    return Response(registry, signer, audit, Containment())


def agent(**fields):
    """A lightweight stand-in for a detected agent (pacify only needs pid / agent_id / state)."""
    base = {"pid": None, "agent_id": "y", "state": "flagged"}
    base.update(fields)
    return types.SimpleNamespace(**base)


def rung_names(results):
    return [r.rung for r in results]


# ------------------------------------------------------------- a real child process
def test_pacify_suspend_records_audit_revokes_and_marks_contained(response, registry, audit, sleeper):
    ns = types.SimpleNamespace(pid=sleeper.pid, agent_id="x", state="flagged")

    results = response.pacify(ns, Rung.SUSPEND, auto=True, exe_path=None)

    assert rung_names(results) == ["throttle", "quarantine", "revoke", "suspend"]
    assert all(isinstance(r, ActionResult) for r in results)
    begin = audit.events("pacify.begin")[0].data
    assert begin == {"agent": "x", "pid": sleeper.pid, "up_to": "SUSPEND", "auto": True}
    for name in ("throttle", "quarantine", "revoke", "suspend"):
        assert len(audit.events(f"pacify.{name}")) == 1, name
    assert audit.events("pacify.terminate") == []  # the ladder stops where it was told to
    assert len(audit.events("pacify.escalate_to_human")) == 1
    assert registry.is_revoked("x")
    assert ns.state == "contained"
    assert audit.verify()[0]  # the whole trail is still a valid hash chain


def test_release_reverses_a_suspension(response, audit, sleeper):
    ns = types.SimpleNamespace(pid=sleeper.pid, agent_id="x", state="flagged")
    response.pacify(ns, Rung.SUSPEND, auto=True, exe_path=None)

    released = response.release(ns)

    assert released.ok
    assert released.rung == "release"
    assert ns.state == "healthy"
    assert audit.events("response.release")[0].data["agent"] == "x"


def test_releasing_a_process_that_already_exited_reports_failure(response, audit, sleeper):
    sleeper.kill()
    sleeper.wait(timeout=10)
    ns = types.SimpleNamespace(pid=sleeper.pid, agent_id="gone", state="contained")

    released = response.release(ns)

    assert released.ok is False
    assert ns.state == "contained"  # not marked healthy: nothing was actually resumed
    assert len(audit.events("response.release")) == 1


def test_pacify_falls_back_to_the_pid_when_an_agent_has_no_id(response, registry, sleeper):
    ns = types.SimpleNamespace(pid=sleeper.pid)  # neither agent_id nor state

    response.pacify(ns, Rung.REVOKE, auto=False)

    assert registry.is_revoked(f"pid:{sleeper.pid}")
    assert not hasattr(ns, "state")  # nothing is invented on the agent object


def test_pacify_survives_a_process_that_already_exited(response, registry, audit, sleeper):
    sleeper.kill()
    sleeper.wait(timeout=10)
    ns = types.SimpleNamespace(pid=sleeper.pid, agent_id="gone", state="flagged")

    results = response.pacify(ns, Rung.SUSPEND, auto=True)

    by_rung = {r.rung: r for r in results}
    assert by_rung["throttle"].ok is False
    assert by_rung["suspend"].ok is False
    assert by_rung["revoke"].ok is True  # the credential is pulled even though the process is gone
    assert registry.is_revoked("gone")
    assert ns.state == "contained"
    assert audit.events("pacify.suspend")[0].data["ok"] is False


# ------------------------------------------------------------------- no pid at all
def test_pacify_with_no_pid_does_not_raise_and_still_revokes(response, registry, audit):
    ns = types.SimpleNamespace(pid=None, agent_id="y", state="flagged")

    response.pacify(ns, Rung.SUSPEND, auto=True, exe_path=None)

    assert audit.events("pacify.suspend")
    assert registry.is_revoked("y")
    assert ns.state == "contained"


@pytest.mark.parametrize("rung", list(Rung), ids=lambda r: r.name.lower())
def test_every_rung_works_without_a_pid(response, registry, audit, rung):
    ns = agent()

    results = response.pacify(ns, rung, auto=True, exe_path=None)

    assert rung_names(results) == [r.name.lower() for r in Rung if r <= rung]
    for r in Rung:
        assert bool(audit.events(f"pacify.{r.name.lower()}")) is (r <= rung), r.name
    assert registry.is_revoked("y") is (rung >= Rung.REVOKE)
    assert ns.state == "contained"
    assert len(audit.events("pacify.escalate_to_human")) == 1


def test_release_without_a_pid_is_still_audited(response, audit):
    response.release(agent())

    assert len(audit.events("response.release")) == 1


# ------------------------------------------------------------- hooks and degradation
def test_pacify_reports_to_the_escalation_hook_and_keeps_history(registry, signer, audit):
    seen = []
    resp = Response(registry, signer, audit, Containment(), escalate=seen.append)

    resp.pacify(agent(), Rung.THROTTLE, auto=False)

    [event] = seen
    assert (event["agent"], event["up_to"], event["auto"]) == ("y", "THROTTLE", False)
    assert resp.history == seen


def test_revoke_rung_is_skipped_without_a_signing_authority(registry, signer, audit):
    resp = Response(registry, signer.verifier(), audit, Containment())

    results = resp.pacify(agent(), Rung.REVOKE, auto=True)

    assert results[-1].rung == "revoke"
    assert "skipped" in results[-1].detail
    assert not registry.is_revoked("y")


def test_quarantine_rung_stores_the_binary_in_the_encrypted_vault(registry, signer, audit, tmp_path):
    binary = tmp_path / "rogue_agent.py"
    binary.write_bytes(b"print('exfiltrate')\n")
    vault = Quarantine()
    resp = Response(registry, signer, audit, Containment(vault))

    results = resp.pacify(agent(agent_id="q-agent"), Rung.QUARANTINE, auto=True, exe_path=str(binary))

    assert rung_names(results) == ["throttle", "quarantine"]
    assert "encrypted quarantine" in results[-1].detail
    [item] = vault.list()
    assert (item.agent_id, item.original_path) == ("q-agent", str(binary))
    # preserve-by-moving: the binary is taken out of its runnable location (AG-A07)
    # but kept intact and restorable in the encrypted vault — not destroyed.
    assert not binary.exists()
    assert vault.restore(item.item_id, str(tmp_path / "recovered.py"))


def test_quarantine_rung_degrades_gracefully(response):
    no_vault = response.pacify(agent(), Rung.QUARANTINE, auto=True, exe_path="/some/binary")
    no_path = response.pacify(agent(), Rung.QUARANTINE, auto=True, exe_path=None)

    assert "no quarantine configured" in no_vault[-1].detail
    assert "no binary path" in no_path[-1].detail


def test_a_failed_quarantine_does_not_stop_the_ladder(registry, signer, audit, tmp_path):
    resp = Response(registry, signer, audit, Containment(Quarantine()))

    results = resp.pacify(agent(), Rung.REVOKE, auto=True, exe_path=str(tmp_path / "missing.bin"))

    by_rung = {r.rung: r for r in results}
    assert by_rung["quarantine"].ok is False
    assert "quarantine failed" in by_rung["quarantine"].detail
    assert registry.is_revoked("y")  # the credential was still pulled


def test_missing_psutil_is_reported_not_raised(monkeypatch, response, registry, sleeper):
    monkeypatch.setattr(response_module, "_HAVE_PSUTIL", False)
    c = Containment()
    for action in (c.throttle, c.suspend, c.resume, c.terminate):
        assert "unavailable" in action(sleeper.pid)

    results = response.pacify(agent(pid=sleeper.pid), Rung.SUSPEND, auto=True)

    by_rung = {r.rung: r for r in results}
    assert by_rung["throttle"].ok is False
    assert by_rung["suspend"].ok is False
    assert registry.is_revoked("y")


def test_standalone_egress_block_only_records_the_intent():
    detail = Containment().block_egress("203.0.113.9:443")

    assert "203.0.113.9" in detail
    assert "requested" in detail


def test_rungs_climb_from_the_gentlest_to_the_most_final():
    assert [r.name for r in sorted(Rung)] == ["THROTTLE", "QUARANTINE", "REVOKE", "SUSPEND", "TERMINATE"]
    assert RUNG_BY_NAME["suspend"] is Rung.SUSPEND
    assert set(RUNG_BY_NAME) == {r.name.lower() for r in Rung}
