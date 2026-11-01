"""Optional partner adapters: absent by default, upgrades when present, never a hard dependency.

The ``_partners_absent`` autouse fixture (see conftest) hides sentinel-vision and cryptomigrate, so the
"not installed" assertions hold on any machine. Tests that need a partner *present* simulate one.
"""

from __future__ import annotations

import json
import subprocess
import sys
import types

import pytest

from foldward.config import Settings
from foldward.core import Foldward
from foldward.integrations import PartnerStatus, cryptomigrate, partner_status, sentinel_vision
from foldward.quarantine import Quarantine
from foldward.response import Containment


def attestation_payload(att: dict) -> bytes:
    body = {k: att[k] for k in ("format", "issued_at", "notary", "state")}
    return json.dumps(body, sort_keys=True).encode()


# ------------------------------------------------------------------ partners absent
def test_sentinel_vision_probe_reports_not_installed():
    assert sentinel_vision.probe() == (False, "not installed")
    assert sentinel_vision.is_present() is False


def test_cryptomigrate_probe_reports_not_installed():
    assert cryptomigrate.probe() == (False, "not installed")
    assert cryptomigrate.is_present() is False


def test_partner_status_reports_neither_partner():
    status = partner_status()

    assert isinstance(status, PartnerStatus)
    assert status.sentinel_vision is False
    assert status.cryptomigrate is False
    assert status.sentinel_vision_how == "not installed"
    assert status.cryptomigrate_how == "not installed"


def test_make_containment_without_sentinel_vision_is_the_base_ladder():
    containment = sentinel_vision.make_containment(None)

    assert isinstance(containment, Containment)
    assert type(containment) is Containment


def test_base_containment_keeps_the_vault_it_is_given(tmp_path):
    binary = tmp_path / "agent.bin"
    binary.write_bytes(b"\x7fELF")
    vault = Quarantine()

    containment = sentinel_vision.make_containment(vault)

    assert "stored in encrypted quarantine" in containment.quarantine_binary(str(binary), "agent-1", "pacified")
    assert len(vault) == 1


def test_sentinel_vision_adapter_degrades_to_notes_never_exceptions():
    adapter = sentinel_vision.SentinelVisionAdapter()

    assert adapter.available is False
    assert adapter.scan("/some/binary")["verdict"] == "unknown"
    assert "no firewall" in adapter.block_ip("45.12.10.9")
    handoff = adapter.quarantine_add("/some/binary", "pacified")
    assert handoff.status == "unavailable"
    assert "no sentinel-vision" in handoff.detail
    log = adapter.plugin_log_append({"event": "x"})
    assert log.ok is False
    assert "no sentinel-vision plugin-log" in log.detail
    assert adapter.plugin_log_verify()["intact"] is None


def test_cryptomigrate_adapter_degrades_to_notes_never_exceptions(tmp_path):
    adapter = cryptomigrate.CryptomigrateAdapter()

    assert adapter.available is False
    assert adapter.crypto_scan(str(tmp_path)) == {
        "available": False,
        "findings": [],
        "detail": "cryptomigrate not installed",
    }


def test_attestation_is_self_signed_without_cryptomigrate(signer):
    state = {"audit_len": 3}

    att = cryptomigrate.CryptomigrateAdapter().attest(state, signer)

    assert att["notary"] == "foldward"
    assert att["state"] == state
    assert att["signer_ref"] == signer.public_ref
    assert signer.verifier().verify(attestation_payload(att), att["signature"])


def test_attestation_needs_a_signing_authority_to_carry_a_signature(signer):
    att = cryptomigrate.CryptomigrateAdapter().attest({}, signer.verifier())

    assert att["signature"] is None
    assert att["signer_ref"] == signer.public_ref


def test_the_guard_runs_standalone_with_no_partners(guard):
    assert guard.partners.sentinel_vision is False
    assert guard.partners.cryptomigrate is False
    assert type(guard.containment) is Containment
    assert guard.attest()["notary"] == "foldward"


# ----------------------------------------------------------------- partners present
def test_an_importable_package_is_not_trusted_as_sentinel_vision(monkeypatch):
    # Anything named sentinel_vision on the Python path (a squatted PyPI package, a planted
    # folder) is ignored when Foldward runs on its own (INT-03); cryptomigrate is unchanged.
    monkeypatch.setitem(sys.modules, "sentinel_vision", types.ModuleType("sentinel_vision"))
    monkeypatch.setitem(sys.modules, "cryptomigrate", types.ModuleType("cryptomigrate"))

    assert sentinel_vision.probe() == (False, "not installed")
    assert cryptomigrate.probe() == (True, "in-process (import cryptomigrate)")


def test_when_hosted_by_sentinel_vision_the_host_is_used_in_process(monkeypatch):
    host = types.ModuleType("sentinel_vision")
    host.__version__ = "0.5.2"
    monkeypatch.setitem(sys.modules, "sentinel_vision", host)
    sentinel_vision.mark_hosted()  # what the plugin entry point does

    assert sentinel_vision.probe() == (True, "in-process (hosted by Sentinel Vision 0.5.2)")
    assert partner_status().sentinel_vision is True


def test_cryptomigrate_on_path_is_detected_through_its_cli(monkeypatch):
    on_path = types.SimpleNamespace(which=lambda name, *args, **kwargs: f"/opt/bin/{name}")
    monkeypatch.setattr(cryptomigrate, "shutil", on_path)

    assert cryptomigrate.probe() == (True, "cli (cryptomigrate)")


def test_cryptomigrate_becomes_the_notary_when_it_is_present(monkeypatch, signer):
    monkeypatch.setitem(sys.modules, "cryptomigrate", types.ModuleType("cryptomigrate"))
    adapter = cryptomigrate.CryptomigrateAdapter()

    assert adapter.available is True
    assert adapter.attest({}, signer)["notary"] == "cryptomigrate"


def test_cryptomigrate_scan_errors_are_reported_not_raised(monkeypatch, tmp_path):
    # present, but exposing no discovery entry point (an older or different version)
    monkeypatch.setitem(sys.modules, "cryptomigrate", types.ModuleType("cryptomigrate"))

    result = cryptomigrate.CryptomigrateAdapter().crypto_scan(str(tmp_path))

    assert result["available"] is True
    assert result["findings"] == []
    assert "scan error" in result["detail"]


_ITEM_ID = "0123456789abcdef0123456789abcdef"


class FakeSentinelVisionCli:
    """Stands in for ``sentinel-vision-cli``: records every invocation and returns a canned result.
    ``--version`` answers like the real tool (just the version number) and isn't recorded."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.returncode = 0
        self.stdout = "ok"
        self.stderr = ""
        self.version = "0.5.2"

    def run(self, cmd, **_kwargs):
        if list(cmd)[1:] == ["--version"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=self.version + "\n", stderr="")
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, self.returncode, stdout=self.stdout, stderr=self.stderr)


@pytest.fixture
def sv_cli(monkeypatch):
    """A Sentinel Vision found in its install folder, whose folder passes the ownership check."""
    cli = FakeSentinelVisionCli()
    in_install_dir = types.SimpleNamespace(which=lambda name, *args, **kwargs: f"/opt/sv/{name}")
    monkeypatch.setattr(sentinel_vision, "shutil", in_install_dir)
    monkeypatch.setattr(sentinel_vision, "subprocess", types.SimpleNamespace(run=cli.run))
    monkeypatch.setattr(sentinel_vision, "_location_problem", lambda path, root: None)
    return cli


def test_sentinel_vision_is_found_with_its_path_and_version(sv_cli):
    # `status` shows exactly what was found (AG-A04, AG-C04)
    assert sentinel_vision.probe() == (True, "cli /opt/sv/sentinel-vision-cli, version 0.5.2")


def test_an_install_folder_others_can_change_is_not_trusted(sv_cli, monkeypatch):
    monkeypatch.setattr(sentinel_vision, "_location_problem", lambda path, root: f"{path} can be changed by other users")

    present, how = sentinel_vision.probe()

    assert present is False
    assert "isn't trusted" in how
    assert type(sentinel_vision.make_containment(None)) is Containment


def test_a_sentinel_vision_older_than_0_5_1_is_not_used(sv_cli):
    sv_cli.version = "0.4.1"

    present, how = sentinel_vision.probe()

    assert present is False
    assert "needs 0.5.1 or newer" in how


def test_the_guard_swaps_in_sentinel_vision_containment_when_it_is_present(sv_cli):
    g = Foldward(Settings())

    assert g.partners.sentinel_vision is True
    assert isinstance(g.containment, Containment)
    assert type(g.containment) is not Containment


def test_sentinel_vision_containment_routes_egress_blocks_to_the_os_firewall(sv_cli):
    containment = sentinel_vision.make_containment(None)

    detail = containment.block_egress("45.12.10.9:443")

    assert type(containment) is not Containment
    assert "45.12.10.9" in detail
    assert sv_cli.calls == [["/opt/sv/sentinel-vision-cli", "net", "block", "--", "45.12.10.9"]]  # port stripped


def test_an_ipv6_egress_block_targets_that_exact_address(sv_cli):
    sentinel_vision.make_containment(None).block_egress("[2606:4700:4700::1111]:443")

    assert sv_cli.calls == [["/opt/sv/sentinel-vision-cli", "net", "block", "--", "2606:4700:4700::1111"]]


@pytest.mark.parametrize("bad", ["-h", "--help", "10.0.0.5", "203.0.113.9", "not-an-ip", ""])
def test_only_a_public_address_reaches_the_firewall(sv_cli, bad):
    # an option-looking or private address is refused before sentinel-vision is called (AG-F08)
    detail = sentinel_vision.make_containment(None).block_egress(bad)

    assert detail.startswith("firewall block refused")
    assert sv_cli.calls == []


def test_sentinel_vision_containment_hands_binaries_to_its_vault(sv_cli, tmp_path):
    sv_cli.stdout = _ITEM_ID + "\n"
    binary = tmp_path / "agent.bin"
    binary.write_bytes(b"\x7fELF")
    own_vault = Quarantine()
    containment = sentinel_vision.make_containment(own_vault)

    detail = containment.quarantine_binary(str(binary), "agent-1", "pacified")

    assert detail == f"handed to sentinel-vision vault (id {_ITEM_ID})"
    assert sv_cli.calls == [
        ["/opt/sv/sentinel-vision-cli", "quarantine", "add", "--reason", "pacified", "--", str(binary)]
    ]
    assert len(own_vault) == 0  # sentinel-vision is the system of record, not Foldward's own store


def test_a_success_without_a_valid_item_id_is_not_trusted(sv_cli, tmp_path):
    sv_cli.stdout = "ok"
    binary = tmp_path / "agent.bin"
    binary.write_bytes(b"\x7fELF")
    own_vault = Quarantine()

    detail = sentinel_vision.make_containment(own_vault).quarantine_binary(str(binary), "agent-1", "pacified")

    assert detail.startswith("quarantine refused")
    assert "valid item id" in detail
    assert len(own_vault) == 0  # sentinel-vision may already hold it: no second copy


def test_a_sentinel_vision_refusal_is_final(sv_cli, tmp_path):
    # exit 3 = refused on purpose: Foldward must not move the file itself instead (INT-04)
    sv_cli.returncode, sv_cli.stderr = 3, "error: operating-system files are never quarantined on request"
    binary = tmp_path / "agent.bin"
    binary.write_bytes(b"\x7fELF")
    own_vault = Quarantine()

    detail = sentinel_vision.make_containment(own_vault).quarantine_binary(str(binary), "agent-1", "pacified")

    assert detail.startswith("quarantine refused")
    assert "operating-system files" in detail
    assert len(own_vault) == 0
    assert binary.exists()


def test_sentinel_vision_containment_falls_back_to_the_own_vault_when_it_is_unavailable(sv_cli, tmp_path):
    sv_cli.returncode, sv_cli.stderr = 2, "error: protection service not reachable"
    binary = tmp_path / "agent.bin"
    binary.write_bytes(b"\x7fELF")
    own_vault = Quarantine()
    containment = sentinel_vision.make_containment(own_vault)

    detail = containment.quarantine_binary(str(binary), "agent-1", "pacified")

    assert "stored in encrypted quarantine" in detail
    assert "sentinel-vision unavailable" in detail
    assert len(own_vault) == 1
    assert not binary.exists()


@pytest.mark.parametrize(
    ("returncode", "stdout", "verdict"),
    [
        (1, '{"scanned": 1, "threats": 2, "errors": 0}', "malware"),  # exit 1 means threats found (INT-01)
        (0, '{"scanned": 1, "threats": 0, "errors": 0}', "clean"),
        (0, '{"scanned": 1, "threats": 2, "errors": 0}', "unknown"),  # output and exit code disagree
        (0, '{"scanned": 1, "threats": 0, "errors": 1}', "unknown"),  # it couldn't read the file: not clean
        (0, '{"scanned": 0, "threats": 0, "errors": 0}', "unknown"),  # nothing was scanned: not clean
        (0, '{"threats": 0}', "unknown"),  # no file count
        (0, "{}", "unknown"),  # no threat count
        (0, "this is not json", "unknown"),
        (2, "", "unknown"),  # an error is not a verdict
    ],
)
def test_scan_verdicts_follow_the_cli_contract(sv_cli, returncode, stdout, verdict):
    sv_cli.returncode, sv_cli.stdout = returncode, stdout

    result = sentinel_vision.SentinelVisionAdapter().scan("/some/binary")

    assert result["verdict"] == verdict
    assert sv_cli.calls[0] == ["/opt/sv/sentinel-vision-cli", "scan", "--no-quarantine", "--json", "--", "/some/binary"]


# ----------------------------------------------------------- SV 0.4.1+ protected log
def test_plugin_log_append_uses_the_cli_when_present(sv_cli):
    res = sentinel_vision.SentinelVisionAdapter().plugin_log_append({"event": "pacify", "agent": "rogue-1"})

    assert res.ok is True
    assert "protected log" in res.detail
    assert sv_cli.calls[0][:4] == ["/opt/sv/sentinel-vision-cli", "plugin-log", "append", "foldward"]
    assert sv_cli.calls[0][4] == "--json"
    assert json.loads(sv_cli.calls[0][5]) == {"event": "pacify", "agent": "rogue-1"}


def test_plugin_log_verify_checks_both_the_current_and_legacy_logs(sv_cli):
    sv_cli.stdout = '{"intact": true, "entries": 2, "protected": true}'

    result = sentinel_vision.SentinelVisionAdapter().plugin_log_verify()

    verified = [c[3] for c in sv_cli.calls if c[1:3] == ["plugin-log", "verify"]]
    assert verified == ["foldward", "agent-guard"]  # the new name, then the pre-rename log
    assert result["intact"] is True


def test_plugin_log_verify_reports_a_broken_chain_not_a_missing_surface(sv_cli):
    sv_cli.returncode, sv_cli.stdout = 1, '{"intact": false, "entries": 2, "protected": true}'  # SV exits 1

    result = sentinel_vision.SentinelVisionAdapter().plugin_log_verify()

    assert result["intact"] is False


def test_plugin_log_verify_is_unknown_unless_every_log_was_checked(sv_cli, monkeypatch):
    adapter = sentinel_vision.SentinelVisionAdapter()
    answers = {
        "foldward": subprocess.CompletedProcess([], 2, stdout="", stderr="error: service not reachable"),
        "agent-guard": subprocess.CompletedProcess([], 0, stdout='{"intact": true, "entries": 0}', stderr=""),
    }
    monkeypatch.setattr(adapter, "_run", lambda args, timeout: answers[args[2]])

    assert adapter.plugin_log_verify()["intact"] is None  # a never-written legacy log alone proves nothing


def test_plugin_log_verify_distrusts_an_answer_that_contradicts_its_exit_code(sv_cli):
    sv_cli.returncode, sv_cli.stdout = 1, '{"intact": true, "entries": 2, "protected": true}'

    assert sentinel_vision.SentinelVisionAdapter().plugin_log_verify()["intact"] is None


def test_pacify_mirrors_a_record_to_the_protected_log_when_present(guard):
    appended: list[dict] = []
    guard.sv = types.SimpleNamespace(
        plugin_log_append=lambda rec: appended.append(rec) or types.SimpleNamespace(ok=True, detail="appended")
    )
    agent = types.SimpleNamespace(
        pid=None, agent_id="rogue-1", state="flagged", label="rogue",
        proc=types.SimpleNamespace(exe=None),
    )

    guard.pacify(agent, "revoke", auto=True)

    assert len(appended) == 1
    assert appended[0]["event"] == "pacify"
    assert appended[0]["agent"] == "rogue-1"
    assert appended[0]["rung"] == "revoke"
    assert "audit_head" in appended[0]


def test_a_record_that_cant_be_mirrored_is_reported_and_retried(guard, monkeypatch):
    # INT-05: a failed copy to the protected log is never silent
    answers = [types.SimpleNamespace(ok=False, detail="service unreachable"), types.SimpleNamespace(ok=True, detail="ok")]
    tried: list[dict] = []
    guard.sv = types.SimpleNamespace(plugin_log_append=lambda rec: tried.append(rec) or answers.pop(0))
    alerts: list[str] = []
    guard.alert_listeners.append(lambda title, text, level: alerts.append(title))
    monkeypatch.setattr(guard.detector, "snapshot_processes", lambda: [])
    agent = types.SimpleNamespace(
        pid=None, agent_id="rogue-1", state="flagged", label="rogue", proc=types.SimpleNamespace(exe=None)
    )

    guard.pacify(agent, "revoke", auto=True)

    assert "Containment record not yet protected" in alerts
    assert guard.audit.events("mirror.failed")
    guard.scan()  # the next scan retries
    assert len(tried) == 2
    assert guard.audit.events("mirror.retried")
    assert guard._pending_mirror == []


def test_plugin_pages_are_namespaced_to_avoid_host_key_collisions():
    pytest.importorskip("PySide6")
    from foldward.gui.plugin import register

    pages = register()
    keys = [p.key for p in pages]

    assert keys, "register() returned no pages"
    assert all(k.startswith("ag_") for k in keys)
    # sentinel-vision skips a plugin page whose key matches one of its built-ins
    sv_builtins = {"overview", "quarantine", "settings", "scan", "network", "history", "protection"}
    assert not (set(keys) & sv_builtins)
    assert all(p.label.startswith("Foldward ·") for p in pages)
