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
    assert "no firewall" in adapter.block_ip("203.0.113.9")
    assert "no sentinel-vision" in adapter.quarantine_add("/some/binary", "pacified")
    assert "no sentinel-vision plugin-log" in adapter.plugin_log_append({"event": "x"})
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
def test_importable_partners_are_detected_in_process(monkeypatch):
    monkeypatch.setitem(sys.modules, "sentinel_vision", types.ModuleType("sentinel_vision"))
    monkeypatch.setitem(sys.modules, "cryptomigrate", types.ModuleType("cryptomigrate"))

    assert sentinel_vision.probe() == (True, "in-process (import sentinel_vision)")
    assert cryptomigrate.probe() == (True, "in-process (import cryptomigrate)")
    status = partner_status()
    assert (status.sentinel_vision, status.cryptomigrate) == (True, True)


def test_partners_on_path_are_detected_through_their_cli(monkeypatch):
    on_path = types.SimpleNamespace(which=lambda name, *args, **kwargs: f"/opt/bin/{name}")
    monkeypatch.setattr(sentinel_vision, "shutil", on_path)
    monkeypatch.setattr(cryptomigrate, "shutil", on_path)

    assert sentinel_vision.probe() == (True, "cli (sentinel-vision-cli)")
    assert cryptomigrate.probe() == (True, "cli (cryptomigrate)")


def test_the_guard_swaps_in_sentinel_vision_containment_when_it_is_present(monkeypatch):
    monkeypatch.setitem(sys.modules, "sentinel_vision", types.ModuleType("sentinel_vision"))

    g = Foldward(Settings())

    assert g.partners.sentinel_vision is True
    assert isinstance(g.containment, Containment)
    assert type(g.containment) is not Containment


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


class FakeSentinelVisionCli:
    """Stands in for ``sentinel-vision-cli``: records every invocation and returns a canned result."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.returncode = 0
        self.stdout = "ok"
        self.stderr = ""

    def run(self, cmd, **_kwargs):
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, self.returncode, stdout=self.stdout, stderr=self.stderr)


@pytest.fixture
def sv_cli(monkeypatch):
    cli = FakeSentinelVisionCli()
    found_on_path = types.SimpleNamespace(which=lambda name, *args, **kwargs: f"/opt/sv/{name}")
    monkeypatch.setattr(sentinel_vision, "shutil", found_on_path)
    monkeypatch.setattr(sentinel_vision, "subprocess", types.SimpleNamespace(run=cli.run))
    return cli


def test_sentinel_vision_containment_routes_egress_blocks_to_the_os_firewall(sv_cli):
    containment = sentinel_vision.make_containment(None)

    detail = containment.block_egress("203.0.113.9:443")

    assert type(containment) is not Containment
    assert "203.0.113.9" in detail
    assert sv_cli.calls == [["/opt/sv/sentinel-vision-cli", "net", "block", "203.0.113.9"]]  # port stripped


def test_sentinel_vision_containment_hands_binaries_to_its_vault(sv_cli, tmp_path):
    binary = tmp_path / "agent.bin"
    binary.write_bytes(b"\x7fELF")
    own_vault = Quarantine()
    containment = sentinel_vision.make_containment(own_vault)

    detail = containment.quarantine_binary(str(binary), "agent-1", "pacified")

    assert detail.startswith("handed to sentinel-vision vault")
    assert sv_cli.calls == [["/opt/sv/sentinel-vision-cli", "quarantine", "add", str(binary), "--reason", "pacified"]]
    assert len(own_vault) == 0  # sentinel-vision is the system of record, not Foldward's own store


def test_sentinel_vision_containment_falls_back_to_the_own_vault_when_the_verb_is_missing(sv_cli, tmp_path):
    sv_cli.returncode, sv_cli.stderr = 2, "unknown command: quarantine add"
    binary = tmp_path / "agent.bin"
    binary.write_bytes(b"\x7fELF")
    own_vault = Quarantine()
    containment = sentinel_vision.make_containment(own_vault)

    detail = containment.quarantine_binary(str(binary), "agent-1", "pacified")

    assert "stored in encrypted quarantine" in detail
    assert len(own_vault) == 1


@pytest.mark.parametrize(
    ("stdout", "verdict"),
    [
        ('{"threats": 2}', "malware"),
        ('{"infected": 1}', "malware"),
        ('{"threats": 0}', "clean"),
        ("{}", "clean"),
        ("this is not json", "unknown"),
    ],
)
def test_scan_verdicts_come_from_the_cli_output(sv_cli, stdout, verdict):
    sv_cli.stdout = stdout

    result = sentinel_vision.SentinelVisionAdapter().scan("/some/binary")

    assert result["verdict"] == verdict
    assert sv_cli.calls[0][:3] == ["/opt/sv/sentinel-vision-cli", "scan", "/some/binary"]


# ----------------------------------------------------------- SV 0.4.1 protected log
def test_plugin_log_append_uses_the_cli_when_present(sv_cli):
    detail = sentinel_vision.SentinelVisionAdapter().plugin_log_append({"event": "pacify", "agent": "rogue-1"})

    assert "protected log" in detail
    assert sv_cli.calls[0][:4] == ["/opt/sv/sentinel-vision-cli", "plugin-log", "append", "agent-guard"]
    assert sv_cli.calls[0][4] == "--json"
    assert json.loads(sv_cli.calls[0][5]) == {"event": "pacify", "agent": "rogue-1"}


def test_pacify_mirrors_a_record_to_the_protected_log_when_present(guard):
    appended: list[dict] = []
    guard.sv = types.SimpleNamespace(plugin_log_append=lambda rec: appended.append(rec) or "ok")
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
    assert all(p.label.startswith("AG ·") for p in pages)
