"""sentinel-vision's published command-line contract, replayed through Foldward's adapter (INT-01, INT-04).

``tests/data/sentinel_vision_contract.json`` is a copy of sentinel-vision's ``docs/plugin-contract.json``.
sentinel-vision's own tests run its real tool against that file; here every example answer in it is fed to
Foldward's adapter, and every command the adapter runs is checked against the contract's argument template. A
change on either side that would break the other fails a test, and a new answer in the contract fails until
Foldward decides what to do with it.

To update: copy the new file from sentinel-vision and run these tests. Set ``SENTINEL_VISION_REPO`` to a
sentinel-vision checkout to also check that the copy is current.
"""

from __future__ import annotations

import json
import os
import subprocess
import types
from pathlib import Path

import pytest

from foldward.integrations import sentinel_vision as sv
from foldward.quarantine import Quarantine

CONTRACT_FILE = Path(__file__).parent / "data" / "sentinel_vision_contract.json"
CONTRACT = json.loads(CONTRACT_FILE.read_text("utf-8"))
ANSWERS = [(c["name"], case["case"]) for c in CONTRACT["commands"] for case in c["cases"]]
CLI = "/opt/SentinelVision/sentinel-vision-cli"


def _command(name: str) -> dict:
    [command] = [c for c in CONTRACT["commands"] if c["name"] == name]
    return command


def _case(name: str, case: str) -> dict:
    [found] = [c for c in _command(name)["cases"] if c["case"] == case]
    return found


def _follows(argv: list[str], template: list[str]) -> bool:
    """Literal words equal, ``<placeholders>`` filled with exactly one argument each."""
    return len(argv) == len(template) and all(t.startswith("<") or a == t for a, t in zip(argv, template))


class ContractCli:
    """Stands in for sentinel-vision-cli and answers exactly as one of the contract's examples."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.answer = (0, "", "")

    def play(self, name: str, case: str) -> None:
        c = _case(name, case)
        self.answer = (c["exit"], c["example"], c.get("example_stderr", ""))

    def run(self, cmd, **_kwargs):
        cmd = list(cmd)
        assert cmd[0] == CLI
        if cmd[1:] == _command("version")["argv"]:
            v = _case("version", "ok")
            return subprocess.CompletedProcess(cmd, v["exit"], stdout=v["example"], stderr="")
        self.calls.append(cmd[1:])
        code, out, err = self.answer
        return subprocess.CompletedProcess(cmd, code, stdout=out, stderr=err)


@pytest.fixture
def cli(monkeypatch):
    fake = ContractCli()
    monkeypatch.setattr(sv, "shutil", types.SimpleNamespace(which=lambda name, *args, **kwargs: CLI))
    monkeypatch.setattr(sv, "subprocess", types.SimpleNamespace(run=fake.run))
    monkeypatch.setattr(sv, "_location_problem", lambda path, root: None)
    return fake


# ----------------------------------------------------------------------------- the contract itself
def test_the_contract_is_one_foldward_supports():
    assert CONTRACT["plugin_api_version"] == 1
    assert tuple(int(x) for x in CONTRACT["sentinel_vision"].split(".")) >= sv.MIN_VERSION
    assert sorted(CONTRACT["exit_codes"]) == ["0", "1", "2", "3"]
    assert (sv.EXIT_OK, sv.EXIT_FOUND, sv.EXIT_ERROR, sv.EXIT_REFUSED) == (0, 1, 2, 3)


@pytest.mark.skipif(not os.environ.get("SENTINEL_VISION_REPO"), reason="set SENTINEL_VISION_REPO to compare")
def test_the_copy_matches_sentinel_vision():
    published = Path(os.environ["SENTINEL_VISION_REPO"]) / "docs" / "plugin-contract.json"
    assert json.loads(published.read_text("utf-8")) == CONTRACT


# ----------------------------------------------------------------------------- what Foldward runs
def test_every_command_foldward_runs_follows_the_contract(cli, tmp_path):
    adapter = sv.SentinelVisionAdapter()
    target = str(tmp_path / "-agent.bin")  # a name that starts with "-" stays a file name after --

    adapter.quarantine_add(target, "contained by Foldward")
    adapter.plugin_log_append({"event": "pacify"})
    adapter.plugin_log_verify()  # the current log and the pre-rename one
    adapter.block_ip("45.12.10.9")
    adapter.scan(target)

    expected = ["quarantine add", "plugin-log append", "plugin-log verify", "plugin-log verify", "net block", "scan"]
    assert len(cli.calls) == len(expected)
    for argv, name in zip(cli.calls, expected):
        assert _follows(argv, _command(name)["argv"]), (name, argv)
    assert cli.calls[0][-2:] == ["--", target]
    assert cli.calls[-2][-2:] == ["--", "45.12.10.9"]
    assert cli.calls[-1][-2:] == ["--", target]


# ----------------------------------------------------------------------------- every example answer
def _reading(adapter: sv.SentinelVisionAdapter, name: str):
    """What Foldward makes of sentinel-vision's answer to one command."""
    if name == "version":
        return sv.probe()
    if name == "quarantine add":
        res = adapter.quarantine_add("/x/agent.bin", "contained by Foldward")
        return res.status, res.item_id
    if name == "plugin-log append":
        return adapter.plugin_log_append({"event": "pacify"}).ok
    if name == "plugin-log verify":
        return adapter.plugin_log_verify()["intact"]
    if name == "net block":
        return adapter.block_ip("45.12.10.9")
    if name == "scan":
        return adapter.scan("/x/agent.bin")["verdict"]
    raise AssertionError(f"Foldward doesn't use {name!r}: decide how to read it before relying on it")


EXPECTED = {
    ("version", "ok"): lambda got: got == (True, f"cli {CLI}, version {CONTRACT['sentinel_vision']}"),
    ("quarantine add", "moved"): lambda got: got == ("ok", _case("quarantine add", "moved")["example"].strip()),
    ("quarantine add", "refused"): lambda got: got == ("refused", None),  # final: never moved another way
    ("quarantine add", "error"): lambda got: got == ("unavailable", None),  # Foldward's own vault takes over
    ("plugin-log append", "appended"): lambda got: got is True,
    ("plugin-log append", "error"): lambda got: got is False,
    ("plugin-log verify", "intact"): lambda got: got is True,
    ("plugin-log verify", "broken"): lambda got: got is False,
    ("net block", "blocked"): lambda got: got == "requested OS firewall block of 45.12.10.9",
    ("net block", "error"): lambda got: got.startswith("firewall block of 45.12.10.9 failed (exit 2)"),
    ("scan", "clean"): lambda got: got == "clean",
    ("scan", "threats"): lambda got: got == "malware",
}


@pytest.mark.parametrize(("name", "case"), ANSWERS, ids=[f"{n} / {c}" for n, c in ANSWERS])
def test_every_answer_in_the_contract_is_read_as_foldward_expects(cli, name, case):
    assert (name, case) in EXPECTED, f"the contract has a new answer ({name} / {case}): decide what Foldward does"
    cli.play(name, case)

    got = _reading(sv.SentinelVisionAdapter(), name)

    assert EXPECTED[(name, case)](got), got


def test_every_expected_answer_is_still_in_the_contract():
    assert set(EXPECTED) == set(ANSWERS)


# ----------------------------------------------------------------------------- what containment does with them
def _contain(cli: ContractCli, tmp_path: Path, case: str) -> tuple[str, Quarantine, Path]:
    cli.play("quarantine add", case)
    binary = tmp_path / "agent.bin"
    binary.write_bytes(b"\x7fELF")
    own_vault = Quarantine(tmp_path / "vault")
    detail = sv.make_containment(own_vault).quarantine_binary(str(binary), "agent-1", "pacified")
    return detail, own_vault, binary


def test_a_refusal_in_the_contract_is_final_for_containment(cli, tmp_path):
    detail, own_vault, binary = _contain(cli, tmp_path, "refused")

    assert detail.startswith("quarantine refused")
    assert len(own_vault) == 0 and binary.exists()  # Foldward doesn't move it some other way


def test_an_error_in_the_contract_falls_back_to_the_own_vault(cli, tmp_path):
    detail, own_vault, binary = _contain(cli, tmp_path, "error")

    assert "sentinel-vision unavailable" in detail
    assert len(own_vault) == 1 and not binary.exists()


def test_a_move_in_the_contract_leaves_the_own_vault_empty(cli, tmp_path):
    detail, own_vault, _binary = _contain(cli, tmp_path, "moved")

    assert detail == f"handed to sentinel-vision vault (id {_case('quarantine add', 'moved')['example'].strip()})"
    assert len(own_vault) == 0
