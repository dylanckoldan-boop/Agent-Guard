"""The opt-in update check: version comparison, graceful failure, and the CLI.

Every test injects a fake fetch (or patches the CLI), so nothing here touches the
network — matching the rule that the check only ever runs when a person asks."""

from __future__ import annotations

import foldward.cli as cli
from foldward import __version__
from foldward.update import INSTALL_COMMAND, UpdateStatus, check_for_update


def _fetch(tag):
    return lambda url, timeout: ({"tag_name": tag} if tag is not None else {})


def test_no_releases_is_not_an_update():
    st = check_for_update(fetch=_fetch(None))

    assert (st.available, st.latest) == (False, None)
    assert "No published releases" in st.detail


def test_a_newer_release_is_offered_with_the_install_command():
    st = check_for_update(fetch=_fetch("v99.0.0"))

    assert st.available is True
    assert st.latest == "99.0.0"
    assert st.install_command == 'pip install --upgrade "foldward @ git+https://github.com/dylanckoldan-boop/Foldward@v99.0.0"'
    assert st.install_command in st.detail


def test_the_current_version_is_up_to_date():
    st = check_for_update(fetch=_fetch("v" + __version__))

    assert st.available is False
    assert "latest" in st.detail.lower()


def test_an_older_release_is_not_offered_as_an_update():
    st = check_for_update(fetch=_fetch("v0.0.0"))

    assert st.available is False


def test_a_network_failure_degrades_to_a_clear_message_never_raises():
    def boom(url, timeout):
        raise OSError("name resolution failed")

    st = check_for_update(fetch=boom)

    assert st.available is False
    assert "couldn't check" in st.detail.lower()


def test_cli_update_prints_the_status(capsys, monkeypatch):
    monkeypatch.setattr(
        cli, "check_for_update",
        lambda: UpdateStatus(__version__, "9.9.9", True, "Update available: test", INSTALL_COMMAND),
    )

    code = cli.main(["update"])

    assert code == 0
    assert "Update available" in capsys.readouterr().out


def test_cli_update_json_is_machine_readable(capsys, monkeypatch):
    monkeypatch.setattr(
        cli, "check_for_update",
        lambda: UpdateStatus(__version__, None, False, "No published releases yet.", INSTALL_COMMAND),
    )

    code = cli.main(["update", "--json"])
    out = capsys.readouterr().out

    assert code == 0
    assert '"available": false' in out
    assert '"install_command"' in out
