"""Shared fixtures for the Foldward test suite.

Two autouse fixtures keep every test hermetic:

* ``_isolate`` redirects all on-disk state (settings file, quarantine store and key)
  into a per-test temp directory, so the suite can never touch the real user data dir.
* ``_partners_absent`` makes the optional partners (sentinel-vision, cryptomigrate) look
  uninstalled, so results do not depend on what else happens to be installed on the
  machine running the tests. Tests that need a partner *present* simulate one on top.
"""

from __future__ import annotations

import subprocess
import sys
import types

import pytest

import foldward.cli as cli_module
import foldward.config as cfg
import foldward.quarantine as quarantine_module
from foldward.config import Settings
from foldward.core import Foldward
from foldward.crypto import AuditLog, new_signer
from foldward.integrations import cryptomigrate as cm_integ
from foldward.integrations import sentinel_vision as sv_integ

_REAL_PATH_HELPERS = {"data_root": cfg.data_root, "sub_dir": cfg.sub_dir}


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Point every Foldward path at ``<tmp_path>/Foldward``."""
    root = tmp_path / "Foldward"
    root.mkdir()

    def data_root():
        return root

    def sub_dir(name):
        d = root / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    # foldward.config is the source of truth: Settings.path() and app_banner() resolve ``data_root`` through it
    # at call time...
    monkeypatch.setattr(cfg, "data_root", data_root)
    monkeypatch.setattr(cfg, "sub_dir", sub_dir)
    # ...but a module that did ``from foldward.config import <name>`` holds its own reference, so patch those too.
    monkeypatch.setattr(quarantine_module, "sub_dir", sub_dir)
    monkeypatch.setattr(cli_module, "data_root", data_root)

    # Fail loudly, rather than silently write to the real data dir, if another module starts binding them by name.
    stray = [
        f"{mod_name}.{attr}"
        for mod_name, mod in list(sys.modules.items())
        if mod is not None and mod_name.startswith("foldward")
        for attr, real in _REAL_PATH_HELPERS.items()
        if getattr(mod, attr, None) is real
    ]
    assert not stray, f"{stray} would bypass test isolation; patch them in conftest._isolate"

    # Backstop: even a stray call to the *real* helper would resolve inside tmp_path.
    for var, sub in (
        ("XDG_DATA_HOME", "xdg-data"),
        ("LOCALAPPDATA", "local-app-data"),
        ("HOME", "home"),
        ("USERPROFILE", "home"),
    ):
        monkeypatch.setenv(var, str(tmp_path / sub))

    yield root


@pytest.fixture(autouse=True)
def _partners_absent(monkeypatch):
    """Report sentinel-vision and cryptomigrate as not installed (neither importable nor on PATH)."""
    monkeypatch.setitem(sys.modules, "sentinel_vision", None)  # ``import sentinel_vision`` -> ImportError
    monkeypatch.setitem(sys.modules, "cryptomigrate", None)
    no_cli = types.SimpleNamespace(which=lambda _name, *args, **kwargs: None)
    monkeypatch.setattr(sv_integ, "shutil", no_cli)
    monkeypatch.setattr(cm_integ, "shutil", no_cli)
    # not hosted by sentinel-vision unless a test says so, and no version answers left over
    monkeypatch.setattr(sv_integ, "_hosted", False)
    monkeypatch.setattr(sv_integ, "_version_cache", {})


@pytest.fixture
def signer():
    """A fresh circle signing authority (the strongest scheme this environment supports)."""
    return new_signer()


@pytest.fixture
def audit(signer):
    """A hash-chained audit log whose head can be signed by ``signer``."""
    return AuditLog(signer)


@pytest.fixture
def guard():
    """A fully wired Foldward with default (conservative) settings and isolated storage."""
    return Foldward(Settings())


@pytest.fixture
def sleeper():
    """A real, harmless child process owned by the test, so process control can be exercised
    on something that is safe to freeze, resume and kill. Always reaped on teardown."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield proc
    finally:
        proc.kill()  # SIGKILL also ends a SIGSTOPped process
        proc.wait(timeout=10)
