"""Opt-in update check.

This is the *only* part of Foldward that contacts the network, and only when you
ask it to — the ``foldward-cli update`` command or the GUI's "Check for updates"
button. It asks GitHub for the latest published release and compares versions. It
sends nothing about you, carries no identifier, and never runs on its own: the
watch/scan/containment path stays entirely offline.

It only *reports* whether a newer version exists and prints the command to
install it. It deliberately does **not** download or run code — applying an update
is an explicit step you take, so a check can never turn into remote code
execution. A future signed auto-updater would verify a release signature before
applying anything.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from foldward import __version__

_RELEASES_API = "https://api.github.com/repos/dylanckoldan-boop/Foldward/releases/latest"
INSTALL_COMMAND = 'pip install --upgrade "git+https://github.com/dylanckoldan-boop/Foldward"'


@dataclass
class UpdateStatus:
    current: str
    latest: str | None
    available: bool
    detail: str
    install_command: str = INSTALL_COMMAND


def _version_tuple(v: str) -> tuple[int, ...]:
    out: list[int] = []
    for part in (v or "").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out) or (0,)


def _default_fetch(url: str, timeout: float) -> dict:
    req = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "foldward-update-check"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # fixed https GitHub API URL
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}  # the repository has no published releases yet
        raise


def check_for_update(timeout: float = 5.0, url: str = _RELEASES_API, fetch=None) -> UpdateStatus:
    """Return how the installed version compares to the latest GitHub release.

    ``fetch(url, timeout) -> dict`` is injectable so the check is unit-tested
    without touching the network. Any failure degrades to a clear, non-fatal
    message — a missing network or GitHub outage is never an error you have to
    handle."""
    current = __version__
    try:
        data = (fetch or _default_fetch)(url, timeout)
    except Exception as exc:  # a check must never raise into the caller
        return UpdateStatus(current, None, False, f"Couldn't check for updates: {exc}")
    latest = (data.get("tag_name") or "").lstrip("vV").strip() or None
    if latest is None:
        return UpdateStatus(current, None, False, "No published releases yet.")
    available = _version_tuple(latest) > _version_tuple(current)
    detail = (
        f"Update available: {current} → {latest}. Run:  {INSTALL_COMMAND}"
        if available
        else f"You're on the latest version ({current})."
    )
    return UpdateStatus(current, latest, available, detail)
