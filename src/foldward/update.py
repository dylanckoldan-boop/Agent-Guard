"""Opt-in update check.

This is the *only* part of Foldward that contacts the network, and only when you
ask it to — the ``foldward-cli update`` command or the GUI's "Check for updates"
button. It asks GitHub for the latest published release and compares versions. It
sends nothing about you, carries no identifier, and never runs on its own: the
watch/scan/containment path stays entirely offline.

It only *reports* whether a newer version exists and prints the command to
install it. It deliberately does **not** download or run code — applying an update
is an explicit step you take, so a check can never turn into remote code
execution. The printed command installs exactly the released tag, never whatever
the main branch holds at that moment (INT-06). A future signed auto-updater would
verify a release signature before applying anything.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from foldward import __version__

_REPO = "https://github.com/dylanckoldan-boop/Foldward"
_RELEASES_API = "https://api.github.com/repos/dylanckoldan-boop/Foldward/releases/latest"
_TAG_RE = re.compile(r"^v?(\d{1,4}(?:\.\d{1,4}){1,3})$")


def install_command(version: str) -> str:
    """The pip command for one released version, pinned to its tag."""
    return f'pip install --upgrade "foldward @ git+{_REPO}@v{version}"'


INSTALL_COMMAND = install_command(__version__)


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
    if not url.startswith("https://api.github.com/"):
        raise ValueError("update checks only ask the GitHub API over https")
    req = urllib.request.Request(  # noqa: S310 - https GitHub API only, checked above
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "foldward-update-check"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https GitHub API only
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
    tag = str((data or {}).get("tag_name") or "").strip() if isinstance(data, dict) else ""
    if not tag:
        return UpdateStatus(current, None, False, "No published releases yet.")
    m = _TAG_RE.match(tag)
    if not m:
        # never paste an unexpected tag into a command the user may copy
        return UpdateStatus(current, None, False, f"The latest release tag isn't a version number; see {_REPO}/releases")
    latest = m.group(1)
    available = _version_tuple(latest) > _version_tuple(current)
    command = install_command(latest)
    detail = (
        f"Update available: {current} → {latest}. Run:  {command}"
        if available
        else f"You're on the latest version ({current})."
    )
    return UpdateStatus(current, latest, available, detail, command)
