"""Route B adapter: sentinel-vision.

Lights up only when sentinel-vision is installed alongside Foldward, and only after
Foldward has checked that it is talking to the real program (AG-A04, INT-02, INT-03):

* **Hosted** — when Sentinel Vision itself loads Foldward as a plugin (it calls
  :func:`foldward.gui.plugin.register`), ``sentinel_vision`` is the host's own,
  already-loaded package, so Foldward may use its in-process plugin API.
* **Command-line tool** — ``sentinel-vision-cli`` is taken only from Sentinel
  Vision's install folder (``Program Files\\Sentinel Vision`` on Windows,
  ``/Applications/SentinelVision.app/Contents/MacOS`` on macOS, ``/opt/SentinelVision``
  on Linux) — never from ``$PATH`` and never as an importable package that merely has
  the right name. On macOS and Linux the tool and its folder must belong to root and
  be closed to writes by others; it must report version 0.5.2 or newer (the first
  whose `quarantine add --reason TEXT -- PATH` parses on every supported Python and
  that answers a refusal with exit 3).

What Foldward uses — the plugin contract in sentinel-vision's ``docs/PLUGINS.md``,
whose exit codes are 0 success, 1 threats found or a broken chain, 2 error, and,
since 0.5.2, 3 refused on purpose. Every argument that comes from a file name or an
address follows ``--``, so it can never be read as an option (AG-F08, INT-01).

* ``quarantine add`` — hands a contained agent's file to sentinel-vision's vault.
  A refusal (an operating-system file, a link…) is final: Foldward reports it and
  does **not** fall back to its own vault. Only when sentinel-vision is absent or
  can't be reached does Foldward's own vault, which applies the same safety rules,
  take the file (INT-04).
* ``plugin-log append|verify`` — the protected, append-only record of every
  containment (on Windows, kept by sentinel-vision's protection service). Any
  program running as the user can add to that log, so a refusal because it is
  full is flagged (``LogResult.full``), and from 0.5.3 ``verify`` also tells how
  full it is (:meth:`SentinelVisionAdapter.plugin_log_room`) (INT-N01).
* ``net block`` — an OS-firewall block for a public address. The ladder doesn't
  call it yet (planned).
* ``scan --json`` — a malware verdict for a file. Not used in decisions yet (planned).

Everything degrades to a clear note, never an exception.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass

from foldward.quarantine import Quarantine
from foldward.response import Containment

_CLI = "sentinel-vision-cli"
_PLUGIN_NAME = "foldward"  # the name sentinel-vision files Foldward's records under
_LEGACY_PLUGIN_NAME = "agent-guard"  # the pre-rename name; still read & verified so old records aren't orphaned
MIN_VERSION = (0, 5, 2)
_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
# exit codes of sentinel-vision-cli (docs/PLUGINS.md)
EXIT_OK, EXIT_FOUND, EXIT_ERROR, EXIT_REFUSED = 0, 1, 2, 3

_hosted = False
_version_cache: dict[str, tuple[int, ...] | None] = {}


def mark_hosted() -> None:
    """Called by the plugin entry point: Foldward is running inside Sentinel Vision,
    so ``sentinel_vision`` is the host's own package and may be used in-process."""
    global _hosted
    _hosted = True


def is_hosted() -> bool:
    return _hosted


# ----------------------------------------------------------------------------- discovery
def _windows_program_files() -> list[str]:
    """Program Files folders, asked from Windows (SHGetKnownFolderPath) rather than
    read from %ProgramFiles%, which a program running as the user can redefine."""
    try:
        import ctypes
        import uuid
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                        ("Data4", ctypes.c_ubyte * 8)]

        found: list[str] = []
        for fid in ("905e63b6-c1bf-494e-b29c-65b732d3d21a",   # FOLDERID_ProgramFiles
                    "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e"):  # FOLDERID_ProgramFilesX86
            u = uuid.UUID(fid)
            g = GUID(u.time_low, u.time_mid, u.time_hi_version, (ctypes.c_ubyte * 8)(*u.bytes[8:]))
            out = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(out)) == 0:  # type: ignore[attr-defined]
                if out.value and out.value not in found:
                    found.append(out.value)
                ctypes.windll.ole32.CoTaskMemFree(out)  # type: ignore[attr-defined]
        if found:
            return found
    except Exception:
        pass
    return [r"C:\Program Files", r"C:\Program Files (x86)"]


def _canonical_dirs() -> list[str]:
    """Where Sentinel Vision's installers put the command-line tool (its docs/INSTALL.md)."""
    if sys.platform == "win32":
        return [os.path.join(pf, "Sentinel Vision") for pf in _windows_program_files()]
    if sys.platform == "darwin":
        return ["/Applications/SentinelVision.app/Contents/MacOS"]
    return ["/opt/SentinelVision"]


def _location_problem(path: str, root: str) -> str | None:
    """Why the tool at ``path`` can't be trusted, or None. On macOS and Linux the
    file and every folder from it up to ``root`` (the install folder) must belong to
    root and be closed to writes by group and others, as Sentinel Vision's install
    steps leave them. On Windows the folder is the system's Program Files, which only
    administrators can change."""
    if sys.platform == "win32":
        return None
    real, top = os.path.realpath(path), os.path.realpath(root)
    if not (real == top or real.startswith(top.rstrip("/") + "/")):
        return f"{real} is outside {top}"
    p = real
    while True:
        try:
            st = os.stat(p)
        except OSError as exc:
            return f"can't check {p}: {exc.strerror}"
        if st.st_uid != 0:
            return f"{p} isn't owned by root"
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return f"{p} can be changed by other users"
        if p == top:
            return None
        parent = os.path.dirname(p)
        if parent == p:
            return None
        p = parent


def _cli_version(cli: str) -> tuple[int, ...] | None:
    if cli in _version_cache:
        return _version_cache[cli]
    version = None
    try:
        out = subprocess.run([cli, "--version"], capture_output=True, text=True, timeout=15)  # noqa: S603 - verified path, fixed argument
        m = _VERSION_RE.search(out.stdout or "") if out.returncode == 0 else None
        version = tuple(int(x) for x in m.groups()) if m else None
    except Exception:
        version = None
    _version_cache[cli] = version
    return version


def _fmt(version: tuple[int, ...]) -> str:
    return ".".join(str(x) for x in version)


@dataclass
class Discovery:
    present: bool
    how: str
    cli: str | None = None
    version: str | None = None
    in_process: bool = False


def discover() -> Discovery:
    """Find Sentinel Vision and say how it was found, or why it wasn't trusted."""
    cli, version, problem = None, None, None
    for d in _canonical_dirs():
        found = shutil.which(_CLI, path=d)
        if not found:
            continue
        why = _location_problem(found, d)
        if why:
            problem = f"found {found}, but it isn't trusted: {why}"
            break
        v = _cli_version(found)
        if v is None:
            problem = f"found {found}, but couldn't read its version"
            break
        if v < MIN_VERSION:
            problem = f"found {found} version {_fmt(v)}; Foldward needs {_fmt(MIN_VERSION)} or newer"
            break
        cli, version = found, _fmt(v)
        break
    if _hosted:
        try:
            import sentinel_vision

            host_version = str(getattr(sentinel_vision, "__version__", "unknown"))
            return Discovery(True, f"in-process (hosted by Sentinel Vision {host_version})", cli, host_version, True)
        except Exception:
            pass
    if cli:
        return Discovery(True, f"cli {cli}, version {version}", cli, version)
    return Discovery(False, problem or "not installed")


def probe() -> tuple[bool, str]:
    """Return (present, how)."""
    d = discover()
    return d.present, d.how


def is_present() -> bool:
    return probe()[0]


def _host_only(hostport: str) -> str:
    """Host from 'ip:port' / '[v6]:port' / bare host — IPv6-safe, so a bracketed
    address is not truncated at a colon inside it."""
    s = (hostport or "").strip()
    if s.startswith("["):
        return s[1:].split("]", 1)[0]
    if s.count(":") == 1:
        return s.rsplit(":", 1)[0]
    return s


def _tail(text: str, limit: int = 300) -> str:
    return " ".join((text or "").split())[:limit]


# ----------------------------------------------------------------------------- the adapter
@dataclass
class HandOff:
    """The result of asking sentinel-vision to quarantine a file."""

    status: str  # "ok" | "refused" | "unavailable" | "error"
    detail: str
    item_id: str | None = None


@dataclass
class LogResult:
    ok: bool
    detail: str
    full: bool = False  # the protected log refused the record because it is full (INT-N01)


_LOG_FULL = "log is full"  # sentinel-vision's error for a full plugin log (docs/plugin-contract.json)


class SentinelVisionAdapter:
    """Thin wrapper over whichever sentinel-vision surface was found and trusted."""

    def __init__(self, discovery: Discovery | None = None) -> None:
        self.discovery = discovery or discover()
        self._mod = None
        if self.discovery.present and self.discovery.in_process:
            try:
                import sentinel_vision

                self._mod = sentinel_vision
            except Exception:
                self._mod = None
        self._cli = self.discovery.cli if self.discovery.present else None

    @property
    def available(self) -> bool:
        return self._mod is not None or self._cli is not None

    def _run(self, args: list[str], timeout: float) -> subprocess.CompletedProcess:
        return subprocess.run([self._cli, *args], capture_output=True, text=True, timeout=timeout)  # noqa: S603 - verified path, argument list

    # -- scan (planned: not used in decisions yet) --------------------------
    def scan(self, path: str) -> dict:
        """Return {'verdict': 'malware'|'clean'|'unknown', 'detail': str}. sentinel-vision
        exits 1 when it finds threats, so 0 and 1 are both answers (INT-01)."""
        if not self._cli:
            return {"verdict": "unknown", "detail": "no scan surface available"}
        try:
            out = self._run(["scan", "--no-quarantine", "--json", "--", path], timeout=600)
        except Exception as exc:
            return {"verdict": "unknown", "detail": f"scan error: {exc}"}
        if out.returncode not in (EXIT_OK, EXIT_FOUND):
            return {"verdict": "unknown", "detail": f"scan failed (exit {out.returncode}): {_tail(out.stderr)}"}
        try:
            data = json.loads(out.stdout or "")
        except ValueError:
            return {"verdict": "unknown", "detail": "unreadable scan output"}
        counts = {k: data.get(k) for k in ("threats", "scanned", "errors")} if isinstance(data, dict) else {}
        if len(counts) != 3 or not all(_count(v) for v in counts.values()):
            return {"verdict": "unknown", "detail": "scan output has no threat or file count"}
        threats = counts["threats"]
        if (threats > 0) != (out.returncode == EXIT_FOUND):
            return {"verdict": "unknown", "detail": "scan output and exit code disagree"}
        if threats:
            return {"verdict": "malware", "detail": f"sentinel-vision: {threats} threat(s)"}
        if counts["errors"] or not counts["scanned"]:
            # a file sentinel-vision couldn't read isn't a clean file
            return {
                "verdict": "unknown",
                "detail": f"sentinel-vision couldn't check it ({counts['scanned']} scanned, {counts['errors']} error(s))",
            }
        return {"verdict": "clean", "detail": "sentinel-vision: no threats"}

    # -- firewall (planned: the ladder doesn't call it yet) -----------------
    def block_ip(self, ip: str) -> str:
        """Ask sentinel-vision to block a public address at the OS firewall. Only a
        real, public IP address is passed on, after ``--`` (AG-F08)."""
        try:
            addr = ipaddress.ip_address((ip or "").strip())
        except ValueError:
            return f"firewall block refused: {ip!r} is not an IP address"
        if not addr.is_global:
            return f"firewall block refused: {addr} is not a public address"
        if not self._cli:
            return "no firewall surface available"
        try:
            out = self._run(["net", "block", "--", str(addr)], timeout=60)
        except Exception as exc:
            return f"firewall block failed: {exc}"
        if out.returncode != EXIT_OK:
            return f"firewall block of {addr} failed (exit {out.returncode}): {_tail(out.stderr)}"
        return f"requested OS firewall block of {addr}"

    # -- quarantine (Route B verb) ------------------------------------------
    def quarantine_add(self, path: str, reason: str) -> HandOff:
        """Hand a file to sentinel-vision's vault. The file is *moved* (encrypted in,
        original deleted); on success the tool prints only the new 32-character id."""
        if not self._cli:
            return HandOff("unavailable", "no sentinel-vision quarantine surface available")
        reason = _tail(reason, 200) or "contained by Foldward"
        try:
            out = self._run(["quarantine", "add", "--reason", reason, "--", path], timeout=600)
        except Exception as exc:
            return HandOff("unavailable", f"sentinel-vision quarantine add failed: {exc}")
        if out.returncode == EXIT_OK:
            lines = (out.stdout or "").strip().splitlines()
            item = lines[-1].strip() if lines else ""
            if _ID_RE.match(item):
                return HandOff("ok", f"handed to sentinel-vision vault (id {item})", item)
            return HandOff(
                "error",
                f"sentinel-vision reported success without a valid item id ({item[:40]!r}); check its quarantine list",
            )
        if out.returncode == EXIT_REFUSED:
            return HandOff("refused", f"sentinel-vision refused it: {_tail(out.stderr)}")
        return HandOff("unavailable", f"sentinel-vision quarantine add failed (exit {out.returncode}): {_tail(out.stderr)}")

    # -- protected, append-only records -------------------------------------
    def plugin_log_append(self, record: dict) -> LogResult:
        """Append a record to sentinel-vision's protected, append-only plugin log
        — its 'records nothing else can erase'. On Windows the protection service
        keeps it where a program running as the user can add and read but cannot
        change or delete. Uses the in-process API only when hosted by sentinel-vision,
        otherwise the command-line tool. ``full`` is set when the log refused the record
        because it is full: any program running as the user can fill it (INT-N01)."""
        problem = None
        if self._mod is not None:
            try:
                from sentinel_vision.plugin_api import plugin_log  # type: ignore

                plugin_log(_PLUGIN_NAME).append(record)
                return LogResult(True, "appended to sentinel-vision protected log (in-process)")
            except Exception as exc:
                problem = f"plugin-log append failed (in-process): {_tail(str(exc))}"
        if self._cli:
            try:
                out = self._run(["plugin-log", "append", _PLUGIN_NAME, "--json", json.dumps(record)], timeout=60)
            except Exception as exc:
                return LogResult(False, f"plugin-log append failed: {exc}")
            if out.returncode == EXIT_OK:
                return LogResult(True, "appended to sentinel-vision protected log")
            err = _tail(out.stderr)
            return LogResult(False, f"plugin-log append failed (exit {out.returncode}): {err}", _LOG_FULL in err)
        if problem:
            return LogResult(False, problem, _LOG_FULL in problem)
        return LogResult(False, "no sentinel-vision plugin-log surface available")

    def plugin_log_room(self) -> dict | None:
        """How full Foldward's protected log is, ``{'bytes': used, 'limit': most}``, from
        sentinel-vision 0.5.3 or newer; None when it can't say. Any program running as the
        user can add records to the log, so a log filling up may be filled on purpose (INT-N01)."""
        report = None
        if self._mod is not None:
            try:
                from sentinel_vision.plugin_api import plugin_log  # type: ignore

                report = plugin_log(_PLUGIN_NAME).verify_report()  # 0.5.3 and newer
            except Exception:
                report = None
        if report is None and self._cli:
            try:
                out = self._run(["plugin-log", "verify", _PLUGIN_NAME], timeout=60)
                if out.returncode in (EXIT_OK, EXIT_FOUND):
                    report = json.loads(out.stdout or "")
            except Exception:
                report = None
        if not isinstance(report, dict):
            return None
        used, limit = report.get("bytes"), report.get("limit")
        if not (_count(used) and _count(limit) and limit > 0):
            return None  # an older sentinel-vision doesn't report them
        return {"bytes": used, "limit": limit}

    def plugin_log_verify(self) -> dict:
        """Ask sentinel-vision whether Foldward's protected log chain is intact.

        Verifies both the current ``foldward`` log and the pre-rename
        ``agent-guard`` log, so records written before the rename are still
        checked. A present-but-broken chain (SV exits 1 with ``intact: false``) is
        reported as broken, not as a missing surface. sentinel-vision answers a log
        that was never written as intact with 0 entries. The combined ``intact`` is
        False if any log is broken, None if any couldn't be checked (or there is no
        surface to ask), and True only when every log was checked and is intact."""
        if not self._cli:
            return {"intact": None, "detail": "no sentinel-vision plugin-log surface available"}
        logs = {name: self._verify_one(name) for name in (_PLUGIN_NAME, _LEGACY_PLUGIN_NAME)}
        answers = [v["intact"] for v in logs.values()]
        intact = False if False in answers else None if None in answers else True
        detail = "; ".join(f"{name}: {v['detail']}" for name, v in logs.items())
        return {"intact": intact, "detail": detail, "logs": logs}

    def _verify_one(self, name: str) -> dict:
        try:
            out = self._run(["plugin-log", "verify", name], timeout=60)
            if out.returncode in (EXIT_OK, EXIT_FOUND):  # 0 = intact, 1 = broken — both are answers
                data = json.loads(out.stdout or "{}")
                if not isinstance(data, dict):
                    raise ValueError("not an object")
                intact = data.get("intact")
                if not isinstance(intact, bool):
                    raise ValueError("no intact flag")
                if intact != (out.returncode == EXIT_OK):
                    return {"intact": None, "detail": "verify output and exit code disagree"}
                return {"intact": intact, "detail": f"{data.get('entries', '?')} entries"}
            return {"intact": None, "detail": f"verify error (exit {out.returncode})"}
        except Exception as exc:
            return {"intact": None, "detail": f"verify unavailable: {exc}"}


def _count(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def make_containment(quarantine: Quarantine | None, adapter: SentinelVisionAdapter | None = None) -> Containment:
    """Build a Containment that routes egress blocks and binary quarantine through
    sentinel-vision when present, falling back to Foldward's own mechanisms."""
    adapter = adapter or SentinelVisionAdapter()
    base = Containment(quarantine)
    if not adapter.available:
        return base

    class _SVContainment(Containment):
        def block_egress(self, host: str) -> str:
            return adapter.block_ip(_host_only(host))

        def quarantine_binary(self, path: str, agent_id: str, reason: str) -> str:
            res = adapter.quarantine_add(path, reason)
            if res.status == "ok":
                return res.detail
            if res.status in ("refused", "error"):
                # final: sentinel-vision said no on purpose, or may already hold the file
                return f"quarantine refused: {res.detail}"
            # sentinel-vision is absent or unreachable: Foldward's own vault, which
            # applies the same safety rules (INT-04)
            own = super().quarantine_binary(path, agent_id, reason)
            return f"{own} (sentinel-vision unavailable: {res.detail})"

    return _SVContainment(quarantine)
