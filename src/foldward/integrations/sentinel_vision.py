"""Route B adapter: sentinel-vision.

Lights up only when sentinel-vision is installed alongside Foldward. It is
reached two ways, in order of preference:

* **in-process** — a guarded ``import sentinel_vision`` lets Foldward call its
  objects directly (``Scanner``, ``network.firewall.block_ip``, ``Quarantine``,
  and the Route-B ``quarantine.add`` verb / protected store).
* **CLI** — ``sentinel-vision-cli`` as a process-isolated fallback.

What Foldward gains when the port is open:

* **scan(binary)** — turns "behaved oddly" into a verdict: is the agent's own
  code known malware, validly signed, or clean?
* **block_egress(ip)** — the pacify ladder's "cut egress" rung becomes a real
  system-wide OS-firewall block, against feeds that already know criminal netblocks.
* **quarantine_binary(...)** — hands the neutralized binary to SV's AES-256-GCM
  vault with rollback (Route B ``quarantine add`` verb), making SV the
  system-of-record for contained artifacts.
* **protected_store_dir()** — SV's admin-only service directory, where Agent
  Guard can keep its audit + registry so a compromised agent cannot erase its own
  containment record. This is the real Layer-4 Wall.

Everything is wrapped so a missing or older sentinel-vision degrades to None /
a best-effort note, never an exception.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

from foldward.quarantine import Quarantine
from foldward.response import Containment

_CLI = "sentinel-vision-cli"
_PLUGIN_NAME = "agent-guard"  # the name sentinel-vision files Foldward's records under


def _canonical_dirs() -> list[str]:
    """The trusted directories sentinel-vision installs its CLI into — never
    ``$PATH``. A ``sentinel-vision-cli`` planted earlier on PATH must not be run
    as if it were the real thing, since Foldward executes it with the agent's
    fate in its hands (AG-A04 / AG-C04)."""
    if sys.platform == "win32":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        return [os.path.join(pf, "Sentinel Vision"), os.path.join(pf86, "Sentinel Vision")]
    if sys.platform == "darwin":
        return ["/Applications/Sentinel Vision.app/Contents/MacOS", "/usr/local/sentinel-vision/bin"]
    return ["/opt/sentinel-vision/bin", "/usr/lib/sentinel-vision", "/usr/libexec/sentinel-vision"]


def _resolve_cli() -> str | None:
    """Locate sentinel-vision-cli in a canonical install directory, ignoring
    ``$PATH`` entirely (``shutil.which`` is scoped to the trusted dirs)."""
    return shutil.which(_CLI, path=os.pathsep.join(_canonical_dirs()))


def _host_only(hostport: str) -> str:
    """Host from 'ip:port' / '[v6]:port' / bare host — IPv6-safe, so a bracketed
    address is not truncated at a colon inside it."""
    s = (hostport or "").strip()
    if s.startswith("["):
        return s[1:].split("]", 1)[0]
    if s.count(":") == 1:
        return s.rsplit(":", 1)[0]
    return s


def probe() -> tuple[bool, str]:
    """Return (present, how). Prefers the importable package, then the CLI
    resolved from a canonical install location (not from $PATH)."""
    try:
        import sentinel_vision  # noqa: F401

        return True, "in-process (import sentinel_vision)"
    except Exception:
        pass
    if _resolve_cli():
        return True, f"cli ({_CLI})"
    return False, "not installed"


def is_present() -> bool:
    return probe()[0]


class SentinelVisionAdapter:
    """Thin wrapper over whichever sentinel-vision surface is available."""

    def __init__(self) -> None:
        self._mod = None
        try:
            import sentinel_vision

            self._mod = sentinel_vision
        except Exception:
            self._mod = None
        self._cli = _resolve_cli()

    @property
    def available(self) -> bool:
        return self._mod is not None or self._cli is not None

    # -- scan ---------------------------------------------------------------
    def scan(self, path: str) -> dict:
        """Return {'verdict': 'malware'|'signed'|'clean'|'unknown', 'detail': str}."""
        if self._cli:
            try:
                out = subprocess.run(
                    [self._cli, "scan", path, "--no-quarantine", "--json"],
                    capture_output=True, text=True, timeout=120,
                )
                if out.returncode != 0:
                    return {"verdict": "unknown", "detail": f"scan failed (exit {out.returncode}): {out.stderr.strip()}"}
                data = json.loads(out.stdout or "{}")
                threats = data.get("threats") or data.get("infected") or 0
                verdict = "malware" if threats else "clean"
                return {"verdict": verdict, "detail": f"sentinel-vision: {threats} threat(s)"}
            except Exception as exc:
                return {"verdict": "unknown", "detail": f"scan error: {exc}"}
        # in-process path would call sentinel_vision.scanner.Scanner here; kept
        # behind the public CLI contract for stability across SV refactors.
        return {"verdict": "unknown", "detail": "no scan surface available"}

    # -- firewall -----------------------------------------------------------
    def block_ip(self, ip: str) -> str:
        if self._mod is not None:
            try:
                from sentinel_vision.network.firewall import block_ip  # type: ignore

                return block_ip(ip)
            except Exception as exc:
                return f"firewall block failed: {exc}"
        if self._cli:
            try:
                out = subprocess.run([self._cli, "net", "block", ip], capture_output=True, text=True, timeout=30)
                if out.returncode != 0:
                    return f"firewall block of {ip} failed (exit {out.returncode}): {out.stderr.strip()}"
                return f"requested OS firewall block of {ip}"
            except Exception as exc:
                return f"firewall block failed: {exc}"
        return "no firewall surface available"

    # -- quarantine (Route B verb) ------------------------------------------
    def quarantine_add(self, path: str, reason: str) -> str:
        """Hand a binary to sentinel-vision's vault. In SV 0.4.1 the file is
        *moved* (encrypted in, original deleted); on success the CLI prints only
        the new id and exits 0, and on any problem it exits 2 and nothing changes
        (it refuses OS files and SV's own files). ``--source`` defaults to
        ``foldward`` on SV's side, so it is not passed here."""
        if self._cli:
            try:
                out = subprocess.run(
                    [self._cli, "quarantine", "add", path, "--reason", reason],
                    capture_output=True, text=True, timeout=60,
                )
                if out.returncode == 0:
                    return f"handed to sentinel-vision vault (id {out.stdout.strip() or '?'})"
                return f"sentinel-vision quarantine add unavailable: {out.stderr.strip()}"
            except Exception as exc:
                return f"quarantine add failed: {exc}"
        return "no sentinel-vision quarantine surface available"

    # -- protected, append-only records -------------------------------------
    def plugin_log_append(self, record: dict) -> str:
        """Append a record to sentinel-vision's protected, append-only plugin log
        — its 'records nothing else can erase'. On Windows the protection service
        keeps it where a program running as the user can add and read but cannot
        change or delete. config.plugin_dir is deliberately NOT used: it is an
        ordinary user folder, not protected. Prefers the in-process API, falls
        back to the CLI."""
        if self._mod is not None:
            try:
                from sentinel_vision.plugin_api import plugin_log  # type: ignore

                plugin_log(_PLUGIN_NAME).append(record)
                return "appended to sentinel-vision protected log (in-process)"
            except Exception:
                pass  # fall through to the CLI
        if self._cli:
            try:
                out = subprocess.run(
                    [self._cli, "plugin-log", "append", _PLUGIN_NAME, "--json", json.dumps(record)],
                    capture_output=True, text=True, timeout=30,
                )
                if out.returncode == 0:
                    return "appended to sentinel-vision protected log"
                return f"plugin-log append unavailable: {out.stderr.strip()}"
            except Exception as exc:
                return f"plugin-log append failed: {exc}"
        return "no sentinel-vision plugin-log surface available"

    def plugin_log_verify(self) -> dict:
        """Ask sentinel-vision whether Foldward's protected log chain is intact."""
        if self._cli:
            try:
                out = subprocess.run(
                    [self._cli, "plugin-log", "verify", _PLUGIN_NAME],
                    capture_output=True, text=True, timeout=30,
                )
                if out.returncode == 0:
                    return json.loads(out.stdout or "{}")
            except Exception:
                pass
        return {"intact": None, "detail": "no sentinel-vision plugin-log surface available"}


def make_containment(quarantine: Quarantine | None) -> Containment:
    """Build a Containment that routes egress blocks and binary quarantine through
    sentinel-vision when present, falling back to Foldward's own mechanisms."""
    adapter = SentinelVisionAdapter()
    base = Containment(quarantine)
    if not adapter.available:
        return base

    class _SVContainment(Containment):
        def block_egress(self, host: str) -> str:
            return adapter.block_ip(_host_only(host))

        def quarantine_binary(self, path: str, agent_id: str, reason: str) -> str:
            res = adapter.quarantine_add(path, reason)
            if "unavailable" in res or "failed" in res or "no sentinel" in res:
                return super().quarantine_binary(path, agent_id, reason)  # fall back to own vault
            return res

    return _SVContainment(quarantine)
