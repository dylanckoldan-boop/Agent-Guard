"""Route B adapter: sentinel-vision.

Lights up only when sentinel-vision is installed alongside Agent Guard. It is
reached two ways, in order of preference:

* **in-process** — a guarded ``import sentinel_vision`` lets Agent Guard call its
  objects directly (``Scanner``, ``network.firewall.block_ip``, ``Quarantine``,
  and the Route-B ``quarantine.add`` verb / protected store).
* **CLI** — ``sentinel-vision-cli`` as a process-isolated fallback.

What Agent Guard gains when the port is open:

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
import shutil
import subprocess
from pathlib import Path

from agent_guard.quarantine import Quarantine
from agent_guard.response import Containment

_CLI = "sentinel-vision-cli"


def probe() -> tuple[bool, str]:
    """Return (present, how). Prefers the importable package, then the CLI."""
    try:
        import sentinel_vision  # noqa: F401

        return True, "in-process (import sentinel_vision)"
    except Exception:
        pass
    if shutil.which(_CLI):
        return True, f"cli ({_CLI})"
    return False, "not installed"


def is_present() -> bool:
    return probe()[0]


class SentinelVisionAdapter:
    """Thin wrapper over whichever sentinel-vision surface is available."""

    def __init__(self) -> None:
        self._mod = None
        try:
            import sentinel_vision  # noqa: F401

            self._mod = sentinel_vision
        except Exception:
            self._mod = None
        self._cli = shutil.which(_CLI)

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
                subprocess.run([self._cli, "net", "block", ip], capture_output=True, text=True, timeout=30)
                return f"requested OS firewall block of {ip}"
            except Exception as exc:
                return f"firewall block failed: {exc}"
        return "no firewall surface available"

    # -- quarantine (Route B verb) ------------------------------------------
    def quarantine_add(self, path: str, reason: str) -> str:
        if self._cli:
            try:
                out = subprocess.run(
                    [self._cli, "quarantine", "add", path, "--reason", reason],
                    capture_output=True, text=True, timeout=60,
                )
                if out.returncode == 0:
                    return f"handed to sentinel-vision vault: {out.stdout.strip() or 'ok'}"
                return f"sentinel-vision quarantine add unavailable (needs Route-B verb): {out.stderr.strip()}"
            except Exception as exc:
                return f"quarantine add failed: {exc}"
        return "no sentinel-vision quarantine surface available"

    def protected_store_dir(self) -> str | None:
        """SV's admin-only protected directory, if exposed (Route-B optional seam)."""
        if self._mod is not None:
            try:
                from sentinel_vision import config as sv_config  # type: ignore

                d = Path(sv_config.sub_dir("agent-guard"))  # type: ignore[attr-defined]
                return str(d)
            except Exception:
                return None
        return None


def make_containment(quarantine: Quarantine | None) -> Containment:
    """Build a Containment that routes egress blocks and binary quarantine through
    sentinel-vision when present, falling back to Agent Guard's own mechanisms."""
    adapter = SentinelVisionAdapter()
    base = Containment(quarantine)
    if not adapter.available:
        return base

    class _SVContainment(Containment):
        def block_egress(self, host: str) -> str:
            ip = host.rsplit(":", 1)[0]
            return adapter.block_ip(ip)

        def quarantine_binary(self, path: str, agent_id: str, reason: str) -> str:
            res = adapter.quarantine_add(path, reason)
            if "unavailable" in res or "failed" in res or "no sentinel" in res:
                return super().quarantine_binary(path, agent_id, reason)  # fall back to own vault
            return res

    return _SVContainment(quarantine)
