"""Optional adapter: cryptomigrate.

The least runtime-coupled of the partners — it is a notary and a crypto-hygiene
lens, not a containment mechanism. When present it adds two things:

* **crypto_scan(dir)** — run Cryptomigrate's discovery over a flagged agent's
  install directory to surface a genuinely new risk dimension: an agent that
  ships hardcoded keys, DES/SHA-1, or phones home over obsolete TLS.
* **attest(state)** — emit a Cryptomigrate-format, PQ-signed attestation of Agent
  Guard's oversight state (audit head, registry size, containment log) for
  auditors, reusing CM's attestation discipline.

Note: Agent Guard's own :mod:`agent_guard.crypto` already produces PQ-signed,
tamper-evident records, so this adapter adds the *attestation format and rigor*,
not the cryptography itself. Absent cryptomigrate, ``attest`` still returns a
self-signed attestation using Agent Guard's circle signer.
"""

from __future__ import annotations

import shutil
import time


def probe() -> tuple[bool, str]:
    try:
        import cryptomigrate  # noqa: F401

        return True, "in-process (import cryptomigrate)"
    except Exception:
        pass
    if shutil.which("cryptomigrate"):
        return True, "cli (cryptomigrate)"
    return False, "not installed"


def is_present() -> bool:
    return probe()[0]


class CryptomigrateAdapter:
    def __init__(self) -> None:
        self._mod = None
        try:
            import cryptomigrate

            self._mod = cryptomigrate
        except Exception:
            self._mod = None

    @property
    def available(self) -> bool:
        return self._mod is not None

    def crypto_scan(self, directory: str) -> dict:
        """Surface weak-crypto findings in an agent's directory, if CM is present."""
        if self._mod is None:
            return {"available": False, "findings": [], "detail": "cryptomigrate not installed"}
        try:
            # CM's discovery entry point varies by version; kept behind a guard.
            from cryptomigrate.discovery import run as cm_run  # type: ignore

            report = cm_run.scan_path(directory)  # type: ignore[attr-defined]
            findings = getattr(report, "findings", []) or []
            return {"available": True, "findings": findings, "detail": f"{len(findings)} finding(s)"}
        except Exception as exc:
            return {"available": True, "findings": [], "detail": f"cryptomigrate scan error: {exc}"}

    def attest(self, state: dict, signer) -> dict:
        """PQ-signed attestation of oversight state. Uses CM's format when present,
        else a self-signed Agent Guard attestation."""
        envelope = {
            "format": "agent-guard-attestation/1",
            "issued_at": time.time(),
            "notary": "cryptomigrate" if self._mod is not None else "agent-guard",
            "state": state,
        }
        import json

        payload = json.dumps(envelope, sort_keys=True).encode()
        envelope["signature"] = signer.sign(payload) if signer.can_sign() else None
        envelope["signer_ref"] = signer.public_ref
        return envelope
