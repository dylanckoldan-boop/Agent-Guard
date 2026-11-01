"""Optional partner: cryptomigrate — detected, not used yet.

cryptomigrate (crypto discovery, migration and signed attestation) is planned as
Foldward's *notary and crypto-hygiene lens*:

* **crypto_scan(dir)** (planned) — run cryptomigrate's discovery over a flagged
  agent's install directory for hardcoded keys, DES/SHA-1 or obsolete TLS.
  cryptomigrate 1.1 has no single-directory scan that Foldward can call, so this
  returns a note, not findings.
* **attest(state)** — Foldward's own attestation of its oversight state (audit
  head, registry size, containments), signed with its circle key. It always names
  Foldward as the notary: cryptomigrate takes no part in it yet.

Detection never imports or runs cryptomigrate (AG-A04): a module that merely has
its name — a squatted package, a folder planted on the Python path — is never
executed inside Foldward. ``probe`` only looks it up.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import time

_PLANNED = "planned: Foldward doesn't call cryptomigrate yet"


def probe() -> tuple[bool, str]:
    """Return (present, how) without importing or running cryptomigrate."""
    try:
        spec = importlib.util.find_spec("cryptomigrate")
    except (ImportError, ValueError):
        spec = None
    if spec is not None:
        return True, f"installed ({spec.origin or 'package'}); detected only, not used yet"
    cli = shutil.which("cryptomigrate")
    if cli:
        return True, f"command-line tool {cli}; detected only, not used yet"
    return False, "not installed"


def is_present() -> bool:
    return probe()[0]


class CryptomigrateAdapter:
    """The planned cryptomigrate surface. Nothing here imports or runs cryptomigrate."""

    @property
    def available(self) -> bool:
        return False  # nothing is wired to cryptomigrate yet

    def crypto_scan(self, directory: str) -> dict:
        """Planned: weak-crypto findings in an agent's directory."""
        return {"available": False, "findings": [], "detail": _PLANNED}

    def attest(self, state: dict, signer) -> dict:
        """Foldward's own attestation of its oversight state, signed with its circle key
        when the signer can sign (a verifier alone leaves the signature empty)."""
        envelope = {
            "format": "foldward-attestation/1",
            "issued_at": time.time(),
            "notary": "foldward",
            "state": state,
        }
        payload = json.dumps(envelope, sort_keys=True).encode()
        envelope["signature"] = signer.sign(payload) if signer.can_sign() else None
        envelope["signer_ref"] = signer.public_ref
        return envelope
