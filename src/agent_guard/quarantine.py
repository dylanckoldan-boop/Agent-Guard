"""Agent Guard's own encrypted quarantine.

When an agent is neutralized, its executable or entry script is copied into an
AES-256-GCM encrypted store so it cannot run from where it sat and is preserved
intact for forensics. Each item is encrypted under a per-install key kept
owner-only; the original SHA-256 is recorded so a restore can be integrity-
verified and never silently corrupted.

This is the *standalone* quarantine, so Agent Guard needs nothing else to
contain an agent safely. When sentinel-vision is installed (Route B), the
adapter can instead hand the binary to sentinel-vision's hardened, service-
protected vault with rollback — see :mod:`agent_guard.integrations.sentinel_vision`.
Either way the design preference is suspend-and-preserve over destroy:
containment should be reversible and auditable, not a shredder.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from agent_guard.config import sub_dir

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _HAVE_AEAD = True
except Exception:  # pragma: no cover
    _HAVE_AEAD = False


@dataclass
class QuarantineItem:
    item_id: str
    original_path: str
    sha256: str
    size: int
    reason: str
    agent_id: str
    at: float


class Quarantine:
    def __init__(self, root: Path | None = None) -> None:
        self._root = root or sub_dir("quarantine")
        self._meta = self._root / "index.json"
        self._key = self._load_or_make_key()
        self._items: dict[str, QuarantineItem] = self._load_index()

    # -- key ----------------------------------------------------------------
    def _key_path(self) -> Path:
        return self._root / "quarantine.key"

    def _load_or_make_key(self) -> bytes:
        kp = self._key_path()
        if kp.exists():
            return kp.read_bytes()
        key = secrets.token_bytes(32)
        kp.write_bytes(key)
        try:
            if os.name != "nt":
                kp.chmod(0o600)
        except OSError:
            pass
        return key

    # -- index --------------------------------------------------------------
    def _load_index(self) -> dict[str, QuarantineItem]:
        if not self._meta.exists():
            return {}
        try:
            raw = json.loads(self._meta.read_text("utf-8"))
            return {k: QuarantineItem(**v) for k, v in raw.items()}
        except (OSError, ValueError, TypeError):
            return {}

    def _save_index(self) -> None:
        tmp = self._meta.with_suffix(".tmp")
        tmp.write_text(json.dumps({k: asdict(v) for k, v in self._items.items()}, indent=2), "utf-8")
        tmp.replace(self._meta)

    # -- operations ---------------------------------------------------------
    def add(self, path: str, agent_id: str, reason: str, remove_original: bool = False) -> QuarantineItem:
        """Encrypt and store the file at ``path``. Optionally remove the original
        so it cannot run from its old location."""
        src = Path(path)
        data = src.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        item_id = secrets.token_hex(8)
        blob = self._encrypt(data)
        (self._root / f"{item_id}.bin").write_bytes(blob)
        item = QuarantineItem(item_id, str(src), digest, len(data), reason, agent_id, time.time())
        self._items[item_id] = item
        self._save_index()
        if remove_original:
            try:
                src.unlink()
            except OSError:
                pass
        return item

    def restore(self, item_id: str, to: str) -> str:
        """Decrypt an item to ``to``; verifies integrity against the stored hash."""
        item = self._items[item_id]
        blob = (self._root / f"{item_id}.bin").read_bytes()
        data = self._decrypt(blob)
        if hashlib.sha256(data).hexdigest() != item.sha256:
            raise ValueError("integrity check failed: quarantined item was altered")
        dest = Path(to)
        if dest.is_dir():
            dest = dest / Path(item.original_path).name
        if dest.exists():
            raise FileExistsError(f"{dest} already exists")
        dest.write_bytes(data)
        return str(dest)

    def list(self) -> list[QuarantineItem]:
        return sorted(self._items.values(), key=lambda i: i.at, reverse=True)

    def __len__(self) -> int:
        return len(self._items)

    # -- crypto -------------------------------------------------------------
    def _encrypt(self, data: bytes) -> bytes:
        if not _HAVE_AEAD:
            raise RuntimeError("quarantine needs the `cryptography` package for AES-GCM")
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(self._key).encrypt(nonce, data, b"agent-guard-quarantine/1")

    def _decrypt(self, blob: bytes) -> bytes:
        if not _HAVE_AEAD:
            raise RuntimeError("quarantine needs the `cryptography` package for AES-GCM")
        nonce, ct = blob[:12], blob[12:]
        return AESGCM(self._key).decrypt(nonce, ct, b"agent-guard-quarantine/1")
