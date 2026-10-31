"""Foldward's own encrypted quarantine.

When an agent is neutralized, its executable or entry script is copied into an
AES-256-GCM encrypted store so it cannot run from where it sat and is preserved
intact for forensics. Each item is encrypted under a per-install key kept
owner-only; the original SHA-256 is recorded so a restore can be integrity-
verified and never silently corrupted.

This is the *standalone* quarantine, so Foldward needs nothing else to
contain an agent safely. When sentinel-vision is installed (Route B), the
adapter can instead hand the binary to sentinel-vision's hardened, service-
protected vault with rollback — see :mod:`foldward.integrations.sentinel_vision`.
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

from foldward.config import sub_dir

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
    # A quarantined artifact is normally an executable or script; cap what we will
    # read into memory so a hostile or mistaken path (a huge/sparse/device-backed
    # file) can't exhaust memory.
    MAX_BYTES = 512 * 1024 * 1024

    def add(self, path: str, agent_id: str, reason: str, remove_original: bool = True) -> QuarantineItem:
        """Encrypt and store the file at ``path``, then **move** it out of its old
        location by default so it can no longer run from there (AG-A07). Pass
        ``remove_original=False`` to copy instead of move."""
        src = Path(path)
        size = src.stat().st_size  # raises FileNotFoundError before any state changes
        if size > self.MAX_BYTES:
            raise ValueError(f"refusing to quarantine {size} bytes (cap {self.MAX_BYTES})")
        data = src.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        item_id = secrets.token_hex(8)
        blob = self._encrypt(data, item_id)
        with open(self._root / f"{item_id}.bin", "xb") as fh:  # exclusive: never clobber an item
            fh.write(blob)
        item = QuarantineItem(item_id, str(src), digest, len(data), reason, agent_id, time.time())
        self._items[item_id] = item
        self._save_index()
        if remove_original:
            try:
                src.unlink()
            except OSError:
                pass  # best effort: the encrypted copy is already safely stored
        return item

    def restore(self, item_id: str, to: str) -> str:
        """Decrypt an item to ``to``; verifies integrity against the stored hash."""
        item = self._items[item_id]
        blob = (self._root / f"{item_id}.bin").read_bytes()
        data = self._decrypt(blob, item_id)
        if hashlib.sha256(data).hexdigest() != item.sha256:
            raise ValueError("integrity check failed: quarantined item was altered")
        dest = Path(to)
        if dest.is_dir():
            dest = dest / Path(item.original_path).name
        try:
            with open(dest, "xb") as fh:  # exclusive create: never overwrite an existing file
                fh.write(data)
        except FileExistsError:
            raise FileExistsError(f"{dest} already exists") from None
        return str(dest)

    def list(self) -> list[QuarantineItem]:
        return sorted(self._items.values(), key=lambda i: i.at, reverse=True)

    def __len__(self) -> int:
        return len(self._items)

    # -- crypto -------------------------------------------------------------
    def _aad(self, item_id: str) -> bytes:
        # Bind each ciphertext to its own item id, so a blob can't be swapped for
        # another item's (the AAD would no longer authenticate).
        return f"foldward-quarantine/1:{item_id}".encode()

    def _encrypt(self, data: bytes, item_id: str) -> bytes:
        if not _HAVE_AEAD:
            raise RuntimeError("quarantine needs the `cryptography` package for AES-GCM")
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(self._key).encrypt(nonce, data, self._aad(item_id))

    def _decrypt(self, blob: bytes, item_id: str) -> bytes:
        if not _HAVE_AEAD:
            raise RuntimeError("quarantine needs the `cryptography` package for AES-GCM")
        nonce, ct = blob[:12], blob[12:]
        return AESGCM(self._key).decrypt(nonce, ct, self._aad(item_id))
