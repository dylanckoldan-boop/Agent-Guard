"""Foldward's own encrypted quarantine.

When an agent is neutralized, its executable or entry script is **moved** into an
AES-256-GCM encrypted store, so it cannot run from where it sat and is preserved
intact for forensics. Each item is encrypted under a per-install key kept
owner-only; the original SHA-256 is recorded so a restore can be integrity-verified
and never silently corrupted.

This is the *standalone* quarantine, so Foldward needs nothing else to contain an
agent safely. When sentinel-vision is installed (Route B), the adapter hands the
file to sentinel-vision's hardened, service-protected vault instead — see
:mod:`foldward.integrations.sentinel_vision`. Both apply the same safety rules:

* only an existing regular file is taken — never a link, a FIFO or a device, which
  could stall or exhaust the read (AG-N02);
* never an operating-system file, Foldward's own interpreter or program files, or
  anything inside Foldward's data folder;
* a relative path is refused (the caller resolves it against the agent's own
  working directory first);
* if the original can't be removed, nothing is kept and the call fails, so a
  "quarantined" result always means the file is gone from where it was (INT-04).

The design preference is suspend-and-preserve over destroy: containment should be
reversible and auditable, not a shredder.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import stat
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from foldward import config
from foldward.config import sub_dir
from foldward.osutil import is_system_path, write_private

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _HAVE_AEAD = True
except Exception:  # pragma: no cover
    _HAVE_AEAD = False


class QuarantineError(ValueError):
    """The file could not be quarantined; nothing was changed."""


class QuarantineRefused(QuarantineError):
    """The file was refused on purpose (a link, a device, an OS file, too large...)."""


@dataclass
class QuarantineItem:
    item_id: str
    original_path: str
    sha256: str
    size: int
    reason: str
    agent_id: str
    at: float


_PACKAGE_DIR = os.path.normcase(os.path.realpath(os.path.dirname(os.path.abspath(__file__))))


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


class Quarantine:
    # A quarantined artifact is normally an executable or script; cap what we will
    # read so a hostile or mistaken path can't exhaust memory, and stop reading if it
    # takes too long (a file on a stalled network share).
    MAX_BYTES = 512 * 1024 * 1024
    READ_BUDGET_S = 60.0

    def __init__(self, root: Path | None = None) -> None:
        # the store itself, and with the default location the whole data folder
        # (keys, audit, registry), are never quarantine targets
        self._own_dirs = [root] if root is not None else [config.data_root()]
        self._root = root or sub_dir("quarantine")
        self._root.mkdir(parents=True, exist_ok=True)
        self._meta = self._root / "index.json"
        self._key = self._load_or_make_key()
        self._items: dict[str, QuarantineItem] = self._load_index()

    # -- key ----------------------------------------------------------------
    def _key_path(self) -> Path:
        return self._root / "quarantine.key"

    def _load_or_make_key(self) -> bytes:
        kp = self._key_path()
        if kp.exists():
            key = kp.read_bytes()
            if len(key) != 32:
                raise QuarantineError("the quarantine key is damaged (expected 32 bytes)")
            return key
        key = secrets.token_bytes(32)
        # created owner-only from the start: no window with default permissions
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        return key

    # -- index --------------------------------------------------------------
    def _load_index(self) -> dict[str, QuarantineItem]:
        if not self._meta.exists():
            return {}
        try:
            raw = json.loads(self._meta.read_text("utf-8"))
            return {k: QuarantineItem(**v) for k, v in raw.items()}
        except (OSError, ValueError, TypeError, AttributeError):
            return {}

    def _save_index(self) -> None:
        write_private(self._meta, json.dumps({k: asdict(v) for k, v in self._items.items()}, indent=2).encode())

    # -- checks -------------------------------------------------------------
    def _refusal(self, src: str) -> str | None:
        if not os.path.isabs(src):
            return f"refusing a relative path ({src}); resolve it against the agent's folder first"
        if is_system_path(src):
            return "operating-system files are never quarantined"
        real = os.path.normcase(os.path.realpath(src))
        if real == os.path.normcase(os.path.realpath(sys.executable)):
            return "Foldward's own interpreter is never quarantined"
        if _within(real, _PACKAGE_DIR):
            return "Foldward's own program files are never quarantined"
        for own in self._own_dirs:
            if _within(real, os.path.normcase(os.path.realpath(own))):
                return "Foldward's own data is never quarantined"
        return None

    def _read_regular(self, src: str) -> tuple[bytes, os.stat_result]:
        """Read an existing regular file, without following links or blocking on a
        FIFO or device, within the size cap and time budget."""
        if os.path.islink(src):
            raise QuarantineRefused(f"links are never quarantined: {src}")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(src, flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise QuarantineRefused(f"links are never quarantined: {src}") from exc
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise QuarantineRefused(f"not a regular file: {src}")
            if st.st_size > self.MAX_BYTES:
                raise QuarantineRefused(f"refusing to quarantine {st.st_size} bytes (cap {self.MAX_BYTES})")
            chunks: list[bytes] = []
            total = 0
            deadline = time.monotonic() + self.READ_BUDGET_S
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.MAX_BYTES:
                    raise QuarantineRefused(f"the file grew past the cap ({self.MAX_BYTES} bytes) while being read")
                if time.monotonic() > deadline:
                    raise QuarantineError(f"reading {src} took longer than {self.READ_BUDGET_S:.0f} s")
                chunks.append(chunk)
            return b"".join(chunks), st
        finally:
            os.close(fd)

    # -- operations ---------------------------------------------------------
    def add(self, path: str, agent_id: str, reason: str, remove_original: bool = True) -> QuarantineItem:
        """Encrypt and store the file at ``path``, then **move** it out of its old
        location by default so it can no longer run from there (AG-A07). Pass
        ``remove_original=False`` to copy instead of move."""
        src = os.fspath(path)
        why = self._refusal(src)
        if why:
            raise QuarantineRefused(why)
        data, st = self._read_regular(src)  # raises FileNotFoundError before any state changes
        digest = hashlib.sha256(data).hexdigest()
        item_id = secrets.token_hex(8)
        blob = self._encrypt(data, item_id)
        fd = os.open(  # exclusive: never clobber an item
            self._root / f"{item_id}.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600
        )
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        item = QuarantineItem(item_id, src, digest, len(data), reason, agent_id, time.time())
        self._items[item_id] = item
        self._save_index()
        if remove_original:
            try:
                now = os.lstat(src)
                if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
                    raise QuarantineError("the file was replaced while it was being quarantined")
                os.unlink(src)
            except (OSError, QuarantineError) as exc:
                self._discard(item_id)
                raise QuarantineError(f"could not remove the original, so nothing was quarantined: {exc}") from exc
        return item

    def _discard(self, item_id: str) -> None:
        self._items.pop(item_id, None)
        try:
            (self._root / f"{item_id}.bin").unlink()
        except OSError:
            pass
        self._save_index()

    def restore(self, item_id: str, to: str) -> str:
        """Decrypt an item to ``to``; verifies integrity against the stored hash."""
        item = self._items[item_id]
        blob = (self._root / f"{item_id}.bin").read_bytes()
        data = self._decrypt(blob, item_id)
        if hashlib.sha256(data).hexdigest() != item.sha256:
            raise QuarantineError("integrity check failed: quarantined item was altered")
        dest = Path(to)
        if dest.is_dir():
            dest = dest / Path(item.original_path).name
        try:
            with open(dest, "xb") as fh:  # exclusive create: never overwrite an existing file or follow a link
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
