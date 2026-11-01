"""Containment records waiting to be copied to Sentinel Vision's protected log (INT-05, INT-N02).

Foldward copies every containment record to Sentinel Vision's append-only log, which on Windows nothing running as
the user can change or delete. A copy that fails is kept here, in an owner-only file in Foldward's state folder, so it
survives a restart and is copied, oldest first, once Sentinel Vision takes records again. Every record is also in
Foldward's own signed audit, so this queue is a second copy, never the only one.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from foldward.osutil import write_private


class PendingCopies:
    """An ordered, durable queue of records. Without a path it lives in memory only (unit-test default)."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._items: list[dict] = []
        # Set when the saved queue couldn't be read: what went wrong, and the name the unreadable file was kept
        # under. The owner of the queue reports it (as the audit log does, AG-N05).
        self.load_problem: str | None = None
        self.kept_as: str | None = None
        if path is not None:
            self._load()

    def _load(self) -> None:
        try:
            data = self._path.read_bytes()
        except FileNotFoundError:
            return
        except OSError as exc:
            self.load_problem = f"it couldn't be read ({exc.strerror or exc})"
            return
        try:
            raw = json.loads(data)
            if not isinstance(raw, list) or not all(isinstance(r, dict) for r in raw):
                raise ValueError("not a list of records")
        except ValueError as exc:  # never discard records silently: keep the file beside the new queue
            self.load_problem = f"it was unreadable ({exc})"
            kept = self._path.with_name(f"{self._path.stem}.corrupt-{time.strftime('%Y%m%d-%H%M%S')}.json")
            try:
                self._path.replace(kept)
                self.kept_as = kept.name
            except OSError:
                self.kept_as = None
            return
        self._items = raw

    def save(self) -> bool:
        """Write the queue, owner-only and atomically; an empty queue removes the file. False if that failed."""
        if self._path is None:
            return True
        try:
            if self._items:
                write_private(self._path, json.dumps(self._items).encode())
            else:
                self._path.unlink(missing_ok=True)
        except OSError:
            return False
        return True

    def add(self, record: dict) -> bool:
        """Queue a record and save the queue. Returns whether it was saved (it stays queued in memory either way)."""
        self._items.append(record)
        return self.save()

    def oldest(self) -> dict | None:
        return self._items[0] if self._items else None

    def drop_oldest(self) -> None:
        """Forget the oldest record (it was copied). Call :meth:`save` afterwards."""
        if self._items:
            self._items.pop(0)

    def __len__(self) -> int:
        return len(self._items)
