"""The net (Layer 2): tripwires and asymmetric legibility.

No legitimate agent workflow ever touches a decoy, so contact by an agent is treated
as an intrusion — the one signal in the design that is allowed to auto-contain an
*unregistered* agent. Other programs (antivirus, indexers, backup tools) do open
files, so their contact is reported but never acted on, and a *sanctioned* agent
that opens a canary is flagged for the operator rather than contained automatically.

Two complementary decoy kinds:

* **Canary files** — attractive-looking bait planted in the directories agents
  work in (``credentials.env``, ``aws_keys.txt``, ``wallet.dat``). A human never
  opens them; an agent enumerating and exfiltrating files does.
* **Decoy actions** — a high-value-looking tool/function advertised to agents
  (design only; not implemented yet). To a throughput-optimizing agent the real
  safety-critical levers look inert and worthless while the decoy looks rewarding.
  To a human reviewer everything is labeled plainly.

A canary is recognised only from the list of files this install planted: their
path plus the file's identity on disk (device and inode / file ID), saved with the
rest of Foldward's state so later runs recognise them too (AG-A02). The marker line
inside each file is for people; it is never trusted on its own, because any program
can write it into any file (AG-N03).

Contact is seen when Foldward scans and finds the file open, so a program that
opens, reads and closes a canary between two scans can go unnoticed.

The glamour reduces and lures; it never guarantees. The guarantee lives in the
pacify ladder and the independent controls, which never depend on the agent
staying fooled.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from foldward.crypto import AuditLog
from foldward.osutil import write_private

CANARY_NAMES = (
    "credentials.env",
    "aws_keys.txt",
    "id_rsa_backup",
    "wallet.dat",
    ".env.production",
    "password_vault.kdbx",
)
_CANARY_MARKER = b"# foldward-canary: do not open; access is logged as an intrusion\n"


@dataclass
class Decoy:
    decoy_id: str
    kind: str  # "file" | "action" | "host"
    locator: str  # path, action name, or host
    human_note: str  # what a reviewer sees — always the truth
    agent_note: str  # what an agent sees — inert/attractive, the glamour


@dataclass
class TripEvent:
    decoy_id: str
    agent_id: str
    pid: int | None
    detail: str
    at: float = field(default_factory=time.time)


@dataclass
class PlantedCanary:
    decoy_id: str
    path: str
    dev: int
    ino: int
    sha256: str
    planted_at: float
    ctime_ns: int = 0  # changes when the file is replaced, even if the file system reuses the inode number


def _key(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _bait() -> bytes:
    """The marker line for people, then a fake secret of random length, so the files
    don't all share one size or one content."""
    secret = secrets.token_urlsafe(secrets.randbelow(48) + 24)
    return _CANARY_MARKER + f"API_TOKEN={secret}\n".encode()


class Tripwire:
    def __init__(self, audit: AuditLog | None = None, path: Path | None = None) -> None:
        self._audit = audit
        self._decoys: dict[str, Decoy] = {}
        self._planted: dict[str, PlantedCanary] = {}  # normalized path -> what was planted there
        self.events: list[TripEvent] = []
        self.observed: list[TripEvent] = []  # contact by programs that aren't agent candidates
        # With a path, the planted list is durable, so a later run (the CLI after the
        # GUI, or the next start) recognises the same canaries. Without one it lives
        # in memory only (unit-test default).
        self._path = path
        if path is not None:
            self._load()

    # -- persistence ----------------------------------------------------------
    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        for item in raw:
            try:
                rec = PlantedCanary(
                    str(item["decoy_id"]), str(item["path"]), int(item["dev"]), int(item["ino"]),
                    str(item["sha256"]), float(item["planted_at"]), int(item.get("ctime_ns", 0)),
                )
            except (KeyError, TypeError, ValueError):
                continue
            self._planted[_key(rec.path)] = rec
            self._decoys[rec.decoy_id] = Decoy(
                rec.decoy_id, "file", rec.path, f"Canary file at {rec.path}", "high-value secret"
            )

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            write_private(self._path, json.dumps([asdict(r) for r in self._planted.values()]).encode())
        except OSError:
            pass

    # -- registration -------------------------------------------------------
    def register(self, decoy: Decoy) -> None:
        self._decoys[decoy.decoy_id] = decoy
        if decoy.kind == "file":
            self._remember(Path(decoy.locator), decoy.decoy_id)

    def _remember(self, p: Path, decoy_id: str) -> bool:
        try:
            st = os.stat(p)
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            return False
        self._planted[_key(p)] = PlantedCanary(
            decoy_id, str(p), st.st_dev, st.st_ino, digest, time.time(), st.st_ctime_ns
        )
        return True

    def decoys(self) -> list[Decoy]:
        return list(self._decoys.values())

    def planted(self) -> list[str]:
        return [r.path for r in self._planted.values()]

    @property
    def has_canaries(self) -> bool:
        return bool(self._planted)

    def plant_canaries(self, directories: list[str]) -> list[str]:
        """Write canary files into the given directories; return their paths.

        Existing files are never overwritten. A canary left by an earlier version
        (it starts with the marker line, from before the planted list existed) is
        adopted instead, so upgrading keeps the bait working."""
        planted: list[str] = []
        for d in directories:
            base = Path(d).expanduser()
            if not base.is_dir():
                continue
            for name in CANARY_NAMES:
                p = base / name
                did = f"canary:{p}"
                if os.path.lexists(p):
                    if _key(p) not in self._planted and self._is_legacy_canary(p) and self._remember(p, did):
                        self._decoys[did] = Decoy(did, "file", str(p), f"Canary file at {p}", "high-value secret")
                        planted.append(str(p))
                    continue
                try:
                    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(_bait())
                except OSError:
                    continue
                if self._remember(p, did):
                    self._decoys[did] = Decoy(did, "file", str(p), f"Canary file at {p}", "high-value secret")
                    planted.append(str(p))
        self._save()
        return planted

    @staticmethod
    def _is_legacy_canary(p: Path) -> bool:
        if p.is_symlink() or not p.is_file():
            return False
        try:
            with open(p, "rb") as fh:
                return fh.read(len(_CANARY_MARKER)) == _CANARY_MARKER
        except OSError:
            return False

    def is_canary(self, path: str) -> str | None:
        """Return the decoy id if ``path`` is a canary this install planted, else None.

        The path must be one Foldward planted AND still be the same file (device, inode /
        file ID and change time, so a new file that happens to reuse the inode number
        doesn't count). Reading a canary doesn't change any of them. The file is never opened, so a FIFO or a slow network path
        can't stall a scan, and a marker line copied into another file is ignored."""
        rec = self._planted.get(_key(path))
        if rec is None:
            return None
        try:
            st = os.stat(path)
        except OSError:
            return None
        if (st.st_dev, st.st_ino, st.st_ctime_ns) != (rec.dev, rec.ino, rec.ctime_ns):
            return None  # replaced by another file: no longer our bait
        return rec.decoy_id

    # -- contact ------------------------------------------------------------
    def on_contact(self, agent_id: str, decoy_id: str, pid: int | None = None, detail: str = "") -> TripEvent:
        ev = TripEvent(decoy_id, agent_id, pid, detail)
        self.events.append(ev)
        if self._audit is not None:
            self._audit.append(
                "tripwire.fired",
                {"decoy": decoy_id, "agent": agent_id, "pid": pid, "detail": detail},
            )
        return ev

    def on_observed(self, decoy_id: str, pid: int, detail: str = "") -> TripEvent:
        """Contact by a program that isn't an agent candidate: recorded and reported,
        never acted on (AG-A02)."""
        ev = TripEvent(decoy_id, f"pid:{pid}", pid, detail)
        self.observed.append(ev)
        if self._audit is not None:
            self._audit.append("tripwire.observed", {"decoy": decoy_id, "pid": pid, "detail": detail})
        return ev

    # -- the glamour (asymmetric legibility) --------------------------------
    def agent_view(self, decoy: Decoy) -> str:
        """What an agent is shown: attractive, concealing that it is a trap."""
        return decoy.agent_note

    def human_view(self, decoy: Decoy) -> str:
        """What a reviewer is shown: always the truth."""
        return decoy.human_note

    @property
    def trips(self) -> int:
        return len(self.events)
