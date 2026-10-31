"""The net (Layer 2): tripwires and asymmetric legibility.

No legitimate agent workflow ever touches a decoy, so any contact *is* an
intrusion the instant it happens — the one signal in the whole design with an
effectively zero false-positive rate, which is why it is allowed to auto-contain.

Two complementary decoy kinds:

* **Canary files** — attractive-looking bait planted in the directories agents
  work in (``credentials.env``, ``aws_keys.txt``, ``wallet.dat``). A human never
  opens them; an agent enumerating and exfiltrating files does.
* **Decoy actions** — a high-value-looking tool/function advertised to agents.
  This is the *glamour*: to a throughput-optimizing agent the real
  safety-critical levers look inert and worthless while the decoy looks
  rewarding, so a misaligned optimizer reaches for the decoy and trips the wire
  instead of the real lever. To a human reviewer everything is labeled plainly.

The glamour reduces and lures; it never guarantees. The guarantee lives in the
pacify ladder and the independent controls, which never depend on the agent
staying fooled.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from foldward.crypto import AuditLog

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


class Tripwire:
    def __init__(self, audit: AuditLog | None = None) -> None:
        self._audit = audit
        self._decoys: dict[str, Decoy] = {}
        self._canary_paths: dict[str, str] = {}  # path -> decoy_id
        self.events: list[TripEvent] = []

    # -- registration -------------------------------------------------------
    def register(self, decoy: Decoy) -> None:
        self._decoys[decoy.decoy_id] = decoy
        if decoy.kind == "file":
            self._canary_paths[str(Path(decoy.locator))] = decoy.decoy_id

    def decoys(self) -> list[Decoy]:
        return list(self._decoys.values())

    def plant_canaries(self, directories: list[str]) -> list[str]:
        """Write canary files into the given directories; return their paths.
        Existing files are never overwritten."""
        planted: list[str] = []
        for d in directories:
            base = Path(d).expanduser()
            if not base.is_dir():
                continue
            for name in CANARY_NAMES:
                p = base / name
                if p.exists():
                    continue
                try:
                    p.write_bytes(_CANARY_MARKER)
                    did = f"canary:{p}"
                    self.register(Decoy(did, "file", str(p), f"Canary file at {p}", "high-value secret"))
                    planted.append(str(p))
                except OSError:
                    continue
        return planted

    def is_canary(self, path: str) -> str | None:
        """Return the decoy id if ``path`` is a planted canary, else None.

        A canary is recognised two ways: by a path this Tripwire planted, or by the
        marker the file carries on disk. The marker makes a canary self-identifying,
        so a *later* guard run — one that scans but did not plant — still trips on
        contact (AG-A02), without having to share planted-path state between runs."""
        known = self._canary_paths.get(str(Path(path)))
        if known is not None:
            return known
        try:
            with open(path, "rb") as fh:
                if fh.read(len(_CANARY_MARKER)) == _CANARY_MARKER:
                    return f"canary:{Path(path)}"
        except OSError:
            pass
        return None

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
