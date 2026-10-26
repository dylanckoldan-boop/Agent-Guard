"""The oversight mesh (Layer 4): consensus, and the 'many doors' channel.

Two mechanisms live here.

**Consensus before action.** A single flag never pacifies anything on its own.
Risk is assembled from several independent *sentinels* — identity, reach,
behaviour, tripwire — each with a weight. Containment is gated on a quorum: the
weighted risk must clear a threshold *and* enough independent sentinels must
agree, so one noisy or compromised sentinel can neither force a containment nor,
by staying silent, veto one on its own. The tripwire is special-cased: a decoy
touch is self-authorizing because no legitimate agent can produce it.

**The 'many doors' oversight channel.** Mix networks shuffle entrances and exits
so a watcher cannot link one to the other. The crucial design decision is *whose*
traffic goes through the doors:

* The **watched agents'** traffic is *never* mixed — east-west flow analysis is
  one of the net's best detection signals, so blinding it would be a gift to a
  compromised agent. It stays fully observable.
* The **oversight** traffic — sentinel votes, containment commands — *is* mixed,
  so a hijacked agent cannot tell which sentinel flagged it, trace telemetry back
  to the consensus core, or pick out the channel carrying its own pacification in
  time to jam it.

So the control plane is hidden and the data plane is watched. Authentication
proves *who* is talking (the signed registry); mixing hides *that* they are
talking and to whom — different protections, stacked. Mixing is kept off the
fast path for time-critical containment commands.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field


@dataclass
class Sentinel:
    name: str
    kind: str   # identity | reach | behaviour | tripwire
    weight: float
    note: str = ""


DEFAULT_SENTINELS = [
    Sentinel("admission", "identity", 1.0, "valid credential & scope"),
    Sentinel("flow", "reach", 1.2, "egress, fan-out, novel peers"),
    Sentinel("conduct", "behaviour", 1.0, "child spawns, path scope"),
    Sentinel("tripwire", "tripwire", 3.0, "decoy contact — self-authorizing"),
]


@dataclass
class Decision:
    contain: bool
    weighted_risk: float
    agreeing: int
    rationale: str


class Consensus:
    """Aggregates sentinel contributions into a containment decision."""

    def __init__(self, sentinels: list[Sentinel] | None = None, quorum: int = 2, threshold: float = 60.0) -> None:
        self.sentinels = sentinels or list(DEFAULT_SENTINELS)
        self.quorum = quorum
        self.threshold = threshold

    def decide(self, contributions: dict[str, float], decoy: bool = False) -> Decision:
        """``contributions`` maps sentinel kind -> risk points it raised (0..100)."""
        if decoy:
            return Decision(True, 100.0, len(self.sentinels), "decoy contact — self-authorizing, quorum waived")
        weighted = 0.0
        agreeing = 0
        for s in self.sentinels:
            pts = contributions.get(s.kind, 0.0)
            if pts > 0:
                agreeing += 1
                weighted += pts * s.weight
        weighted = min(100.0, weighted / max(1.0, sum(s.weight for s in self.sentinels)) * len(self.sentinels))
        contain = weighted >= self.threshold and agreeing >= self.quorum
        why = (
            f"weighted risk {weighted:.0f} ≥ {self.threshold:.0f} and {agreeing} sentinels agree (quorum {self.quorum})"
            if contain
            else f"held: risk {weighted:.0f}, {agreeing} sentinel(s) agreeing (need {self.quorum})"
        )
        return Decision(contain, weighted, agreeing, why)


@dataclass
class MixStats:
    real_emitted: int = 0
    cover_emitted: int = 0

    @property
    def total(self) -> int:
        return self.real_emitted + self.cover_emitted


class MixChannel:
    """Traffic-analysis-resistant channel for *oversight* records only.

    Each real oversight message is emitted in a batch padded with at least
    ``min_cover`` indistinguishable cover messages, in shuffled order, so an
    observer cannot link a flag to the sentinel that raised it or to the agent it
    concerns. Time-critical containment commands bypass mixing (``urgent=True``).
    This never touches watched-agent traffic.
    """

    def __init__(self, enabled: bool = True, min_cover: int = 3, rng: random.Random | None = None) -> None:
        self.enabled = enabled
        self.min_cover = min_cover
        self.stats = MixStats()
        self._rng = rng or random.Random()

    def emit(self, record: dict, *, urgent: bool = False) -> list[dict]:
        """Return the batch actually put on the wire (real + cover, shuffled)."""
        real = {**record, "_cover": False, "_t": time.time()}
        if not self.enabled or urgent:
            self.stats.real_emitted += 1
            return [real]
        batch = [real]
        for _ in range(self.min_cover):
            batch.append({"_cover": True, "_t": time.time(), "_nonce": self._rng.getrandbits(48)})
        self._rng.shuffle(batch)
        self.stats.real_emitted += 1
        self.stats.cover_emitted += self.min_cover
        return batch


@dataclass
class MeshSnapshot:
    """What the GUI 'Mesh' view renders — the spiderweb."""

    core_state: str                      # "nominal" | "deciding" | "containing"
    sentinels: list[dict] = field(default_factory=list)
    agents: list[dict] = field(default_factory=list)  # {label, state, score}
    mix_enabled: bool = True
    mix_cover_ratio: float = 0.0
