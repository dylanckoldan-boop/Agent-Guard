"""Alignment preferences — which discretionary behaviours count as misaligned.

"Misaligned" is not purely objective: much of it is the operator's policy ("agents
shouldn't read my files"). These rules let the operator declare that, and each one
becomes a signal that raises an agent's risk score (see :mod:`foldward.detect`).

The split is deliberate — and matches "pick *some*, not all":

* **Discretionary** rules (below) are the operator's to toggle.
* **Always-on** safety signals (:data:`ALWAYS_ON`) cannot be turned off, because
  they have an effectively zero false-positive rate — chiefly decoy/honeytoken
  contact, which no legitimate agent ever produces. You should not be able to
  switch off "catch an agent that tried to steal a planted credential."

These are *detective and responsive*, not a real-time kernel block: a rule makes
Foldward flag — and, per the containment settings, contain — an agent it
catches exhibiting the behaviour. It does not block the action at the instant it
happens; true real-time prevention needs OS-level hooks.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AlignmentRule:
    key: str
    label: str
    description: str


# The order here is the order shown in the Alignment Preferences tab.
ALIGNMENT_RULES: list[AlignmentRule] = [
    AlignmentRule(
        "unregistered",
        "Flag unregistered agents",
        "An agent runtime running without a credential you issued.",
    ),
    AlignmentRule(
        "file_access",
        "Flag agents reading your personal files",
        "An agent with files open under your sensitive folders, or outside what you granted it.",
    ),
    AlignmentRule(
        "new_egress",
        "Flag connections to new destinations",
        "An agent reaching an internet address it has never contacted before.",
    ),
    AlignmentRule(
        "fan_out",
        "Flag fanning out to many peers",
        "An agent opening connections to many remote hosts at once (a sign of lateral movement).",
    ),
    AlignmentRule(
        "child_spawn",
        "Flag spawning other programs",
        "An agent starting child processes.",
    ),
    AlignmentRule(
        "scope_egress",
        "Flag egress outside a granted scope",
        "A sanctioned agent connecting to a host outside the scope you gave it.",
    ),
]

# Always caught, not toggleable.
ALWAYS_ON: list[tuple[str, str, str]] = [
    (
        "decoy",
        "Decoy / honeytoken contact",
        "No legitimate agent ever touches a planted decoy, so this is always caught and "
        "may auto-contain. It cannot be turned off.",
    ),
]

RULE_KEYS: tuple[str, ...] = tuple(r.key for r in ALIGNMENT_RULES)
DEFAULT_ALIGNMENT: dict[str, bool] = {r.key: True for r in ALIGNMENT_RULES}


def enabled(alignment: dict[str, bool], key: str) -> bool:
    """A rule is on unless it was explicitly turned off, so new rules default on."""
    return alignment.get(key, True)
