"""Foldward — a containment net for autonomous AI agents.

Foldward holds an oversight mesh across a fleet of AI agents (natively
spawned or *uploaded* onto a host) and catches rogue agent activity: a
misaligned objective surfacing at the edges, a hijacked agent reaching for
something it was never scoped to touch, or any contact with a planted decoy.
When it catches one, it *pacifies* it — graduated, reversible-first
containment on resources the defender owns, never a reach into the agent's own
infrastructure.

The package is a **standalone application** with zero required dependency on
any other project. When `sentinel-vision` or `cryptomigrate` happen to be
installed alongside it, Foldward detects them at runtime and opens a port
(see :mod:`foldward.integrations`) — but it is fully useful with neither.

Design in four layers (see ``docs/ARCHITECTURE.md``; what is built today is listed
in ``docs/CLAIMS.md``):

1. **Admission** — agents you sanction carry a signed, least-privilege identity,
   bound to their process; an unregistered agent is flagged for review.
2. **The net (tripwire)** — canary files no normal workflow opens; an
   unregistered agent holding one open is contained, other programs are reported.
3. **Pacify ladder** — throttle → quarantine → revoke → suspend → terminate,
   climbing only as far as the threat demands (the agent is frozen first when the
   ladder reaches suspend), all inside our own perimeter.
4. **Consensus + audit** — a flag contains only after an in-process quorum agrees
   (a canary hit by an unregistered agent is self-authorizing); every step lands in
   a hash-chained, tamper-evident audit whose head can be post-quantum signed.

Everything runs with the user's rights, so a program running as the user can
interfere with it; see the README's "Scope and limitations".
"""

from __future__ import annotations

__all__ = ["APP_NAME", "APP_SLUG", "__version__"]

APP_NAME = "Foldward"
APP_SLUG = "foldward"
__version__ = "0.2.1"
