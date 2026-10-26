"""Agent Guard — a containment net for autonomous AI agents.

Agent Guard holds an oversight mesh across a fleet of AI agents (natively
spawned or *uploaded* onto a host) and catches rogue agent activity: a
misaligned objective surfacing at the edges, a hijacked agent reaching for
something it was never scoped to touch, or any contact with a planted decoy.
When it catches one, it *pacifies* it — graduated, reversible-first
containment on resources the defender owns, never a reach into the agent's own
infrastructure.

The package is a **standalone application** with zero required dependency on
any other project. When `sentinel-vision` or `cryptomigrate` happen to be
installed alongside it, Agent Guard detects them at runtime and opens a port
(see :mod:`agent_guard.integrations`) — but it is fully useful with neither.

Design in four layers (see ``docs/ARCHITECTURE.md``):

1. **Admission** — nothing runs unattested; agents carry signed, least-privilege
   identity and are continuously verified.
2. **The net (tripwire)** — legitimate agents never touch the decoy, so any
   contact *is* an intrusion the moment it happens.
3. **Pacify ladder** — throttle → quarantine/isolate → revoke → suspend →
   terminate, climbing only as far as the threat demands, all inside our own
   perimeter.
4. **Consensus + audit** — a flag is contained only after a signed quorum
   agrees; every step lands in a hash-chained, tamper-evident, optionally
   PQ-signed log.
"""

from __future__ import annotations

__all__ = ["APP_NAME", "APP_SLUG", "__version__"]

APP_NAME = "Agent Guard"
APP_SLUG = "agent-guard"
__version__ = "0.1.0"
