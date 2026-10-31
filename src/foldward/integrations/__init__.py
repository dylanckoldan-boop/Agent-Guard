"""Optional integration adapters — detected at runtime, never a dependency.

The partners (``sentinel-vision``, ``cryptomigrate``) appear nowhere in Agent
Guard's package metadata — not as a dependency, not as an optional extra. The
only thing that knows about them is a guarded import / CLI probe here. Agent
Guard is fully functional with neither installed; each one, when present, is a
pure upgrade (see ``docs/ARCHITECTURE.md``, Route B).
"""

from __future__ import annotations

from dataclasses import dataclass

from foldward.integrations import cryptomigrate, sentinel_vision


@dataclass
class PartnerStatus:
    sentinel_vision: bool
    sentinel_vision_how: str
    cryptomigrate: bool
    cryptomigrate_how: str


def partner_status() -> PartnerStatus:
    sv, sv_how = sentinel_vision.probe()
    cm, cm_how = cryptomigrate.probe()
    return PartnerStatus(sv, sv_how, cm, cm_how)


__all__ = ["PartnerStatus", "cryptomigrate", "partner_status", "sentinel_vision"]
