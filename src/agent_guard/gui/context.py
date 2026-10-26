"""The context passed to every page.

A page never imports the window it lives in — it takes a :class:`GuardContext`.
Agent Guard's own window builds one directly; under Route B, the plugin adapter
builds one from sentinel-vision's ``AppContext`` (see :mod:`agent_guard.gui.plugin`).
That one indirection is what lets the exact same pages run standalone *and*
hosted inside sentinel-vision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from agent_guard.core import AgentGuard
from agent_guard.gui.workers import Bridge


@dataclass
class GuardContext:
    guard: AgentGuard
    bridge: Bridge
    notify: Callable[[str, str, str], None]        # (title, text, level)
    navigate: Callable[[str], None]                # (page_key)
