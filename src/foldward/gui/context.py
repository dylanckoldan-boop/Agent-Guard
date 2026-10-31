"""The context passed to every page.

A page never imports the window it lives in — it takes a :class:`GuardContext`.
Foldward's own window builds one directly; under Route B, the plugin adapter
builds one from sentinel-vision's ``AppContext`` (see :mod:`foldward.gui.plugin`).
That one indirection is what lets the exact same pages run standalone *and*
hosted inside sentinel-vision.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from foldward.core import Foldward
from foldward.gui.workers import Bridge


@dataclass
class GuardContext:
    guard: Foldward
    bridge: Bridge
    notify: Callable[[str, str, str], None]        # (title, text, level)
    navigate: Callable[[str], None]                # (page_key)
