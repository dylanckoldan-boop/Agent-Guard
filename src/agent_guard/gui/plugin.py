"""Route B: appear as a tab inside sentinel-vision — with no dependency either way.

sentinel-vision, when installed alongside Agent Guard, discovers this through the
``sentinel_vision.plugins`` entry point (declared in ``pyproject.toml``) and calls
:func:`register`. Agent Guard imports nothing from sentinel-vision here; it only
hands back page descriptors. sentinel-vision's plugin host does the rest.

**The contract** (what the sentinel-vision instance implements — see
``docs/SENTINEL_VISION_INTEGRATION.md``):

* Agent Guard's entry point ``register()`` returns a list of :class:`PluginPage`,
  each ``(key, label, factory)``.
* ``factory(host_ctx)`` returns a ``QWidget`` to drop into sentinel-vision's
  stack, with a sidebar button labeled ``label``. ``host_ctx`` is duck-typed:
  Agent Guard uses only ``host_ctx.notify(title, text, level)`` and
  ``host_ctx.navigate(key)`` if present — both satisfied by sentinel-vision's
  ``AppContext``.

Agent Guard runs its *own* engine inside the host (sentinel-vision does not
provide it), so the pages behave identically to standalone; the host just lends
its window, tray and notifications.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class PluginPage:
    key: str
    label: str
    factory: Callable[[object], object]  # (host_ctx) -> QWidget


def register() -> list[PluginPage]:
    # Imported lazily so merely *discovering* the entry point is cheap and never
    # forces PySide6 to load unless the host actually builds the pages.
    from agent_guard.config import Settings
    from agent_guard.core import AgentGuard
    from agent_guard.gui.context import GuardContext
    from agent_guard.gui.pages import NAV
    from agent_guard.gui.workers import Bridge

    guard = AgentGuard(Settings.load())  # one engine shared by all hosted pages

    def _factory(cls):
        def build(host_ctx: object):
            notify = getattr(host_ctx, "notify", lambda *a, **k: None)
            navigate = getattr(host_ctx, "navigate", lambda *a, **k: None)
            ctx = GuardContext(guard, Bridge(), notify, navigate)
            page = cls(ctx)
            guard.alert_listeners.append(lambda t, x, l: notify(t, x, l))
            return page

        return build

    # Drop the standalone-only "Settings" and "Overview" duplication if the host
    # prefers; by default expose the operational pages.
    return [PluginPage(key, label.strip(), _factory(cls)) for key, label, cls in NAV]
