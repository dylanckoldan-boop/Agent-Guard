"""Route B: appear as a tab inside sentinel-vision — with no dependency either way.

sentinel-vision, when installed alongside Foldward, discovers this through the
``sentinel_vision.plugins`` entry point (declared in ``pyproject.toml``) and calls
:func:`register`. Foldward imports nothing from sentinel-vision here; it only
hands back page descriptors. sentinel-vision's plugin host does the rest.

**The contract** (what the sentinel-vision instance implements — see
``docs/SENTINEL_VISION_INTEGRATION.md``):

* Foldward's entry point ``register()`` returns a list of :class:`PluginPage`,
  each ``(key, label, factory)``.
* ``factory(host_ctx)`` returns a ``QWidget`` to drop into sentinel-vision's
  stack, with a sidebar button labeled ``label``. ``host_ctx`` is duck-typed:
  Foldward uses only ``host_ctx.notify(title, text, level)`` and
  ``host_ctx.navigate(key)`` if present — both satisfied by sentinel-vision's
  ``AppContext``.

Foldward runs its *own* engine inside the host (sentinel-vision does not
provide it), so the pages behave identically to standalone; the host just lends
its window, tray and notifications.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class PluginPage:
    key: str
    label: str
    factory: Callable[[object], object]  # (host_ctx) -> QWidget


def register() -> list[PluginPage]:
    # Imported lazily so merely *discovering* the entry point is cheap and never
    # forces PySide6 to load unless the host actually builds the pages.
    from foldward.config import Settings
    from foldward.core import Foldward
    from foldward.gui.context import GuardContext
    from foldward.gui.pages import NAV
    from foldward.gui.workers import Bridge

    guard = Foldward(Settings.load())  # one engine shared by all hosted pages

    def _factory(cls):
        def build(host_ctx: object):
            notify = getattr(host_ctx, "notify", lambda *a, **k: None)
            navigate = getattr(host_ctx, "navigate", lambda *a, **k: None)
            ctx = GuardContext(guard, Bridge(), notify, navigate)
            page = cls(ctx)
            guard.alert_listeners.append(lambda t, x, lvl: notify(t, x, lvl))
            return page

        return build

    # The host skips any page whose key collides with one of its own built-ins
    # (sentinel-vision has overview/quarantine/settings), so namespace every key
    # with "ag_" and label it clearly so Foldward's pages are distinct in the
    # host's sidebar.
    def _label(nav_label: str) -> str:
        name = nav_label.strip().split(None, 1)[-1]  # drop the leading glyph
        return f"AG · {name}"

    # Prefer the host's ready-made descriptor when hosted (it is importable only
    # because sentinel-vision is the caller) so an isinstance check on its side
    # still passes; fall back to our own duck-typed descriptor otherwise. This is
    # not a dependency: the import lives inside register(), which only the host calls.
    descriptor = PluginPage
    try:
        from sentinel_vision.plugin_api import PluginPage as _HostDescriptor  # type: ignore

        descriptor = _HostDescriptor
    except Exception:
        pass

    return [descriptor(f"ag_{key}", _label(label), _factory(cls)) for key, label, cls in NAV]
