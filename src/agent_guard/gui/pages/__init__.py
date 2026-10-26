"""Page registry. Each entry is (key, sidebar label, Page subclass)."""

from __future__ import annotations

from agent_guard.gui.pages.base import Page
from agent_guard.gui.pages.dashboard import DashboardPage
from agent_guard.gui.pages.detections import DetectionsPage
from agent_guard.gui.pages.mesh import MeshPage
from agent_guard.gui.pages.net import NetPage
from agent_guard.gui.pages.quarantine import QuarantinePage
from agent_guard.gui.pages.settings import SettingsPage

NAV = [
    ("overview", "◉  Overview", DashboardPage),
    ("net", "⊹  The Net", NetPage),
    ("detections", "!  Detections", DetectionsPage),
    ("mesh", "✸  Mesh", MeshPage),
    ("quarantine", "⊘  Quarantine", QuarantinePage),
    ("settings", "⚙  Settings", SettingsPage),
]

__all__ = [
    "NAV", "Page", "DashboardPage", "NetPage", "DetectionsPage",
    "MeshPage", "QuarantinePage", "SettingsPage",
]
