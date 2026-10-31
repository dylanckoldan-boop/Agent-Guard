"""Page registry. Each entry is (key, sidebar label, Page subclass)."""

from __future__ import annotations

from foldward.gui.pages.alignment import AlignmentPage
from foldward.gui.pages.base import Page
from foldward.gui.pages.dashboard import DashboardPage
from foldward.gui.pages.detections import DetectionsPage
from foldward.gui.pages.mesh import MeshPage
from foldward.gui.pages.net import NetPage
from foldward.gui.pages.quarantine import QuarantinePage
from foldward.gui.pages.settings import SettingsPage

NAV = [
    ("overview", "◉  Overview", DashboardPage),
    ("net", "⊹  The Net", NetPage),
    ("detections", "!  Detections", DetectionsPage),
    ("alignment", "◈  Alignment", AlignmentPage),
    ("mesh", "✸  Mesh", MeshPage),
    ("quarantine", "⊘  Quarantine", QuarantinePage),
    ("settings", "⚙  Settings", SettingsPage),
]

__all__ = [
    "NAV",
    "AlignmentPage",
    "DashboardPage",
    "DetectionsPage",
    "MeshPage",
    "NetPage",
    "Page",
    "QuarantinePage",
    "SettingsPage",
]
