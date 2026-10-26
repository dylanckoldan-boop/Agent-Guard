"""Base page: a titled QWidget with a refresh hook, driven by a GuardContext."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from agent_guard.gui import theme
from agent_guard.gui.context import GuardContext


class Page(QWidget):
    title = ""
    subtitle = ""
    refresh_ms = 2500

    def __init__(self, ctx: GuardContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.setObjectName("page")
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(26, 22, 26, 22)
        self.root.setSpacing(14)
        h1 = QLabel(self.title)
        h1.setObjectName("h1")
        self.root.addWidget(h1)
        if self.subtitle:
            sub = QLabel(self.subtitle)
            sub.setObjectName("muted")
            sub.setWordWrap(True)
            self.root.addWidget(sub)

    @property
    def guard(self):
        return self.ctx.guard

    def refresh(self) -> None:
        """Called when the page becomes visible and periodically while visible."""

    def action(self, name: str) -> None:
        """Optional deep-link action (e.g. navigate('net', 'scan'))."""
