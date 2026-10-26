"""The Net — every agent process, mapped and scored, with the pacify ladder."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHBoxLayout, QHeaderView, QMenu, QMessageBox, QPushButton, QTableView

from agent_guard.gui import theme
from agent_guard.gui.pages.base import Page
from agent_guard.gui.widgets import RowTableModel, card, label


class NetPage(Page):
    title = "The Net"
    subtitle = "every agent process on this machine, mapped to its identity and scored on reach and behaviour"
    refresh_ms = 1800

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        c, cl = card()
        cl.addWidget(label("Watched agents", obj="h2"))
        self.model = RowTableModel(
            ["Agent", "PID", "Identity", "Reach", "Risk", "Why", "State"],
            color_for=lambda d: theme.STATE_COLORS.get(getattr(d, "state", "healthy")),
        )
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        cl.addWidget(self.table)

        bar = QHBoxLayout()
        self.b_scan = QPushButton("Run scan")
        self.b_scan.setObjectName("primary")
        self.b_throttle = QPushButton("Throttle")
        self.b_quar = QPushButton("Quarantine")
        self.b_revoke = QPushButton("Revoke")
        self.b_suspend = QPushButton("Suspend")
        self.b_suspend.setObjectName("danger")
        self.b_release = QPushButton("Release")
        for b in (self.b_scan, self.b_throttle, self.b_quar, self.b_revoke, self.b_suspend):
            bar.addWidget(b)
        bar.addStretch(1)
        bar.addWidget(self.b_release)
        cl.addLayout(bar)
        self.root.addWidget(c, 1)

        self.b_scan.clicked.connect(self.refresh)
        self.b_throttle.clicked.connect(lambda: self._pacify("throttle"))
        self.b_quar.clicked.connect(lambda: self._pacify("quarantine"))
        self.b_revoke.clicked.connect(lambda: self._pacify("revoke"))
        self.b_suspend.clicked.connect(lambda: self._pacify("suspend"))
        self.b_release.clicked.connect(self._release)

    def refresh(self) -> None:
        dets = self.guard.scan()
        rows = []
        for d in dets:
            hosts = len(d.proc.remote_hosts)
            ident = "sanctioned" if d.sanctioned else "unregistered"
            rows.append((d.label, d.pid, ident, f"{hosts} hosts", d.score, d.why, d.state))
        self.model.set_rows(rows, dets)

    def _selected(self):
        sm = self.table.selectionModel()
        if sm is None:
            return None
        idx = sm.selectedRows()
        if not idx:
            return None
        r = idx[0].row()
        return self.model.objects[r] if r < len(self.model.objects) else None

    def _pacify(self, rung: str) -> None:
        d = self._selected()
        if d is None:
            QMessageBox.information(self, "Pacify", "Select an agent first.")
            return
        if rung in ("suspend", "revoke") and self.guard.settings.report_only:
            if QMessageBox.question(
                self, "Confirm containment",
                f"{rung.capitalize()} {d.label} (pid {d.pid})?\n\nThis is reversible — the agent is preserved and can be released.",
            ) != QMessageBox.Yes:
                return
        self.guard.pacify(d, rung, auto=False)
        self.ctx.notify("Agent pacified", f"{d.label} contained → {rung}", "danger")
        self.refresh()

    def _release(self) -> None:
        d = self._selected()
        if d is None:
            return
        self.guard.release(d)
        self.ctx.notify("Agent released", f"{d.label} resumed", "info")
        self.refresh()

    def _menu(self, pos) -> None:
        if self._selected() is None:
            return
        m = QMenu(self)
        m.addAction("Throttle", lambda: self._pacify("throttle"))
        m.addAction("Quarantine binary", lambda: self._pacify("quarantine"))
        m.addAction("Revoke credential", lambda: self._pacify("revoke"))
        m.addAction("Suspend (freeze)", lambda: self._pacify("suspend"))
        m.addSeparator()
        m.addAction("Release", self._release)
        m.exec(self.table.viewport().mapToGlobal(pos))
