"""Quarantine — neutralized agent binaries, encrypted and preserved."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QPushButton,
    QTableView,
)

from agent_guard.gui.pages.base import Page
from agent_guard.gui.widgets import RowTableModel, card, label


class QuarantinePage(Page):
    title = "Quarantine"
    subtitle = "neutralized agent binaries, encrypted (AES-256-GCM) with hash-verified restore"
    refresh_ms = 4000

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        c, cl = card()
        cl.addWidget(label("Encrypted store", obj="h2"))
        self.model = RowTableModel(["ID", "Origin", "Agent", "Reason", "When"])
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        cl.addWidget(self.table)

        bar = QHBoxLayout()
        bar.addStretch(1)
        self.b_restore = QPushButton("Restore selected…")
        bar.addWidget(self.b_restore)
        cl.addLayout(bar)
        note = label(
            "With sentinel-vision connected, binaries go to its hardened, service-protected vault with rollback "
            "(Route B). Standalone, Agent Guard keeps its own AES-256-GCM store. Restores verify the original SHA-256.",
            obj="muted", wrap=True,
        )
        cl.addWidget(note)
        self.root.addWidget(c, 1)
        self.b_restore.clicked.connect(self._restore)

    def refresh(self) -> None:
        items = self.guard.quarantine.list()
        from datetime import datetime

        rows = [
            (i.item_id, i.original_path, i.agent_id, i.reason, datetime.fromtimestamp(i.at).strftime("%Y-%m-%d %H:%M"))
            for i in items
        ]
        self.model.set_rows(rows, items)

    def _restore(self) -> None:
        sm = self.table.selectionModel()
        if sm is None or not sm.selectedRows():
            QMessageBox.information(self, "Restore", "Select a quarantined item first.")
            return
        item = self.model.objects[sm.selectedRows()[0].row()]
        dest = QFileDialog.getExistingDirectory(self, "Restore to folder")
        if not dest:
            return
        try:
            path = self.guard.quarantine.restore(item.item_id, dest)
            QMessageBox.information(self, "Restored", f"Restored to {path}")
        except Exception as exc:
            QMessageBox.warning(self, "Restore failed", str(exc))
