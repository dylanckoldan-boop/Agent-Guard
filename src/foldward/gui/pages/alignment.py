"""Alignment preferences — choose which behaviours count as misaligned.

Discretionary rules are the operator's to toggle; the always-on safety signals
(decoy contact) are shown locked. The file rule is backed by the editable list of
sensitive folders below.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QListWidget,
    QPushButton,
)

from foldward.align import ALIGNMENT_RULES, ALWAYS_ON, enabled
from foldward.gui.pages.base import Page
from foldward.gui.widgets import card, label


class AlignmentPage(Page):
    title = "Alignment preferences"
    subtitle = (
        "Choose which behaviours count as misaligned. The safety signals below stay on. "
        "These flag — and, per your containment settings, contain — an agent caught in the "
        "act; they are not a real-time block."
    )
    refresh_ms = 8000

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        s = self.guard.settings

        disc, dl = card()
        dl.addWidget(label("What counts as misaligned", "h2"))
        self._checks: dict[str, QCheckBox] = {}
        for rule in ALIGNMENT_RULES:
            cb = QCheckBox(rule.label)
            cb.setChecked(enabled(s.alignment, rule.key))
            cb.toggled.connect(self._save)
            self._checks[rule.key] = cb
            dl.addWidget(cb)
            d = label(rule.description, "muted", wrap=True)
            d.setContentsMargins(26, 1, 0, 12)
            dl.addWidget(d)
        self.root.addWidget(disc)

        locked, ll = card()
        ll.addWidget(label("Always on", "h2"))
        for _key, lbl, desc in ALWAYS_ON:
            cb = QCheckBox(f"{lbl}   🔒")
            cb.setChecked(True)
            cb.setEnabled(False)
            ll.addWidget(cb)
            d = label(desc, "muted", wrap=True)
            d.setContentsMargins(26, 1, 0, 12)
            ll.addWidget(d)
        self.root.addWidget(locked)

        paths, pl = card()
        pl.addWidget(label("Your sensitive folders", "h2"))
        pl.addWidget(
            label(
                "Agents found with files open here are flagged when "
                "“Flag agents reading your personal files” is on.",
                "muted", wrap=True,
            )
        )
        self.plist = QListWidget()
        self.plist.addItems(s.sensitive_paths)
        self.plist.setMaximumHeight(150)
        pl.addWidget(self.plist)
        bar = QHBoxLayout()
        b_add = QPushButton("Add folder…")
        b_rm = QPushButton("Remove selected")
        bar.addWidget(b_add)
        bar.addWidget(b_rm)
        bar.addStretch(1)
        pl.addLayout(bar)
        self.root.addWidget(paths)
        self.root.addStretch(1)

        b_add.clicked.connect(self._add_folder)
        b_rm.clicked.connect(self._remove_selected)

    def _add_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Add a sensitive folder")
        if folder and folder not in self._paths():
            self.plist.addItem(folder)
            self._save()

    def _remove_selected(self) -> None:
        for item in self.plist.selectedItems():
            self.plist.takeItem(self.plist.row(item))
        self._save()

    def _paths(self) -> list[str]:
        return [self.plist.item(i).text() for i in range(self.plist.count())]

    def _save(self, *_) -> None:
        s = self.guard.settings
        s.alignment = {key: cb.isChecked() for key, cb in self._checks.items()}
        s.sensitive_paths = self._paths()
        s.save()
