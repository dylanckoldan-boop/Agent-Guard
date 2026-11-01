"""Settings — containment authority, oversight, partner status."""

from __future__ import annotations

from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout, QPushButton

from foldward import __version__
from foldward.gui import theme
from foldward.gui.pages.base import Page
from foldward.gui.widgets import card, label


class SettingsPage(Page):
    title = "Settings"
    subtitle = "containment authority, oversight, partners"
    refresh_ms = 8000

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        s = self.guard.settings
        row = QHBoxLayout()
        row.setSpacing(14)

        left, ll = card()
        ll.addWidget(label("Containment authority", obj="h2"))
        self.cb_report = QCheckBox("Report-only by default (you click to act)")
        self.cb_report.setChecked(s.report_only)
        self.cb_decoy = QCheckBox("Auto-contain on a decoy touch (the zero-false-positive signal)")
        self.cb_decoy.setChecked(s.auto_contain_on_decoy)
        ll.addWidget(self.cb_report)
        ll.addWidget(self.cb_decoy)
        ceil = QHBoxLayout()
        ceil.addWidget(label("Auto-contain ceiling", obj="muted"))
        self.combo = QComboBox()
        self.combo.addItems(["throttle", "quarantine", "revoke", "suspend", "terminate"])
        self.combo.setCurrentText(s.auto_contain_max_rung)
        ceil.addWidget(self.combo)
        ceil.addStretch(1)
        ll.addLayout(ceil)
        ll.addStretch(1)
        row.addWidget(left, 1)

        right, rl = card()
        rl.addWidget(label("Oversight & partners", obj="h2"))
        self.cb_mix = QCheckBox("Mix oversight traffic (many-doors resistance, control plane only)")
        self.cb_mix.setChecked(s.mix_oversight_traffic)
        rl.addWidget(self.cb_mix)
        p = self.guard.partners
        rl.addWidget(self._partner("sentinel-vision", "hardened vault · protected log", p.sentinel_vision))
        rl.addWidget(label(f"sentinel-vision: {p.sentinel_vision_how}", obj="muted", wrap=True))
        rl.addWidget(self._partner("cryptomigrate", "detected only · crypto scan and notary planned", p.cryptomigrate))
        rl.addWidget(label("Both optional. Foldward runs fully standalone with neither.", obj="muted", wrap=True))

        rl.addSpacing(8)
        rl.addWidget(label("Version & updates", obj="h2"))
        up = QHBoxLayout()
        up.addWidget(label(f"Foldward {__version__}"))
        self.b_update = QPushButton("Check for updates")
        self.b_update.clicked.connect(self._check_updates)
        up.addWidget(self.b_update)
        up.addStretch(1)
        rl.addLayout(up)
        self.lbl_update = label("", wrap=True)
        self.lbl_update.setStyleSheet(f"color:{theme.MUTED};font-size:12px;")
        rl.addWidget(self.lbl_update)

        rl.addStretch(1)
        row.addWidget(right, 1)
        self.root.addLayout(row, 1)

        for w in (self.cb_report, self.cb_decoy, self.cb_mix):
            w.toggled.connect(self._save)
        self.combo.currentTextChanged.connect(self._save)

    def _partner(self, name: str, desc: str, present: bool):
        c = label(
            f"<b>{name}</b> — {desc}<br><span style='color:{theme.OK if present else theme.FAINT};"
            f"font-family:{theme.MONO};font-size:10px'>{'connected' if present else 'not installed'}</span>"
        )
        c.setStyleSheet(f"background:{theme.SURFACE_2};border:1px solid {theme.BORDER};border-radius:10px;padding:11px;")
        c.setWordWrap(True)
        return c

    def _check_updates(self) -> None:
        # Opt-in and explicit: contacts GitHub only when this button is clicked,
        # and only to compare version numbers (see foldward.update).
        self.lbl_update.setText("Checking GitHub for a newer release…")
        self.b_update.repaint()
        from foldward.update import check_for_update

        self.lbl_update.setText(check_for_update().detail)

    def _save(self, *_) -> None:
        s = self.guard.settings
        s.report_only = self.cb_report.isChecked()
        s.auto_contain_on_decoy = self.cb_decoy.isChecked()
        s.mix_oversight_traffic = self.cb_mix.isChecked()
        s.auto_contain_max_rung = self.combo.currentText()
        self.guard.mix.enabled = s.mix_oversight_traffic
        s.save()
