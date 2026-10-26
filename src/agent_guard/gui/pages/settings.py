"""Settings — containment authority, oversight, partner status."""

from __future__ import annotations

from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout, QVBoxLayout

from agent_guard.gui import theme
from agent_guard.gui.pages.base import Page
from agent_guard.gui.widgets import card, label


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
        rl.addWidget(label("Oversight &amp; partners", obj="h2"))
        self.cb_mix = QCheckBox("Mix oversight traffic (many-doors resistance, control plane only)")
        self.cb_mix.setChecked(s.mix_oversight_traffic)
        rl.addWidget(self.cb_mix)
        p = self.guard.partners
        rl.addWidget(self._partner("sentinel-vision", "scan · firewall · hardened vault · the Wall", p.sentinel_vision))
        rl.addWidget(self._partner("cryptomigrate", "crypto-posture scan · PQ-signed attestation", p.cryptomigrate))
        rl.addWidget(label("Both optional. Agent Guard runs fully standalone with neither.", obj="muted", wrap=True))
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

    def _save(self, *_) -> None:
        s = self.guard.settings
        s.report_only = self.cb_report.isChecked()
        s.auto_contain_on_decoy = self.cb_decoy.isChecked()
        s.mix_oversight_traffic = self.cb_mix.isChecked()
        s.auto_contain_max_rung = self.combo.currentText()
        self.guard.mix.enabled = s.mix_oversight_traffic
        s.save()
