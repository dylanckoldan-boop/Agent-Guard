"""Mesh — the oversight spiderweb and the 'many doors' panel."""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout

from agent_guard.gui import theme
from agent_guard.gui.pages.base import Page
from agent_guard.gui.widgets import MeshWidget, card, label


def _legend_row(color: str, title: str, desc: str):
    row = QHBoxLayout()
    dot = label("●")
    dot.setStyleSheet(f"color:{color};font-size:15px;")
    dot.setFixedWidth(18)
    row.addWidget(dot)
    txt = label(f"<b>{title}</b> — {desc}")
    txt.setWordWrap(True)
    txt.setStyleSheet(f"color:{theme.MUTED};")
    row.addWidget(txt, 1)
    return row


class MeshPage(Page):
    title = "Mesh"
    subtitle = "the oversight web — agents on the rim, sentinels voting, consensus at the core"
    refresh_ms = 2000

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        row = QHBoxLayout()
        row.setSpacing(14)

        fig, fl = card(10)
        self.mesh = MeshWidget()
        fl.addWidget(self.mesh)
        row.addWidget(fig, 3)

        side, sl = card()
        sl.addWidget(label("Legend", obj="h2"))
        sl.addLayout(_legend_row(theme.CORE, "Consensus core", "decides; a flag contains only on quorum"))
        sl.addLayout(_legend_row(theme.SENTINEL, "Sentinel", "observes &amp; votes — identity, flow, conduct, tripwire"))
        sl.addLayout(_legend_row(theme.OK, "Healthy agent", "attested, within scope"))
        sl.addLayout(_legend_row(theme.WARN, "Flagged", "under review"))
        sl.addLayout(_legend_row(theme.DANGER, "Contained", "pacified, preserved"))
        self.mixnote = label("", obj="mono", wrap=True)
        self.mixnote.setStyleSheet(
            f"background:{theme.SURFACE_2};border:1px solid {theme.BORDER};border-radius:10px;"
            f"padding:11px;color:{theme.MUTED};font-size:11px;"
        )
        sl.addSpacing(6)
        sl.addWidget(self.mixnote)
        sl.addStretch(1)
        row.addWidget(side, 2)
        self.root.addLayout(row, 1)

    def refresh(self) -> None:
        snap = self.guard.snapshot()
        self.mesh.set_snapshot(snap.mesh)
        ratio = snap.mesh.mix_cover_ratio if snap.mesh else 0.0
        on = snap.mesh.mix_enabled if snap.mesh else False
        self.mixnote.setText(
            "Many-doors principle: the agents' own traffic on the rim stays fully observable — that is the net. "
            f"Only the oversight traffic (sentinel votes, containment commands) is mixed "
            f"[{'on' if on else 'off'}, cover {ratio*100:.0f}%], so a hijacked agent can't tell which sentinel "
            "flagged it or trace the core. Control plane hidden, data plane watched."
        )
