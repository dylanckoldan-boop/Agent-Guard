"""Detections — the pacify ladder for the latest containment, and the signed audit trail."""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout

from agent_guard.gui import theme
from agent_guard.gui.pages.base import Page
from agent_guard.gui.widgets import card, label

RUNGS = ["Throttle", "Quarantine", "Revoke", "Suspend", "Terminate"]
RUNG_DESC = ["CPU idle", "binary → vault", "signed", "frozen · resumable", "held for human"]


class DetectionsPage(Page):
    title = "Detections"
    subtitle = "what the net caught, and what happened next"
    refresh_ms = 2500

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        row = QHBoxLayout()
        row.setSpacing(14)

        left, ll = card()
        ll.addWidget(label("Pacify ladder", obj="h2"))
        self.ladder_caption = label("No containment yet.", obj="muted", wrap=True)
        ll.addWidget(self.ladder_caption)
        self.rungs_row = QHBoxLayout()
        self.rungs_row.setSpacing(7)
        self._rung_widgets = []
        for name, desc in zip(RUNGS, RUNG_DESC):
            w = label(f"<div style='font-weight:600'>{name}</div>"
                      f"<div style='color:{theme.FAINT};font-size:9px'>{desc}</div>")
            w.setStyleSheet(
                f"background:{theme.SURFACE_2};border:1px solid {theme.BORDER};border-radius:9px;padding:9px 4px;"
            )
            w.setWordWrap(True)
            self._rung_widgets.append(w)
            self.rungs_row.addWidget(w, 1)
        ll.addLayout(self.rungs_row)
        self.ladder_note = label("", obj="muted", wrap=True)
        ll.addWidget(self.ladder_note)
        ll.addStretch(1)
        row.addWidget(left, 1)

        right, rl = card()
        rl.addWidget(label("Signed audit trail", obj="h2"))
        self.trail = QVBoxLayout()
        self.trail.setSpacing(6)
        rl.addLayout(self.trail)
        self.head = label("", obj="mono", wrap=True)
        self.head.setStyleSheet(f"color:{theme.FAINT};font-size:10px;")
        rl.addSpacing(6)
        rl.addWidget(self.head)
        rl.addStretch(1)
        row.addWidget(right, 1)
        self.root.addLayout(row, 1)

    def refresh(self) -> None:
        g = self.guard
        history = g.response.history
        reached = 0
        if history:
            last = history[-1]
            reached = {"THROTTLE": 1, "QUARANTINE": 2, "REVOKE": 3, "SUSPEND": 4, "TERMINATE": 5}.get(last["up_to"], 0)
            self.ladder_caption.setText(
                f"{last['agent']} — {'auto' if last.get('auto') else 'operator'}-contained to {last['up_to'].lower()}."
            )
            self.ladder_note.setText(
                f"Stopped at {last['up_to'].lower()} — preserved intact. Terminate requires operator sign-off. "
                "Release reverses a suspension if cleared."
            )
        else:
            self.ladder_caption.setText("No containment yet. The net is watching.")
            self.ladder_note.setText("")
        for i, w in enumerate(self._rung_widgets):
            if i + 1 < reached:
                w.setStyleSheet(f"background:{theme.SURFACE_2};border:1px solid {theme.BORDER};border-radius:9px;padding:9px 4px;opacity:0.5;")
            elif i + 1 == reached:
                w.setStyleSheet(f"background:rgba(255,92,108,0.12);border:1px solid {theme.DANGER};border-radius:9px;padding:9px 4px;")
            else:
                w.setStyleSheet(f"background:{theme.SURFACE_2};border:1px solid {theme.BORDER};border-radius:9px;padding:9px 4px;")

        while self.trail.count():
            item = self.trail.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
                w.deleteLater()
        for e in g.audit.tail(10)[::-1]:
            lvl = theme.DANGER if ("tripwire" in e.event or "suspend" in e.event) else (
                theme.WARN if "pacify" in e.event or "flagged" in e.event else theme.ACCENT)
            w = label(f"#{e.seq}  {e.event}")
            w.setStyleSheet(f"background:{theme.SURFACE_2};border-left:3px solid {lvl};border-radius:8px;padding:8px 10px;font-size:11.5px;")
            self.trail.addWidget(w)
        ok, _ = g.audit.verify()
        self.head.setText(f"head: {g.audit.head[:16]}… · {g.signer.scheme} · chain {'intact' if ok else 'BROKEN'}")
