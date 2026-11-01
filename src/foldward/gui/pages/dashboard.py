"""Overview — the landing screen: status hero, stat row, compact net, detections."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QVBoxLayout

from foldward.gui import theme
from foldward.gui.pages.base import Page
from foldward.gui.widgets import StatCard, card, label


class DashboardPage(Page):
    title = "Overview"
    subtitle = "agents under watch"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)

        hero, hl = card(18)
        row = QHBoxLayout()
        self.hero_title = label("Net is holding", obj="h2")
        self.hero_title.setStyleSheet("font-size:16px;font-weight:600;")
        self.hero_sub = label("", obj="muted", wrap=True)
        col = QVBoxLayout()
        col.addWidget(self.hero_title)
        col.addWidget(self.hero_sub)
        row.addLayout(col, 1)
        self.hero_meta = label("", obj="mono")
        self.hero_meta.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        row.addWidget(self.hero_meta)
        hl.addLayout(row)
        self.root.addWidget(hero)

        grid = QGridLayout()
        grid.setSpacing(10)
        self.c_agents = StatCard("Agents")
        self.c_flagged = StatCard("Flagged")
        self.c_contained = StatCard("Contained")
        self.c_revoked = StatCard("Revoked")
        self.c_trips = StatCard("Tripwires")
        self.c_audit = StatCard("Audit")
        for i, c in enumerate((self.c_agents, self.c_flagged, self.c_contained, self.c_revoked, self.c_trips, self.c_audit)):
            grid.addWidget(c, 0, i)
        self.root.addLayout(grid)

        feed_card, fl = card()
        fl.addWidget(label("Recent detections", obj="h2"))
        self.feed = QVBoxLayout()
        self.feed.setSpacing(7)
        fl.addLayout(self.feed)
        self.root.addWidget(feed_card, 1)

    def refresh(self) -> None:
        snap = self.guard.snapshot()
        healthy = snap.healthy
        self.hero_title.setText("Net is holding" if snap.contained or snap.flagged else "All clear")
        text = (
            f"{snap.contained} pacified and preserved · {snap.flagged} flagged for review · "
            f"{healthy} healthy · all containment reversible"
        )
        if snap.warnings:  # start-up problems the operator must see (AG-A09, AG-N04, AG-N05)
            text += "\n\n" + "\n".join(f"⚠ {w}" for w in snap.warnings)
        self.hero_sub.setText(text)
        ok = "intact" if snap.audit_ok else "BROKEN"
        self.hero_meta.setText(
            f"consensus core: {snap.mesh.core_state if snap.mesh else 'nominal'}\n"
            f"audit: {snap.audit_len} entries, {ok}\nrevocations: {snap.revoked} signed"
        )
        self.c_agents.set(str(snap.total_agents), "under watch")
        self.c_flagged.set(str(snap.flagged), "need review", theme.WARN if snap.flagged else theme.TEXT)
        self.c_contained.set(str(snap.contained), "contained", theme.DANGER if snap.contained else theme.TEXT)
        self.c_revoked.set(str(snap.revoked), "signed")
        self.c_trips.set(str(snap.trips), "decoy touched", theme.DANGER if snap.trips else theme.TEXT)
        self.c_audit.set(str(snap.audit_len), "chain " + ("intact" if snap.audit_ok else "broken"),
                         theme.OK if snap.audit_ok else theme.DANGER)

        while self.feed.count():
            item = self.feed.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)  # detach now, not deferred, so no ghost renders before deleteLater
                w.deleteLater()
        events = self.guard.audit.tail(8)[::-1]
        if not events:
            self.feed.addWidget(label("No activity yet. The net is watching.", obj="muted"))
        for e in events:
            lvl = theme.DANGER if "tripwire" in e.event or "suspend" in e.event or "terminate" in e.event else (
                theme.WARN if "flagged" in e.event or "pacify" in e.event else theme.ACCENT)
            w = QLabel(f"#{e.seq}  {e.event}  {self._brief(e.data)}")
            w.setStyleSheet(
                f"background:{theme.SURFACE_2};border-left:3px solid {lvl};border-radius:9px;"
                f"padding:9px 11px;font-size:12px;"
            )
            w.setWordWrap(True)
            self.feed.addWidget(w)
        self.feed.addStretch(1)  # stack items at the top instead of distributing the gap

    @staticmethod
    def _brief(data: dict) -> str:
        bits = []
        for k in ("agent", "pid", "why", "reason", "detail", "score"):
            if k in data:
                bits.append(f"{k}={data[k]}")
        return "  ".join(bits[:3])
