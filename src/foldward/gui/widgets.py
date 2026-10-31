"""Reusable widgets: cards, chips, the shield glyph, the mesh spiderweb, a table model."""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from foldward.gui import theme


# ----------------------------------------------------------------------- shield icon
def _shield_path(rect: QRectF) -> QPainterPath:
    x, y, w, h = rect.x(), rect.y(), rect.width(), rect.height()
    p = QPainterPath()
    p.moveTo(x + w / 2, y)
    p.lineTo(x + w, y + h * 0.18)
    p.cubicTo(x + w, y + h * 0.6, x + w * 0.82, y + h * 0.86, x + w / 2, y + h)
    p.cubicTo(x + w * 0.18, y + h * 0.86, x, y + h * 0.6, x, y + h * 0.18)
    p.closeSubpath()
    return p


def paint_shield(painter: QPainter, rect: QRectF, color: QColor, glyph: str = "eye") -> None:
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(QPen(color, max(1.5, rect.width() * 0.05)))
    painter.setBrush(Qt.NoBrush)
    painter.drawPath(_shield_path(rect))
    cx, cy, s = rect.center().x(), rect.y() + rect.height() * 0.46, rect.width()
    painter.setPen(QPen(color, max(1.6, s * 0.06), Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    if glyph == "check":
        path = QPainterPath()
        path.moveTo(cx - s * 0.18, cy)
        path.lineTo(cx - s * 0.03, cy + s * 0.15)
        path.lineTo(cx + s * 0.22, cy - s * 0.15)
        painter.drawPath(path)
    else:  # eye + net
        painter.setBrush(color)
        painter.drawEllipse(QPointF(cx, cy), s * 0.06, s * 0.06)
        painter.setBrush(Qt.NoBrush)
        painter.drawLine(QPointF(cx, cy + s * 0.08), QPointF(cx, cy + s * 0.28))


def app_icon(color: str = theme.ACCENT) -> QIcon:
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        m = size * 0.08
        paint_shield(p, QRectF(m, m, size - 2 * m, size - 2 * m), QColor(color), "eye")
        p.end()
        icon.addPixmap(pm)
    return icon


# ----------------------------------------------------------------------- layout helpers
def card(padding: int = 16) -> tuple[QFrame, QVBoxLayout]:
    f = QFrame()
    f.setObjectName("card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(padding, padding, padding, padding)
    lay.setSpacing(8)
    return f, lay


def label(text: str = "", obj: str | None = None, wrap: bool = False) -> QLabel:
    lbl = QLabel(text)
    if obj:
        lbl.setObjectName(obj)
    lbl.setWordWrap(wrap)
    return lbl


def chip(text: str, color: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color:{color}; background:{_tint(color)}; border-radius:9px; padding:2px 9px;"
        f"font-family:{theme.MONO}; font-size:10px; font-weight:600;"
    )
    lbl.setAlignment(Qt.AlignCenter)
    return lbl


def _tint(hex_: str) -> str:
    c = QColor(hex_)
    return f"rgba({c.red()},{c.green()},{c.blue()},0.13)"


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "—", accent: str = theme.TEXT) -> None:
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(15, 13, 15, 13)
        lay.setSpacing(3)
        self._t = QLabel(title.upper())
        self._t.setObjectName("statLabel")
        self._v = QLabel(value)
        self._v.setObjectName("statValue")
        self._s = QLabel("")
        self._s.setObjectName("statSub")
        for w in (self._t, self._v, self._s):
            lay.addWidget(w)
        self.set_accent(accent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set(self, value: str, sub: str = "", accent: str | None = None) -> None:
        self._v.setText(value)
        self._s.setText(sub)
        if accent:
            self.set_accent(accent)

    def set_accent(self, color: str) -> None:
        self._v.setStyleSheet(f"color:{color}; font-size:23px; font-weight:600; font-family:{theme.MONO};")


# ----------------------------------------------------------------------- mesh widget
class MeshWidget(QWidget):
    """The spiderweb: consensus core at center, a ring of sentinels that observe
    and vote, agents on the outer rim colored by state, and a dashed line from
    the core to any contained agent."""

    def __init__(self) -> None:
        super().__init__()
        self._snap = None
        self.setMinimumHeight(360)

    def set_snapshot(self, snap) -> None:
        self._snap = snap
        self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        R = min(w, h) / 2 - 36
        mono = QFont(self.font())
        mono.setFamilies(["JetBrains Mono", "Menlo", "Consolas", "monospace"])
        mono.setPointSizeF(8.0)
        p.setFont(mono)

        # rings
        p.setPen(QPen(QColor(theme.BORDER), 1))
        for frac in (0.3, 0.56, 0.82, 1.0):
            p.drawEllipse(QPointF(cx, cy), R * frac, R * frac)

        snap = self._snap
        sentinels = (snap.sentinels if snap else []) or [{"name": n} for n in ("admission", "flow", "conduct", "tripwire")]
        agents = (snap.agents if snap else []) or []

        # spokes + sentinel ring (inner, 0.56R) + agents (outer rim, R)
        n_spokes = max(len(agents), 6)
        p.setPen(QPen(QColor("#1c2836"), 1))
        for i in range(n_spokes):
            a = -math.pi / 2 + i * 2 * math.pi / n_spokes
            p.drawLine(QPointF(cx, cy), QPointF(cx + R * math.cos(a), cy + R * math.sin(a)))

        # sentinels
        for i, s in enumerate(sentinels):
            a = -math.pi / 2 + i * 2 * math.pi / max(len(sentinels), 1)
            sx, sy = cx + R * 0.56 * math.cos(a), cy + R * 0.56 * math.sin(a)
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(theme.SENTINEL))
            p.drawEllipse(QPointF(sx, sy), 6, 6)
            p.setPen(QColor(theme.MUTED))
            p.drawText(QRectF(sx - 40, sy - 22, 80, 14), Qt.AlignCenter, s.get("name", ""))

        # agents on the rim
        for i, ag in enumerate(agents):
            a = -math.pi / 2 + i * 2 * math.pi / max(len(agents), 1)
            ax, ay = cx + R * math.cos(a), cy + R * math.sin(a)
            col = QColor(theme.STATE_COLORS.get(ag.get("state", "healthy"), theme.OK))
            if ag.get("state") == "contained":
                p.setPen(QPen(col, 2))
                p.setBrush(Qt.NoBrush)
                p.drawLine(QPointF(cx + 27 * math.cos(a), cy + 27 * math.sin(a)),
                           QPointF(ax - 18 * math.cos(a), ay - 18 * math.sin(a)))
                p.setPen(QPen(col, 2))
                p.drawEllipse(QPointF(ax, ay), 15, 15)
            p.setPen(Qt.NoPen)
            p.setBrush(col)
            p.drawEllipse(QPointF(ax, ay), 10, 10)

        # core
        core_state = snap.core_state if snap else "nominal"
        p.setPen(QPen(QColor(theme.CORE), 1.6))
        p.setBrush(QColor("#19122e"))
        p.drawEllipse(QPointF(cx, cy), 26, 26)
        p.setPen(QColor(theme.CORE))
        p.drawText(QRectF(cx - 40, cy - 8, 80, 16), Qt.AlignCenter, core_state)


# ----------------------------------------------------------------------- table model
class RowTableModel(QAbstractTableModel):
    def __init__(
        self,
        headers: Sequence[str],
        color_for: Callable[[object], str | None] | None = None,
    ) -> None:
        super().__init__()
        self.headers = list(headers)
        self.rows: list[tuple] = []
        self.objects: list[object] = []
        self.color_for = color_for

    def set_rows(self, rows: list[tuple], objects: list[object] | None = None) -> None:
        self.beginResetModel()
        self.rows = rows
        self.objects = objects if objects is not None else rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        r, c = index.row(), index.column()
        if role == Qt.DisplayRole:
            v = self.rows[r][c]
            return "" if v is None else str(v)
        if role == Qt.ForegroundRole and self.color_for:
            col = self.color_for(self.objects[r])
            if col:
                return QColor(col)
        if role == Qt.UserRole:
            return self.objects[r]
        return None

    def headerData(self, section: int, orientation, role: int = Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None


def hbox(*widgets, spacing: int = 10) -> QHBoxLayout:
    lay = QHBoxLayout()
    lay.setSpacing(spacing)
    for wdg in widgets:
        if wdg is None:
            lay.addStretch(1)
        elif isinstance(wdg, QWidget):
            lay.addWidget(wdg)
        else:
            lay.addLayout(wdg)
    return lay
