"""Visual identity — a deep-ink control-room palette with a luminous teal accent.

Deliberately the same palette as sentinel-vision, so Agent Guard's pages look
native whether they run in Agent Guard's own window or, under Route B, hosted
inside sentinel-vision's shell.
"""

from __future__ import annotations

from PySide6.QtGui import QColor

BG = "#0b1016"
SURFACE = "#111821"
SURFACE_2 = "#16202b"
SURFACE_3 = "#1b2735"
BORDER = "#223041"
BORDER_2 = "#2b3b4e"
TEXT = "#e6edf3"
MUTED = "#8b9bb0"
FAINT = "#5f7084"
ACCENT = "#2ee6c5"
ACCENT_DIM = "#1a8f7c"
OK = "#3ddc84"
WARN = "#ffb547"
DANGER = "#ff5c6c"
CRIT = "#ff2d55"
CORE = "#a996f7"      # consensus core
SENTINEL = "#8b9bb0"  # sentinel nodes

# risk/state → color
STATE_COLORS = {"healthy": OK, "flagged": WARN, "contained": DANGER}

MONO = "'JetBrains Mono','Cascadia Mono','SF Mono',Menlo,Consolas,monospace"
SANS = "'Inter','Segoe UI Variable','Segoe UI','SF Pro Text','Helvetica Neue',Arial,sans-serif"


def qcolor(hex_: str, alpha: int = 255) -> QColor:
    c = QColor(hex_)
    c.setAlpha(alpha)
    return c


def risk_color(score: int) -> str:
    if score >= 85:
        return DANGER
    if score >= 60:
        return WARN
    if score >= 30:
        return "#7fb3ff"
    return OK


STYLESHEET = f"""
* {{ font-family: {SANS}; font-size: 13px; color: {TEXT}; }}
QMainWindow, QWidget#root, QWidget#page {{ background: {BG}; }}
QToolTip {{ background: {SURFACE_2}; color: {TEXT}; border: 1px solid {BORDER}; padding: 6px; }}

QWidget#sidebar {{ background: #0e151d; border-right: 1px solid {BORDER}; }}
QLabel#brand {{ font-size: 14px; font-weight: 700; letter-spacing: 1px; }}
QLabel#brandSub {{ color: {FAINT}; font-size: 10px; }}
QPushButton#nav {{
    text-align: left; padding: 9px 12px; border: none; border-radius: 9px;
    color: {MUTED}; background: transparent; font-size: 13px;
}}
QPushButton#nav:hover {{ background: {SURFACE_2}; color: {TEXT}; }}
QPushButton#nav:checked {{ background: {SURFACE_2}; color: {ACCENT}; font-weight: 600; border-left: 2px solid {ACCENT}; }}

QLabel#h1 {{ font-size: 20px; font-weight: 600; }}
QLabel#h2 {{ font-size: 13px; font-weight: 600; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#mono {{ font-family: {MONO}; color: {MUTED}; font-size: 12px; }}

QFrame#card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 12px; }}
QLabel#statValue {{ font-size: 23px; font-weight: 600; font-family: {MONO}; }}
QLabel#statLabel {{ color: {MUTED}; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; }}
QLabel#statSub {{ color: {FAINT}; font-size: 10px; }}

QPushButton {{
    background: {SURFACE_2}; border: 1px solid {BORDER_2}; border-radius: 8px; padding: 7px 14px; font-weight: 600;
}}
QPushButton:hover {{ border-color: {ACCENT_DIM}; }}
QPushButton:pressed {{ background: {BORDER}; }}
QPushButton:disabled {{ color: {MUTED}; border-color: {SURFACE_2}; }}
QPushButton#primary {{ background: {ACCENT}; color: #04211c; border: none; }}
QPushButton#primary:hover {{ background: #5cf0d6; }}
QPushButton#danger {{ background: transparent; color: {DANGER}; border: 1px solid {DANGER}; }}
QPushButton#danger:hover {{ background: rgba(255,92,108,0.12); }}

QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextEdit {{
    background: {SURFACE_2}; border: 1px solid {BORDER}; border-radius: 8px; padding: 6px 8px;
    selection-background-color: {ACCENT_DIM};
}}
QLineEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px; border: 1px solid {BORDER_2}; background: {SURFACE_2}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

QTableView {{
    background: {SURFACE}; alternate-background-color: #131c26; border: 1px solid {BORDER}; border-radius: 10px;
    gridline-color: transparent; selection-background-color: #1d3340; selection-color: {TEXT};
}}
QHeaderView::section {{
    background: {SURFACE}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
    padding: 8px 6px; font-size: 10px; font-weight: 600; text-transform: uppercase;
}}
QTableView::item {{ padding: 4px 6px; border: none; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {BORDER_2}; border-radius: 4px; min-height: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollArea {{ border: none; background: transparent; }}
QMenu {{ background: {SURFACE}; border: 1px solid {BORDER}; padding: 4px; }}
QMenu::item {{ padding: 6px 18px; border-radius: 4px; }}
QMenu::item:selected {{ background: {SURFACE_2}; }}
"""
