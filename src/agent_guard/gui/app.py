"""Standalone main window, system tray, and the application entry point."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from agent_guard import APP_NAME, __version__
from agent_guard.config import Settings
from agent_guard.core import AgentGuard
from agent_guard.gui import theme
from agent_guard.gui.context import GuardContext
from agent_guard.gui.pages import NAV
from agent_guard.gui.widgets import app_icon
from agent_guard.gui.workers import Bridge


class MainWindow(QMainWindow):
    def __init__(self, guard: AgentGuard) -> None:
        super().__init__()
        self.guard = guard
        self.bridge = Bridge(self)  # parented, so Qt tears it down with the window tree
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(app_icon())
        self.resize(1240, 820)
        self.setMinimumSize(980, 640)
        self._quitting = False
        self._stopped = False

        root = QWidget()
        root.setObjectName("root")
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        self.setCentralWidget(root)

        # sidebar
        side = QWidget()
        side.setObjectName("sidebar")
        side.setFixedWidth(214)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(12, 16, 12, 12)
        sl.setSpacing(3)
        brand = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(app_icon().pixmap(30, 34))
        brand.addWidget(logo)
        bt = QVBoxLayout()
        bt.setSpacing(0)
        b1 = QLabel("AGENT GUARD")
        b1.setObjectName("brand")
        b2 = QLabel("containment net")
        b2.setObjectName("brandSub")
        bt.addWidget(b1)
        bt.addWidget(b2)
        brand.addLayout(bt)
        brand.addStretch(1)
        sl.addLayout(brand)
        sl.addSpacing(14)

        self.stack = QStackedWidget()
        self.ctx = GuardContext(guard, self.bridge, self.notify, self.navigate)
        self.pages: dict[str, QWidget] = {}
        self.buttons: dict[str, QPushButton] = {}
        group = QButtonGroup(self)
        group.setExclusive(True)
        for key, text, cls in NAV:
            page = cls(self.ctx)
            self.pages[key] = page
            self.stack.addWidget(page)
            btn = QPushButton(text)
            btn.setObjectName("nav")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _c=False, k=key: self.navigate(k))
            group.addButton(btn)
            self.buttons[key] = btn
            sl.addWidget(btn)
        sl.addStretch(1)
        self.status_pill = QLabel()
        self.status_pill.setTextFormat(Qt.RichText)
        sl.addWidget(self.status_pill)
        ver = QLabel(f"v{__version__} · MIT")
        ver.setObjectName("brandSub")
        sl.addWidget(ver)
        h.addWidget(side)

        self.stack.setParent(root)
        h.addWidget(self.stack, 1)

        # tray
        self.tray = QSystemTrayIcon(app_icon(), self)
        self._tray_menu = QMenu()  # kept on self: setContextMenu does not take ownership
        self._tray_menu.addAction(QAction("Open Agent Guard", self, triggered=self.show_normal))
        self._tray_menu.addAction(QAction("Run scan", self, triggered=lambda: (self.show_normal(), self.navigate("net"))))
        self._tray_menu.addSeparator()
        self._tray_menu.addAction(QAction("Quit", self, triggered=self.quit))
        self.tray.setContextMenu(self._tray_menu)
        self.tray.activated.connect(
            lambda r: self.show_normal() if r in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None
        )
        self.tray.setToolTip(APP_NAME)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

        # guard alerts → UI thread
        guard.alert_listeners.append(lambda t, x, l: self.bridge.alert.emit(t, x, l))
        self.bridge.alert.connect(self.notify)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(600)
        self._ticks = 0

        self.navigate("overview")
        self._update_status()

    def navigate(self, key: str, action: str | None = None) -> None:
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        self.buttons[key].setChecked(True)
        page.refresh()
        if action and hasattr(page, "action"):
            page.action(action)

    def _tick(self) -> None:
        self._ticks += 1
        page = self.stack.currentWidget()
        if self.isVisible() and not self.isMinimized():
            if (self._ticks * 600) % max(600, getattr(page, "refresh_ms", 2500)) < 600:
                page.refresh()
        if self._ticks % 8 == 0:
            self._update_status()

    def _update_status(self) -> None:
        snap = self.guard.snapshot()
        p = self.guard.partners
        def dot(ok, c=theme.OK):
            return f"<span style='color:{c if ok else theme.FAINT}'>●</span>"
        self.status_pill.setText(
            f"{dot(True)} Net: watching<br>"
            f"{dot(self.guard.mix.enabled, theme.ACCENT)} Oversight mix: {'on' if self.guard.mix.enabled else 'off'}<br>"
            f"{dot(p.sentinel_vision or p.cryptomigrate)} Partners: "
            f"{'SV ' if p.sentinel_vision else ''}{'CM' if p.cryptomigrate else ''}{'none' if not (p.sentinel_vision or p.cryptomigrate) else ''}<br>"
            f"{dot(snap.audit_ok)} Audit: {'intact' if snap.audit_ok else 'broken'}"
        )
        self.tray.setIcon(app_icon(theme.ACCENT if snap.contained == 0 else theme.DANGER))

    def notify(self, title: str, text: str, level: str = "info") -> None:
        if self.guard.settings.quiet_mode and level != "danger":
            return
        icon = {"danger": QSystemTrayIcon.Critical, "info": QSystemTrayIcon.Information}.get(level, QSystemTrayIcon.Warning)
        if self.tray.isVisible():
            self.tray.showMessage(title, text, icon, 7000)

    def show_normal(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def stop(self) -> None:
        """Deterministic teardown: stop timers and drop every reference that
        points back at our widgets, so nothing fires while Qt and Python unwind
        at interpreter exit. Idempotent — safe to call from closeEvent and again
        from main() after the event loop returns."""
        if self._stopped:
            return
        self._stopped = True
        try:
            self.timer.stop()
        except Exception:
            pass
        try:
            self.guard.alert_listeners.clear()  # this listener lambda captures self.bridge
        except Exception:
            pass
        try:
            self.tray.hide()
        except Exception:
            pass

    def closeEvent(self, e) -> None:  # noqa: N802
        if not self._quitting and self.guard.settings.minimize_to_tray and self.tray.isVisible():
            e.ignore()
            self.hide()
            self.notify(APP_NAME, "Still watching in the background. Right-click the tray icon to quit.")
            return
        self.stop()
        e.accept()
        QApplication.quit()

    def quit(self) -> None:
        self._quitting = True
        self.close()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setWindowIcon(app_icon())
    app.setStyle("Fusion")
    app.setStyleSheet(theme.STYLESHEET)
    app.setQuitOnLastWindowClosed(False)
    guard = AgentGuard(Settings.load())
    win = MainWindow(guard)
    win.show()
    exit_code = app.exec()
    # Tear the window down while the QApplication is still alive, so Qt controls
    # the destruction order of the widgets (and the parented Bridge) rather than
    # Python's garbage collector racing it at interpreter exit.
    win.stop()
    win.deleteLater()
    app.processEvents()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
