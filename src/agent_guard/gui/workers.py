"""Background execution. All guard work runs off the UI thread; results return
via signals. Mirrors sentinel-vision's worker pattern so the two compose."""

from __future__ import annotations

import threading
import traceback
from collections.abc import Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal


class TaskSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)
    message = Signal(str)


class Task(QRunnable):
    def __init__(self, fn: Callable[["Task"], object]) -> None:
        super().__init__()
        self.fn = fn
        self.signals = TaskSignals()
        self.cancel = threading.Event()
        self.setAutoDelete(False)  # Python owns the lifetime (see `start`)

    def message(self, text: str) -> None:
        self.signals.message.emit(text)

    def run(self) -> None:
        try:
            result = self.fn(self)
        except Exception as exc:  # pragma: no cover - GUI thread safety
            traceback.print_exc()
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        self.signals.finished.emit(result)


_LIVE: set[Task] = set()


def start(task: Task) -> Task:
    _LIVE.add(task)
    release = lambda *_: _LIVE.discard(task)  # noqa: E731
    task.signals.finished.connect(release)
    task.signals.failed.connect(release)
    QThreadPool.globalInstance().start(task)
    return task


class Bridge(QObject):
    """Thread-safe hop from guard callbacks (any thread) into the Qt event loop."""

    alert = Signal(str, str, str)   # title, text, level
    scanned = Signal(object)        # list[DetectedAgent]
    status_changed = Signal()
