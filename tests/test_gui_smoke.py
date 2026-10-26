"""GUI smoke tests: every page builds, refreshes and paints headlessly; the sentinel-vision plugin seam works.

Skipped cleanly when PySide6 is not installed.
"""

from __future__ import annotations

import gc
import json
import os
import types
from importlib.metadata import PackageNotFoundError, distribution

import pytest

from agent_guard.detect import DetectedAgent, ProcessInfo, Reason
from agent_guard.mesh import MeshSnapshot

os.environ["QT_QPA_PLATFORM"] = "offscreen"  # headless; must be set before PySide6 / the gui are imported

# importorskip (rather than import statements) keeps this module importable, and cleanly skipped, without PySide6.
pytest.importorskip("PySide6")
qt_widgets = pytest.importorskip("PySide6.QtWidgets")
shiboken6 = pytest.importorskip("shiboken6")
plugin = pytest.importorskip("agent_guard.gui.plugin")
MainWindow = pytest.importorskip("agent_guard.gui.app").MainWindow
NAV = pytest.importorskip("agent_guard.gui.pages").NAV
QApplication, QWidget = qt_widgets.QApplication, qt_widgets.QWidget

KEYS = [key for key, _label, _page in NAV]


@pytest.fixture(scope="session")
def qapp():
    # QApplication.instance() guards against double-creation; the session scope keeps one alive until exit.
    app = QApplication.instance() or QApplication([])
    yield app
    gc.collect()
    app.processEvents()


@pytest.fixture
def track(qapp):
    """Register top-level widgets built by a test; their C++ objects are deleted deterministically on teardown.

    The pages connect lambdas that capture ``self`` to their child widgets' signals. That is a reference cycle
    across the Python/C++ boundary which Python's GC cannot break, so left alone such widgets are destroyed during
    interpreter shutdown *after* the QApplication and the process segfaults on exit. Deleting them here, while
    the application is still alive, makes teardown deterministic.
    """
    made = []
    yield made.append
    for widget in reversed(made):
        if shiboken6.isValid(widget):
            shiboken6.delete(widget)
    qapp.processEvents()


@pytest.fixture
def window(guard, track):
    win = MainWindow(guard)
    track(win)
    yield win
    win.timer.stop()
    guard.alert_listeners.clear()  # drop the guard -> window back-reference


@pytest.fixture
def host():
    """A duck-typed host context, as sentinel-vision's AppContext would provide."""
    notified = []
    return types.SimpleNamespace(
        notify=lambda *args, **kwargs: notified.append(args),
        navigate=lambda *args, **kwargs: None,
        notified=notified,
    )


def rogue(agent_id="rogue-1") -> DetectedAgent:
    proc = ProcessInfo(pid=424242, name="rogue", exe="", cmdline=["rogue"])
    reasons = [Reason("touched a decoy", 100, "tripwire")]
    return DetectedAgent(None, "rogue", proc, False, 100, reasons, agent_id=agent_id)


# ------------------------------------------------------------------ standalone window
@pytest.mark.parametrize("key", KEYS)
def test_every_page_navigates_and_refreshes(window, key):
    window.navigate(key)
    window.pages[key].refresh()

    assert window.stack.currentWidget() is window.pages[key]
    assert window.buttons[key].isChecked()


def test_main_window_has_a_page_and_a_sidebar_button_for_every_nav_entry(window):
    assert list(window.pages) == KEYS
    assert list(window.buttons) == KEYS
    assert window.windowTitle() == "Agent Guard"


def test_pages_paint_without_error(window):
    for key in KEYS:
        window.navigate(key)
        assert not window.pages[key].grab().isNull(), key


def test_mesh_widget_paints_agents_in_every_state(window):
    agents = [
        {"label": "a", "state": "healthy", "score": 0},
        {"label": "b", "state": "flagged", "score": 70},
        {"label": "c", "state": "contained", "score": 100},
    ]
    window.navigate("mesh")
    window.pages["mesh"].mesh.set_snapshot(MeshSnapshot(core_state="containing", agents=agents))

    assert not window.pages["mesh"].grab().isNull()


def test_net_page_lists_what_the_detector_finds(window, monkeypatch):
    proc = ProcessInfo(
        pid=424242, name="crew", exe="", cmdline=["python", "crewai_runner.py"], remote_hosts=["203.0.113.5:443"]
    )
    monkeypatch.setattr(window.guard.detector, "snapshot_processes", lambda: [proc])

    window.navigate("net")

    model = window.pages["net"].model
    assert model.rowCount() == 1
    row = [model.data(model.index(0, col)) for col in range(model.columnCount())]
    assert row[:4] == ["crew", "424242", "unregistered", "1 hosts"]
    assert row[6] == "healthy"


def test_overview_page_reports_when_the_net_is_holding(window, monkeypatch):
    noisy = ProcessInfo(
        pid=424242,
        name="crew",
        exe="",
        cmdline=["python", "crewai_runner.py"],
        remote_hosts=[f"203.0.113.{i}:443" for i in range(1, 11)],
    )
    monkeypatch.setattr(window.guard.detector, "snapshot_processes", lambda: [noisy])
    window.navigate("overview")
    assert window.pages["overview"].hero_title.text() == "All clear"

    window.guard.scan()  # flagged: unregistered + fan-out + novel egress
    window.navigate("overview")

    assert window.pages["overview"].hero_title.text() == "Net is holding"


def test_detections_page_reflects_the_latest_containment(window):
    window.guard.pacify(rogue(), "revoke", auto=False)

    window.navigate("detections")

    caption = window.pages["detections"].ladder_caption.text()
    assert "rogue-1" in caption
    assert "operator-contained to revoke" in caption


def test_quarantine_page_lists_stored_binaries(window, tmp_path):
    binary = tmp_path / "agent.bin"
    binary.write_bytes(b"\x7fELF")
    window.guard.quarantine.add(str(binary), "agent-1", "pacified")

    window.navigate("quarantine")

    model = window.pages["quarantine"].model
    assert model.rowCount() == 1
    assert model.data(model.index(0, 2)) == "agent-1"


def test_settings_toggles_are_saved_to_the_isolated_settings_file(window, tmp_path):
    page = window.pages["settings"]

    page.cb_decoy.setChecked(False)
    page.cb_mix.setChecked(False)

    assert window.guard.settings.auto_contain_on_decoy is False
    assert window.guard.mix.enabled is False
    saved = json.loads((tmp_path / "AgentGuard" / "settings.json").read_text("utf-8"))
    assert saved["auto_contain_on_decoy"] is False
    assert saved["mix_oversight_traffic"] is False


def test_guard_alerts_reach_the_window_without_error(window):
    window.guard._evaluate(rogue())  # decoy touch: flagged, escalated and pacified alerts

    assert window.guard.snapshot().audit_ok


def test_closing_the_window_stops_its_refresh_timer(window):
    assert window.timer.isActive()

    window.close()

    assert not window.timer.isActive()


# ----------------------------------------------------------- sentinel-vision plugin seam
def test_plugin_register_returns_a_page_descriptor_per_nav_entry():
    pages = plugin.register()

    assert pages
    assert [p.key for p in pages] == KEYS
    assert all(p.label and callable(p.factory) for p in pages)


def test_each_plugin_factory_builds_a_widget(host, track):
    for page in plugin.register():
        widget = page.factory(host)
        track(widget)

        assert isinstance(widget, QWidget), page.key


def test_hosted_pages_forward_guard_alerts_to_the_host(host, track):
    overview = next(p for p in plugin.register() if p.key == "overview")
    page = overview.factory(host)
    track(page)

    [listener] = page.guard.alert_listeners
    listener("Rogue agent flagged", "details", "warning")

    assert host.notified == [("Rogue agent flagged", "details", "warning")]


def test_a_host_without_notify_or_navigate_is_tolerated(track):
    widget = plugin.register()[0].factory(object())
    track(widget)

    assert isinstance(widget, QWidget)


def test_plugin_is_advertised_on_the_sentinel_vision_entry_point_group():
    try:
        dist = distribution("agent-guard")
    except PackageNotFoundError:
        pytest.skip("agent-guard is not installed, so there is no entry-point metadata to inspect")

    [ep] = [e for e in dist.entry_points if e.group == "sentinel_vision.plugins" and e.name == "agent_guard"]

    assert ep.value == "agent_guard.gui.plugin:register"
    assert ep.load() is plugin.register
