#!/usr/bin/env python3
"""Entry point for the honeypot/SIEM dashboard.

Run via ./run.sh (creates the venv and installs dependencies on first
use) rather than directly, unless you've already set up the venv
yourself -- see requirements.txt.
"""
import os
import sys

# Every site this app's embedded browsers ever point at (Kibana, the
# eshop) uses a self-signed cert with no real CA --
# ui/browser_widget.py's certificateError handler already accepts these
# unconditionally for normal page navigation and its subresource loads
# (it doesn't check origin either, same trade-off this makes), but
# confirmed live it does NOT cover every connection Chromium's network
# stack can open for a heavy page (WooCommerce/Elementor pull in dozens
# of JS/CSS/font subresources): a stray parallel/speculative connection
# occasionally fails the handshake with "certificate unknown" and lands
# in reverse_proxy's error log, even though every other resource on the
# same page load succeeds. Setting this before Chromium initializes
# covers those too, at the engine level -- a supplement to the existing
# signal handler (kept in place; still needed on some code paths), not a
# new category of risk beyond what that handler already accepted. Must
# be set before QtWebEngineWidgets is imported below -- Chromium reads
# this env var once, at engine startup.
def _is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    try:
        with open("/proc/sys/kernel/osrelease", encoding="utf-8") as release:
            return "microsoft" in release.read().lower()
    except OSError:
        return False


def _set_webengine_chromium_flags() -> None:
    """Add this app's required Chromium flags without discarding any the
    user already put in QTWEBENGINE_CHROMIUM_FLAGS.

    On WSL/WSLg, QtWebEngine's GPU compositor tries to import the web
    view's texture through dma_buf and fails ("Compositor returned null
    texture" / "Failed to get native pixmap due to dma_buf acquisition
    failure"), leaving every embedded browser blank. Software compositing
    avoids that path and renders the pages correctly; it is scoped to WSL
    so native Linux keeps hardware compositing.
    """
    flags = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "").split()
    for flag in ("--ignore-certificate-errors",):
        if flag not in flags:
            flags.append(flag)
    if _is_wsl() and "--disable-gpu-compositing" not in flags:
        flags.append("--disable-gpu-compositing")
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join(flags)


_set_webengine_chromium_flags()

# Must be imported before the QApplication instance is constructed below --
# PyQt6 raises ImportError otherwise ("QtWebEngineWidgets must be imported
# or Qt.AA_ShareOpenGLContexts must be set before a QCoreApplication
# instance is created"). Only main.py's import order matters here; every
# other module that touches QWebEngineView (ui/browser_widget.py etc.) can
# import it normally since by the time those run, this has already fired.
from PyQt6 import QtWebEngineWidgets  # noqa: F401
from PyQt6.QtWidgets import QApplication

from core.state import AppState
from ui import theme
from ui.main_window import MainWindow
from ui.wizard import SetupWizard


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("PressHaven.io")
    app.setOrganizationName("DP_Repository")

    state = AppState.load()
    theme.apply_theme(state.theme)

    wizard = None
    if not state.first_run_complete:
        wizard = SetupWizard(state)
        result = wizard.exec()
        if result != SetupWizard.DialogCode.Accepted:
            # User cancelled first-run setup entirely -- nothing usable
            # exists yet (no confirmed .env), so exit rather than open a
            # main window pointed at an unconfigured/half-configured stack.
            return 0
        state = AppState.load()  # SetupWizard.accept() already saved it

    window = MainWindow(state)
    window.show()
    if os.environ.get("DASHBOARD_STALL_WATCH"):
        # Diagnose UI freezes: stack of the stuck GUI thread -> logs/stall-*.txt
        import threading
        from PyQt6.QtCore import QTimer
        from core.paths import LOG_DIR
        from core.stall_watch import HEARTBEAT_MS, StallWatch
        watch = StallWatch(threading.get_ident(), LOG_DIR)
        beat = QTimer(window)
        beat.timeout.connect(watch.beat)
        beat.start(HEARTBEAT_MS)
        watch.start()
    if wizard is not None and wizard.start_stacks:
        window.services_page.start_all()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
