"""SIEM Analytics page: browser_widget.BrowserWidget pointed at the configured SIEM
host's Kibana -- https://<remote_siem.host or localhost>:5601/. The address
bar is fully editable regardless (e.g. to navigate straight to a specific
saved dashboard's URL), this is only the starting point.

Beyond a bare embedded browser:
  - "Remember credentials" (default on): toggles between a persistent
    (named) QWebEngineProfile and the off-the-record default every other
    embedded browser in this app uses -- see browser_widget.py. Kibana is
    the one place in this app where staying logged in across restarts is
    obviously wanted, unlike the Attack Simulation page's eshop browser.
  - Autologin: whenever Kibana's own login page loads, its username/
    password fields are filled in and submitted automatically using the
    SIEM stack's own ELASTIC_USERNAME/ELASTIC_PASSWORD (core/
    kibana_credentials.py) -- the elk_dockerized .env already documents
    these as "also used for dashboard login". Silently does nothing if the
    credentials can't be read (missing .env, unreachable remote) --
    Kibana's own login form is still right there either way.
  - Bookmarks: one-click buttons to the SIEM's saved dashboards and the
    Discover page, laid out in a FlowLayout (ui/flow_layout.py) alongside
    the "Remember credentials" checkbox so an arbitrary number of them
    wraps onto additional rows instead of forcing the window wider.
  - "Export PDF…": full-page screenshots of every bookmark page, each with
    a short explanation of what it shows (ui/kibana_export.py captures in a
    hidden view sharing this page's login; core/kibana_report.py writes the
    PDF).
  - A causality banner on load failure: QWebEngineView's own error page
    just says something generic like "can't reach this page", with no way
    for the user to tell "is the SIEM stack down, or something else" --
    this checks whether Kibana's own container is actually running and
    says so explicitly, since "reachable but broken" and "not running at
    all" call for different next steps.
"""
from __future__ import annotations

import json
import os

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QCheckBox, QFileDialog, QMessageBox, QProgressDialog, QPushButton, QVBoxLayout,
    QWidget,
)

from core import shipper_health as sh
from core.docker_ctl import target_for, targets_for
from core.kibana_credentials import get_elastic_credentials
from core.kibana_report import render_kibana_pdf
from core.state import AppState
from ui.browser_widget import BrowserWidget
from ui.common import ErrorBanner, Job, confirm, danger_button
from ui.flow_layout import FlowLayout
from ui.kibana_export import KibanaCapture

KIBANA_PORT = 5601
_PROFILE_NAME = "kibana_dashboard"

# (button label, path relative to the Kibana root) -- the dashboard ids match
# siem/kibana/build_dashboards.py's DASHBOARDS (kept in step by
# test_dashboard_app_links_every_dashboard), plus the honeypot-* data view's
# Rules list and Discover.
_BOOKMARKS = [
    ("Home", "/app/home"),
    ("Web Traffic & Threat Overview", "/app/dashboards#/view/dashboard-web-threat-overview"),
    ("IDS Alerts (Suricata)", "/app/dashboards#/view/dashboard-ids-alerts"),
    ("Threat Decisions & Decay", "/app/dashboards#/view/dashboard-threat-decisions"),
    ("Session Analysis", "/app/dashboards#/view/dashboard-session-analysis"),
    ("Attack Patterns", "/app/dashboards#/view/dashboard-attack-patterns"),
    ("Threat Intelligence", "/app/dashboards#/view/dashboard-threat-intel"),
    ("Infrastructure & Ops Logs", "/app/dashboards#/view/dashboard-infra-logs"),
    # The active alerting rules kibana_alerts_setup seeds (siem/kibana/
    # build_alert_rules.py) -- Stack Management's Rules list, where each
    # Honeypot rule's status (active/ok) and its fired alerts are shown.
    ("Alerts (Rules)", "/app/management/insightsAndAlerting/triggersActions/rules"),
    ("Discover", "/app/discover"),
]

# Kibana's login form (x-pack security plugin, stable across 7.x-9.x) uses
# these data-test-subj attributes on its username/password inputs and
# submit button -- confirmed against this repo's own Kibana 8.17.3 and 9.5.5.
# React controls these inputs, so a plain `input.value = x` doesn't stick
# (React's onChange never fires) -- setNativeValue() below is the standard
# workaround: call the native <input> value setter (bypassing React's
# instance-level override) and then dispatch an 'input' event so React's
# change handler actually observes the new value.
#
# The login page is a React SPA: loadFinished fires on the initial (near-
# empty) HTML shell, well before the form actually renders -- confirmed
# live the fields don't exist yet at that point. Polls for up to ~10s
# instead of injecting once immediately, since guessing a fixed delay from
# the Python side is exactly the kind of timing assumption that's fragile
# across machines/first-run-vs-cached-bundle load times.
_AUTOLOGIN_JS_TEMPLATE = """
(function() {
    function setNativeValue(element, value) {
        var valueSetter = Object.getOwnPropertyDescriptor(element, 'value').set;
        var prototype = Object.getPrototypeOf(element);
        var prototypeValueSetter = Object.getOwnPropertyDescriptor(prototype, 'value').set;
        if (valueSetter && valueSetter !== prototypeValueSetter) {
            prototypeValueSetter.call(element, value);
        } else {
            valueSetter.call(element, value);
        }
        element.dispatchEvent(new Event('input', { bubbles: true }));
    }
    var attempts = 0;
    var timer = setInterval(function() {
        attempts += 1;
        var u = document.querySelector('[data-test-subj="loginUsername"]');
        var p = document.querySelector('[data-test-subj="loginPassword"]');
        var btn = document.querySelector('[data-test-subj="loginSubmit"]');
        if (u && p && btn) {
            clearInterval(timer);
            setNativeValue(u, %(username)s);
            setNativeValue(p, %(password)s);
            btn.click();
        } else if (attempts > 40) {
            clearInterval(timer);
        }
    }, 250);
})();
"""


def _default_kibana_url(state: AppState) -> str:
    host = state.primary_remote_host("siem")
    return f"https://{host}:{KIBANA_PORT}/"


class KibanaPage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._credentials: tuple[str, str] | None = None
        self._autologin_attempted_for_url: str | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # "Remember credentials" and the dashboard bookmarks share one
        # FlowLayout so they wrap together as a unit -- the bookmark list
        # can grow (more saved dashboards later) without ever forcing the
        # window wider than the screen.
        toolbar = FlowLayout(margin=6, h_spacing=8, v_spacing=6)
        self.remember_check = QCheckBox("Remember credentials (keep me logged in across restarts)")
        self.remember_check.setChecked(state.kibana_remember_credentials)
        self.remember_check.toggled.connect(self._on_remember_toggled)
        toolbar.addWidget(self.remember_check)

        for label, path in _BOOKMARKS:
            btn = QPushButton(label)
            btn.clicked.connect(lambda _checked, p=path: self._navigate_to(p))
            toolbar.addWidget(btn)

        self.export_btn = QPushButton("Export PDF…")
        self.export_btn.setToolTip(
            "Full-page screenshot of every page button above, each with an explanation "
            "of what it shows, in one PDF")
        self.export_btn.clicked.connect(self._export_pdf)
        toolbar.addWidget(self.export_btn)
        self._capture: KibanaCapture | None = None
        self._export_path = ""

        # Wipe every honeypot-* document from Elasticsearch -- the same
        # _delete_by_query the Log Pipeline page's "Clear all documents"
        # button runs (core/shipper_health.clear_all_documents), surfaced
        # here too since this is the page people actually look at the SIEM
        # data on. Indices and mappings stay, so Vector keeps shipping.
        self._clear_jobs: set[Job] = set()
        self.clear_btn = danger_button("Clear Elasticsearch", self._clear_elasticsearch)
        self.clear_btn.setToolTip(
            "Permanently delete every honeypot-* document stored in Elasticsearch "
            "(all shipped logs, metrics, alerts and events, and the Kibana history "
            "built from them). The indices stay and Vector keeps shipping new data.")
        toolbar.addWidget(self.clear_btn)

        toolbar_widget = QWidget()
        toolbar_widget.setLayout(toolbar)
        layout.addWidget(toolbar_widget)

        self.banner = ErrorBanner()
        layout.addWidget(self.banner)

        self._browser_layout = QVBoxLayout()
        self._browser_layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(self._browser_layout, stretch=1)

        self.browser: BrowserWidget | None = None
        self._build_browser()

    def showEvent(self, event) -> None:
        """Retries the load, but ONLY if the last one actually failed (the
        red banner is still up) -- if Kibana is already showing whatever
        dashboard/page the user navigated to, a blind reload here would
        throw that away for no reason (and Kibana is a stateful SPA
        session, unlike the mostly-stateless pages elsewhere in this app).
        Reloads the same URL that failed (not the home page), so a retry
        after e.g. the SIEM stack finishing its own startup lands back on
        whatever the user was actually trying to reach."""
        super().showEvent(event)
        if self.banner.isVisible():
            self.browser.view.reload()

    def _build_browser(self) -> None:
        profile_name = _PROFILE_NAME if self.state.kibana_remember_credentials else None
        self.browser = BrowserWidget(_default_kibana_url(self.state), profile_name=profile_name)
        self.browser.view.loadFinished.connect(self._on_load_finished)
        self._browser_layout.addWidget(self.browser)

        # Read once per browser build (not per page load) -- a remote SIEM
        # fetches this over SSH (core/kibana_credentials.py), no need to
        # repeat that round-trip on every navigation.
        self._credentials = get_elastic_credentials(self.state)
        self._autologin_attempted_for_url = None

    def _autologin_script(self) -> str | None:
        if not self._credentials:
            return None
        username, password = self._credentials
        return _AUTOLOGIN_JS_TEMPLATE % {
            "username": json.dumps(username),
            "password": json.dumps(password),
        }

    def _export_pdf(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Kibana PDF", "kibana-pages.pdf", "PDF files (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        self._export_path = path
        self.export_btn.setEnabled(False)
        # The capture shares this browser's profile; rebuilding the browser
        # (the toggle below) mid-capture would delete it out from under it.
        self.remember_check.setEnabled(False)

        self._progress = QProgressDialog("Capturing SIEM Analytics pages…", "Cancel", 0, len(_BOOKMARKS), self)
        self._progress.setWindowTitle("Kibana PDF export")
        self._progress.setWindowModality(Qt.WindowModality.WindowModal)
        self._progress.setMinimumDuration(0)
        self._progress.setValue(0)

        self._capture = KibanaCapture(
            self.browser.profile, _default_kibana_url(self.state), _BOOKMARKS,
            autologin_js=self._autologin_script(), parent=self)
        self._capture.progress.connect(self._on_capture_progress)
        self._capture.done.connect(self._on_capture_done)
        self._progress.canceled.connect(self._capture.cancel)
        self._capture.start()

    def _on_capture_progress(self, index: int, label: str) -> None:
        self._progress.setValue(index)
        self._progress.setLabelText(f"Capturing {index + 1}/{len(_BOOKMARKS)}: {label}…")

    def _on_capture_done(self, shots: list) -> None:
        cancelled = self._progress.wasCanceled()
        self._progress.canceled.disconnect()
        self._progress.close()
        self._capture.deleteLater()
        self._capture = None
        self.export_btn.setEnabled(True)
        self.remember_check.setEnabled(True)
        if cancelled or not shots:
            return
        path = self._export_path
        try:
            captured = render_kibana_pdf(shots, path, _default_kibana_url(self.state))
        except Exception as e:  # noqa: BLE001 -- surface any render failure to the user
            QMessageBox.warning(self, "Export failed", str(e))
            return
        missing = len(shots) - captured
        note = (f"\n\n{missing} page(s) could not be captured; the PDF says why."
                if missing else "")
        if QMessageBox.question(
            self, "Saved",
            f"Saved the Kibana PDF ({captured} page screenshot(s)) to:\n{path}{note}\n\nOpen it now?",
        ) == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))

    def _navigate_to(self, path: str) -> None:
        base = _default_kibana_url(self.state).rstrip("/")
        self.browser.navigate(base + path)

    def _clear_elasticsearch(self) -> None:
        if not confirm(
            self, "Clear Elasticsearch",
            "This permanently deletes every honeypot-* document currently stored in "
            "Elasticsearch — all shipped logs, metrics, alerts and events, and the "
            "Kibana history and dashboards built from them.\n\n"
            "The indices themselves stay and Vector keeps shipping new data, so the "
            "pipeline is unaffected, but the data already in the SIEM cannot be recovered.\n\n"
            "Delete all documents now?",
        ):
            return
        self.clear_btn.setEnabled(False)
        self.clear_btn.setText("Clearing…")
        siem = targets_for("siem", self.state)
        job = Job(lambda: sh.clear_all_documents(siem, self.state), self)
        self._clear_jobs.add(job)

        def finished(result, error):
            self.clear_btn.setEnabled(True)
            self.clear_btn.setText("Clear Elasticsearch")
            self._clear_jobs.discard(job)
            job.deleteLater()
            if error or result is None:
                QMessageBox.warning(self, "Clear Elasticsearch failed", error or "no data")
                return
            deleted, derr = result
            if derr:
                QMessageBox.warning(self, "Clear Elasticsearch failed", derr)
                return
            QMessageBox.information(
                self, "Elasticsearch cleared",
                f"Deleted {deleted:,} document(s) from the SIEM.\n\n"
                "Reload a dashboard to see it empty; new data will appear as Vector ships it.")
        job.done.connect(finished)
        job.start()

    def _on_remember_toggled(self, checked: bool) -> None:
        self.state.kibana_remember_credentials = checked
        self.state.save()

        # Swapping which QWebEngineProfile is in use means a different
        # cookie/cache store entirely -- can't just flip a flag on the
        # existing view, the browser has to be rebuilt against the new
        # profile. Whatever page was loaded is lost; that's an inherent
        # consequence of switching storage, not a bug.
        old = self.browser
        self._browser_layout.removeWidget(old)
        old.deleteLater()
        self.banner.setVisible(False)
        self._build_browser()

    def _on_load_finished(self, ok: bool) -> None:
        if ok:
            self.banner.setVisible(False)
            self._maybe_autologin()
            return

        target = target_for("siem", self.state)
        containers = target.ps()
        kibana_container = next((c for c in containers if c.get("Service") == "kibana"), None)

        if kibana_container is None:
            self.banner.setText(
                "⚠ Couldn't load Kibana because the SIEM stack doesn't appear to be running "
                f"at all for this target ({target.label}) -- no 'kibana' container found. "
                "Start it from the Workloads page, then reload this page."
            )
        elif kibana_container.get("State") != "running":
            self.banner.setText(
                "⚠ Couldn't load Kibana -- its container exists but isn't running "
                f"(state: {kibana_container.get('State', 'unknown')}). Start it from the "
                "Workloads page, then reload this page."
            )
        else:
            self.banner.setText(
                "⚠ Couldn't load Kibana -- its container IS running, so this isn't a "
                "\"SIEM is down\" problem. Check its logs on the Workloads / Global Visualization pages "
                "(startup can take a minute; a cert/network issue would also show here)."
            )
        self.banner.setVisible(True)

    def _maybe_autologin(self) -> None:
        if not self._credentials:
            return

        url = self.browser.view.url()
        if url.path() != "/login":
            return

        url_str = url.toString()
        if self._autologin_attempted_for_url == url_str:
            # Duplicate loadFinished(True) for the same /login URL (e.g. a
            # hash-only navigation) -- already submitted once, don't resubmit.
            return
        self._autologin_attempted_for_url = url_str

        self.browser.page.runJavaScript(self._autologin_script())
