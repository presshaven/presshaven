"""Attack Simulation page: an embedded browser on the eshop (address bar included --
production by default, but reverse_proxy's own routing decides whether a
given request actually lands on production or a honeypot pool, same as a
real visitor), a pattern-preset dropdown (core/patterns.py) with two
SEPARATE one-click buttons -- "Run pattern (curl)" sends the preset's real
request (its own headers/body -- the actual payload), "Run pattern
(browser)" navigates the embedded browser to the preset's URL as a plain
GET using whatever session the browser already holds. Deliberately two
buttons, not one that did both: that used to send TWO different requests
per click (curl with the real payload, then an automatic bare-GET browser
navigation to the same path) with two different signal profiles a couple
seconds apart, which made the pattern-analyzer log look internally
inconsistent for what looked like "one pattern run" -- see
_run_selected_pattern_curl()/_run_selected_pattern_browser(). A live
pattern-analyzer log tail sits next to the browser so the routing decision
is visible as it happens, and a Postman-style manual request builder
(method/URL/headers/body, loadable from the same presets, sent via curl)
covers anything the canned presets don't.

"Reset local score" clears the browser's own cookie jar (a dedicated
off-the-record profile, see browser_widget.py) rather than touching Redis
directly. Since sessions became tamper-proof (signed cookie + passive
fingerprint recovery, lua/session_identity_rules.lua), losing the cookie no
longer starts a fresh session: the proxy recognises the same browser and
hands its session back, exactly as it does for a user who clears
cookies. "Unpoison host IP" below removes the session itself. That only
affects the BROWSER though -- patterns themselves run via curl (stateless,
no cookies at all), so a poisoned threat_ips/session entry for the shared
host IP (every pattern run from this machine, and any local browser
testing, shows up as the same docker-bridge-gateway IP -- confirmed live
throughout this project's development) sticks around independently of the
browser's own cookies and can make the NEXT pattern run land on a
honeypot pool from the start regardless of which CVE it's testing.
"Unpoison host IP" (core/redis_inspect.clear_local_threat_state) is the
server-side equivalent: wipes threat_ips/session:*/honeypot_pool_session:*/fp_session:*
entries for any private/loopback IP, so pattern runs always start from a
clean slate. Confirmed it can never touch real user data -- a genuine
external user's source IP survives Docker's DNAT on a real two-host
deployment, so it would never fall in that private/loopback range.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time

from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QTabWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)
from PyQt6.QtCore import Qt, QEventLoop, QPoint, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices, QPixmap

from core import honeypot_layer
from core.docker_ctl import target_for
from core.env_upload import EnvUploadError, load_project_env
from core.patterns import (COMPONENTS, GDPR_RESTORE_PRESET, PATTERN_PRESETS, KINDS, SURFACES,
                           PatternPreset, build_curl_argv, filter_presets, group_presets,
                           is_gdpr_restore, selection_label)
from core.pattern_registry import active_presets
from ui.pattern_picker import PatternPickerButton
from ui.report_stages import ReportStagesWidget
from core.eta import EtaTracker, format_eta
from core import pattern_report_pdf
from core.pattern_report import ReportError, ReportWorker
from core.redis_inspect import RedisInspectError, clear_local_threat_state
from core.state import AppState
from core.learning import explain_event
from core.pattern_log_parser import COLOR_HIGH, COLOR_LOW, COLOR_MED, SCORE_MAX, LineBuffer, PatternEvent, parse_line
from ui import theme
from ui.common import (ErrorBanner, clear_all_attacks, danger_button,
                       gdpr_screen_characteristics, request_gdpr_consent)
from ui.flow_layout import FlowLayout, labeled
from ui.responsive import ResponsiveSplitter
from ui.browser_widget import BrowserWidget
from ui.kibana_timeline_capture import KibanaTimelineCapture
from ui.page_learn import pattern_lesson_html
from ui.process_runner import LogPanel
from ui.scenario_runner import ScenarioScriptsTab

_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

# Clears the page origin's localStorage and sessionStorage (what "clear site
# data" wipes alongside cookies); mirrors the helper in ui/page_pool_test.py.
_CLEAR_STORAGE_JS = ("(function(){var n=0;try{n+=localStorage.length;localStorage.clear();}catch(e){}"
                     "try{n+=sessionStorage.length;sessionStorage.clear();}catch(e){}return String(n);})()")

# --- PDF-report screenshot capture tuning (see _capture_browser) ---
# Render the site smaller (zoom out) so a screenshot shows more of the page at
# a smaller scale, per request. Per-page, reset on each navigation, so it's
# re-applied after every load.
_CAPTURE_ZOOM = 0.67
# During capture the browser pane is widened to (almost) the whole splitter so
# the grab has as many native pixels as possible -- the PDF then downscales
# that, which is what makes the embedded image sharp WITHOUT any sharpen
# filter/effect (more captured pixels per printed inch = higher effective DPI).
# The tabs get a sliver rather than 0 so the splitter handle stays usable.

# Matches router.lua's default honeypot_threshold (init.lua) -- the score
# badge's own color bands, not just the diagram's per-signal ones.
_SCORE_MED_AT = 30
_SCORE_HIGH_AT = 80


_ZWSP = "​"  # zero-width space -- a wrap opportunity with no visible glyph


def _wrap_anywhere(label: QLabel, run: int = 14) -> None:
    """Make a QLabel wrap even inside a long unbreakable token.

    QLabel's word wrap only breaks at whitespace, so a long percent-encoded
    URI (no spaces) overflows the card. This inserts zero-width spaces into
    long non-space runs -- and marks natural separators (/ & ? = , |) as break
    points -- so setWordWrap(True) can fold the line. It edits only what the
    widget DISPLAYS; "Copy selected" reads the original PatternEvent text (see
    _event_copy_text), so the copied string keeps no zero-width characters."""
    text = label.text()
    out: list[str] = []
    since = 0
    for ch in text:
        out.append(ch)
        if ch.isspace() or ch in "/&?=,|":
            since = 0
        else:
            since += 1
            if since >= run:
                out.append(_ZWSP)
                since = 0
    label.setText("".join(out))


def _picker_greyed() -> list[PatternPreset]:
    """Presets the pattern picker shows disabled (not selectable): in the
    database proxy honeypot layer, the CVEs the single-eshop / two-database
    honeypot cannot isolate (db_isolated=False). In the default reverse proxy
    layer nothing is greyed.

    That topology switches the DATABASE per request but shares one filesystem
    and one PHP runtime, so file-upload / path-traversal / config-disclosure /
    RCE attacks land on the real production-shared filesystem/runtime rather
    than the switched database -- running them here would not be contained;
    see ids/ids/db_proxy/COVERAGE.md."""
    if not honeypot_layer.is_database():
        return []
    return [p for p in active_presets() if not p.db_isolated]


def _picker_groups(kind: str = "", component: str = "", surface: str = "",
                   include_restore: bool = False):
    """Grouped presets for a PatternPickerButton: the active battery narrowed
    to a test category (kind/component/surface; "" means any), grouped under
    headings by core.patterns.group_presets. The gdpr_signature session-restore
    demo is not a CVE in the battery (not in PATTERN_PRESETS), so it is appended
    under its own heading only when asked -- a single-run target, never part of
    the Multi-run batch."""
    groups = list(group_presets(active_presets(), kind, component, surface))
    if include_restore:
        groups.append(("GDPR signature", [GDPR_RESTORE_PRESET]))
    return groups


def _event_copy_text(event: PatternEvent) -> str:
    """Plain-text rendering of one event -- exactly its label/detail as
    shown on the card, with its real log timestamp prepended (falls back to
    "unknown time" if the tail wasn't run with --timestamps, or the line
    predates the timestamp-extraction feature)."""
    ts = event.timestamp or "unknown time"
    text = f"{ts}  {event.label}"
    if event.detail:
        text += f"  |  {event.detail}"
    return text


class _EventCard(QFrame):
    """One pattern-event card -- a selection checkbox plus the event's
    label/detail, colored by event.color. Selection state lives on the
    card itself (self.checkbox) so PatternDiagramWidget can just walk its
    layout for "Copy selected" rather than maintaining a parallel list that
    could drift out of sync with which cards actually still exist."""

    def __init__(self, event: PatternEvent, parent=None):
        super().__init__(parent)
        self.event = event

        colors = theme.scheme_colors()
        card_bg, detail_color = colors["bg_alt"], colors["fg_muted"]
        self.setStyleSheet(
            f"_EventCard {{ background-color: {card_bg}; border-left: 4px solid {event.color}; "
            f"border-radius: {theme.corner_radius_css(3)}; }}"
        )
        card_layout = QHBoxLayout(self)
        card_layout.setContentsMargins(4, 4, 8, 4)
        card_layout.setSpacing(4)

        # Plain-language "what does this signal mean" on hover, for
        # students reading the timeline (core/learning.explain_event).
        explanation = explain_event(event.label)
        if explanation:
            self.setToolTip(explanation)

        self.checkbox = QCheckBox()
        self.checkbox.setToolTip("Select for \"Copy selected\"")
        card_layout.addWidget(self.checkbox, alignment=Qt.AlignmentFlag.AlignTop)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        label = QLabel(event.label)
        label.setStyleSheet(f"color: {event.color}; font-weight: bold;")
        # Wrap the label too (some events -- e.g. a "HIGH RISK SCORE" routing
        # line -- can carry long text). TextWrapAnywhere so an unbreakable token
        # (a long percent-encoded URI with no spaces) still wraps instead of
        # overflowing the card.
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        _wrap_anywhere(label)
        text_layout.addWidget(label)

        if event.detail:
            detail = QLabel(event.detail)
            detail.setStyleSheet(f"color: {detail_color}; font-size: 11px;")
            detail.setWordWrap(True)
            detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            _wrap_anywhere(detail)
            text_layout.addWidget(detail)

        if event.timestamp:
            ts_label = QLabel(event.timestamp)
            ts_label.setStyleSheet(f"color: {detail_color}; font-size: 10px;")
            text_layout.addWidget(ts_label)

        card_layout.addLayout(text_layout, stretch=1)


class PatternDiagramWidget(QWidget):
    """Scrolling, newest-first timeline of colored pattern-analyzer event
    cards -- the "what just happened, and why" view, complementing the
    raw log tab. Fed one PatternEvent at a time by PatternsPage as its
    pattern_log tail streams in.

    Each card carries a selection checkbox -- "Copy selected" builds a
    plain-text block from every checked card (one or many), each line
    exactly the card's own label/detail text plus its real log timestamp
    (PatternEvent.timestamp, from `docker compose logs --timestamps` --
    see page_patterns.py's _start_pattern_log() and
    core/pattern_log_parser.py's _DOCKER_TIMESTAMP_RE)."""

    MAX_EVENTS = 200

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Pattern-analyzer activity, newest first:"))
        top_row.addStretch()
        self.select_all_btn = QPushButton("Select/Deselect all")
        self.select_all_btn.setToolTip(
            "Selects every message's checkbox below, or deselects them all if "
            "every one is already checked."
        )
        self.select_all_btn.clicked.connect(self._toggle_select_all)
        top_row.addWidget(self.select_all_btn)
        self.copy_btn = QPushButton("Copy selected")
        self.copy_btn.setToolTip("Copy every checked message below as plain text, with its log timestamp.")
        self.copy_btn.clicked.connect(self._copy_selected)
        top_row.addWidget(self.copy_btn)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        top_row.addWidget(clear_btn)
        layout.addLayout(top_row)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        # No horizontal scrolling: keep the cards bounded to the viewport width
        # so long labels/details (a full attack URI + its matched patterns) wrap
        # onto multiple lines and stay fully visible, instead of running off the
        # right edge behind a horizontal scrollbar.
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(self.scroll)

        self._inner = QWidget()
        self._inner_layout = QVBoxLayout(self._inner)
        self._inner_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(self._inner)

        self._count = 0

    def clear(self) -> None:
        while self._inner_layout.count():
            item = self._inner_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._count = 0

    def _cards(self) -> list[_EventCard]:
        cards = []
        for i in range(self._inner_layout.count()):
            widget = self._inner_layout.itemAt(i).widget()
            if isinstance(widget, _EventCard):
                cards.append(widget)
        return cards

    def _toggle_select_all(self) -> None:
        cards = self._cards()
        if not cards:
            return
        # If everything's already checked, this click means "deselect all";
        # otherwise (none or only some checked) it means "select all" --
        # same convention as a tri-state "select all" checkbox, just as a
        # plain button instead (this is a QHBoxLayout of QPushButtons, not
        # a checkbox list, so a real tri-state checkbox doesn't fit here).
        select = not all(card.checkbox.isChecked() for card in cards)
        for card in cards:
            card.checkbox.setChecked(select)

    def _copy_selected(self) -> None:
        selected = [card for card in self._cards() if card.checkbox.isChecked()]
        if not selected:
            QMessageBox.information(
                self, "Nothing selected",
                "Tick the checkbox on one or more messages below first, then Copy selected.",
            )
            return
        text = "\n".join(_event_copy_text(card.event) for card in selected)
        QApplication.clipboard().setText(text)

    def add_event(self, event: PatternEvent) -> None:
        card = _EventCard(event)
        self._inner_layout.insertWidget(0, card)
        self._count += 1

        # Bounded history -- this tab is "what just happened", not an
        # archive (the raw log tab already covers that, capped via
        # LogPanel's own setMaximumBlockCount).
        while self._count > self.MAX_EVENTS:
            item = self._inner_layout.takeAt(self._inner_layout.count() - 1)
            if item.widget():
                item.widget().deleteLater()
            self._count -= 1


def _default_eshop_url(state: AppState) -> str:
    host = state.primary_remote_host("edge")
    return f"https://{host}/"


class PatternsPage(QWidget):
    # Emitted (with a pattern label) whenever a pattern is run from this page,
    # so the Workload Telemetry page can drop a time-aligned marker on its graphs.
    pattern_ran = pyqtSignal(str)
    # Shown -> MainWindow asks the StatusPoller for an immediate poll.
    refresh_requested = pyqtSignal()

    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        # Guards showEvent()'s auto-restart of the log tail against
        # clobbering an in-flight "Unpoison host IP" reverse_proxy
        # restart (which can take over a minute -- see _unpoison_host_ip's
        # own comment) if the user switches away from this page and back
        # while it's still running: showEvent calling _start_pattern_log()
        # would call LogPanel.run(), which kills whatever process is
        # currently attached first -- including a restart still in
        # progress, not just the harmless log tail it's meant to refresh.
        self._unpoison_restarting = False

        layout = QVBoxLayout(self)

        # Wraps onto more rows in a narrow window instead of forcing it wider.
        toolbar = FlowLayout()
        self.reset_btn = QPushButton("Reset local score + cookies")
        self.reset_btn.setToolTip(
            "Clears this browser's cookies. The reverse proxy recognises the same "
            "browser by its passive fingerprint and gives it back its session, as it "
            "would a user clearing cookies; use \"Unpoison host IP\" to really "
            "start from a fresh session."
        )
        self.reset_btn.clicked.connect(self._reset_local_score)
        toolbar.addWidget(self.reset_btn)

        # A checkbox popup rather than a 30-row dropdown: the checked set is the
        # Multi-run / report battery, the highlighted row is the single-run
        # target (see PatternPickerButton). Filled by _apply_category_filters.
        self.pattern_picker = PatternPickerButton(mode="multi")
        self.pattern_picker.selection_changed.connect(self._refresh_multi_run_button)
        # Test-category filters now live INSIDE the picker popup (top), instead
        # of a toolbar row of their own -- same (kind, component, surface)
        # selection, read back via _selection(), re-applied on category_changed.
        self.pattern_picker.add_category_filters([
            ("kind", "Type", KINDS, "Generic attacks are classes and tools (XSS, SQL injection, "
             "wordlist scans, scanner user agents); CVE patterns are one published vulnerability."),
            ("component", "Target", COMPONENTS, "WordPress core, or a plugin / theme."),
            ("surface", "Surface", SURFACES, "Frontend: what visitors see (XSS, defacement). "
             "Backend: admin, configuration, authentication and data (wp-config, SQL injection)."),
        ])
        self.pattern_picker.category_changed.connect(self._apply_category_filters)
        self.pattern_picker.setMinimumWidth(340)
        toolbar.addWidget(labeled("Pattern:", self.pattern_picker))
        self.explain_btn = QPushButton("What is this?")
        self.explain_btn.setToolTip(
            "How the selected pattern works, its OWASP Top 10 / MITRE ATT&CK "
            "category, and how to defend against it.")
        self.explain_btn.clicked.connect(self._explain_selected_pattern)
        toolbar.addWidget(self.explain_btn)
        # Two separate buttons, not one "Run pattern" that did both --
        # confirmed live this was the actual cause of pattern-analyzer
        # scores that looked internally inconsistent ("math doesn't add
        # up"): the old single button ran the preset via curl (its real
        # headers/body -- the CVE-specific payload) AND THEN navigated the
        # embedded browser to the same path with a PLAIN GET (no pattern
        # headers at all). That's two genuinely different requests with
        # two genuinely different signal profiles, a couple seconds apart
        # -- e.g. curl scoring 100 (CVE header + automation UA + URI
        # pattern) immediately followed by the browser's bare GET scoring
        # only 25 (URI pattern alone), both landing on HONEYPOT because
        # the SESSION was already sticky-bound from the first -- which
        # reads as "two wildly different scores for the same pattern" if
        # you don't already know two separate requests were involved.
        # Splitting into two buttons means exactly one request goes out
        # per click, sent exactly the way that button says it will be.
        self.run_curl_btn = QPushButton("Run pattern (curl)")
        self.run_curl_btn.setToolTip(
            "Sends the preset's real request (method/headers/body) via curl -- "
            "stateless, no browser cookies involved. This is what actually "
            "carries the pattern payload (e.g. the CVE-specific header)."
        )
        self.run_curl_btn.clicked.connect(self._run_selected_pattern_curl)
        toolbar.addWidget(self.run_curl_btn)
        self.run_browser_btn = QPushButton("Run pattern (browser)")
        self.run_browser_btn.setToolTip(
            "Navigates the embedded browser to the preset's URL as a plain GET, "
            "using whatever session cookie the browser already holds -- the "
            "visitor's-eye view of that path, NOT a re-send of the preset's own "
            "headers/body (a browser navigation can't carry those). Useful to see "
            "what a real visitor would see at this URL, or to confirm a session "
            "that curl already bound to a honeypot pool routes consistently."
        )
        self.run_browser_btn.clicked.connect(self._run_selected_pattern_browser)
        toolbar.addWidget(self.run_browser_btn)
        # Runs every pattern the test-category selector currently lists, one
        # after another, each exactly like "Run pattern (curl)". Click again
        # while it runs to stop after the current pattern.
        self.multi_run_btn = QPushButton("Multi-run (curl)")
        self.multi_run_btn.setToolTip(
            "Runs every pattern matching the Type / Target / Surface selection "
            "below, one after another, each sent via curl like \"Run pattern "
            "(curl)\". No threat-state reset between them, so the score builds "
            "up as it would for a real user. Click again to stop.")
        self.multi_run_btn.clicked.connect(self._toggle_multi_run)
        toolbar.addWidget(self.multi_run_btn)
        self._multi_queue: list[PatternPreset] = []
        self._multi_total = 0
        # Bumped on every start, so a pending step of a stopped run that is
        # restarted within the gap doesn't fire into the new run.
        self._multi_gen = 0

        self.unpoison_btn = QPushButton("Unpoison host IP")
        self.unpoison_btn.setToolTip(
            "Clears threat_ips/session/pool-assignment entries in Redis for "
            "this machine's own shared IP, and restarts reverse_proxy (needed "
            "to also flush its in-memory copy of that same data) -- so the "
            "next pattern run always starts from a fresh, production-routed "
            "session. Server-side: affects curl-run patterns too, not just "
            "the embedded browser. Can take up to a couple minutes -- "
            "confirmed live reverse_proxy's own graceful shutdown often "
            "waits out in-flight keepalive connections (keepalive_timeout "
            "120s on its upstreams) rather than restarting instantly -- but "
            "no data loss, same as the Restart button elsewhere in this app."
        )
        self.unpoison_btn.clicked.connect(self._unpoison_host_ip)
        toolbar.addWidget(self.unpoison_btn)

        # Global reset: unlike "Unpoison host IP" (just this host's own
        # entries + a proxy restart), this wipes every adversary's scored
        # session, IP reputation, cached Suricata alerts and sticky pool
        # assignments across the whole session store, plus the dashboard's
        # recorded event history -- a clean slate for a fresh demo/lab.
        self.clear_attacks_btn = danger_button("Clear all attacks")
        self.clear_attacks_btn.setToolTip(
            "Wipe all accumulated attack state and history across the session store "
            "(keeps the honeypot pool registry and running containers).")
        self.clear_attacks_btn.clicked.connect(
            lambda: clear_all_attacks(self, self.state, on_cleared=self._clear_pattern_analyzer))
        toolbar.addWidget(self.clear_attacks_btn)

        self.export_btn = QPushButton("Export report (PDF)")
        self.export_btn.setToolTip(
            "Runs a fixed battery of pattern test scenarios against the live "
            "reverse_proxy and saves a PDF report: every preset run once from a "
            "freshly reset threat state (score/route/signals + a browser "
            "screenshot each), then a threat-increase scenario (two semi-random "
            "patterns x3 rounds, no reset, showing the score climb), then a "
            "threat-decay scenario (no reset -- samples the score decaying over "
            "~2 min against the router's own decay model). Takes a few minutes; "
            "shows progress and can be cancelled."
        )
        self.export_btn.clicked.connect(self._export_report)
        toolbar.addWidget(self.export_btn)

        layout.addLayout(toolbar)

        # One-line reminder of the picker's two roles (its single biggest
        # source of confusion), sitting where the category-filter row used to
        # be now that those filters live inside the picker popup.
        picker_hint = QLabel(
            "Open <b>Pattern</b> to choose: the <b>checked</b> patterns are the "
            "Multi-run / PDF battery; the <b>highlighted</b> one is what a single "
            "<i>Run pattern</i> targets. Filter the list from the same popup.")
        picker_hint.setTextFormat(Qt.TextFormat.RichText)
        picker_hint.setWordWrap(True)
        picker_hint.setStyleSheet("color: #888888; font-size: 11px;")
        layout.addWidget(picker_hint)

        # The test-category filters moved into the pattern picker popup (see
        # add_category_filters above); this just does the initial population /
        # multi-run count.
        self._apply_category_filters()

        # Explains the greyed-out presets. Shown only in the database proxy
        # layer (single-eshop / two-database honeypot), which isolates
        # database-layer attacks only.
        self.coverage_note = coverage_note = QLabel(
            "Database proxy layer: greyed-out CVEs can't be isolated here. "
            "File-upload, path-traversal, config-disclosure and RCE attacks hit "
            "the shared filesystem/runtime, not the switched database. "
            "See ids/db_proxy/COVERAGE.md."
        )
        coverage_note.setWordWrap(True)
        coverage_note.setStyleSheet("color: #888888; font-size: 11px;")
        coverage_note.setVisible(honeypot_layer.is_database())
        layout.addWidget(coverage_note)

        # Report-export state (set up in _export_report, torn down on finish).
        self._report_worker: ReportWorker | None = None
        self._report_tmpdir: str | None = None
        self._report_gdpr = None  # GdprConsent for the current export, if agreed
        self._report_out_path: str = ""

        # In-page progress row for report export, kept OUT of the embedded
        # browser's area on purpose: the PDF's per-pattern screenshots are
        # grabs of that browser, so a modal QProgressDialog floating over the
        # window used to land in the screenshots. A sibling widget above the
        # splitter never overlaps the browser, so nothing has to be hidden
        # during the grab. Hidden until an export is running.
        # A staged overview (every export phase shown going pending -> active
        # -> done) rather than one anonymous bar, so it's clear which phase is
        # running and how many remain. The Cancel button sits beside it.
        self.report_progress_row = QFrame()
        self.report_progress_row.setFrameShape(QFrame.Shape.StyledPanel)
        _prog_outer = QVBoxLayout(self.report_progress_row)
        _prog_outer.setContentsMargins(10, 8, 10, 8)
        _prog_outer.setSpacing(6)
        _prog_header = QLabel("Generating PDF report")
        _prog_header.setStyleSheet("font-weight: 600;")
        _prog_outer.addWidget(_prog_header)
        _prog_layout = QHBoxLayout()
        _prog_layout.setContentsMargins(0, 0, 0, 0)
        self.report_stages = ReportStagesWidget()
        self.report_cancel_btn = QPushButton("Cancel")
        self.report_cancel_btn.clicked.connect(self._cancel_report)
        _prog_layout.addWidget(self.report_stages, stretch=1)
        _cancel_col = QVBoxLayout()
        _cancel_col.addWidget(self.report_cancel_btn)
        _cancel_col.addStretch(1)
        _prog_layout.addLayout(_cancel_col)
        _prog_outer.addLayout(_prog_layout)
        # Auto-updating estimate of how much longer the export will take (see
        # core/eta.py). The tracker re-anchors on every progress emission; a
        # 1 s timer ticks the figure down smoothly between emissions.
        self.report_eta_label = QLabel("")
        self.report_eta_label.setStyleSheet("color: #9aa0a6; font-size: 11px;")
        _prog_outer.addWidget(self.report_eta_label)
        self._report_eta = EtaTracker()
        self._report_t0 = 0.0
        self._report_eta_timer = QTimer(self)
        self._report_eta_timer.setInterval(1000)
        self._report_eta_timer.timeout.connect(self._tick_report_eta)
        self.report_progress_row.setVisible(False)

        # Same red banner pattern as the Kibana/Backups/Pool State Store pages -- the
        # embedded browser's own error page just says something generic
        # like "can't reach this page" with no way to tell "is the eshop
        # actually down, or something else" (a pattern_analyzer/router.lua
        # bug, a bad pattern request, ...). production_eshop/reverse_proxy
        # not running means nothing works at all; a honeypot_eshop_N pool
        # being down means some fraction of traffic (whichever gets routed
        # to it) would silently fail while production traffic looks fine --
        # worth surfacing either way before assuming a pattern itself is
        # what's broken.
        self.error_banner = ErrorBanner()
        layout.addWidget(self.error_banner)

        # Second row: status/result info, kept separate from the controls
        # above so the window doesn't need to grow wide enough to fit both
        # on one line.
        status_row = QHBoxLayout()
        self.result_label = QLabel("")
        status_row.addWidget(self.result_label)
        status_row.addStretch()

        # Live risk score, colored to match router.lua's own
        # honeypot_threshold bands (see _score_badge_color()). Updated from
        # the "[LOCATION / HEADER] route_decision=... risk_score=..."
        # line, which nginx.conf emits exactly once per request regardless
        # of outcome -- the single most reliable per-request summary line
        # to drive this from.
        self.score_badge = QLabel(f"Score: --/{SCORE_MAX}")
        self.score_badge.setStyleSheet(
            "QLabel { background-color: #444444; color: #d4d4d4; padding: 4px 10px; "
            f"border-radius: {theme.corner_radius_css(4)}; font-weight: bold; }}"
        )
        status_row.addWidget(self.score_badge)

        # Routing outcome (production vs. honeypot) from the latest
        # "outcome"-kind log event -- a separate signal from the score
        # badge, since a request can score low but still land on honeypot
        # (sticky session, IP reputation, ...) or vice versa.
        self.route_label = QLabel("Route: --")
        self.route_label.setStyleSheet(
            "QLabel { background-color: #444444; color: #d4d4d4; padding: 4px 10px; "
            f"border-radius: {theme.corner_radius_css(4)}; font-weight: bold; }}"
        )
        status_row.addSpacing(6)
        status_row.addWidget(self.route_label)
        layout.addLayout(status_row)

        layout.addWidget(self.report_progress_row)

        # Browser beside the analyzer tabs, stacked above them in a narrow window.
        self.splitter = ResponsiveSplitter(breakpoint=1100)
        layout.addWidget(self.splitter, stretch=1)

        self.browser = BrowserWidget(_default_eshop_url(state))
        self.splitter.addWidget(self.browser)

        tabs = QTabWidget()
        self.pattern_log = LogPanel(show_stop_button=False)
        tabs.addTab(self.pattern_log, "Pattern analyzer log")
        self.diagram = PatternDiagramWidget()
        tabs.addTab(self.diagram, "Pattern analyzer")
        self.manual_tab = _ManualRequestTab(state)
        tabs.addTab(self.manual_tab, "Manual request (curl)")
        self.scenario_tab = ScenarioScriptsTab(state)
        tabs.addTab(self.scenario_tab, "Scenario scripts")
        self.tabs = tabs
        tabs.setCurrentWidget(self.diagram)  # GUI card view, not the raw log, is the default
        self.splitter.addWidget(tabs)
        self.splitter.setSizes([700, 500])

        self._line_buffer = LineBuffer()
        self.pattern_log.line_received.connect(self._on_pattern_log_output)

        self._start_pattern_log()

    def showEvent(self, event) -> None:
        """Restarts the pattern-analyzer log tail every time this page
        becomes visible again (switching to it from the sidebar/Ctrl+N,
        or un-minimizing the window while it's the current page) -- a
        fresh `docker compose logs --tail=200 -f` rather than whatever
        was left running (or had died) from the last time this page was
        open, so what you see is never stale just because you were on a
        different page for a while. Skipped while an "Unpoison host IP"
        restart is in flight -- see _unpoison_restarting's comment."""
        super().showEvent(event)
        if not self._unpoison_restarting:
            self._start_pattern_log()
        # Fresh status via the background poller (MainWindow wires this to
        # StatusPoller.poll_now()); a synchronous ps() here froze the UI.
        self.refresh_requested.emit()

    # ---- target / base URL ----

    def _selection(self) -> tuple[str, str, str]:
        """The test-category selector as (kind, component, surface); "" = all.
        Read from the filters embedded in the pattern picker popup."""
        return (self.pattern_picker.category_value("kind"),
                self.pattern_picker.category_value("component"),
                self.pattern_picker.category_value("surface"))

    def _selected_presets(self) -> list[PatternPreset]:
        """The patterns Multi-run / the report cover: the checked rows of the
        picker (greyed, non-DB-isolatable ones can't be checked, so they're
        already left out)."""
        return self.pattern_picker.checked_presets()

    def _apply_category_filters(self) -> None:
        """Narrow the pattern list to the selected test categories, keeping the
        checked batch by identity across the change."""
        kind, component, surface = self._selection()
        self.pattern_picker.set_groups(
            _picker_groups(kind, component, surface, include_restore=True),
            greyed=_picker_greyed(), batch_excluded=[GDPR_RESTORE_PRESET])
        self._refresh_multi_run_button()

    def _refresh_multi_run_button(self) -> None:
        count = len(self._selected_presets())
        if not self._multi_queue:
            self.multi_run_btn.setText(f"Multi-run (curl, {count})")
            self.multi_run_btn.setEnabled(
                count > 0 and getattr(self, "_report_worker", None) is None)

    def _target(self):
        return target_for("edge", self.state)

    def _base_url(self) -> str:
        url = self.browser.view.url()
        if url.isValid() and url.scheme() in ("http", "https") and url.host():
            return f"{url.scheme()}://{url.host()}"
        return _default_eshop_url(self.state).rstrip("/")

    def set_honeypot_layer(self) -> None:
        """The ids stack's honeypot layer changed (Workloads page): re-grey the
        presets and show/hide the coverage note to match."""
        self._apply_category_filters()
        self.manual_tab.preset_combo.set_groups(
            _picker_groups(), greyed=_picker_greyed(), blank_label="(blank request)")
        self.coverage_note.setVisible(honeypot_layer.is_database())

    def reload_patterns(self) -> None:
        """A pattern was enabled/disabled/added/removed in the Pattern Database:
        rebuild the selector and the manual preset list so the battery reflects
        only the patterns that are currently enabled."""
        self._apply_category_filters()
        self.manual_tab.preset_combo.set_groups(
            _picker_groups(), greyed=_picker_greyed(), blank_label="(blank request)")

    # ---- reachability banner (production_eshop, reverse_proxy, and the
    # honeypot pools or both databases, depending on the layer) ----

    def apply_status(self, results: dict[str, list[dict]]) -> None:
        """Called from MainWindow's existing background StatusPoller
        (same results dict Workloads / Global Visualization pagess already get -- no extra
        polling of our own) every poll tick while this page might not
        even be the visible one, so the banner is already current the
        moment the user switches to it. showEvent() also asks the poller for
        an immediate poll (refresh_requested) rather than waiting out the
        rest of the current poll interval."""
        self._update_reachability_banner(results.get(self._target().key, []))

    def _update_reachability_banner(self, containers: list[dict]) -> None:
        by_service = {c.get("Service"): c for c in containers}
        # Database proxy layer: the one production_eshop serves every request
        # and picks the database (production_database vs honeypot_database)
        # per request, so watch both databases instead of the pool eshops.
        if honeypot_layer.is_database():
            watched = ["production_eshop", "reverse_proxy", "production_database", "honeypot_database"]
        else:
            watched = ["production_eshop", "reverse_proxy", "honeypot_eshop_1", "honeypot_eshop_2", "honeypot_eshop_3"]

        down = []
        for service in watched:
            container = by_service.get(service)
            if container is None:
                down.append(f"{service} (not running)")
            elif container.get("State") != "running":
                down.append(f"{service} ({container.get('State', 'unknown')})")

        if down:
            self.error_banner.setText(
                "⚠ Not reachable: " + ", ".join(down) + " -- patterns/browsing here may "
                "fail or behave unexpectedly until it's back up. Start it from the "
                "Workloads page."
            )
            self.error_banner.setVisible(True)
        else:
            self.error_banner.setVisible(False)

    # ---- threat log tail -> parsed events (score badge + diagram tab) ----

    def _start_pattern_log(self, tail: int = 200) -> None:
        self._line_buffer = LineBuffer()
        self._pending_final_score_event = None
        self._pending_final_score_generation = 0
        # --timestamps: lets pattern_log_parser.parse_line() attach each
        # event's real log timestamp (PatternEvent.timestamp) -- used by the
        # Pattern analyzer tab's "Copy selected" (see PatternDiagramWidget).
        argv, cwd = self._target().build("logs", "--timestamps", f"--tail={tail}", "-f", "reverse_proxy")
        self.pattern_log.run(argv, cwd)

    def _on_pattern_log_output(self, chunk: str) -> None:
        for line in self._line_buffer.feed(chunk):
            event = parse_line(line)
            if event is None:
                continue
            self._handle_pattern_event(event)

    def _handle_pattern_event(self, event: PatternEvent) -> None:
        # pattern_analyzer.lua's own "Final score: N/80 (verdict)" line is
        # logged for EVERY request, including ones on an already
        # honeypot_bound session -- there, the routing decision comes from
        # the EXISTING sticky binding (router.lua Stage 2), not from this
        # request's own score, so a "Final score: 0/80 | clean" card right
        # next to "Session bound to ... HONEYPOT" reads as a contradiction
        # ("routed to honeypot but score 0??") rather than the (correct,
        # just differently-sourced) reality. Chronologically, threat_
        # analyzer's own log line always comes BEFORE router.lua's -- with
        # this tab showing newest-first, that means the final_score event
        # arrives here one step ahead of the routing event it might need
        # to be dropped for, hence the one-event lookahead buffer below.
        # Only ever drops a genuinely 0-score card; a nonzero score in that
        # position (this request ALSO tripped something, just not enough
        # alone) is still worth keeping.
        if event.kind == "final_score":
            self._flush_pending_final_score()
            self._pending_final_score_event = event
            self._pending_final_score_generation += 1
            # Safety net: if no follow-up log line arrives within a
            # couple seconds (traffic went quiet, or this genuinely was
            # the last event in the tail), flush anyway. Without this, a
            # final_score event that ISN'T actually followed by a sticky
            # "Session bound to" line (the only case meant to suppress
            # it) could stay invisibly buffered indefinitely with nothing
            # left to trigger flushing it -- the generation check below
            # is what keeps this from wrongly flushing a NEWER pending
            # event if one has since replaced it.
            gen = self._pending_final_score_generation
            QTimer.singleShot(1500, lambda g=gen: self._flush_pending_final_score_if_gen(g))
            return

        if (self._pending_final_score_event is not None and event.kind == "routing"
                and event.label == "Session bound to" and self._pending_final_score_event.score == 0):
            self._pending_final_score_event = None  # suppressed
        else:
            self._flush_pending_final_score()

        self._add_pattern_event(event)

    def _flush_pending_final_score_if_gen(self, gen: int) -> None:
        if self._pending_final_score_generation == gen:
            self._flush_pending_final_score()

    def _flush_pending_final_score(self) -> None:
        if self._pending_final_score_event is not None:
            self._add_pattern_event(self._pending_final_score_event)
            self._pending_final_score_event = None

    def _add_pattern_event(self, event: PatternEvent) -> None:
        self.diagram.add_event(event)
        if event.kind == "outcome":
            if event.score is not None:
                self._update_score_badge(event.score)
            self._update_route_label(event)

    def _update_score_badge(self, score: int) -> None:
        if score >= _SCORE_HIGH_AT:
            color = COLOR_HIGH
        elif score >= _SCORE_MED_AT:
            color = COLOR_MED
        else:
            color = COLOR_LOW
        self.score_badge.setText(f"Score: {score}/{SCORE_MAX}")
        self.score_badge.setStyleSheet(
            f"QLabel {{ background-color: {color}; color: #1e1e1e; padding: 4px 10px; "
            f"border-radius: {theme.corner_radius_css(4)}; font-weight: bold; }}"
        )

    def _update_route_label(self, event: PatternEvent) -> None:
        is_honeypot = "HONEYPOT" in event.label.upper()
        text = "Routed to HONEYPOT" if is_honeypot else "Routed to PROD"
        color = COLOR_MED if is_honeypot else COLOR_LOW
        self.route_label.setText(text)
        self.route_label.setStyleSheet(
            f"QLabel {{ background-color: {color}; color: #1e1e1e; padding: 4px 10px; "
            f"border-radius: {theme.corner_radius_css(4)}; font-weight: bold; }}"
        )

    # ---- toolbar actions ----

    def _reset_local_score(self) -> None:
        self.browser.clear_cookies()
        self.browser.reload_home()
        self.result_label.setText(
            "Cookies cleared -- the proxy will recover this browser's session by its "
            "fingerprint. Use \"Unpoison host IP\" for a fresh session.")
        self.result_label.setStyleSheet("color: #5cb85c;")

    def _explain_selected_pattern(self) -> None:
        preset: PatternPreset = self.pattern_picker.current_preset()
        if preset is None:
            return
        box = QMessageBox(self)
        box.setWindowTitle(f"About {preset.cve}")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(pattern_lesson_html(preset))
        box.exec()

    def _run_selected_pattern_curl(self) -> None:
        """Sends the preset's real request (its own method/headers/body --
        the actual pattern payload) via curl. Stateless: no browser
        cookies read or written. This is the ONLY button that carries the
        preset's headers/body -- Run pattern (browser) below sends a
        plain GET instead, since a browser navigation has no way to carry
        those."""
        preset: PatternPreset = self.pattern_picker.current_preset()
        if preset is None:
            return
        if is_gdpr_restore(preset):
            self._demo_session_restore()
            return
        if not self._runnable(preset):
            return
        self._send_curl(preset)

    def _send_curl(self, preset: PatternPreset, prefix: str = "") -> None:
        """One curl run of `preset` (shared by the single and multi-run
        buttons); `prefix` goes in front of the result line."""
        self.pattern_ran.emit(f"{preset.cve} — {preset.name} (curl)")
        base_url = self._base_url()
        argv = build_curl_argv(preset, base_url)
        # Also present the internal test secret so production_eshop's
        # honeypot-db-backend-header mu-plugin reports which database container
        # actually served this request (X-DB-* headers) -- surfaced in the
        # Pattern analyzer GUI below. No-op if the secret can't be read.
        secret = self._internal_secret() if honeypot_layer.is_database() else ""
        if secret:
            argv = [*argv, "-H", f"X-Internal-Test-Auth: {secret}"]

        self.result_label.setText(f"{prefix}Running {preset.cve} (curl)...")
        self.result_label.setStyleSheet("color: #888888;")
        self.repaint()

        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        except (subprocess.TimeoutExpired, OSError) as e:
            self.result_label.setText(f"{prefix}✗ {preset.cve} (curl) failed: {e}")
            self.result_label.setStyleSheet("color: #d9534f;")
            return

        status_line = result.stdout.splitlines()[0] if result.stdout else "(no response)"
        self.result_label.setText(f"{prefix}{preset.cve} (curl): {status_line}")
        self.result_label.setStyleSheet("color: #5cb85c;")
        self._show_db_backend(result.stdout)

    # Pause between multi-run patterns, so each one's pattern-analyzer lines
    # and Resources-page marker stay apart and the UI repaints in between.
    _MULTI_RUN_GAP_MS = 1500

    def _toggle_multi_run(self) -> None:
        """Start a multi-run of the current selection, or stop the running one."""
        if self._multi_queue:
            self._multi_queue = []
            self._finish_multi_run("Multi-run stopped.")
            return
        presets = self._selected_presets()
        if not presets:
            return
        self._multi_queue = list(presets)
        self._multi_total = len(presets)
        self._multi_gen += 1
        self.multi_run_btn.setText("Stop multi-run")
        for widget in (self.run_curl_btn, self.run_browser_btn, self.export_btn):
            widget.setEnabled(False)
        self.pattern_picker.set_categories_enabled(False)
        self._multi_run_next()

    def _multi_run_next(self, gen: int | None = None) -> None:
        if not self._multi_queue or (gen is not None and gen != self._multi_gen):
            return  # stopped (or restarted since this step was scheduled)
        preset = self._multi_queue.pop(0)
        done = self._multi_total - len(self._multi_queue)
        self._send_curl(preset, prefix=f"[{done}/{self._multi_total}] ")
        if self._multi_queue:
            gen = self._multi_gen
            QTimer.singleShot(self._MULTI_RUN_GAP_MS, lambda: self._multi_run_next(gen))
        else:
            self._finish_multi_run(
                f"Multi-run done: {self._multi_total} pattern(s) "
                f"({selection_label(*self._selection())}). Last: {self.result_label.text()}")

    def _finish_multi_run(self, message: str) -> None:
        for widget in (self.run_curl_btn, self.run_browser_btn, self.export_btn):
            widget.setEnabled(True)
        self.pattern_picker.set_categories_enabled(True)
        self._apply_category_filters()  # restores the button's label/count
        self.result_label.setText(message)

    def _run_selected_pattern_browser(self) -> None:
        """Navigates the embedded browser to the preset's URL as a plain
        GET, using whatever session cookie the browser already holds --
        the visitor's-eye view of that path. Does NOT send the preset's
        headers/body (Run pattern (curl) above is the one that does)."""
        preset: PatternPreset = self.pattern_picker.current_preset()
        if preset is None:
            return
        if is_gdpr_restore(preset):
            self._demo_session_restore()
            return
        if not self._runnable(preset):
            return
        self.pattern_ran.emit(f"{preset.cve} — {preset.name} (browser)")
        base_url = self._base_url()
        self.result_label.setText(f"Navigating to {preset.path} (browser)...")
        self.result_label.setStyleSheet("color: #888888;")
        self.browser.navigate(base_url + preset.path)

    def _demo_session_restore(self) -> None:
        """Interactive counterpart to the gdpr_signature restore pattern: wipe
        this window's cookies AND localStorage (dropping the SERVERID session
        and the stored GDPR consent), then reload so the consent banner
        reappears for re-consent. The browser characteristics are unchanged, so
        on re-consent the proxy re-derives the SAME one-way signature and
        re-routes to the honeypot the window was bound to. The full
        attack -> bind -> clear -> restore proof (with a consent-withheld
        control) is in the exported PDF, section 4."""
        self.pattern_ran.emit(f"{GDPR_RESTORE_PRESET.cve} — {GDPR_RESTORE_PRESET.name}")
        self.browser.clear_cookies()
        try:
            self.browser.view.page().runJavaScript(_CLEAR_STORAGE_JS)
        except Exception:  # noqa: BLE001 -- storage clear is best-effort
            pass
        self.browser.reload_home()
        self.result_label.setText(
            "Cleared this window's cookies and localStorage (session + stored consent "
            "dropped). Re-agree when the GDPR banner reappears: the proxy re-derives the "
            "same gdpr_signature and re-routes to the honeypot it was bound to. Export the "
            "report (with GDPR agreed) for the full attack → clear → restore proof "
            "(section 4).")
        self.result_label.setStyleSheet("color: #5cb85c;")

    def _runnable(self, preset: PatternPreset) -> bool:
        """Guard: the greyed-out (db_isolated=False) presets aren't selectable
        in the combo, but if one is ever current, refuse to run it here and
        explain why (this honeypot can't contain it)."""
        if preset.db_isolated or not honeypot_layer.is_database():
            return True
        QMessageBox.information(
            self, "Not applicable to this honeypot",
            f"{preset.cve} -- {preset.name}\n\nThis database-proxy honeypot "
            f"cannot isolate this pattern:\n\n{preset.coverage_note}",
        )
        return False

    def _internal_secret(self) -> str:
        """The INTERNAL_TEST_SECRET from the edge .env (cached), used to unlock
        production_eshop's X-DB-* debug headers. Empty string if unreadable."""
        cached = getattr(self, "_internal_secret_cache", None)
        if cached is not None:
            return cached
        secret = ""
        try:
            env = load_project_env("edge", self._target().remote)
            secret = env.get("INTERNAL_TEST_SECRET", "").strip()
        except EnvUploadError:
            secret = ""
        self._internal_secret_cache = secret
        return secret

    def _show_db_backend(self, response_text: str) -> None:
        """Parse the X-DB-* response headers emitted by production_eshop's
        honeypot-db-backend-header mu-plugin and add a "database container
        response" card to the Pattern analyzer GUI, exposing which database
        (production vs honeypot) actually served the request -- proven by the
        real SELECTs the mu-plugin ran against the resolved $wpdb. Silently does
        nothing if the headers aren't present (secret missing, or a request that
        didn't reach WordPress)."""
        head = response_text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
        fields: dict[str, str] = {}
        for line in head.splitlines():
            low = line.lower()
            for key in ("x-db-backend", "x-db-host", "x-db-server", "x-db-probe"):
                if low.startswith(key + ":"):
                    fields[key] = line.split(":", 1)[1].strip()
        backend = fields.get("x-db-backend")
        if not backend:
            return
        is_honeypot = backend.lower() == "honeypot"
        color = COLOR_HIGH if is_honeypot else COLOR_LOW
        host = fields.get("x-db-host", "?")
        label = f"Database container: {backend.upper()} ({host})"
        # The actual SELECTs that ran, as reported by the DB container itself.
        detail = fields.get("x-db-probe", "")
        server = fields.get("x-db-server")
        if server and server not in detail:
            detail = f"served by {server} | {detail}" if detail else f"served by {server}"
        self.diagram.add_event(PatternEvent("database", label, detail, color))

    def _unpoison_host_ip(self) -> None:
        target = self._target()
        self.result_label.setText("Unpoisoning host IP (clearing Redis)...")
        self.result_label.setStyleSheet("color: #888888;")
        self.repaint()

        try:
            summary = clear_local_threat_state(target.remote)
        except RedisInspectError as e:
            self.result_label.setText(f"✗ Unpoison failed: {e}")
            self.result_label.setStyleSheet("color: #d9534f;")
            return

        # Clearing Redis alone isn't enough: pattern_analyzer.lua's hot-path
        # IP-reputation check (check_ip_reputation(), pattern_analyzer.lua)
        # reads ngx.shared.threat_intel -- an in-memory dict living INSIDE
        # the reverse_proxy worker process, not Redis -- "it never touches
        # Redis directly, for latency" (see init_worker.lua's own comment
        # on this). Writers such as vulnerability_handler.lua update
        # that shared dict directly (bypassing Redis-then-resync) for
        # exactly this reason, and it has no TTL, so a stale in-memory
        # entry survives indefinitely regardless of what Redis says.
        # Confirmed live: after clearing Redis alone, the NEXT request
        # still routed to honeypot at the same poisoned score -- only a
        # reverse_proxy restart (fresh worker process = fresh empty shared
        # dict) actually cleared it. There's no API to reach into another
        # process's Lua shared-memory zone from outside, so this is the
        # only real fix.
        #
        # Run through the same LogPanel that tails pattern-analyzer logs
        # (QProcess, non-blocking) rather than a synchronous
        # subprocess.run() -- confirmed live this restart specifically can
        # take over a minute (nginx's graceful shutdown waits out
        # in-flight keepalive connections rather than dropping them, and
        # this container's upstreams are configured with keepalive_timeout
        # 120s), and every other Restart button in this app (Health/
        # Workloads pages) is already non-blocking for exactly this reason
        # -- freezing the whole UI for a minute-plus on a button click
        # would be a real regression from that established pattern, not
        # just a cosmetic difference. The panel doubles as visible
        # progress feedback during the wait instead of a frozen button.
        self._unpoison_summary = summary
        self.result_label.setText(
            "Redis cleared -- restarting reverse_proxy to flush its in-memory "
            "copy too (can take a while -- see the Pattern analyzer log tab)..."
        )
        argv, cwd = target.build("restart", "reverse_proxy")
        # Connect AFTER run(), not before: run() calls stop() internally
        # first, which kills whatever was previously running (the log
        # tail started in __init__) and synchronously fires ITS finished
        # signal -- connecting before run() catches that stale kill event
        # (confirmed live: exit code 9/SIGKILL, instantly) instead of this
        # restart command's actual completion.
        self._unpoison_restarting = True
        self.pattern_log.run(argv, cwd)
        self.pattern_log.finished.connect(self._on_unpoison_restart_finished)

    def _on_unpoison_restart_finished(self, exit_code: int) -> None:
        self.pattern_log.finished.disconnect(self._on_unpoison_restart_finished)
        self._unpoison_restarting = False
        summary = getattr(self, "_unpoison_summary", {})

        if exit_code != 0:
            self.result_label.setText(
                f"✗ Redis cleared, but reverse_proxy restart exited with code {exit_code}"
            )
            self.result_label.setStyleSheet("color: #d9534f;")
        else:
            cleared = (
                bool(summary.get("threat_ips_removed"))
                or bool(summary.get("sessions_removed"))
                or bool(summary.get("pool_assignments_removed"))
            )
            detail = (
                f"{summary.get('sessions_removed', 0)} session(s), "
                f"threat_ips {summary.get('threat_ips_removed', [])}, "
                f"pool assignments {summary.get('pool_assignments_removed', [])}"
                if cleared else "Redis was already clean"
            )
            self.result_label.setText(f"✓ Unpoisoned + reverse_proxy restarted: {detail}")
            self.result_label.setStyleSheet("color: #5cb85c;")

        # tail=0: only show what happens from now on, not the pre-restart history.
        self._start_pattern_log(tail=0)  # resume live tailing on the fresh container
        if exit_code == 0:
            # Drop the browser's old session cookie and load the home page: the
            # clean request it makes is what puts "score 0 / PROD" into the threat
            # analyzer, so it shows the host as clean. Slight delay so the log tail
            # is attached before the request is logged.
            self.browser.clear_cookies()
            QTimer.singleShot(1500, self.browser.reload_home)

    # ---- PDF report export ----

    def _export_report(self) -> None:
        if self._report_worker is not None:
            return  # already running
        # The report covers the checked battery (same set as Multi-run), and its
        # header names the test-category selection. Unlike Multi-run it also
        # keeps the non-DB-isolatable ones in the current selection, which the
        # picker can't check: the report's bypass section is where those show.
        presets = list(self.pattern_picker.checked_presets())
        for p in filter_presets(active_presets(), *self._selection()):
            if honeypot_layer.is_database() and not p.db_isolated and p not in presets:
                presets.append(p)
        if not presets:
            QMessageBox.information(self, "Nothing to export",
                                    "No pattern matches the current selection.")
            return
        default_name = "pattern_report.pdf"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save pattern report", default_name, "PDF files (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"

        # GDPR consent gate: the export runs automated test traffic, so the
        # operator must agree before it starts. On agreement the traffic carries
        # a consented gdpr_token (see ids/GDPR.md); Cancel aborts the export.
        proceed, gdpr = request_gdpr_consent(self, self._base_url())
        if not proceed:
            return
        self._report_gdpr = gdpr  # cleaned up in _on_report_thread_finished

        self._report_out_path = path

        # Per-run temp dir for the browser screenshots the PDF embeds.
        self._report_tmpdir = tempfile.mkdtemp(prefix="pattern_report_")

        # Result state for the single teardown point (_on_report_thread_finished).
        self._report_render_error = ""
        self._report_worker_error = ""

        # Start the pattern analyzer from empty so it shows only this run, live:
        # the report's requests stream into it as they happen, next to the browser
        # that loads each pattern page.
        self._clear_pattern_analyzer()
        self._saved_zoom = self.browser.view.zoomFactor()

        worker = ReportWorker(self._target(), self._base_url(), presets=presets,
                              selection=selection_label(*self._selection()),
                              gdpr=self._report_gdpr,
                              gdpr_characteristics=gdpr_screen_characteristics())
        worker.progress.connect(self._on_report_progress)
        # Queued (worker is a QThread, this slot lives on the GUI thread) --
        # screenshot capture MUST run here where the QWebEngineView lives.
        worker.screenshot_request.connect(self._on_report_screenshot_request)
        worker.kibana_timeline_request.connect(self._on_report_kibana_timeline_request)
        worker.finished_ok.connect(self._on_report_finished)
        worker.failed.connect(self._on_report_failed)
        # QThread.finished fires on EVERY exit path (success, failure, AND an
        # early return from cancel -- which emits neither finished_ok nor
        # failed), so teardown hangs off it, not off those two, or a cancelled
        # run would leak the dialog/tmpdir and leave the button disabled.
        worker.finished.connect(self._on_report_thread_finished)
        self._report_worker = worker

        self.report_stages.reset(len(presets))
        self.report_cancel_btn.setEnabled(True)
        self.report_cancel_btn.setText("Cancel")
        self._report_t0 = time.monotonic()
        self._report_eta.reset()
        self.report_eta_label.setText("Estimated time remaining: estimating…")
        self._report_eta_timer.start()
        self.report_progress_row.setVisible(True)

        self.export_btn.setEnabled(False)
        self.multi_run_btn.setEnabled(False)
        self.pattern_picker.set_categories_enabled(False)
        # The browser is idle for most of the export -- only a screenshot grab
        # actually uses it (see _on_report_screenshot_request). Veil it now so
        # it clearly reads as "not in use", and lift the veil only for a grab.
        self.browser.set_dimmed(
            True, "Idle during export — shown live only while a screenshot is being captured.")
        worker.start()

    def _on_report_progress(self, message: str, current: int, total: int) -> None:
        fraction = current / total if total else 0.0
        self.report_stages.update(fraction, message)
        self._report_eta.update(time.monotonic() - self._report_t0, fraction)
        self._tick_report_eta()

    def _tick_report_eta(self) -> None:
        """Refresh the "estimated time remaining" line (on the 1 s timer and on
        each real progress emission)."""
        if self._report_worker is None:
            return
        remaining = self._report_eta.remaining_at(time.monotonic() - self._report_t0)
        self.report_eta_label.setText(f"Estimated time remaining: {format_eta(remaining)}")

    def _on_report_screenshot_request(self, url: str, key: str) -> None:
        """GUI-thread screenshot: navigate the embedded browser to `url`, wait
        for it to finish loading, grab it, and hand the saved path back to the
        worker (which is blocked waiting for exactly this)."""
        path = ""
        # This is the only moment the browser is actually in use during an
        # export, so lift the idle veil for the capture and put it back after.
        self.browser.set_dimmed(False)
        try:
            path = self._capture_browser(url, key)
        finally:
            if self._report_worker is not None and self._report_worker._cancel:  # noqa: SLF001
                self.browser.set_dimmed(False)   # teardown is imminent; don't flash the veil back
            else:
                self.browser.set_dimmed(
                    True, "Idle during export — shown live only while a screenshot is being captured.")
            if self._report_worker is not None:
                self._report_worker.provide_screenshot(key, path)

    def _on_report_kibana_timeline_request(self, start: float, end: float, key: str) -> None:
        """GUI-thread Kibana screenshot of the requests between ``start`` and
        ``end`` (epoch), handed back to the worker like _on_report_screenshot_request."""
        worker = self._report_worker

        def _done(path: str) -> None:
            if worker is not None and worker is self._report_worker:
                worker.provide_kibana_timeline(key, path)

        try:
            if getattr(self, "_kibana_capture", None) is None:
                # Imported here: ui.page_kibana pulls in the SIEM Analytics page's
                # widgets, which this page otherwise doesn't need.
                from core.kibana_credentials import get_elastic_credentials
                from ui.page_kibana import _AUTOLOGIN_JS_TEMPLATE, _default_kibana_url
                import json as _json
                creds = get_elastic_credentials(self.state)
                login = (_AUTOLOGIN_JS_TEMPLATE % {"username": _json.dumps(creds[0]),
                                                   "password": _json.dumps(creds[1])}
                         if creds else None)
                self._kibana_capture = KibanaTimelineCapture(
                    _default_kibana_url(self.state), login, parent=self)
            safe_key = key.replace("/", "_").replace(":", "_")
            out = os.path.join(self._report_tmpdir, f"{safe_key}.png")
            self._kibana_capture.capture(start, end, out, _done)
        except Exception:  # noqa: BLE001 -- the report just goes without it
            _done("")

    def _clear_pattern_analyzer(self) -> None:
        """Empty the pattern analyzer tab and reset the score/route badges."""
        self.diagram.clear()
        self._pending_final_score_event = None
        self._pending_final_score_generation = getattr(self, "_pending_final_score_generation", 0) + 1
        self.tabs.setCurrentWidget(self.diagram)
        self._update_score_badge(0)
        self.route_label.setText("Routed to PROD")
        self.route_label.setStyleSheet(
            f"QLabel {{ background-color: {COLOR_LOW}; color: #1e1e1e; padding: 4px 10px; "
            f"border-radius: {theme.corner_radius_css(4)}; font-weight: bold; }}"
        )

    def _capture_browser(self, url: str, key: str) -> str:
        """Load `url` in the embedded browser and grab it. The browser pane is
        widened just for this (more native pixels, sharper once the PDF
        downscales it) and put back right after, so the pattern analyzer stays
        visible for the rest of the run."""
        sizes = self.splitter.sizes()
        total_w = sum(sizes) or self.splitter.width()
        self.splitter.setSizes([max(total_w - 24, 200), 24])
        try:
            return self._capture_browser_widened(url, key)
        finally:
            self.splitter.setSizes(sizes)

    def _capture_browser_widened(self, url: str, key: str) -> str:
        assert self._report_tmpdir is not None
        view = self.browser.view

        # Navigate and wait for loadFinished, with a hard timeout so a stuck
        # load can never hang the whole export. Zoom is per-page and resets on
        # each load, so it's (re)applied both before AND after the navigation.
        view.setZoomFactor(_CAPTURE_ZOOM)
        loop = QEventLoop()

        def _on_load(_ok: bool) -> None:
            loop.quit()

        conn = view.loadFinished.connect(_on_load)
        self.browser.navigate(url)
        QTimer.singleShot(9000, loop.quit)
        loop.exec()
        try:
            view.loadFinished.disconnect(conn)
        except TypeError:
            pass
        view.setZoomFactor(_CAPTURE_ZOOM)
        # Settle so the page reflows at the capture zoom and actually paints
        # before the grab.
        self._spin(700)

        safe_key = key.replace("/", "_").replace(":", "_")
        path = os.path.join(self._report_tmpdir, f"{safe_key}.png")

        # The export's progress indicator is now an in-page widget above the
        # splitter (see report_progress_row in __init__), not a floating dialog,
        # so it never overlaps the browser and nothing has to be hidden for the
        # grab. view.grab() renders just the widget tree; on GPU compositor
        # setups where the web layer isn't in that render it comes back blank,
        # and the fallback reads the on-screen framebuffer for the browser's
        # region only -- which the progress row (being elsewhere) can't taint.
        win = self.window()
        win.raise_()
        win.activateWindow()
        self._spin(150)  # let the raise reach the framebuffer

        pixmap = view.grab()
        if pixmap.isNull() or self._looks_blank(pixmap):
            fallback = self.screen_grab(view)
            if not fallback.isNull() and not self._looks_blank(fallback):
                pixmap = fallback

        # Save the full-resolution capture as-is (no scaling/sharpening here --
        # the PDF downscales it to its display width, which is what yields a
        # crisp image at print DPI). Force devicePixelRatio 1 so every physical
        # pixel a HiDPI grab produced is written to the PNG rather than being
        # treated as a smaller logical image.
        image = pixmap.toImage()
        image.setDevicePixelRatio(1.0)
        image.save(path)
        return path

    @staticmethod
    def screen_grab(view):
        """The on-screen pixels of `view`, read through its TOP-LEVEL window.
        Never view.winId(): asking a child widget for its id turns it into a
        native window for good, and a native QWebEngineView inside the
        layout paints black patches, takes clicks at its old position and
        stops resizing with the window (the pool test hit this as soon as a
        frame's grab came back blank, e.g. the delayed windows')."""
        win = view.window()
        handle = win.windowHandle()
        screen = handle.screen() if handle else QApplication.primaryScreen()
        if screen is None:
            return QPixmap()
        pos = view.mapTo(win, QPoint(0, 0))
        return screen.grabWindow(int(win.winId()), pos.x(), pos.y(),
                                 view.width(), view.height())

    def _spin(self, ms: int) -> None:
        """Run the GUI event loop for `ms` (lets navigation/reflow/repaint and
        window show/hide actually happen mid-capture without blocking)."""
        loop = QEventLoop()
        QTimer.singleShot(ms, loop.quit)
        loop.exec()

    @staticmethod
    def _looks_blank(pixmap) -> bool:
        """True only if the grab is essentially ONE flat colour (nothing
        rendered). Deliberately strict: the eshop pages are mostly white, so a
        loose 'few distinct colours' test used to false-positive on a
        perfectly good screenshot and needlessly fall back to the framebuffer
        grab. Samples a dense grid and calls it blank only when the single
        dominant colour covers >=99% of the samples."""
        img = pixmap.toImage()
        if img.isNull() or img.width() < 4 or img.height() < 4:
            return True
        counts: dict[int, int] = {}
        total = 0
        step_x = max(1, img.width() // 40)
        step_y = max(1, img.height() // 40)
        for y in range(0, img.height(), step_y):
            for x in range(0, img.width(), step_x):
                rgb = img.pixelColor(x, y).rgb()
                counts[rgb] = counts.get(rgb, 0) + 1
                total += 1
        if total == 0:
            return True
        return (max(counts.values()) / total) >= 0.99

    def _cancel_report(self) -> None:
        if self._report_worker is not None:
            self._report_worker.cancel()
        self.report_cancel_btn.setEnabled(False)
        self.report_cancel_btn.setText("Cancelling…")

    def _on_report_finished(self, data) -> None:
        # Fires before QThread.finished. Render the PDF here (GUI thread --
        # QtGui/print machinery); the teardown below reads _report_render_error.
        try:
            pattern_report_pdf.render_pdf(data, self._report_out_path)
        except Exception as e:  # noqa: BLE001 -- report any render failure to the user
            self._report_render_error = str(e)

    def _on_report_failed(self, message: str) -> None:
        self._report_worker_error = message

    def _on_report_thread_finished(self) -> None:
        """Single teardown point -- runs on success, failure, and cancel."""
        out_path = self._report_out_path
        cancelled = self._report_worker is not None and self._report_worker._cancel  # noqa: SLF001
        error = self._report_worker_error or self._report_render_error

        self._report_eta_timer.stop()
        self.report_progress_row.setVisible(False)
        self.browser.set_dimmed(False)   # export over -- hand the browser back
        self.pattern_picker.set_categories_enabled(True)
        if not cancelled and not error:
            self.report_stages.mark_all_done()
        if getattr(self, "_kibana_capture", None) is not None:
            self._kibana_capture.close()
            self._kibana_capture.deleteLater()
            self._kibana_capture = None
        if self._report_worker is not None:
            self._report_worker.deleteLater()
            self._report_worker = None
        if self._report_tmpdir is not None:
            shutil.rmtree(self._report_tmpdir, ignore_errors=True)
            self._report_tmpdir = None
        if getattr(self, "_report_gdpr", None) is not None:
            self._report_gdpr.cleanup()  # remove the temp key material
            self._report_gdpr = None
        # Restore the page zoom (the pane width is restored after each capture).
        if getattr(self, "_saved_zoom", None) is not None:
            self.browser.view.setZoomFactor(self._saved_zoom)
            self._saved_zoom = None
        self.export_btn.setEnabled(True)
        self._apply_category_filters()  # re-enables Multi-run
        self.browser.reload_home()

        if cancelled:
            self.result_label.setText("Report export cancelled.")
            self.result_label.setStyleSheet("color: #888888;")
            return
        if error:
            self.result_label.setText(f"✗ Report export failed: {error}")
            self.result_label.setStyleSheet("color: #d9534f;")
            QMessageBox.warning(self, "Report export failed", error)
            return
        self.result_label.setText(f"✓ Report saved: {out_path}")
        self.result_label.setStyleSheet("color: #5cb85c;")
        if QMessageBox.question(
            self, "Report saved",
            f"Saved pattern report to:\n{out_path}\n\nOpen it now?",
        ) == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(out_path))

    def rebuild_targets(self) -> None:
        """Call when remote settings change (Connectors & Config page) -- the next
        pattern run / log tail picks up the new target automatically since
        _target()/_base_url() are computed fresh each time; this just
        restarts the log tail against the (possibly new) target."""
        self._start_pattern_log()


class _ManualRequestTab(QWidget):
    """Postman-style manual request builder: method/URL/headers/body,
    loadable from the same pattern presets (editable afterward), sent via
    curl with the raw response (status + headers + body, from curl's own
    -i output) shown below."""

    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state

        layout = QVBoxLayout(self)

        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("Load preset:"))
        self.preset_combo = PatternPickerButton(mode="single")
        self.preset_combo.set_groups(_picker_groups(), greyed=_picker_greyed(),
                                     blank_label="(blank request)")
        preset_row.addWidget(self.preset_combo, stretch=1)
        load_btn = QPushButton("Load")
        load_btn.setToolTip("Fill the fields below from this preset -- still editable before sending.")
        load_btn.clicked.connect(self._load_preset)
        preset_row.addWidget(load_btn)
        layout.addLayout(preset_row)

        request_row = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(_METHODS)
        request_row.addWidget(self.method_combo)
        self.url_edit = QLineEdit(_default_eshop_url(state).rstrip("/") + "/")
        request_row.addWidget(self.url_edit, stretch=1)
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self._send)
        request_row.addWidget(self.send_btn)
        layout.addLayout(request_row)

        headers_group = QGroupBox("Headers")
        headers_layout = QVBoxLayout(headers_group)
        self.headers_table = QTableWidget(0, 2)
        self.headers_table.setHorizontalHeaderLabels(["Name", "Value"])
        self.headers_table.setMaximumHeight(120)
        headers_layout.addWidget(self.headers_table)
        headers_btn_row = QHBoxLayout()
        add_header_btn = QPushButton("Add header")
        add_header_btn.clicked.connect(lambda: self.headers_table.insertRow(self.headers_table.rowCount()))
        remove_header_btn = QPushButton("Remove selected")
        remove_header_btn.clicked.connect(self._remove_selected_header)
        headers_btn_row.addWidget(add_header_btn)
        headers_btn_row.addWidget(remove_header_btn)
        headers_btn_row.addStretch()
        headers_layout.addLayout(headers_btn_row)
        layout.addWidget(headers_group)

        body_group = QGroupBox("Body (sent as POST data -- also switches the request to use it as the "
                                "curl -d payload regardless of method)")
        body_layout = QVBoxLayout(body_group)
        self.body_edit = QPlainTextEdit()
        self.body_edit.setMaximumHeight(100)
        body_layout.addWidget(self.body_edit)
        layout.addWidget(body_group)

        layout.addWidget(QLabel("Response:"))
        self.response_view = QPlainTextEdit(readOnly=True)
        self.response_view.setStyleSheet("QPlainTextEdit { font-family: monospace; font-size: 11px; }")
        layout.addWidget(self.response_view, stretch=1)

    def _remove_selected_header(self) -> None:
        rows = sorted({idx.row() for idx in self.headers_table.selectedIndexes()}, reverse=True)
        for row in rows:
            self.headers_table.removeRow(row)

    def _load_preset(self) -> None:
        preset: PatternPreset | None = self.preset_combo.current_preset()
        if preset is None:
            return
        base = _default_eshop_url(self.state).rstrip("/")
        self.method_combo.setCurrentText(preset.method)
        self.url_edit.setText(base + preset.path)
        self.headers_table.setRowCount(0)
        for name, value in preset.headers.items():
            row = self.headers_table.rowCount()
            self.headers_table.insertRow(row)
            self.headers_table.setItem(row, 0, QTableWidgetItem(name))
            self.headers_table.setItem(row, 1, QTableWidgetItem(value))
        self.body_edit.setPlainText(preset.body)

    def _send(self) -> None:
        url = self.url_edit.text().strip()
        if not url:
            return
        method = self.method_combo.currentText()
        body = self.body_edit.toPlainText()

        # -g/--globoff: see core/patterns.py's build_curl_argv -- the same
        # "[" range-globbing surprise applies here for anything a user
        # types or loads with literal brackets in it.
        argv = ["curl", "-sk", "-g", "-i", "-X", method, url]
        for row in range(self.headers_table.rowCount()):
            name_item = self.headers_table.item(row, 0)
            value_item = self.headers_table.item(row, 1)
            name = name_item.text().strip() if name_item else ""
            value = value_item.text().strip() if value_item else ""
            if name:
                argv += ["-H", f"{name}: {value}"]
        if body:
            argv += ["-d", body]

        self.response_view.setPlainText(f"$ {' '.join(argv)}\n\nSending...")
        self.repaint()

        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        except (subprocess.TimeoutExpired, OSError) as e:
            self.response_view.setPlainText(f"$ {' '.join(argv)}\n\nRequest failed: {e}")
            return

        output = result.stdout or "(empty response)"
        if result.stderr:
            output += f"\n\n[stderr]\n{result.stderr}"
        self.response_view.setPlainText(f"$ {' '.join(argv)}\n\n{output}")
