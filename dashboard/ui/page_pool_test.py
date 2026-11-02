"""Segmentation Validation page: 3 to 10 embedded browsers, each its own user session,
to see how the honeypot pool receives several users at once.

In the database proxy layer (core/honeypot_layer.py) a pool is a honeypot
database: one production_eshop serves every window and connects a diverted
session to its own database. The run then offers and plays only the patterns
that layer isolates, and tells the windows apart in each database's MySQL
query log, by the WooCommerce session key in each window's cookie (see
core/pool_evidence.py).

Every frame is a BrowserWidget, i.e. its own off-the-record profile and so its
own cookie jar -- the proxy hands each one a separate signed session cookie.
Cookies alone are not enough, though: a request that arrives WITHOUT a cookie
is matched to an existing session by a passive fingerprint (TLS hello,
User-Agent, Accept-Language, client IP; see session_identity_rules.lua), and
frames of one app on one machine would otherwise share all of it, so every
frame after the first would be folded into the first frame's session. Each
frame therefore gets its own User-Agent suffix and Accept-Language, which is
what makes the proxy see different clients.

"Attack" sends the same pattern request from the frame; once the score tips,
the session is bound to a honeypot pool. The pools scale with the number of
user sessions (pool_manager builds one per session until its resource
limit, then the rest share round-robin), so a window may borrow a pool for a
while and then move to its own. The pool summary (from the Redis pool
registry) shows how many pools are ready, how many sessions each owns and how
many still wait for theirs.
"""
from __future__ import annotations

import hashlib
import json
import random
import secrets
import time
from datetime import datetime

from PyQt6.QtCore import QEventLoop, QObject, Qt, QThread, QTimer, QUrl, pyqtSignal
from PyQt6.QtWebEngineCore import QWebEngineLoadingInfo, QWebEngineScript
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtNetwork import QNetworkCookie
from PyQt6.QtWidgets import (
    QCheckBox, QFileDialog, QGroupBox, QHBoxLayout, QLabel, QMessageBox,
    QProgressBar, QPushButton, QSpinBox, QSplitter, QVBoxLayout, QWidget,
)

from core import honeypot_layer, redis_inspect
from core.docker_ctl import target_for
from core.eta import EtaTracker, format_eta
from core.patterns import PATTERN_PRESETS, GDPR_RESTORE_PRESET, group_presets, is_gdpr_restore
from core.pattern_registry import active_presets
from ui.pattern_picker import PatternPickerButton
from core import pool_evidence
from core.pool_test_report import (COOKIE_FORGERIES, ProductListUnreadable, capacity_warning, CART_PLAN, MAX_ATTEMPTS, MAX_WINDOWS,
                                    MIN_WINDOWS, CartState, ClearEvent, Decision, PatternRun, FrameResult,
                                    LoadTiming, PoolTestData, Sample, StepResult, UsageSample,
                                    browse_action, browse_page, classify, clear_schedule, fallback_patterns,
                                    parse_cart, parse_decision, parse_product_ids, window_plan)
from core.resource_stats import collect_pool_usage, host_stats
from core.state import AppState
from ui import theme
from ui.browser_widget import BrowserWidget
from ui.common import (clear_all_attacks, danger_button,
                       gdpr_screen_characteristics, request_gdpr_consent)
from ui.flow_layout import FlowLayout, labeled

# Name of the proxy's session cookie (init.lua: session.cookie_name).
SESSION_COOKIE = "SERVERID"

# Injected into every validation browser (see _install_gdpr_banner_suppressor)
# to auto-dismiss the proxy's in-page GDPR consent banner.
#
# This run consents to GDPR out-of-band: the dashboard injects each window's OWN
# distinct, consented gdpr_token cookie (_apply_gdpr_cookie), so the proxy
# already treats the window as consented. The banner that gdpr_client.js shows
# doesn't know about that and would otherwise sit on top of every page for the
# whole run. We deliberately do NOT click its "Agree": that handler makes
# gdpr_client.js mint its OWN token from just the screen size -- identical for
# every window on this one display -- which would overwrite the distinct
# per-window cookie and collapse the very segmentation this page demonstrates.
# So we simply take the banner down whenever it appears; the window stays
# consented through the injected token, and the popup never lingers.
_GDPR_BANNER_SUPPRESS_JS = """
(function () {
  "use strict";
  var BANNER_ID = "gdpr-consent-banner";
  function removeBanner() {
    var b = document.getElementById(BANNER_ID);
    if (b && b.parentNode) b.parentNode.removeChild(b);
  }
  function observe() {
    if (!document.documentElement) return;
    new MutationObserver(removeBanner).observe(
      document.documentElement, { childList: true, subtree: true });
  }
  removeBanner();
  observe();
  document.addEventListener("DOMContentLoaded", function () {
    removeBanner();
    observe();
  });
})();
"""


def _install_gdpr_banner_suppressor(profile) -> None:
    """Add the banner-suppressor to `profile` so it runs on every page load in
    that browser (at document creation, before gdpr_client.js inserts its
    banner). Idempotent: skipped if this profile already carries it."""
    scripts = profile.scripts()
    if scripts.find("gdpr-banner-suppressor"):
        return
    script = QWebEngineScript()
    script.setName("gdpr-banner-suppressor")
    script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
    script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
    script.setRunsOnSubFrames(False)
    script.setSourceCode(_GDPR_BANNER_SUPPRESS_JS)
    scripts.insert(script)

# (label, Accept-Language) per frame -- what makes the fingerprints differ.
FRAMES = [
    ("User A", "en-US,en;q=0.9"),
    ("User B", "de-DE,de;q=0.9"),
    ("User C", "fr-FR,fr;q=0.9"),
    ("User D", "es-ES,es;q=0.9"),
    ("User E", "it-IT,it;q=0.9"),
    ("User F", "nl-NL,nl;q=0.9"),
    ("User G", "pl-PL,pl;q=0.9"),
    ("User H", "sv-SE,sv;q=0.9"),
    ("User I", "cs-CZ,cs;q=0.9"),
    ("User J", "sk-SK,sk;q=0.9"),
]
assert len(FRAMES) == MAX_WINDOWS

# Windows per row before the frames wrap onto a second row.
ROW_MAX = 5

# How long the report waits for pool_manager to finish the forced scale-down.
SCALEDOWN_TIMEOUT_S = 300

# How long the report waits for pool_manager to build a pool for every window
# that is still borrowing one (a WordPress pool takes a few minutes).
SCALE_TIMEOUT_S = 900

# How often the pool state line ("Ready pools: ...") refreshes by itself, also
# while a report export runs (the export's steps wait in nested event loops,
# so the timer keeps firing).
POOL_REFRESH_MS = 5000

# A page load that fails is retried after each of these delays. Chromium aborts
# every request in flight with ERR_NETWORK_CHANGED whenever a host network
# interface appears or goes away -- which Docker does on each container it
# creates or removes (veth pairs). One pool build changes interfaces for about
# a minute, so the delays back off to ~15 s in all; the retry is a plain new
# navigation. Windows still on an error page are reloaded before every step.
LOAD_RETRY_DELAYS_MS = (800, 2000, 4000, 8000)
LOAD_RETRIES = len(LOAD_RETRY_DELAYS_MS)
# An attack page is retried at most this often, and only after a failure with
# no response at all (see _LoadRelay): an HTTP error answer means the honeypot
# got the request. A load cut off by ERR_NETWORK_CHANGED left the step's
# screenshot on Chrome's error page and its cart unreadable.
ATTACK_RETRIES = 1

# How long the clean-up after the reassignment check waits for the pool builds
# that check started, before removing them (a build takes about a minute).
CLEANUP_BUILD_TIMEOUT_S = 180

# While the report waits for pools, every window opens its next page this often.
BROWSE_EVERY_S = 10.0


# Clears the page origin's localStorage and sessionStorage, the way "clear site
# data" does; returns how many entries were removed.
_CLEAR_STORAGE_JS = ("(function(){var n=0;try{n+=localStorage.length;localStorage.clear();}catch(e){}"
                     "try{n+=sessionStorage.length;sessionStorage.clear();}catch(e){}return String(n);})()")


# Writes a made-up session into the page origin's localStorage and
# sessionStorage under the names a client-side session would use; returns how
# many entries it wrote. %s is the fake value (a JSON string literal).
_FORGE_STORAGE_JS = ("(function(v){var n=0,k=['SERVERID','session_id','sessionId','wc_session'];"
                     "for(var i=0;i<k.length;i++){try{localStorage.setItem(k[i],v);n++;}catch(e){}"
                     "try{sessionStorage.setItem(k[i],v);n++;}catch(e){}}return String(n);})(%s)")


# True once the cart page shows its cart. The block cart's server HTML already
# holds both its filled and empty-cart blocks; the root keeps "is-loading"
# until the Store API answered, and even then the line items and totals show
# grey skeleton placeholders for a few seconds more -- the screenshots caught
# those. So: no "is-loading", no skeleton left in the cart, and a product name
# or the empty-cart message on show. (Classic shortcode cart: its form or
# empty message.)
_CART_RENDERED_JS = ("(function(){var r=document.querySelector('.wp-block-woocommerce-cart');"
                     "if(r){return !r.classList.contains('is-loading')"
                     "&&!r.querySelector('[class*=skeleton]')"
                     "&&!!r.querySelector('.wc-block-components-product-name,.wc-block-cart__empty-cart__title');}"
                     "return !!document.querySelector('form.woocommerce-cart-form,.cart-empty');})()")


# Scrolls the rendered cart (its items, or the empty-cart message) to the top
# of the window.
_CART_SCROLL_JS = ("(function(){var e=document.querySelector('.wc-block-cart-items,"
                   ".wc-block-cart__empty-cart__title,form.woocommerce-cart-form,.cart-empty,"
                   ".wp-block-woocommerce-cart');if(e){e.scrollIntoView({block:'start'});"
                   "window.scrollBy(0,-20);}return true;})()")


# The HTTP status, title and URL of the page a window is on (status 0: no
# response, e.g. Chromium's error page after a failed load).
_PAGE_STATUS_JS = ("(function(){var s=0;try{var n=performance.getEntriesByType('navigation')[0];"
                   "s=n&&n.responseStatus||0;}catch(e){}return JSON.stringify("
                   "{s:s,t:document.title||'',u:location.href});})()")


# Reads the shop's own cart (WooCommerce Store API) from inside a window, so the
# request carries that window's cookies and is routed exactly like its own traffic.
_CART_JS = ("(function(){try{var x=new XMLHttpRequest();x.open('GET','/wp-json/wc/store/v1/cart',false);"
            "x.send();return x.responseText;}catch(e){return '';}})()")


def product_ids_js(slugs: list[str]) -> str:
    """JS that reads the product IDs for `slugs` from the shop's Store API in one
    request, run inside a window: the lookup is then an ordinary browser request
    of that window's own (production) session. Fetched from Python instead, it
    was a scripted client to the proxy, got diverted to a honeypot and took a
    free pool away from the windows (one of them then had to borrow a pool)."""
    url = "/wp-json/wc/store/v1/products?per_page=100&slug=" + ",".join(slugs)
    return ("(function(){try{var x=new XMLHttpRequest();x.open('GET','" + url + "',false);"
            "x.send();return x.responseText;}catch(e){return '';}})()")


class _Cancelled(Exception):
    """Raised inside the scenario when the user presses Cancel."""


# A grab that comes back solid black (nothing painted yet) is retried this
# often, this far apart.
GRAB_REPAINT_TRIES = 4
GRAB_REPAINT_MS = 250


def _flat_black(pixmap) -> bool:
    """True when the grab is (almost) entirely black: the view had not painted
    yet. A white near-empty page is a real screenshot and stays."""
    img = pixmap.toImage()
    if img.isNull() or img.width() < 4 or img.height() < 4:
        return False
    dark = total = 0
    for y in range(0, img.height(), max(1, img.height() // 30)):
        for x in range(0, img.width(), max(1, img.width() // 30)):
            total += 1
            dark += img.pixelColor(x, y).lightness() < 16
    return total > 0 and dark / total >= 0.99


class _LoadRelay(QObject):
    """A window's page loads, as "did the server answer". loadFinished(False)
    also fires for a page that came back with an HTTP error (a honeypot's 404
    or 400 to an attack request), which the report then retried as if the
    network had failed -- sending the attack several more times -- and showed
    as an error page. `done(answered)` is True whenever a response arrived,
    whatever its status; False only for a failure before one (connection
    refused, ERR_NETWORK_CHANGED, aborted). `http_status` is the last
    response's status (0 when none)."""

    done = pyqtSignal(bool)

    def __init__(self, browser, parent=None):
        super().__init__(parent)
        self.http_status = 0
        browser.page.loadingChanged.connect(self._on_loading)

    def _on_loading(self, info) -> None:
        status = info.status()
        if status == QWebEngineLoadingInfo.LoadStatus.LoadStartedStatus:
            return
        http = info.errorDomain() == QWebEngineLoadingInfo.ErrorDomain.HttpStatusCodeDomain
        answered = status == QWebEngineLoadingInfo.LoadStatus.LoadSucceededStatus or http
        self.http_status = info.errorCode() if http else 0
        self.done.emit(answered)


class _Job(QThread):
    """Runs one blocking callable (docker exec / redis-cli) off the GUI thread."""

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn
        self.result = None
        self.error: Exception | None = None

    def run(self) -> None:
        try:
            self.result = self._fn()
        except Exception as e:  # noqa: BLE001 -- handed back to the GUI thread
            self.error = e


class _UsageSampler(QThread):
    """Samples the honeypot pool containers' memory/CPU every `interval`
    seconds for the whole report run, so the PDF can show resource use going
    up while pools are built and down again at the scale-down."""

    def __init__(self, target, t0: float, parent=None, shared_eshop: bool = False):
        super().__init__(parent)
        self._target, self._t0 = target, t0
        self._shared_eshop = shared_eshop     # database layer: sample production_eshop too
        self.interval = 10.0
        self.samples: list[UsageSample] = []
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        while not self._stop:
            started = time.time()
            try:
                u = collect_pool_usage(self._target, shared_eshop=self._shared_eshop)
                try:
                    ready = redis_inspect.ready_pool_count(self._target.remote)
                except Exception:  # noqa: BLE001
                    ready = None
                host = host_stats(self._target)
                self.samples.append(UsageSample(
                    started - self._t0, u.containers, u.pools, u.mem_bytes / 2 ** 20,
                    u.cpu_percent, ready, host[2] if host else None,
                    u.eshop_mem_bytes / 2 ** 20 if u.eshop_mem_bytes is not None else None,
                    u.eshop_cpu_percent))
            except Exception:  # noqa: BLE001 -- a gap in the curve, not a failed run
                pass
            while not self._stop and time.time() - started < self.interval:
                self.msleep(200)


def frame_identity(base_user_agent: str, index: int) -> tuple[str, str]:
    """User-Agent and Accept-Language that make frame `index` a distinct client."""
    label, language = FRAMES[index]
    return f"{base_user_agent} PoolTest/{label[-1]}", language


def _default_eshop_url(state: AppState) -> str:
    host = state.primary_remote_host("edge")
    return f"https://{host}/"


class PoolTestPage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        # The honeypot layer a report run started on (the Workloads page can
        # switch it meanwhile; the run keeps the one it measured).
        self._layer_db = honeypot_layer.is_database()

        layout = QVBoxLayout(self)

        self.intro = QLabel(self._intro_text())
        self.intro.setWordWrap(True)
        self.intro.setStyleSheet("color: #aaaaaa;")
        layout.addWidget(self.intro)

        # Wraps onto more rows in a narrow window instead of forcing it wider.
        bar = FlowLayout()
        self.count_spin = QSpinBox()
        self.count_spin.setRange(MIN_WINDOWS, MAX_WINDOWS)
        self.count_spin.setValue(MIN_WINDOWS)
        self.count_spin.setToolTip(
            "How many browser windows (separate user sessions) to run side by side.")
        self.count_spin.valueChanged.connect(self.set_window_count)
        bar.addWidget(labeled("Windows:", self.count_spin))
        self.delayed_spin = QSpinBox()
        self.delayed_spin.setRange(0, MIN_WINDOWS)
        self.delayed_spin.setValue(0)
        self.delayed_spin.setToolTip(
            "How many of the windows (the last ones) attack only after the honeypot pool "
            "has been scaled up for them: the report first asks pool_manager for that many "
            "free pools and waits until they are ready, so these windows get a pool of their "
            "own at once instead of borrowing one round-robin. The other windows attack "
            "straight away and show the round-robin borrowing while pools are still being "
            "built.")
        bar.addWidget(labeled("of which wait for pools:", self.delayed_spin))
        # A searchable, grouped checkbox popup capped at half the window instead
        # of a 20-row dropdown (see PatternPickerButton). The checked set is
        # what "Attack from all" spreads across the windows (one attack per
        # window, round-robin -- a segmentation test with varied traffic); the
        # highlighted row is the single-window / GDPR-report target.
        # Registry-disabled patterns never appear.
        self.preset_combo = PatternPickerButton(mode="multi")
        self.preset_combo.setMinimumWidth(320)
        self._fill_presets()
        bar.addWidget(labeled("Pattern:", self.preset_combo))
        self.open_all_btn = QPushButton("Open shop in all")
        self.open_all_btn.clicked.connect(self.open_all)
        bar.addWidget(self.open_all_btn)
        self.attack_all_btn = QPushButton("Attack from all")
        self.attack_all_btn.setToolTip(
            "Each window opens one of the CHECKED patterns (spread round-robin, so "
            "different windows hit different attacks); with none checked, every "
            "window opens the highlighted one.")
        self.attack_all_btn.clicked.connect(self.attack_all)
        bar.addWidget(self.attack_all_btn)
        self.reset_btn = QPushButton("New sessions")
        self.reset_btn.setToolTip("Clear every frame's cookies, so each starts a fresh session.")
        self.reset_btn.clicked.connect(self.reset_sessions)
        bar.addWidget(self.reset_btn)
        self.clear_check = QCheckBox("Session tamper-proofing")
        self.clear_check.setChecked(True)
        self.clear_check.setToolTip(
            "During the report run, random windows tamper with their own session between "
            "steps:\n"
            "\u2022 delete it: clear their cookies or all site data, the way a visitor clears "
            "their browsing data -- the stack must still recognise the window (passive "
            "fingerprint) and keep it on its session;\n"
            "\u2022 forge it: rewrite the SERVERID cookie to an invented session or to another "
            "window's session with a made-up signature -- the proxy must reject it as not "
            "signed by the server (logged in Redis) and never hand out the claimed session; "
            "or write a fake session into localStorage, which the server must ignore.\n"
            "The PDF shows each event and what the stack did with the window afterwards.")
        bar.addWidget(self.clear_check)
        self.export_btn = QPushButton("Export report (PDF)")
        self.export_btn.setToolTip(
            "Which honeypot pool each window's session landed in, and whether that matches "
            "one user per pool (shared only when pools run out).")
        self.export_btn.clicked.connect(self.export_report)
        bar.addWidget(self.export_btn)
        # Global reset: wipe every adversary's scored session, IP reputation,
        # cached Suricata alerts and sticky pool assignments across the
        # session store, plus the dashboard's recorded event history -- a
        # clean slate before a validation run. Keeps the pool registry.
        self.clear_attacks_btn = danger_button("Clear all attacks")
        self.clear_attacks_btn.setToolTip(
            "Wipe all accumulated attack state and history across the session store "
            "(keeps the honeypot pool registry and running containers).")
        self.clear_attacks_btn.clicked.connect(
            lambda: clear_all_attacks(self, self.state, on_cleared=self.refresh_pool_state))
        bar.addWidget(self.clear_attacks_btn)
        layout.addLayout(bar)

        # In-page progress row (not a floating dialog, so it can never land in
        # the frames' screenshots) -- same pattern as the Attack Simulation page.
        self.progress_row = QWidget()
        prog = QHBoxLayout(self.progress_row)
        prog.setContentsMargins(0, 0, 0, 0)
        self.progress_label = QLabel("Preparing report...")
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(320)
        # Auto-updating estimate of how much longer the run will take. It is a
        # rough guide only -- the pool scale-up waits are highly variable -- so
        # it is labelled "~" (see core/eta.py).
        self.eta_label = QLabel("")
        self.eta_label.setStyleSheet("color: #9aa0a6;")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self._cancel_report)
        prog.addWidget(self.progress_label, stretch=1)
        prog.addWidget(self.progress_bar)
        prog.addWidget(self.eta_label)
        prog.addWidget(self.cancel_btn)
        self.progress_row.setVisible(False)
        layout.addWidget(self.progress_row)
        self._exporting = False
        self._cancelled = False
        # ETA tracker + a 1 s timer that ticks the figure down between the
        # scenario's (infrequent) progress emissions.
        self._eta = EtaTracker()
        self._export_t0 = 0.0
        self._eta_timer = QTimer(self)
        self._eta_timer.setInterval(1000)
        self._eta_timer.timeout.connect(self._tick_eta)
        # Idle veil over the frames during an export: they are driven
        # automatically by the run, so dim them "hands off" and only show a
        # frame live while it is actively loading a page or being captured
        # (same idea as the Attack Simulation browser). A depth counter so
        # nested active sections (a probe that falls back to a single load)
        # don't dim the frames back mid-section.
        self._frame_active_depth = 0
        self._frames_dimmed = False
        self._job: _Job | None = None
        # Consent-gated GDPR token for the current export run (set when the
        # operator agrees before exporting). Each window gets a DISTINCT token
        # so their one-way gdpr_signatures stay distinct and segmentation is
        # preserved -- see _apply_gdpr_cookie() and ids/GDPR.md.
        self._gdpr = None
        self._gdpr_chars: dict = {}
        # Report run timeline: seconds since its start (0 = no run going).
        self._t0 = 0.0
        self._samples: list[Sample] = []
        self._loads: list[LoadTiming] = []
        self._pending_loads: list[LoadTiming] = []
        self._marks: list[tuple[float, str]] = []
        self._reserve: dict = {}
        self._baseline: dict = {}   # pool_evidence baseline of the running report
        self._host_cpus, self._host_mem_total = 0, 0.0   # edge host, for the report
        self._sampling = False   # routing reads go into the run's timeline (see _observe)
        self._load_ok = [True] * MAX_WINDOWS     # last page load per window got a response
        self._relays: list[_LoadRelay] = []      # per window, see _LoadRelay
        self._pattern_urls: set[str] = set()     # attack URLs: never reloaded (_recover_error_pages)
        self._load_log: list[dict] = []          # this run's loads that failed at first (_log_load)

        self.pool_label = QLabel("")
        self.pool_label.setWordWrap(True)
        self.refresh_btn = QPushButton("Refresh pool state")
        self.refresh_btn.setToolTip(f"Also refreshes on its own every {POOL_REFRESH_MS // 1000} s, "
                                    "including while a report is being exported.")
        self.refresh_btn.clicked.connect(self.refresh_pool_state)
        row = QHBoxLayout()
        row.addWidget(self.pool_label, stretch=1)
        row.addWidget(self.refresh_btn)
        layout.addLayout(row)
        # The last report export's outcome, on its own line: the pool state
        # above refreshes on a timer and would overwrite it.
        self.export_label = QLabel("")
        self.export_label.setWordWrap(True)
        self.export_label.setVisible(False)
        layout.addWidget(self.export_label)

        # Frames are created on demand and only hidden (cookies cleared) when the
        # window count goes down, so a QWebEngine profile is never torn down
        # while its page is alive. Up to ROW_MAX per row, then a second row.
        self._rows = QSplitter(Qt.Orientation.Vertical)
        self._row_splitters = [QSplitter(Qt.Orientation.Horizontal) for _ in range(2)]
        for row in self._row_splitters:
            self._rows.addWidget(row)
        layout.addWidget(self._rows, stretch=1)
        self._count = 0
        self._boxes: list[QGroupBox] = []
        self._all_browsers: list[BrowserWidget] = []
        self._all_decisions: list[QLabel] = []
        self._all_carts: list[QLabel] = []
        # Per frame: the session id from the SERVERID cookie the proxy set it
        # ("<id>.<mac>"), kept up to date from the profile's cookie store.
        self._session_ids = [""] * MAX_WINDOWS
        # WooCommerce session key -> window, every key a window held during
        # the run (a cleared cookie brings a new one): the database layer's
        # query logs are attributed by it.
        self._wc_keys: dict[str, int] = {}
        # Pools whose query log a database-layer run turned on (None: none).
        self._qlog_pools: set[int] | None = None
        self._cookie_names: list[set[str]] = [set() for _ in range(MAX_WINDOWS)]
        self._visits = [0] * MAX_WINDOWS          # pages each window has browsed this run
        self._seen: list[list[str]] = [[] for _ in range(MAX_WINDOWS)]   # ... this step
        self.set_window_count(MIN_WINDOWS)

        # Keeps the labels under the frames current while browsing by hand.
        self._poll = QTimer(self)
        self._poll.setInterval(3000)
        self._poll.timeout.connect(self.refresh_decisions)
        # Keeps the pool state line current, export or not (see POOL_REFRESH_MS).
        self._pool_poll = QTimer(self)
        self._pool_poll.setInterval(POOL_REFRESH_MS)
        self._pool_poll.timeout.connect(self.refresh_pool_state)

    # ---- honeypot layer ----

    @staticmethod
    def _intro_text() -> str:
        if honeypot_layer.is_database():
            return ("3 to 10 browsers, each a separate session (own cookies, own User-Agent and "
                    "language, so the proxy cannot merge them). Database proxy level: a honeypot "
                    "pool is a honeypot database -- the one shop serves every window and "
                    "connects each diverted session to a database of its own. Attack from "
                    "several at once and check that every user gets a database of their own: "
                    "the databases scale with the user sessions until the resource limit, after "
                    "which the remaining sessions share them round-robin. A report run keeps "
                    "two thirds of its patterns on attacks that reach the honeypot database and "
                    "a third on WordPress attacks that slip past it to the shared files, so the "
                    "report shows both.")
        return ("3 to 10 browsers, each a separate session (own cookies, own User-Agent and "
                "language, so the proxy cannot merge them). Open the shop in each, then attack "
                "from several at once and check that every user lands in a honeypot pool "
                "of their own: the pools scale with the user sessions until the resource "
                "limit, after which the remaining sessions share the pools round-robin.")

    def _fill_presets(self) -> None:
        """The GET patterns a window can open by hand (the same in both
        layers; a report run on the database layer picks which reach the
        honeypot database, see core.pool_test_report.window_plan)."""
        get_presets = [p for p in active_presets() if p.method.upper() == "GET"]
        # Plus the GDPR-signature demonstration: highlighting it leaves the
        # per-window attacks as they are (the checked set, or window_plan when
        # nothing is checked -- see _attack_plan) but makes the report force the
        # "clear all site data" tamper on, so at least one diverted window clears
        # and re-consents -- and the report documents how its gdpr_signature
        # restored it (see export_report / signature_restorations()). It is a
        # report toggle, not a spreadable attack, so it is batch-excluded
        # (highlight-only, no checkbox).
        groups = list(group_presets(get_presets, "", "", ""))
        groups.append(("GDPR signature", [GDPR_RESTORE_PRESET]))
        self.preset_combo.set_groups(groups, batch_excluded=[GDPR_RESTORE_PRESET])

    def set_honeypot_layer(self) -> None:
        """The Workloads page switched the honeypot layer (only the intro and a
        report run's pattern choice depend on it; the dropdown is the same)."""
        self.intro.setText(self._intro_text())

    def reload_patterns(self) -> None:
        """A pattern was enabled/disabled/added/removed in the Pattern Database:
        rebuild the preset dropdown so a disabled pattern can no longer be
        chosen for a segmentation run."""
        self._fill_presets()

    def _pool_kind(self) -> str:
        return ("a honeypot database cloned from production" if self._layer_db
                else "eshop + seeded database")

    # ---- frames ----

    @property
    def browsers(self) -> list[BrowserWidget]:
        return self._all_browsers[:self._count]

    @property
    def decision_labels(self) -> list[QLabel]:
        return self._all_decisions[:self._count]

    @property
    def cart_labels(self) -> list[QLabel]:
        return self._all_carts[:self._count]

    def _add_frame(self) -> None:
        i = len(self._boxes)
        label = FRAMES[i][0]
        # Homepage is the shop (https://localhost by default), not about:blank.
        browser = BrowserWidget(home_url=self._base_url() + "/")
        ua, lang = frame_identity(browser.profile.httpUserAgent(), i)
        browser.profile.setHttpUserAgent(ua)
        browser.profile.setHttpAcceptLanguage(lang)
        # Auto-dismiss the proxy's GDPR consent banner in this window; the run
        # consents out-of-band via a distinct per-window token (see
        # _GDPR_BANNER_SUPPRESS_JS / _apply_gdpr_cookie).
        _install_gdpr_banner_suppressor(browser.profile)
        store = browser.profile.cookieStore()
        store.cookieAdded.connect(lambda c, n=i: self._on_cookie(n, c))
        store.cookieRemoved.connect(lambda c, n=i: self._on_cookie_removed(n, c))
        store.loadAllCookies()
        # Whether this window's last page load succeeded (see _recover_error_pages).
        relay = _LoadRelay(browser, self)
        self._relays.append(relay)
        relay.done.connect(lambda ok, n=i: self._load_ok.__setitem__(n, ok))
        relay.done.connect(lambda ok, n=i: ok and self._refresh_cart_label(n))

        box = QGroupBox(label)
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(4, 4, 4, 4)
        attack_btn = QPushButton(f"Attack from {label[-1]}")
        attack_btn.clicked.connect(lambda _=False, n=i: self.attack(n))
        box_layout.addWidget(attack_btn)
        box_layout.addWidget(browser, stretch=1)
        decision = QLabel("Routing: no session yet")
        decision.setWordWrap(True)
        decision.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box_layout.addWidget(decision)
        cart = QLabel("Cart: —")
        cart.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cart.setStyleSheet(
            "QLabel { color: #cfcfcf; padding: 2px 8px; border: 1px solid #555; "
            f"border-radius: {theme.corner_radius_css(4)}; }}")
        box_layout.addWidget(cart)
        self._boxes.append(box)
        self._all_browsers.append(browser)
        self._all_decisions.append(decision)
        self._all_carts.append(cart)
        self._row_splitters[0].addWidget(box)

    def set_window_count(self, n: int) -> None:
        """Show `n` frames. Frames beyond it are hidden and their session
        dropped (cookies cleared, page blanked), so they stop counting."""
        if self._exporting:
            return
        n = max(MIN_WINDOWS, min(MAX_WINDOWS, n))
        while len(self._boxes) < n:
            self._add_frame()
        for i in range(n, self._count):
            self._all_browsers[i].clear_cookies()
            self._all_browsers[i].navigate("about:blank")
            self._session_ids[i] = ""
        self._count = n
        per_row = n if n <= ROW_MAX else (n + 1) // 2
        for i, box in enumerate(self._boxes):
            if i >= n:
                box.hide()
                continue
            self._row_splitters[0 if i < per_row else 1].addWidget(box)
            box.show()
            self._style_decision(i, Decision())
        self._row_splitters[1].setVisible(n > per_row)
        for row in self._row_splitters:
            row.setSizes([1000 if not w.isHidden() else 0
                          for w in (row.widget(k) for k in range(row.count()))])
        self._rows.setSizes([1000, 1000 if n > per_row else 0])
        if self.count_spin.value() != n:
            self.count_spin.setValue(n)
        self.delayed_spin.setMaximum(n)

    def _delayed(self) -> int:
        return min(self.delayed_spin.value(), self._count)

    def _base_url(self) -> str:
        return _default_eshop_url(self.state).rstrip("/")

    def _preset(self):
        return self.preset_combo.current_preset()

    def open_all(self) -> None:
        for browser in self.browsers:
            browser.navigate(self._base_url() + "/")

    def attack(self, index: int) -> None:
        preset = self._preset()
        if preset is not None:
            self.browsers[index].navigate(self._base_url() + preset.path)

    def attack_all(self) -> None:
        # Spread the checked patterns across the windows (one each, round-robin)
        # so a segmentation run can carry varied attack traffic; with nothing
        # checked, fall back to the highlighted pattern in every window.
        presets = self.preset_combo.checked_presets()
        if not presets:
            current = self._preset()
            presets = [current] if current is not None else []
        if not presets:
            return
        base = self._base_url()
        for i in range(len(self.browsers)):
            self.browsers[i].navigate(base + presets[i % len(presets)].path)

    def _on_cookie(self, index: int, cookie) -> None:
        name = bytes(cookie.name()).decode(errors="replace")
        self._cookie_names[index].add(name)
        if name == SESSION_COOKIE:
            value = bytes(cookie.value()).decode(errors="replace")
            self._session_ids[index] = value.split(".", 1)[0]
        key = pool_evidence.wc_session_key(name, bytes(cookie.value()).decode(errors="replace"))
        if key:
            self._wc_keys[key] = index

    def _on_cookie_removed(self, index: int, cookie) -> None:
        name = bytes(cookie.name()).decode(errors="replace")
        self._cookie_names[index].discard(name)
        if name == SESSION_COOKIE:
            self._session_ids[index] = ""

    # ---- routing decision under each frame ----

    def _style_decision(self, index: int, d: Decision) -> None:
        color = {"HONEYPOT": "#e08a00", "PRODUCTION": "#5cb85c"}.get(d.route, "#777777")
        label = self.decision_labels[index]
        label.setText(d.text())
        label.setStyleSheet(
            f"QLabel {{ background-color: {color}; color: #1e1e1e; padding: 4px 10px; "
            f"border-radius: {theme.corner_radius_css(4)}; font-weight: bold; }}")

    def _style_cart(self, index: int, cart: CartState | None) -> None:
        label = self.cart_labels[index]
        if cart is None:
            label.setText("Cart: —")
            label.setStyleSheet(
                "QLabel { color: #cfcfcf; padding: 2px 8px; border: 1px solid #555; "
                f"border-radius: {theme.corner_radius_css(4)}; }}")
            return
        label.setText(cart.text())
        color = "#5cb85c" if cart.items else "#cfcfcf"
        label.setStyleSheet(
            f"QLabel {{ color: {color}; padding: 2px 8px; border: 1px solid {color}; "
            f"border-radius: {theme.corner_radius_css(4)}; }}")

    def _read_cart(self, index: int) -> CartState | None:
        """The window's cart as the shop (production or its honeypot pool) reports it."""
        browser = self.browsers[index]
        if not browser.view.url().toString().startswith("http"):
            return None
        cart = parse_cart(self._run_js(index, _CART_JS))
        if cart is None:
            # Under load (pools being built) the shop can take longer than the
            # first read allows; one slower retry before calling it unmeasured.
            cart = parse_cart(self._run_js(index, _CART_JS, timeout_ms=15000))
        return cart

    def _run_js(self, index: int, script: str, timeout_ms: int = 6000) -> str:
        """Run `script` in window `index` and return its result ("" on timeout)."""
        loop = QEventLoop()
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        got: list = [None]

        def done(result) -> None:
            got[0] = result
            loop.quit()
        self.browsers[index].page.runJavaScript(script, done)
        timer.start(timeout_ms)
        loop.exec()
        timer.stop()
        return got[0] or ""

    def _read_carts(self) -> list[CartState | None]:
        carts = [self._read_cart(i) for i in range(len(self.browsers))]
        for i, c in enumerate(carts):
            self._style_cart(i, c)
        return carts

    def _refresh_cart_label(self, i: int) -> None:
        """Read window `i`'s cart for its label (non-blocking). Runs when the
        window finishes loading a page, the only time its cart can change --
        polling every window's cart every 3 s sent the shop ~3 requests a
        second for as long as the page was open, and kept the pools busy and
        the log shippers loaded long after a report ended."""
        browser = self.browsers[i]
        if not self._exporting and browser.view.url().toString().startswith("http"):
            browser.page.runJavaScript(
                _CART_JS, lambda r, n=i: self._style_cart(n, parse_cart(r or "")))

    def _remote(self):
        return target_for("edge", self.state).remote

    def _fetch_decisions(self, sids: list[str]) -> list[Decision]:
        remote = self._remote()

        def read() -> list[Decision]:
            out = []
            for sid in sids:
                if not sid:
                    out.append(Decision())
                    continue
                raw, pool, waiting = redis_inspect.session_decision_raw(remote, sid)
                out.append(parse_decision(sid, raw, pool, waiting))
            return out
        return read()

    def refresh_decisions(self) -> None:
        """Async refresh of the labels (skipped while a read or an export runs)."""
        if self._exporting or self._job is not None or not self.isVisible():
            return
        sids = self._session_ids[:self._count]
        job = _Job(lambda: self._fetch_decisions(sids), self)
        self._job = job

        def done() -> None:
            self._job = None
            if job.error is None and not self._exporting:
                for i, d in enumerate(job.result or []):
                    self._style_decision(i, d)
            job.deleteLater()
        job.finished.connect(done)
        job.start()

    def _blocking(self, fn):
        """Run `fn` on a worker thread while the GUI keeps painting (the frames
        keep loading); returns its result or raises its error."""
        job = _Job(fn, self)
        loop = QEventLoop()
        job.finished.connect(loop.quit)
        job.start()
        loop.exec()
        job.wait()
        job.deleteLater()
        if job.error is not None:
            raise job.error
        return job.result

    @staticmethod
    def _spin(ms: int) -> None:
        loop = QEventLoop()
        QTimer.singleShot(ms, loop.quit)
        loop.exec()

    # ---- report export (progress bar, all frames move every step) ----

    # Caption on a dimmed frame during an export. Short, because the frames are
    # narrow (up to five per row) -- the overlay wraps it to fit.
    _FRAME_IDLE_MSG = "Driven by the report — hands off"

    def _cancel_report(self) -> None:
        self._cancelled = True
        self.cancel_btn.setEnabled(False)
        self.progress_label.setText("Cancelling...")

    def _progress(self, message: str, current: int, total: int) -> None:
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.progress_label.setText(message)
        self._eta.update(time.monotonic() - self._export_t0, current / total if total else 0.0)
        self._tick_eta()

    def _tick_eta(self) -> None:
        """Refresh the "estimated time remaining" line (on the 1 s timer and on
        each progress emission)."""
        if not self._exporting:
            return
        remaining = self._eta.remaining_at(time.monotonic() - self._export_t0)
        self.eta_label.setText(f"~ {format_eta(remaining)} left")

    # ---- idle veil over the frames during an export ----

    def _apply_frame_dim(self) -> None:
        """Dim every frame when no active section is in progress, clear them
        while one is (only during an export; a no-op otherwise)."""
        if not self._exporting:
            return
        dim = self._frame_active_depth <= 0
        if dim == self._frames_dimmed:
            return
        self._frames_dimmed = dim
        for b in self.browsers:
            b.set_dimmed(dim, self._FRAME_IDLE_MSG if dim else "")

    def _frames_enter_active(self) -> None:
        self._frame_active_depth += 1
        self._apply_frame_dim()

    def _frames_exit_active(self) -> None:
        self._frame_active_depth = max(0, self._frame_active_depth - 1)
        self._apply_frame_dim()

    def _undim_all_frames(self) -> None:
        """Hand every frame back (export over): clear the veil unconditionally."""
        self._frame_active_depth = 0
        self._frames_dimmed = False
        for b in self._all_browsers:
            b.set_dimmed(False)

    def _load_all(self, urls: list[str], step: str = "", attacks: frozenset = frozenset()) -> None:
        """Navigate each frame to its URL and wait for all loads (hard timeout,
        so one stuck page cannot hang the export). Each completed load's time
        is recorded for the latency figures, under `step`; its routing state is
        filled in by the next _observe()."""
        # A frame already on about:blank never fires loadFinished for about:blank.
        pending = {i for i, u in enumerate(urls)
                   if not (u == "about:blank" and self.browsers[i].view.url().toString()
                           in ("", "about:blank"))}
        loop = QEventLoop()
        self._frames_enter_active()      # show the frames live while they load
        if not pending:
            for browser, url in zip(self.browsers, urls):
                browser.navigate(url)
            self._frames_exit_active()
            return
        started = [time.monotonic()] * len(urls)
        t = self._now()
        retries = [0] * len(urls)
        timer = QTimer(self)   # stoppable: a stale single-shot would cut a later wait short
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        conns = []
        for i, (browser, url) in enumerate(zip(self.browsers, urls)):
            def finished(ok, n=i, u=url, b=browser):
                if n not in pending:
                    return
                # Windows in `attacks` (an attack request) get ATTACK_RETRIES:
                # `ok` is False only when no response came back at all, and the
                # attack step counts its own attempts.
                limit = ATTACK_RETRIES if n in attacks else LOAD_RETRIES
                if not ok and u.startswith("http") and retries[n] < limit:
                    # Transient (see LOAD_RETRY_DELAYS_MS): load it again, and
                    # give the retry a full timeout of its own.
                    delay = LOAD_RETRY_DELAYS_MS[retries[n]]
                    retries[n] += 1

                    def again(n=n, u=u, b=b):
                        if n in pending:
                            started[n] = time.monotonic()
                            b.navigate(u)
                    QTimer.singleShot(delay, again)
                    timer.start(9000 + delay)
                    return
                if u.startswith("http") and (not ok or retries[n]):
                    self._log_load(t, step, n, u, retries[n] + 1, "retried" if ok else "failed")
                if ok and u.startswith("http") and self._t0:
                    self._pending_loads.append(LoadTiming(
                        t, n, step, (time.monotonic() - started[n]) * 1000.0))
                pending.discard(n)
                if not pending:
                    loop.quit()
            conns.append((self._relays[i], self._relays[i].done.connect(finished)))
            browser.navigate(url)
        timer.start(9000)
        loop.exec()
        timer.stop()
        for n in sorted(pending):      # never finished loading within the timeout
            if urls[n].startswith("http"):
                self._log_load(t, step, n, urls[n], retries[n] + 1, "timed out")
        for relay, conn in conns:
            try:
                relay.done.disconnect(conn)
            except TypeError:
                pass
        self._frames_exit_active()

    def _wait_for_render(self, script: str, timeout_ms: int) -> None:
        """Poll every window (on a page that loaded) until `script` returns
        true there, or `timeout_ms` passes."""
        pending = {w for w, b in enumerate(self.browsers)
                   if self._load_ok[w] and b.view.url().toString().startswith("http")}
        deadline = time.monotonic() + timeout_ms / 1000
        while pending and time.monotonic() < deadline:
            for w in sorted(pending):
                if self._run_js(w, script, 2000) is True:
                    pending.discard(w)
            if pending:
                self._spin(500)
        self._spin(300)      # let the last ones paint

    def _page_status(self, w: int) -> dict:
        """{"s": HTTP status (0 = none / error page), "t": title, "u": URL} of
        the page window `w` is showing."""
        try:
            got = json.loads(self._run_js(w, _PAGE_STATUS_JS) or "{}")
        except ValueError:
            got = {}
        return {"s": int(got.get("s") or 0), "t": str(got.get("t") or ""), "u": str(got.get("u") or "")}

    def _product_ids(self, slugs: list[str]) -> dict[str, int]:
        """Product IDs for `slugs`, looked up from inside a window (see
        product_ids_js). When the answer isn't a product list -- the window sits
        on Chromium's error page after a failed load -- it reloads the shop in
        that window and asks again (from the next window on later tries)."""
        shop = self._base_url() + "/"
        error: Exception | None = None
        for attempt in range(LOAD_RETRIES + 1):
            w = attempt % len(self.browsers)
            try:
                return parse_product_ids(self._run_js(w, product_ids_js(slugs)), slugs)
            except ProductListUnreadable as e:
                error = e
                self._load_one(w, shop, step="product lookup")
        raise error

    def _load_one(self, w: int, url: str, timeout_ms: int = 9000, step: str = "",
                  log: bool = True) -> bool:
        """Navigate window `w` alone and wait for the load (retried like _load_all)."""
        browser = self.browsers[w]
        t = self._now()
        self._frames_enter_active()      # show the frames live while this one loads
        for attempt in range(LOAD_RETRIES + 1):
            loop = QEventLoop()
            got: list = [False]

            def finished(ok):
                got[0] = ok
                loop.quit()
            relay = self._relays[w]
            conn = relay.done.connect(finished)
            browser.navigate(url)
            timer = QTimer(self)
            timer.setSingleShot(True)
            timer.timeout.connect(loop.quit)
            timer.start(timeout_ms)
            loop.exec()
            timer.stop()
            try:
                relay.done.disconnect(conn)
            except TypeError:
                pass
            if got[0]:
                if attempt and log:
                    self._log_load(t, step, w, url, attempt + 1, "retried")
                self._frames_exit_active()
                return True
            if attempt < LOAD_RETRIES:
                self._spin(LOAD_RETRY_DELAYS_MS[attempt])
        if log:
            self._log_load(t, step, w, url, LOAD_RETRIES + 1, "failed")
        self._frames_exit_active()
        return False

    def _log_load(self, t: float, step: str, w: int, url: str, attempts: int, outcome: str) -> None:
        """One page load that did not succeed at the first attempt: "retried"
        (loaded on a retry), "failed" / "timed out" (never loaded), later
        "fixed before the next step" when _recover_error_pages reloads it."""
        if self._t0:
            self._load_log.append({"t": round(t, 1), "step": step, "window": w, "url": url,
                                   "attempts": attempts, "outcome": outcome})

    def _recover_error_pages(self) -> int:
        """Reload every window whose last load failed (it shows Chromium's
        error page, e.g. after ERR_NETWORK_CHANGED outlasted the retries), so
        no step starts from an error page. Returns how many were reloaded."""
        n = 0
        for w, browser in enumerate(self.browsers):
            url = browser.view.url().toString()
            if not self._load_ok[w] and url.startswith("http") and url not in self._pattern_urls:
                n += 1
                fixed = self._load_one(w, url, log=False)
                # The load this repairs is already logged: mark it, don't add one.
                last = next((e for e in reversed(self._load_log)
                             if e["window"] == w and e["outcome"] in ("failed", "timed out")), None)
                if last is not None:
                    last["outcome"] = "fixed before the next step" if fixed else last["outcome"] + \
                        ", reload before the next step failed too"
        return n

    def _capture(self) -> tuple[list, list, list[int], list[int]]:
        """Screenshots, carts, and the windows still on an error page (their
        last load failed), for a StepResult."""
        failed = [w for w, b in enumerate(self.browsers)
                  if not self._load_ok[w] and b.view.url().toString().startswith("http")]
        http = [self._relays[w].http_status if w < len(self._relays) else 0
                for w in range(len(self.browsers))]
        # Show the frames live for the grab -- a dim overlay would otherwise
        # land in a screen-grab fallback (the primary view.grab() skips it, but
        # the fallback in _grab does not).
        self._frames_enter_active()
        try:
            return [self._grab(b) for b in self.browsers], self._read_carts(), failed, http
        finally:
            self._frames_exit_active()

    def _latency_probe(self, label: str, total_steps: int, total: int, step: int) -> None:
        """Every window loads the same product page, one window at a time, so
        page-load latency compares like with like: no mix of pages and no ten
        loads competing for this machine's CPU at once. Each load is tagged
        with where that window is served right after (the next _observe())."""
        if not self._t0 or not self.browsers:
            return
        url = f"{self._base_url()}/product/{CART_PLAN[0][0][0]}/"
        self._frames_enter_active()      # show the frames live while they probe
        for w in range(len(self.browsers)):
            if self._cancelled:
                self._frames_exit_active()
                raise _Cancelled()
            self._progress(f"Step {step}/{total_steps}: latency probe ({label}) — "
                           f"window {self._letter(w)}", step, total)
            browser = self.browsers[w]
            loop = QEventLoop()
            started, t = time.monotonic(), self._now()
            got: list = [None]

            def finished(ok, n=w):
                got[0] = ok
                loop.quit()
            relay = self._relays[w]
            conn = relay.done.connect(finished)
            browser.navigate(url)
            timer = QTimer(self)
            timer.setSingleShot(True)
            timer.timeout.connect(loop.quit)
            timer.start(15000)
            loop.exec()
            timer.stop()
            try:
                relay.done.disconnect(conn)
            except TypeError:
                pass
            if got[0]:
                self._pending_loads.append(LoadTiming(t, w, f"latency probe: {label}",
                                                      (time.monotonic() - started) * 1000.0,
                                                      probe=True))
            else:
                # Failed (see LOAD_RETRIES): no timing for it, but don't leave
                # the window on Chromium's error page for the next step.
                fixed = self._load_one(w, url, log=False)
                self._log_load(t, f"latency probe: {label}", w, url, 2, "retried" if fixed else "failed")
        self._frames_exit_active()
        self._settled_decisions(need_sessions=True)   # tags the probe loads

    # ---- run timeline (samples for the scaling / latency figures) ----

    def _now(self) -> float:
        return time.time() - self._t0 if self._t0 else 0.0

    def _observe(self, decisions: list[Decision]) -> None:
        """Show the decisions, add them to the run's timeline as one batch, and
        give the loads since the last batch the state their window is in now."""
        for i, d in enumerate(decisions):
            self._style_decision(i, d)
        if not self._t0 or not self._sampling:
            # After the forced scale-down the windows' routing is no longer the
            # run's (the reassignment check has its own table): don't add it,
            # or its page loads, to the timeline and latency figures.
            self._pending_loads = []
            return
        t = self._now()
        batch = [Sample(t, i, d.session_id, d.route, d.pool, d.waiting)
                 for i, d in enumerate(decisions)]
        self._samples.extend(batch)
        states = classify(batch)
        for lt in self._pending_loads:
            if lt.window < len(states):
                lt.state = states[lt.window]
                self._loads.append(lt)
        self._pending_loads = []

    def _mark(self, title: str) -> None:
        if self._t0:
            self._marks.append((self._now(), title))

    def _grab(self, browser: BrowserWidget):
        from ui.page_patterns import PatternsPage
        pixmap = browser.view.grab()
        # A near-empty page (WordPress's "0" for a rejected admin-ajax call)
        # can finish loading before the view paints its first frame, and the
        # grab is then the black backing store: two step-14 screenshots were
        # solid black while the same response in other windows was white.
        # Give it a few repaints before falling back.
        for _ in range(GRAB_REPAINT_TRIES):
            if pixmap.isNull() or not _flat_black(pixmap):
                break
            browser.view.update()
            self._spin(GRAB_REPAINT_MS)
            pixmap = browser.view.grab()
        if pixmap.isNull() or PatternsPage._looks_blank(pixmap):  # noqa: SLF001
            fallback = PatternsPage.screen_grab(browser.view)
            if not fallback.isNull() and not PatternsPage._looks_blank(fallback):  # noqa: SLF001
                pixmap = fallback
        image = pixmap.toImage()
        image.setDevicePixelRatio(1.0)
        return image

    def _settled_decisions(self, need_sessions: bool) -> list[Decision]:
        """Give the proxy a moment to write its state, then read every
        session's decision (retrying a few times for sessions still missing)."""
        self._spin(1500)
        decisions: list[Decision] = []
        for _ in range(4):
            sids = self._session_ids[:self._count]
            decisions = self._blocking(lambda s=sids: self._fetch_decisions(s))
            if not need_sessions or all(d.session_id for d in decisions):
                break
            self._spin(1000)
        self._observe(decisions)
        return decisions

    def export_report(self) -> None:
        if self._exporting:
            return
        preset = self._preset()
        if preset is None:
            return
        # The GDPR-signature demonstration needs a full wipe to happen mid-run,
        # so force the session-tamper schedule on: a diverted window then clears
        # all its site data and re-consents, and the report shows its signature
        # putting it back on its pool. The windows still run their real attacks.
        if is_gdpr_restore(preset) and not self.clear_check.isChecked():
            self.clear_check.setChecked(True)
        path, _ = QFileDialog.getSaveFileName(
            self, "Save pool test report", "pool_test_report.pdf", "PDF files (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        try:
            remote = self._remote()
            state = self._blocking(lambda: redis_inspect.pool_state(remote))
        except Exception:  # noqa: BLE001 -- no warning then; the run reports it
            state = {}
        capacity = capacity_warning(self._count, self._delayed(), state)
        if QMessageBox.question(
            self, "Reset test sessions?",
            "The report starts from a clean slate: this machine's own sessions and honeypot "
            "pool assignments are removed first (the same reset as 'Unpoison host IP' on "
            f"the Attack Simulation page), then the {self._count} windows each run their own pattern, "
            "and the run waits for the honeypot pools to scale up to them (a few minutes "
            "per batch of new pools)."
            + (f" The last {self._delayed()} window(s) attack only after pools were pre-built "
               "for them." if self._delayed() else "")
            + (" Between steps, a few random windows tamper with their session: they clear "
               "their cookies or all site data, or forge their session cookie or storage, "
               "to check the stack still tells the windows apart and rejects forged sessions."
               if self.clear_check.isChecked() else "")
            + " At the end the windows' sessions are released and the pools they no longer "
            "need are scaled down at once (instead of after POOL_IDLE_TIMEOUT_SECONDS)."
            + (f"\n\n\u26a0 {capacity}" if capacity else "")
            + "\n\nContinue?",
        ) != QMessageBox.StandardButton.Yes:
            return

        # GDPR consent gate: the run fires automated attack traffic from each
        # window, so the operator must agree first. On agreement each window's
        # traffic carries its OWN consented gdpr_token (distinct per window, so
        # segmentation is preserved); Cancel aborts the export. See ids/GDPR.md.
        proceed, gdpr = request_gdpr_consent(self, self._base_url())
        if not proceed:
            return
        self._gdpr = gdpr
        self._gdpr_chars = gdpr_screen_characteristics()

        self._exporting, self._cancelled = True, False
        self._poll.stop()
        total = 9
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Preparing report...")
        self.cancel_btn.setEnabled(True)
        self.progress_row.setVisible(True)
        self.export_label.setVisible(False)
        # ETA line + the veil over the frames (driven automatically from here).
        self._export_t0 = time.monotonic()
        self._eta.reset()
        self.eta_label.setText("~ estimating…")
        self._eta_timer.start()
        self._frame_active_depth = 0
        self._apply_frame_dim()
        for w in (self.export_btn, self.open_all_btn, self.attack_all_btn, self.reset_btn,
                  self.count_spin, self.delayed_spin, self.clear_check):
            w.setEnabled(False)

        error, data = "", None
        try:
            data = self._run_scenario(None, total, preset)
        except Exception as e:  # noqa: BLE001 -- shown to the user below
            error = str(e)

        self._eta_timer.stop()
        self.eta_label.setText("")
        self.progress_row.setVisible(False)
        for w in (self.export_btn, self.open_all_btn, self.attack_all_btn, self.reset_btn,
                  self.count_spin, self.delayed_spin, self.clear_check):
            w.setEnabled(True)
        self._exporting = False
        self._undim_all_frames()      # hand the frames back
        self._poll.start()
        if self._gdpr is not None:
            self._gdpr.cleanup()  # remove the temp key material
            self._gdpr = None

        if self._cancelled and not error:
            self._show_export_result("Report export cancelled.")
            return
        if data is not None and not error:
            self._progress("Rendering PDF...", total - 1, total)
            from core.pool_test_report_pdf import render_pdf
            try:
                verdict = render_pdf(data, path)
            except Exception as e:  # noqa: BLE001
                error = str(e)
        if error:
            self._show_export_result(f"✗ Report export failed: {error}")
            QMessageBox.warning(self, "Report export failed", error)
            return
        self._show_export_result(f"✓ Report saved: {path} — {verdict.headline}.")
        if QMessageBox.question(
            self, "Report saved", f"Saved pool test report to:\n{path}\n\nOpen it now?",
        ) == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _reset_threat_state(self) -> None:
        """Clean slate, like the pattern report: threat state flushed in Redis AND
        in reverse_proxy's in-process caches (/internal-threat-reset), then this
        machine's sessions and pool assignments removed."""
        import subprocess
        remote = self._remote()
        redis_inspect.flush_threat_state(remote)
        try:
            from core.pattern_report import _load_secret_and_halflife
            secret = _load_secret_and_halflife(target_for("edge", self.state))[0]
            subprocess.run(["curl", "-sk", "-o", "/dev/null", "-H",
                            f"X-Internal-Test-Auth: {secret}",
                            self._base_url() + "/internal-threat-reset"], timeout=15)
        except Exception:  # noqa: BLE001 -- best effort; the unpoison below still runs
            pass
        redis_inspect.clear_local_threat_state(remote)

    def _apply_gdpr_cookie(self, index: int) -> None:
        """Set window `index`'s consented gdpr_token cookie (distinct per window)
        into its browser's cookie store, so that window's traffic is treated as
        GDPR-consented. No-op when the operator did not agree for this export."""
        if self._gdpr is None or index >= len(self._all_browsers):
            return
        chars = dict(self._gdpr_chars)
        chars["win"] = index  # keep each window's one-way signature distinct
        value = self._gdpr.cookie_value(chars)
        if not value:
            return
        url = QUrl(self._base_url())
        cookie = QNetworkCookie(self._gdpr.cookie_name.encode(), value.encode())
        cookie.setDomain(url.host())
        cookie.setPath("/")
        cookie.setSecure(url.scheme() == "https")
        self._all_browsers[index].profile.cookieStore().setCookie(cookie, url)

    def _attack_plan(self) -> list[tuple[str, str]]:
        """The per-window (first, second) CVE pair the report run attacks with.

        When the operator has CHECKED patterns in the picker, those drive the
        windows: each window gets a pair from the checked set, spread so
        adjacent windows differ (round-robin, second != first where possible).
        With nothing checked, the pre-tuned window_plan() battery is used
        instead -- its db-layer isolated / non-isolated split and its
        first-request-divert choices. Either way _pattern_queue appends the
        fallbacks, so a window whose chosen pattern never diverts still lands
        on one that does."""
        checked = [p.cve for p in self.preset_combo.checked_presets()]
        if not checked:
            return window_plan(self._count, self._layer_db)
        n = len(checked)
        return [(checked[w % n], checked[(w + 1) % n] if n > 1 else checked[0])
                for w in range(self._count)]

    def _pattern_queue(self, window: int) -> list:
        """Patterns for one window: its primary and secondary choice, then the
        rest of the checked set, then the fallbacks, as presets (so a window
        whose earlier choices never divert within MAX_ATTEMPTS still finds one
        that does)."""
        by_cve = {p.cve: p for p in PATTERN_PRESETS}
        plan = self._attack_plan()[window]
        checked = [p.cve for p in self.preset_combo.checked_presets()]
        order = dict.fromkeys((*plan, *checked, *fallback_patterns(self._layer_db)))
        return [by_cve[c] for c in order if c in by_cve]

    def _letter(self, window: int) -> str:
        return FRAMES[window][0][-1]

    # ---- idle windows browse the shop like a shopper would ----

    def _begin_browse(self) -> None:
        self._seen = [[] for _ in range(MAX_WINDOWS)]

    def _browse_url(self, window: int) -> str:
        """Next page for a window that has nothing else to do in this step."""
        path, label = browse_page(window, self._visits[window])
        self._visits[window] += 1
        self._seen[window].append(label)
        return self._base_url() + path

    def _browsed(self, window: int) -> str:
        return browse_action(self._seen[window])

    def _browse_all(self, step: str) -> None:
        """Every window opens its next page."""
        self._load_all([self._browse_url(w) for w in range(len(self.browsers))], step)

    # ---- windows clearing or forging their own session data ----

    def _clear_browser_data(self, window: int, variant: str, step: int,
                            before: Decision | None) -> ClearEvent:
        """Window `window` tampers with its own session. A clearing removes its
        data the way a visitor would from the browser's settings: its site
        storage (from the page, as "clear site data" does) and/or every cookie
        in its profile. A forgery rewrites it (_forge_session_data)."""
        event = ClearEvent(self._now(), window, step, variant,
                           before_session=self._session_ids[window],
                           before_pool=before.pool if before is not None else None)
        browser = self.browsers[window]
        if event.is_forgery():
            self._forge_session_data(event)
            return event
        if variant in ("storage", "all") and browser.view.url().toString().startswith("http"):
            got = self._run_js(window, _CLEAR_STORAGE_JS)
            event.storage_keys = int(got) if str(got).isdigit() else 0
        if event.clears_cookies():
            event.cookies = sorted(self._cookie_names[window])
            browser.clear_cookies()
            deadline = time.monotonic() + 3.0      # deleteAllCookies() is asynchronous
            while self._session_ids[window] and time.monotonic() < deadline:
                self._spin(100)
            # Full wipe, then re-consent: a visitor who clears their site data
            # and agrees to the banner again sends a fresh gdpr_token. Its
            # one-way signature is unchanged (same screen, same per-window tag),
            # so if this window was already bound to a honeypot the proxy routes
            # it straight back there on the next load -- the report's
            # gdpr_signature section records it (see signature_restorations()).
            if self._gdpr is not None:
                self._apply_gdpr_cookie(window)
                event.reconsented = True
        return event

    def _forge_session_data(self, event: ClearEvent) -> None:
        """Rewrite window `event.window`'s session the way a client-side
        adversary would. Cookie forgeries replace SERVERID with
        "<session id>.<signature>" where the signature is made up (the real
        one is an HMAC only the proxy can compute): an invented id, or another
        window's real id (a hijack attempt). A storage forgery writes a fake
        session into localStorage / sessionStorage."""
        w = event.window
        browser = self.browsers[w]
        if event.variant == "hijack_cookie":
            # The session worth stealing is one that is already diverted (it
            # owns a honeypot pool): success would show as this window
            # jumping onto that pool. Otherwise any other window's session.
            latest: dict[int, int | None] = {}
            for smp in self._samples:
                latest[smp.window] = smp.pool
            others = [i for i in range(len(self.browsers)) if i != w and self._session_ids[i]]
            diverted = [i for i in others if latest.get(i) is not None]
            if others:
                victim = random.choice(diverted or others)
                event.claimed_session = self._session_ids[victim]
                event.claimed_window, event.claimed_pool = victim, latest.get(victim)
            else:
                event.claimed_session = secrets.token_hex(16)
        else:
            event.claimed_session = secrets.token_hex(16)
        fake = f"{event.claimed_session}.{secrets.token_hex(20)}"
        if event.variant == "forge_storage":
            if browser.view.url().toString().startswith("http"):
                got = self._run_js(w, _FORGE_STORAGE_JS % ('"' + fake + '"'))
                event.storage_keys = int(got) if str(got).isdigit() else 0
            event.planted = fake
            return
        # Same name, host and path as the proxy's own cookie, so it replaces it.
        base = QUrl(self._base_url() + "/")
        cookie = QNetworkCookie(SESSION_COOKIE.encode(), fake.encode())
        cookie.setPath("/")
        cookie.setHttpOnly(True)
        cookie.setSecure(base.scheme() == "https")
        browser.profile.cookieStore().setCookie(cookie, base)
        event.planted = fake
        event.planted_sha1 = hashlib.sha1(fake.encode()).hexdigest()
        deadline = time.monotonic() + 3.0          # setCookie() is asynchronous
        while self._session_ids[w] != event.claimed_session and time.monotonic() < deadline:
            self._spin(100)

    def _resolve_cleared(self, cleared: list[ClearEvent], results: list[StepResult]) -> None:
        """Fill in what each clearing or forgery led to from the step it
        happened before, and say it in that step's action for the window. For a
        forged cookie, look its SHA-1 up in the proxy's rejection log."""
        rejections: dict[str, dict] | None = None
        if any(e.variant in COOKIE_FORGERIES for e in cleared):
            remote = self._remote()
            try:
                rejections = {}
                for r in self._blocking(lambda: redis_inspect.cookie_rejections(remote)):
                    rejections.setdefault(r.get("cookie_sha1", ""), r)
            except Exception:  # noqa: BLE001 -- the report says the log was unreadable
                rejections = None
        for e in cleared:
            if e.forges_cookie() and rejections is not None:
                e.rejections_checked = True
                e.rejection = rejections.get(e.planted_sha1)
            if e.step >= len(results):
                continue
            step = results[e.step]
            d = step.decisions[e.window] if e.window < len(step.decisions) else Decision()
            e.after_session, e.after_pool, e.after_route = d.session_id, d.pool, d.route
            e.after_reason = d.reason
            e.resolved = True
            if e.window < len(step.actions):
                step.actions[e.window] = (f"{e.action_note()}; then "
                                          + step.actions[e.window][:1].lower()
                                          + step.actions[e.window][1:])

    def _attack_step(self, n: int, total_steps: int, total: int, windows: list[int],
                     queues: list[list], used: set[str], runs: list[PatternRun],
                     title: str, detail: str) -> StepResult:
        """`windows` open their pattern at the same time (up to MAX_ATTEMPTS
        times each) while the others browse the shop. A window whose pattern
        never diverts moves on to the next one in its queue -- so each window
        is guaranteed a pattern that does."""
        self._mark(title)
        self._begin_browse()
        shop = self._base_url() + "/"
        plan = self._attack_plan()
        state: dict[int, list] = {}     # window -> [preset, attempts, replaced, done]
        tried: dict[int, set[str]] = {}
        for w in windows:
            # Prefer a pattern no other window ran; with many windows they may repeat.
            preset = next((p for p in queues[w] if p.cve not in used), queues[w][0])
            state[w] = [preset, 0, preset.cve != plan[w][0], False]
            tried[w] = {preset.cve}
            used.add(preset.cve)
        last: dict[int, tuple] = {}
        decisions: list[Decision] = []
        while True:
            active = [w for w in windows if not state[w][3]]
            if not active:
                break
            if self._cancelled:
                raise _Cancelled()
            for w in active:
                state[w][1] += 1
            self._progress(f"Step {n}/{total_steps}: " + ", ".join(
                f"{self._letter(w)} attacks with {state[w][0].cve} (attempt {state[w][1]}/{MAX_ATTEMPTS})"
                for w in active), n, total)
            urls = [shop if w in windows else self._browse_url(w)
                    for w in range(len(self.browsers))]
            for w in active:
                urls[w] = self._base_url() + state[w][0].path
                self._pattern_urls.add(urls[w])
            self._load_all(urls, title, attacks=frozenset(active))
            self._spin(700)
            decisions = self._settled_decisions(need_sessions=True)
            for w in active:
                preset, attempts, replaced, _done = state[w]
                d = decisions[w]
                last[w] = (preset, attempts)
                if d.route == "HONEYPOT":
                    runs.append(PatternRun(self._letter(w), preset.cve, preset.name, attempts,
                                           True, d.pool, replaced))
                    state[w][3] = True
                elif attempts >= MAX_ATTEMPTS:
                    runs.append(PatternRun(self._letter(w), preset.cve, preset.name, attempts,
                                           False, d.pool, replaced))
                    nxt = (next((p for p in queues[w] if p.cve not in tried[w] and p.cve not in used), None)
                           or next((p for p in queues[w] if p.cve not in tried[w]), None))
                    if nxt is None:
                        state[w][3] = True
                    else:
                        tried[w].add(nxt.cve)
                        used.add(nxt.cve)
                        state[w] = [nxt, 0, True, False]
        actions = [self._browsed(w) for w in range(len(self.browsers))]
        for w, (preset, attempts) in last.items():
            actions[w] = f"Opens {preset.cve} ({attempts} attempt(s))"
        return StepResult(title, detail, actions, decisions,
                          *self._capture())

    def _wait_for_scaling(self, n: int, total_steps: int, total: int) -> StepResult:
        """Wait until pool_manager has built a pool for every window that is
        still borrowing one (or growth is capped and it never will), then show
        every window on the shop again."""
        title = "Honeypot pools scale up"
        self._mark(title)
        self._begin_browse()
        remote = self._remote()
        before = self._settled_decisions(need_sessions=True)
        start = last_browse = time.monotonic()
        while True:
            if self._cancelled:
                raise _Cancelled()
            sids = self._session_ids[:self._count]
            decisions = self._blocking(lambda s=sids: self._fetch_decisions(s))
            self._observe(decisions)
            try:
                state = self._blocking(lambda: redis_inspect.pool_state(remote))
            except Exception:  # noqa: BLE001 -- keep waiting on the decisions alone
                state = {}
            self._baseline_new_pools(state)
            waiting = [self._letter(i) for i, d in enumerate(decisions) if d.waiting]
            elapsed = int(time.monotonic() - start)
            if not waiting or elapsed >= SCALE_TIMEOUT_S:
                break
            building = ", ".join(sorted((state.get("status") or {}).get("building", {}))) or "none"
            note = f" — growth capped: {state['capped']}" if state.get("capped") else ""
            self._progress(f"Step {n}/{total_steps}: pools scale up — window(s) "
                           f"{', '.join(waiting)} borrow a pool, building pool(s) {building} "
                           f"({elapsed // 60}:{elapsed % 60:02d}){note}", n, total)
            self._spin(2000)
            if time.monotonic() - last_browse >= BROWSE_EVERY_S:
                self._browse_all(title)
                last_browse = time.monotonic()
        self._browse_all(title)
        self._spin(700)
        decisions = self._settled_decisions(need_sessions=True)
        actions = []
        for b, d in zip(before, decisions):
            if b.pool is not None and d.pool is not None and b.pool != d.pool:
                actions.append(f"Moved from borrowed pool {b.pool} to its own pool {d.pool}")
            elif d.waiting:
                actions.append(f"Still borrowing pool {d.pool} (timed out)")
            else:
                actions.append(self._browsed(len(actions)))
        return StepResult(
            title,
            "Windows that found no free pool (not scaled up yet) borrowed a ready one "
            f"round-robin while pool_manager built a pool ({self._pool_kind()}) for each of "
            "them, and must now each be in their own. Once the resource limit is reached no "
            "more pools are built and the remaining windows keep sharing the ready pools "
            "round-robin.",
            actions, decisions, *self._capture())

    def _baseline_new_pools(self, state: dict) -> None:
        """Evidence baseline for pools that became ready during the run, taken
        as soon as they show up (before the windows that will get them attack),
        so the report can show what each of them saw and changed too."""
        new = [p for p in state.get("ready", []) if self._baseline.get("db", {}).get(p) is None]
        if new and self._baseline:
            target = target_for("edge", self.state)
            self._blocking(lambda: pool_evidence.extend_baseline(target, self._baseline, new))

    def _prescale(self, n: int, total_steps: int, total: int, windows: list[int]) -> StepResult:
        """Ask pool_manager for one free pool per delayed window and wait until
        they are ready -- or growth is capped with nothing left building, so
        they never will be. Records how long that took."""
        title = f"Pools pre-built for {len(windows)} delayed window(s)"
        self._mark(title)
        self._begin_browse()
        remote, k = self._remote(), len(windows)
        self._blocking(lambda: redis_inspect.set_pool_reserve(remote, k))
        t_start = self._now()
        reserve = {"requested": k, "start": t_start, "reached": False, "end": None,
                   "free": 0, "reason": ""}
        start = last_browse = time.monotonic()
        try:
            while True:
                if self._cancelled:
                    raise _Cancelled()
                try:
                    state = self._blocking(lambda: redis_inspect.pool_state(remote))
                except Exception:  # noqa: BLE001
                    state = {}
                self._baseline_new_pools(state)
                free = len(state.get("free", []))
                building = (state.get("status") or {}).get("building", {})
                reserve["free"] = free
                # Spares that were already free when the pre-build was asked
                # for: the report counts them apart from the pools built.
                reserve.setdefault("free_at_start", free)
                # ...and pools already being built then (a spare), which finish
                # while waiting without being built for the pre-build.
                reserve.setdefault("building_at_start", sorted(int(p) for p in building))
                elapsed = int(time.monotonic() - start)
                if free >= k:
                    reserve.update(reached=True, end=self._now())
                    break
                if state.get("capped") and not building:
                    reserve.update(end=self._now(), reason=f"growth capped: {state['capped']}")
                    break
                if elapsed >= SCALE_TIMEOUT_S:
                    reserve.update(end=self._now(), reason=f"timed out after {elapsed} s")
                    break
                self._progress(
                    f"Step {n}/{total_steps}: pre-building pools for the delayed windows — "
                    f"{free}/{k} free, building {', '.join(sorted(building)) or 'none'} "
                    f"({elapsed // 60}:{elapsed % 60:02d})"
                    + (f" — growth capped: {state['capped']}" if state.get("capped") else ""),
                    n, total)
                self._spin(2000)
                if time.monotonic() - last_browse >= BROWSE_EVERY_S:
                    self._browse_all(title)
                    last_browse = time.monotonic()
        finally:
            # Stop asking for more: the delayed windows are about to take these.
            self._blocking(lambda: redis_inspect.set_pool_reserve(remote, 0))
        self._reserve = reserve
        self._browse_all(title)
        self._spin(700)
        decisions = self._settled_decisions(need_sessions=True)
        took = (reserve["end"] or self._now()) - t_start
        outcome = (f"{k} free pool(s) ready after {took:.0f} s" if reserve["reached"]
                   else f"only {reserve['free']} of {k} free pool(s) after {took:.0f} s "
                        f"({reserve['reason']})")
        # The outcome once, in the step's text: under each delayed window it
        # read as if a pool were being built for that one window.
        actions = [self._browsed(w) for w in range(len(self.browsers))]
        return StepResult(
            title,
            f"Before windows {', '.join(self._letter(w) for w in windows)} attack, the test asks "
            f"pool_manager for {k} free pool(s) and waits until they are ready, so these "
            "windows find a pool of their own the moment they are diverted instead of "
            "borrowing one round-robin. If the resource limit stops the build first, they "
            f"share the ready pools round-robin instead. Outcome: {outcome}.",
            actions, decisions, *self._capture())

    def _forced_scaledown(self, n: int, total_steps: int, total: int,
                          sampler: _UsageSampler) -> dict:
        """End of the run: release the windows' sessions and have pool_manager
        scale down right away, rather than after POOL_IDLE_TIMEOUT_SECONDS,
        sampling resource use before, during and after."""
        remote = self._remote()
        self._sampling = False          # the run's timeline ends here (see _observe)
        self._progress(f"Step {n}/{total_steps}: forced scale-down — stopping the windows' "
                       "traffic", n, total)
        # No more requests from the windows: one would re-assign its bound session.
        self._load_all(["about:blank"] * len(self.browsers))
        # Every session a window held during the run, not just its current one:
        # a window that cleared its data left its old session behind, still
        # owning (or waiting for) a pool, which then outlived the scale-down.
        sids = ({sid for sid in self._session_ids[:self._count] if sid}
                | {smp.session_id for smp in self._samples if smp.session_id})
        try:
            before = self._blocking(lambda: redis_inspect.pool_state(remote))
        except Exception:  # noqa: BLE001
            before = {}
        sampler.interval = 3.0
        self._spin(4000)                    # a resource sample just before
        requested = self._now()
        done, state = self._scaledown_and_wait(remote, sids, before, f"Step {n}/{total_steps}: "
                                               "forced scale-down", n, total)
        self._spin(8000)                    # resource samples after the removal
        try:
            state = self._blocking(lambda: redis_inspect.pool_state(remote))
        except Exception:  # noqa: BLE001
            pass
        # Reassignment check: the pools the windows were on are gone, but the
        # windows still hold their (released) session cookie. Sending each back
        # to the shop shows the router reassigns it to a surviving pool (or a
        # fresh session) rather than leaving it on a removed pool -- the
        # timeline then shows the move instead of a window frozen on a dead pool.
        removed = sorted(set(before.get("ready", [])) - set(state.get("ready", []) if state else []))
        pool_before, session_before = {}, {}
        for smp in self._samples:
            if smp.t < requested and smp.pool is not None:
                pool_before[smp.window] = smp.pool
                session_before[smp.window] = smp.session_id
        reassign = []
        if removed:
            self._mark("Reassignment after removal")
            self._load_all([self._base_url() + "/"] * len(self.browsers),
                           "reassignment after removal")
            self._spin(700)
            decisions = self._settled_decisions(need_sessions=True)
            for i, d in enumerate(decisions):
                frm = pool_before.get(i)
                if frm in removed:
                    page = self._page_status(i)
                    reassign.append({"window": i, "from": frm, "pool": d.pool, "route": d.route,
                                     "session_before": session_before.get(i, ""),
                                     "session_after": d.session_id,
                                     "status": page["s"], "title": page["t"][:80],
                                     "stranded": d.pool == frm})
        # Later manual use starts afresh, and the windows go quiet: left on the
        # shop, they kept sending requests (and their recovered sessions kept
        # pools busy) after the run.
        self._load_all(["about:blank"] * len(self.browsers))
        for i, browser in enumerate(self.browsers):
            browser.clear_cookies()
            self._session_ids[i] = ""
            self._style_decision(i, Decision())
        cleanup = (self._cleanup_after_reassign(remote, sids | {r["session_after"] for r in reassign
                                                                if r.get("session_after")},
                                                n, total_steps, total) if reassign else {})
        status = (before.get("status") or {}) if before else {}
        return {"requested": requested, "done": done, "sessions": len(sids),
                "pools_before": before.get("ready", []) if before else [],
                "building_before": sorted(int(n) for n in status.get("building", {})),
                "pools_after": state.get("ready", []) if state else [],
                "removed_pools": removed, "reassign": reassign, "cleanup": cleanup,
                "idle_timeout": status.get("idle_timeout"), "spares": status.get("spares"),
                "mem_per_pool": status.get("mem_per_pool"),
                "cpus_per_pool": status.get("cpus_per_pool")}

    def _scaledown_and_wait(self, remote, sids, state: dict, label: str, n: int,
                            total: int) -> tuple[float | None, dict]:
        """Release `sids` and have pool_manager scale down now; wait until it
        reports the request done. Returns (time done or None on timeout, the
        last pool state read)."""
        self._blocking(lambda: redis_inspect.request_scaledown(remote, sorted(sids)))
        start, done = time.monotonic(), None
        while True:
            if self._cancelled:
                raise _Cancelled()
            self._spin(2000)
            try:
                state = self._blocking(lambda: redis_inspect.pool_state(remote))
            except Exception:  # noqa: BLE001
                continue
            elapsed = int(time.monotonic() - start)
            if not state.get("scaledown_pending"):
                done = self._now()
                # pool_state() reads the ready set before the pending flag, in
                # separate calls: a read spanning the last removal paired the
                # ready list from before it with "done" (the clean-up reported
                # pools 1-4 left while pool_manager had already removed pool 4).
                try:
                    state = self._blocking(lambda: redis_inspect.pool_state(remote))
                except Exception:  # noqa: BLE001
                    pass
                break
            if elapsed >= SCALEDOWN_TIMEOUT_S:
                break
            self._progress(f"{label} — {len(state.get('ready', []))} pool(s) left "
                           f"({elapsed // 60}:{elapsed % 60:02d})", n, total)
        return done, state

    def _cleanup_after_reassign(self, remote, sids: set[str], n: int, total_steps: int,
                                total: int) -> dict:
        """The reassignment check sent still-flagged sessions back to the shop
        with no free pool left, so the router parked them on a surviving pool
        and pool_manager started building pools for them -- which the run then
        left behind (~350 MB each, plus the build load) until the idle timeout.
        Release the sessions again (so no finished build is handed to them),
        wait for those builds, and scale down once more to remove the pools
        nobody needs."""
        label = f"Step {n}/{total_steps}: cleaning up after the reassignment check"
        start = self._now()
        _done, state = self._scaledown_and_wait(remote, sids, {}, label, n, total)
        building: set[int] = set()
        t0 = time.monotonic()
        while True:
            now_building = {int(p) for p in (state.get("status") or {}).get("building", {})}
            building |= now_building
            if not now_building or time.monotonic() - t0 >= CLEANUP_BUILD_TIMEOUT_S:
                break
            self._progress(f"{label} — waiting for pool(s) {', '.join(map(str, sorted(now_building)))} "
                           "to finish building before removing them", n, total)
            self._spin(3000)
            try:
                state = self._blocking(lambda: redis_inspect.pool_state(remote))
            except Exception:  # noqa: BLE001
                pass
        done = self._now()
        if building:
            done, state = self._scaledown_and_wait(remote, set(), state, label, n, total)
        return {"start": start, "done": done, "building": sorted(building),
                "pools_after": (state or {}).get("ready", [])}

    def _run_scenario(self, total_unused, _total, preset) -> PoolTestData | None:
        remote, target = self._remote(), target_for("edge", self.state)
        self._layer_db = honeypot_layer.is_database()
        count, delayed = self._count, self._delayed()
        now_windows = list(range(count - delayed))
        later_windows = list(range(count - delayed, count))
        cart_plan = CART_PLAN[:count]
        plan = self._attack_plan()
        # open, fill carts, one attack per immediate window, scale-up, [pre-build,
        # delayed attack, scale-up], second pattern, cart page
        total_steps = 2 + len(now_windows) + (1 if now_windows else 0) \
            + (3 if later_windows else 0) + 2 + 1      # ... + forced scale-down
        total = total_steps + 3
        self._progress("Resetting test sessions...", 0, total)
        self._blocking(self._reset_threat_state)
        for i, browser in enumerate(self.browsers):
            browser.clear_cookies()
            self._session_ids[i] = ""
            self._style_decision(i, Decision())
        self._load_all(["about:blank"] * len(self.browsers))
        self._spin(500)
        self._wc_keys = {}

        # If the operator agreed to GDPR for this export, seed each window with
        # its OWN consented gdpr_token now that its cookie jar is clean, before
        # any attack traffic goes out. Distinct per window so each keeps a
        # distinct gdpr_signature (segmentation stays intact). A later "clear
        # cookies / site data" tamper step drops it along with the session; the
        # window then re-consents (sends a fresh token with the same signature),
        # so a window already bound to a honeypot is routed straight back to its
        # pool -- see _clear_browser_data and signature_restorations().
        if self._gdpr is not None:
            for i in range(len(self.browsers)):
                self._apply_gdpr_cookie(i)

        try:
            ready = self._blocking(lambda: redis_inspect.pool_state(remote)).get("ready", [])
        except Exception:  # noqa: BLE001
            ready = []
        try:
            if self._layer_db:
                # Databases built from now on get their query log turned on
                # by pool_manager; take_baseline turns it on in these.
                self._qlog_pools = set(ready)
                self._blocking(lambda: redis_inspect.set_query_log(remote, True))
            baseline = self._blocking(
                lambda: pool_evidence.take_baseline(target, ready, self._layer_db))
            self._baseline = baseline
            # The run's clock starts here; pool_manager's events carry the edge
            # host's clock, so remember how far Redis' clock is from ours.
            try:
                offset = self._blocking(lambda: redis_inspect.server_time(remote)) - time.time()
            except Exception:  # noqa: BLE001 -- same host: no offset
                offset = 0.0
            try:
                _h = self._blocking(lambda: host_stats(target))
            except Exception:  # noqa: BLE001
                _h = None
            # Read by _run_steps when it builds the report data.
            self._host_cpus = _h[0] if _h else 0
            self._host_mem_total = _h[1] if _h else 0.0
            self._t0 = time.time()
            self._load_log = []
            self._pattern_urls = set()
            self._samples, self._loads, self._pending_loads, self._marks = [], [], [], []
            self._sampling = True
            self._reserve = {}
            self._visits = [0] * MAX_WINDOWS
            sampler = _UsageSampler(target, self._t0, self, shared_eshop=self._layer_db)
            sampler.start()
            try:
                return self._run_steps(remote, target, baseline, offset, sampler, count, delayed,
                                       now_windows, later_windows, cart_plan, plan, total_steps, total)
            finally:
                sampler.stop()
                sampler.wait(30000)
                self._t0 = 0.0
        finally:
            self._stop_query_log(remote, target)

    def _stop_query_log(self, remote, target) -> None:
        """Database layer: turn the query logs a run turned on off again (in
        the pools it started with, and every ready one, built during the run
        with the log on) and withdraw the build flag. Idempotent, so it runs
        once the evidence is read and again after a cancelled or failed run."""
        if self._qlog_pools is None:
            return
        pools, self._qlog_pools = self._qlog_pools, None

        def stop() -> None:
            try:
                ready = set(redis_inspect.pool_state(remote).get("ready", []))
            except Exception:  # noqa: BLE001 -- the pools it knows still get theirs off
                ready = set()
            try:
                redis_inspect.set_query_log(remote, False)
            finally:
                pool_evidence.disable_query_log(target, sorted(pools | ready), True)
        try:
            self._blocking(stop)
        except Exception:  # noqa: BLE001 -- the flag's TTL ends it anyway
            pass

    def _run_steps(self, remote, target, baseline, offset, sampler, count, delayed,
                   now_windows, later_windows, cart_plan, plan, total_steps, total):

        shop = self._base_url() + "/"
        results: list[StepResult] = []
        runs: list[PatternRun] = []
        used: set[str] = set()
        step = 0
        # Tampering (clearing or forging session data) starts once every window
        # has filled its cart (step 3) and can happen before any later step up
        # to the cart page; never the scale-down.
        clear_seed = random.randrange(2 ** 31) if self.clear_check.isChecked() else None
        schedule = clear_schedule(list(range(3, total_steps)), count,
                                  random.Random(clear_seed)) if clear_seed is not None else {}
        cleared: list[ClearEvent] = []

        def next_step(label: str) -> int:
            nonlocal step
            step += 1
            if self._recover_error_pages():
                self._progress(f"Step {step}/{total_steps}: reloaded windows left on an error page",
                               step, total)
            for w, variant in schedule.get(step, []):
                doing = "forges" if variant in COOKIE_FORGERIES or variant == "forge_storage" else "clears"
                self._progress(f"Step {step}/{total_steps}: {FRAMES[w][0]} {doing} its session data",
                               step, total)
                before = results[-1].decisions[w] if results and w < len(results[-1].decisions) else None
                cleared.append(self._clear_browser_data(w, variant, len(results), before))
            self._progress(f"Step {step}/{total_steps}: {label}", step, total)
            return step

        try:
            next_step("all windows open the shop")
            self._mark("All windows open the shop")
            self._load_all([shop] * len(self.browsers), "All windows open the shop")
            self._spin(700)
            decisions = self._settled_decisions(need_sessions=True)
            results.append(StepResult(
                "All windows open the shop", f"{count} new sessions, all routed to production.",
                ["Browses the shop"] * len(self.browsers), decisions,
                *self._capture()))

            # Every window fills its own cart, while still on production.
            next_step("every window fills its cart")
            self._mark("Every window fills its cart")
            slugs = sorted({slug for items in cart_plan for slug, _q in items})
            ids = self._product_ids(slugs)
            self._begin_browse()
            for k in range(max(len(items) for items in cart_plan)):
                urls = [f"{self._base_url()}/?add-to-cart={ids[items[k][0]]}&quantity={items[k][1]}"
                        if k < len(items) else self._browse_url(w) for w, items in enumerate(cart_plan)]
                self._load_all(urls, "Every window fills its cart")
                self._spin(500)
            decisions = self._settled_decisions(need_sessions=True)
            results.append(StepResult(
                "Every window fills its cart",
                "Each window adds its own products. These carts are the baseline: they must "
                "look exactly the same after the session is routed to a honeypot pool.",
                ["Adds " + ", ".join(f"{slug} \u00d7 {q}" for slug, q in items)
                 + (", then looks at " + ", ".join(dict.fromkeys(self._seen[w])) if self._seen[w] else "")
                 for w, items in enumerate(cart_plan)],
                decisions, *self._capture()))
            self._latency_probe("all on production", total_steps, total, step)
            # Every window is still on production: the pools' DB counters since
            # the baseline are their own background (healthchecks, cron, sync).
            self._blocking(lambda: pool_evidence.mark_idle(target, baseline))

            queues = [self._pattern_queue(i) for i in range(count)]
            for w in now_windows:
                n = next_step(f"{FRAMES[w][0]} attacks")
                first = next((p for p in queues[w] if p.cve not in used), queues[w][0])
                results.append(self._attack_step(
                    n, total_steps, total, [w], queues, used, runs,
                    f"{FRAMES[w][0]} attacks with {first.cve}",
                    f"{first.name}. The session must be bound to a pool no other window has -- "
                    "or, when no pool is free yet, borrow one round-robin until the pool being "
                    "built for it is ready -- and the windows that have not attacked yet must "
                    "stay on production."))

            if now_windows:
                results.append(self._wait_for_scaling(next_step("pools scale up"), total_steps, total))
                self._latency_probe("after the scale-up", total_steps, total, step)

            if later_windows:
                results.append(self._prescale(next_step("pre-building pools for the delayed windows"),
                                              total_steps, total, later_windows))
                letters = ", ".join(self._letter(w) for w in later_windows)
                results.append(self._attack_step(
                    next_step(f"delayed windows {letters} attack"), total_steps, total,
                    later_windows, queues, used, runs,
                    f"Delayed windows {letters} attack together",
                    "These windows attack only now that pools were built for them: each must get "
                    "a free pool of its own at once (no borrowing) -- unless the resource limit "
                    "stopped the build, in which case they share the ready pools round-robin."))
                results.append(self._wait_for_scaling(next_step("pools scale up"), total_steps, total))

            # Every window runs a SECOND pattern it has not run yet, all at once.
            next_step("all windows run a second pattern")
            self._mark("All windows run a second pattern")
            self._begin_browse()
            by_cve = {p.cve: p for p in PATTERN_PRESETS}
            second = []
            for w in range(count):
                own = {r.cve for r in runs if r.window == self._letter(w)}
                second.append(next((by_cve[c] for c in (plan[w][1], *fallback_patterns(self._layer_db))
                                    if c in by_cve and c not in own), None))
            urls = [self._base_url() + p.path if p else self._browse_url(w)
                    for w, p in enumerate(second)]
            self._pattern_urls.update(u for u, p in zip(urls, second) if p)
            self._load_all(urls, "All windows run a second pattern",
                           attacks=frozenset(w for w, p in enumerate(second) if p))
            self._spin(700)
            decisions = self._settled_decisions(need_sessions=True)
            for i, d in enumerate(decisions):
                if second[i]:
                    runs.append(PatternRun(self._letter(i), second[i].cve, second[i].name, 1,
                                           d.route == "HONEYPOT", d.pool))
            results.append(StepResult(
                "All windows run a second pattern",
                "Sticky binding: each second pattern must land in the pool the window already "
                "owns, nobody changes pool, nobody is merged.",
                [f"Opens {p.cve}" if p else self._browsed(w) for w, p in enumerate(second)], decisions,
                *self._capture()))

            self._latency_probe("at the end", total_steps, total, step)

            # Last step: open the cart page in every window -- what a shopper would see.
            next_step("every window opens its cart")
            self._mark("Every window opens its cart")
            self._load_all([self._base_url() + "/cart/"] * len(self.browsers),
                           "Every window opens its cart")
            # The block cart renders from the Store API after the page has
            # loaded: a fixed 2.5 s wait still screenshotted bare "Cart" pages.
            self._wait_for_render(_CART_RENDERED_JS, 20000)
            # The cart sits below the storefront header (~1200 px down): bring
            # it into the window, or the screenshot shows only the heading.
            for w in range(len(self.browsers)):
                self._run_js(w, _CART_SCROLL_JS, 2000)
            self._spin(500)
            decisions = self._settled_decisions(need_sessions=True)
            results.append(StepResult(
                "Every window opens its cart",
                "The cart page, served by each window's honeypot pool, must show the same "
                "products and quantities that were added on production.",
                ["Opens the cart page"] * len(self.browsers), decisions,
                *self._capture()))
        except _Cancelled:
            return None
        self._resolve_cleared(cleared, results)

        # Evidence and the registry first: the scale-down removes containers.
        self._progress("Reading what each honeypot container saw...", total - 2, total)
        try:
            pool_state = self._blocking(lambda: redis_inspect.pool_state(remote))
        except Exception:  # noqa: BLE001 -- the report says the state was unreadable
            pool_state = {}
        final = results[-1].decisions
        pools = list(dict.fromkeys(d.pool for d in final if d.pool is not None))
        pools += [n for n in pool_state.get("ready", []) if n not in pools][:max(0, count + 3 - len(pools))]
        wc_keys = {k: self._letter(i) for k, i in self._wc_keys.items() if i < count}
        evidence = self._blocking(lambda: pool_evidence.collect(target, pools, baseline, wc_keys))
        shared_files = None
        if self._layer_db:
            shared_files = self._blocking(lambda: pool_evidence.shared_files_changed(
                target, baseline.get("shared_since", "")))
            # The rest (scale-down, reassignment check) is not evidence.
            self._stop_query_log(remote, target)
        frames = [FrameResult(
            label=FRAMES[i][0], user_agent=b.profile.httpUserAgent(),
            language=b.profile.httpAcceptLanguage(), url=b.view.url().toString(),
            session_id=final[i].session_id, pool=final[i].pool,
            screenshot=results[-1].shots[i]) for i, b in enumerate(self.browsers)]

        try:
            scaledown = self._forced_scaledown(step + 1, total_steps, total, sampler)
        except _Cancelled:
            return None
        now = self._now()
        # The run ends where the clean-up after the reassignment check starts:
        # that clean-up (waiting for builds, a second scale-down) is not part of
        # the test, and in the figures it showed as extra minutes with pools
        # coming back up. Its length is reported on its own.
        cleanup_start = (scaledown.get("cleanup") or {}).get("start")
        duration = cleanup_start if cleanup_start is not None else now
        try:
            raw_events = self._blocking(lambda: redis_inspect.pool_events(remote))
        except Exception:  # noqa: BLE001 -- the latency section says so
            raw_events = []
        t0 = time.time() - now
        events = []
        for e in raw_events:
            at = float(e["at"]) - offset - t0
            if at < -5 or at > duration + 5:
                continue
            e = dict(e, at=at)
            if "start" in e:
                e["start"] = float(e["start"]) - offset - t0
            events.append(e)
        return PoolTestData(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_label=target.label, base_url=self._base_url(),
            pattern="; ".join(
                f"{w}: " + ", ".join(r.cve for r in runs if r.window == w)
                for w in sorted({r.window for r in runs})), frames=frames,
            pool_state=pool_state, steps=results, runs=runs, evidence=evidence,
            since=baseline.get("since", ""), duration=duration, delayed=delayed,
            cleanup_seconds=now - duration,
            samples=list(self._samples), loads=list(self._loads), events=events,
            marks=list(self._marks), reserve=dict(self._reserve),
            usage=[u for u in sampler.samples if u.t <= duration], scaledown=scaledown,
            host_cpus=self._host_cpus, host_mem_total_mb=self._host_mem_total,
            load_log=list(self._load_log),
            cleared=cleared, clear_seed=clear_seed,
            honeypot_layer=(honeypot_layer.DATABASE.id if self._layer_db
                            else honeypot_layer.REVERSE_PROXY.id),
            shared_files=shared_files)

    def reset_sessions(self) -> None:
        for browser in self.browsers:
            browser.clear_cookies()
            browser.navigate(self._base_url() + "/")

    def _show_export_result(self, text: str) -> None:
        self.export_label.setText(text)
        self.export_label.setVisible(True)

    def refresh_pool_state(self) -> None:
        """Read the pool registry off the GUI thread (a stopped stack makes the
        docker call slow). Runs when the page is shown, on the button, and every
        POOL_REFRESH_MS -- also during a report export, whose own registry
        reads go through separate calls, so this one only updates the line."""
        if getattr(self, "_pool_job", None) is not None:
            return
        remote = self._remote()
        job = _Job(lambda: redis_inspect.pool_state(remote), self)
        self._pool_job = job

        def done() -> None:
            self._pool_job = None
            if job.error is not None:
                self.pool_label.setText(f"Pool state unavailable: {job.error}")
            else:
                info = job.result
                owners = ", ".join(f"pool {n}: {c} session(s)"
                                   for n, c in sorted(info["owners"].items()))
                text = f"Ready pools: {info['ready'] or 'none'} — owners: {owners or 'none'}"
                status = info.get("status") or {}
                if status:
                    building = ", ".join(sorted(status.get("building", {})))
                    text += (f" — room for {status.get('room', '?')} more pool(s) under the "
                             "resource limit" + (f", building {building}" if building else ""))
                if info.get("waiting"):
                    text += (f" — scaling up: {info['waiting']} session(s) borrow a pool "
                             "until theirs is built")
                if info["capped"]:
                    text += (f" — pool growth capped: {info['capped']} (further sessions "
                             "share the ready pools round-robin)")
                self.pool_label.setText(text)
            job.deleteLater()
        job.finished.connect(done)
        job.start()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.refresh_pool_state()
        self._poll.start()
        self._pool_poll.start()

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        if not self._exporting:
            self._poll.stop()
            self._pool_poll.stop()
