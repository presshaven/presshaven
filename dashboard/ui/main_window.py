"""Main application window: a grouped navigation rail (Monitor / Threat
operations / Manage / Reporting) with drag-and-drop reordering, a persistent
per-category overflow panel, per-page SVG icons, a page header bar, a menu bar
(Settings menu + re-run wizard), a shared background status poller,
window-geometry persistence, a system tray icon (unhealthy-container
notifications), a custom frameless title bar (ui/title_bar.py: brand, menus,
centred Ctrl+K search, presshaven.io link) and a confirm-before-quit guard
while a mutating docker compose action is in flight."""
from __future__ import annotations

import base64
import time

from PyQt6.QtCore import QByteArray, QSize, Qt
from PyQt6.QtGui import QAction, QIcon, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QListWidgetItem, QMainWindow, QMenu, QMenuBar,
    QMessageBox, QPushButton, QStackedWidget, QSystemTrayIcon, QToolButton,
    QVBoxLayout, QWidget,
)

from core import alert_policy, honeypot_layer, live_events, palette
from core.docker_ctl import all_targets, target_for
from core.paths import DASHBOARD_DIR
from core.learning import PAGE_GUIDES
from core.state import AppState
from ui import page_icons, theme
from ui.command_palette import CommandPalette
from ui.common import Job, confirm
from ui.dependency_banner import DependencyBanner
from ui.host_settings_banner import HostSettingsBanner
from ui.error_monitor import ErrorLogMonitor
from core.container_status import classify
from ui.nav_overflow import (
    GROUP_ROLE, PAGE_ROLE, NavGroupHeader, NavOverflowPanel, NavSidebarList,
    make_page_item,
)
from ui.page_backups import BackupsPage
from ui.page_certs import CertsPage
from ui.page_patterns import PatternsPage
from ui.page_wp_studio import WpStudioPage
from ui.page_targeted_access import TargetedAccessPage
from ui.page_wp_update import WpUpdatePage
from ui.page_pattern_database import PatternDatabasePage
from ui.page_signature_sim import SignatureSimPage
from ui.page_account_persistence import AccountPersistencePage
from ui.page_detection import DetectionPage
from ui.page_honeypot_targets import HoneypotTargetsPage
from ui.page_whitelist import WhitelistPage
from ui.page_container_firewall import ContainerFirewallPage
from ui.page_extras import ExtrasPage
from ui.page_health import HealthPage
from ui.page_kibana import KibanaPage
from ui.page_learn import LearnPage, page_guide_html
from ui.page_live_events import LiveEventsPage
from ui.page_log_search import LogSearchPage
from ui.page_overview import OverviewPage
from ui.page_pipeline import PipelinePage
from ui.page_pool_scaling import PoolScalingPage
from ui.page_pool_test import PoolTestPage
from ui.page_breach_audit import BreachAuditPage
from ui.page_redis import RedisPage
from ui.page_resources import ResourcesPage
from ui.page_services import ServicesPage
from ui.page_sessions import SessionsPage
from ui.page_settings import SettingsPage
from ui.page_suricata import SuricataPage
from ui.responsive import scrollable
from ui.security_feed import SecurityEventFeed
from ui.status_poller import StatusPoller
from ui.title_bar import TitleBar, WindowBorder, WindowResizeGrips
from ui.wizard import SetupWizard

# Bundled instead of relying on QIcon.fromTheme() -- confirmed live that
# "utilities-system-monitor" resolves to a NULL icon on this window
# manager/icon theme, which QSystemTrayIcon happily accepts and then shows
# as blank, clickable empty space in the tray rather than erroring or
# falling back to anything. A file shipped in the repo works the same
# regardless of the host's icon theme.
_APP_ICON_PATH = DASHBOARD_DIR / "resources" / "app_icon.svg"

# Statuses (see ui.health_diagram.classify()) worth a tray notification when
# a container transitions INTO them. Deliberately excludes "down" (a
# container simply not running -- e.g. before the user has hit Start -- is
# the normal resting state, not a problem) and "exited_ok" (a one-shot job
# finishing cleanly is success, not something to alarm about).
_NOTIFY_ON_STATUSES = {"unhealthy", "exited_bad"}

PAGES = [
    "overview", "live_events", "pipeline", "sessions", "suricata", "detection", "whitelist", "honeypot_targets", "container_firewall", "pool_scaling", "services", "health", "resources", "certificates", "redis", "backups",
    "kibana", "patterns", "pattern_database", "signature_sim", "account_persistence", "pool_test", "breach_audit", "log_search", "extras", "wp_studio", "wp_update", "targeted_access", "settings", "learn",
]
PAGE_LABELS = {
    "overview": "Overview",
    "live_events": "Live Events",
    "pipeline": "Log Pipeline",
    "sessions": "Adversary Sessions",
    "suricata": "Network IDS (Suricata)",
    "detection": "Detection Policy",
    "whitelist": "URL Whitelist",
    "honeypot_targets": "Honeypot Targets",
    "container_firewall": "Container Firewall",
    "pool_scaling": "Pool Scaling",
    "services": "Workloads",
    "health": "Global Visualization",
    "resources": "Workload Telemetry",
    "certificates": "PKI & Certificates",
    "redis": "Pool State Store",
    "backups": "Backup & Recovery",
    "kibana": "SIEM Analytics",
    "patterns": "Attack Simulation",
    "pattern_database": "Pattern Database",
    "signature_sim": "Signature Simulation",
    "account_persistence": "Account Persistence",
    "pool_test": "Segmentation Validation",
    "breach_audit": "Breach Validation",
    "log_search": "Forensics Analysis",
    "extras": "Reporting",
    "wp_studio": "WordPress Studio",
    "wp_update": "WordPress Update",
    "targeted_access": "Targeted Access",
    "settings": "Connectors & Config",
    "learn": "Knowledge Base",
}

# The navigation rail's sections, top to bottom. Every page id appears
# exactly once. NAV_ORDER is the full flattened list in default order (used
# as a fallback when state.last_page is invalid). The rows the rail actually
# shows come from the user-editable _nav_layout, and Ctrl+1..9 follow that
# live order.
# Each group lists its default sidebar rows first, then the pages that
# default into its "⋮" overflow panel (see NAV_OVERFLOW), so this order is
# also the View-menu order and the default visible/overflow ordering.
NAV_GROUPS = [
    ("Overview", ["overview"]),
    ("Monitor", ["live_events", "health", "kibana", "pipeline", "resources", "log_search"]),
    ("Threat Operations", ["patterns", "sessions", "suricata", "detection", "honeypot_targets", "whitelist", "container_firewall", "pattern_database", "signature_sim", "account_persistence", "pool_scaling", "pool_test", "breach_audit", "redis"]),
    ("Manage", ["services", "wp_studio", "wp_update", "targeted_access", "settings", "certificates", "backups"]),
    ("Reporting", ["learn", "extras"]),
]

# Pages that stay one click away in their group's "⋮" menu instead of
# taking a row in the rail. Everything here is still reachable through the
# View menu, Ctrl+K palette and the group menu, so this is purely about
# keeping the rail focused on the most useful, informative pages:
# the sidebar shows the live monitoring surfaces (Live Events, Global
# Visualization, SIEM Analytics), the core threat-ops pages and
# workload/config control; diagnostics (Log Pipeline, Workload Telemetry,
# Forensics), reference/validation tooling, and the Reporting group's
# teaching material and one-off exports (Knowledge Base, Implementation
# export) are not needed day to day, so they move into overflow.
NAV_OVERFLOW = {
    "Monitor": ["pipeline", "resources", "log_search"],
    "Threat Operations": ["pattern_database", "signature_sim", "account_persistence", "pool_scaling", "pool_test", "breach_audit", "redis"],
    "Manage": ["certificates", "backups"],
    "Reporting": ["learn", "extras"],
}

NAV_ORDER = [page_id for _group, ids in NAV_GROUPS for page_id in ids]
PAGE_GROUP = {page_id: group for group, ids in NAV_GROUPS for page_id in ids}

APP_TITLE = "PressHaven.io"


def _default_nav_layout() -> dict[str, dict[str, list[str]]]:
    """The rail layout before the user drags anything: every page in its
    category's default visible rows or its default overflow panel."""
    layout: dict[str, dict[str, list[str]]] = {}
    for group, page_ids in NAV_GROUPS:
        overflow = set(NAV_OVERFLOW.get(group, []))
        layout[group] = {
            "visible": [page_id for page_id in page_ids if page_id not in overflow],
            "overflow": [page_id for page_id in page_ids if page_id in overflow],
        }
    return layout


def _normalize_nav_layout(raw) -> dict[str, dict[str, list[str]]]:
    """Merge a saved layout with the code's current defaults.

    Tolerates old state.json files (no layout), unknown page ids, duplicate
    rows, and pages added to NAV_GROUPS since the layout was saved. Every
    page in a category ends up in exactly one of its two lists, so nothing
    can become unreachable just because the saved JSON was stale.
    """
    default = _default_nav_layout()
    if not isinstance(raw, dict):
        return default

    result: dict[str, dict[str, list[str]]] = {}
    for group, page_ids in NAV_GROUPS:
        default_entry = default[group]
        all_pages = set(page_ids)
        entry = raw.get(group)
        visible: list[str] = []
        overflow: list[str] = []
        if isinstance(entry, dict):
            for key, destination in (("visible", visible), ("overflow", overflow)):
                values = entry.get(key)
                if not isinstance(values, list):
                    continue
                for page_id in values:
                    if (page_id in all_pages and page_id not in visible
                            and page_id not in overflow):
                        destination.append(page_id)
        # Anything missing (a new page, a malformed list, a group absent
        # from an old save) takes its default home.
        for page_id in page_ids:
            if page_id in visible or page_id in overflow:
                continue
            if page_id in default_entry["visible"]:
                visible.append(page_id)
            else:
                overflow.append(page_id)
        result[group] = {"visible": visible, "overflow": overflow}
    return result

# Responsive breakpoints, in window pixels: below NARROW_WIDTH the
# navigation rail collapses behind the header's menu button (and closes
# again after a page is picked); below SHORT_HEIGHT the header drops its
# summary line and the dependency banner its details.
NARROW_WIDTH = 900
SHORT_HEIGHT = 700


def _menu_text(label: str) -> str:
    """A label as QAction text: a lone "&" there marks a mnemonic."""
    return label.replace("&", "&&")


class MainWindow(QMainWindow):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        # User-editable rail order / overflow membership. Normalized before
        # the rail is built so a stale or hand-edited state.json can never
        # hide a page.
        self._nav_layout = _normalize_nav_layout(state.nav_layout)
        self._page_actions: list[tuple[QAction, str]] = []
        self._current_page_id = state.last_page if state.last_page in PAGES else "overview"
        self._nav_more_buttons: dict[str, QToolButton] = {}
        # Before any page builds a Target: they all read the active layer.
        honeypot_layer.set_active(state.honeypot_layer)
        self.setWindowTitle(APP_TITLE)
        self.resize(1280, 820)
        if _APP_ICON_PATH.exists():
            self.setWindowIcon(QIcon(str(_APP_ICON_PATH)))
        # Our own title bar replaces the OS one; it holds the menu bar and
        # the centred command-palette search.
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.title_bar = TitleBar(self, self.windowIcon())
        self.title_bar.searchRequested.connect(self._show_palette)
        self.setMenuWidget(self.title_bar)
        self._resize_grips = WindowResizeGrips(self, self.title_bar.host.is_maximized)
        self._border = WindowBorder(self, self.title_bar.host.is_maximized)
        self._restore_geometry()

        self._build_menu()

        central = QWidget()
        central_layout = QVBoxLayout(central)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)
        self.setCentralWidget(central)

        # Persistent across every page (unlike a per-page banner, this
        # can't be missed just because docker/docker compose happened to
        # be fine when whichever page you're currently on was built).
        self.dependency_banner = DependencyBanner()
        # Kernel settings a stack needs on its host (this machine or a
        # remote server), checked in the background per target in use.
        self.host_settings_banner = HostSettingsBanner(state)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        central_layout.addLayout(body, stretch=1)

        self.nav_rail = self._build_nav_rail()
        body.addWidget(self.nav_rail)
        self._narrow: bool | None = None   # set by the first resizeEvent()
        self._short: bool | None = None

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        content_layout.addWidget(self._build_header_bar())
        self.stack = QStackedWidget()
        stack_holder = QWidget()
        stack_layout = QVBoxLayout(stack_holder)
        stack_layout.setContentsMargins(12, 10, 12, 10)
        stack_layout.setSpacing(10)
        stack_layout.addWidget(self.dependency_banner)
        stack_layout.addWidget(self.host_settings_banner)
        stack_layout.addWidget(self.stack, stretch=1)
        content_layout.addWidget(stack_holder, stretch=1)
        body.addWidget(content, stretch=1)

        # App-lifetime background tail of reverse_proxy's logs, independent
        # of whether the Attack Simulation page is open -- persists notable events
        # (honeypot diversions, CVE/high-severity signals, missing
        # dependencies) to AppState.security_events across restarts. No
        # page currently displays this (see ui/security_feed.py); kept
        # running since the underlying data collection is independently
        # useful and the cost is one background log tail.
        self.security_feed = SecurityEventFeed(state, self)
        self.security_feed.start(self._edge_target())

        # Shared across Services (feeds it, from every target's always-
        # running combined log tail) and Health (reads it, to badge nodes)
        # -- see ui/error_monitor.py.
        self.error_monitor = ErrorLogMonitor(self)

        # Landing page -- consumes the security feed created just above (its
        # current score + persisted notable-event history) and the status
        # poller's results (wired in _on_status_results).
        self.overview_page = OverviewPage(state, self.security_feed)
        self.overview_page.open_page_requested.connect(self._open_page)
        self.overview_page.lifecycle_requested.connect(self._on_lifecycle_requested)
        # The landing screen lists every other page as a clickable card; the
        # page list and its labels live here, so hand the directory in.
        self.overview_page.set_page_directory(
            [(pid, PAGE_LABELS[pid]) for pid in PAGES if pid != "overview"])
        self.live_events_page = LiveEventsPage(self.security_feed, state)
        self.pipeline_page = PipelinePage(state)
        self.sessions_page = SessionsPage(state)
        self.suricata_page = SuricataPage(state)
        self.detection_page = DetectionPage(state)
        self.whitelist_page = WhitelistPage(state)
        self.container_firewall_page = ContainerFirewallPage(state)
        self.honeypot_targets_page = HoneypotTargetsPage(state)
        self.pool_scaling_page = PoolScalingPage(state)
        self.services_page = ServicesPage(
            self._get_targets, self.error_monitor, self._grab_health_screenshot, state)
        self.services_page.layer_changed.connect(self._on_honeypot_layer_changed)
        self.health_page = HealthPage(self._get_targets, self.error_monitor)
        self.resources_page = ResourcesPage(self._get_targets)
        self.certs_page = CertsPage()
        self.redis_page = RedisPage(state)
        self.backups_page = BackupsPage(state)
        self.kibana_page = KibanaPage(state)
        self.patterns_page = PatternsPage(state)
        self.pattern_database_page = PatternDatabasePage()
        # Enabling/disabling (or adding/removing) a pattern in the database is
        # a pattern-plugin change: the pages that run patterns re-read the
        # registry so a disabled pattern stops being simulated at once.
        self.pattern_database_page.registry_changed.connect(self._on_pattern_registry_changed)
        # Honeypot Targets toggles the same registry flags.
        self.honeypot_targets_page.registry_changed.connect(self._on_target_registry_changed)
        # Every pattern run drops a time-aligned marker onto the Resources
        # graphs so its resource impact is visible.
        self.patterns_page.pattern_ran.connect(self.resources_page.add_pattern_marker)
        self.signature_sim_page = SignatureSimPage(state)
        self.account_persistence_page = AccountPersistencePage(state)
        self.pool_test_page = PoolTestPage(state)
        self.breach_audit_page = BreachAuditPage(state)
        self.log_search_page = LogSearchPage(state)
        self.extras_page = ExtrasPage(self._grab_health_screenshot)
        self.extras_page.open_page_requested.connect(self._open_page)
        self.wp_studio_page = WpStudioPage(state)
        self.wp_update_page = WpUpdatePage(state)
        self.targeted_access_page = TargetedAccessPage(state)
        self.settings_page = SettingsPage(state, self._on_remote_settings_changed, self.set_poll_interval,
                                      on_test_alert=self._test_alert,
                                      edge_running=self.services_page._edge_running,
                                      on_layer_changed=self._on_layer_set_elsewhere)
        self.learn_page = LearnPage(state, PAGE_LABELS)
        self.learn_page.open_page_requested.connect(self._open_page)

        for page_id, widget in [
            ("overview", self.overview_page),
            ("live_events", self.live_events_page),
            ("pipeline", self.pipeline_page),
            ("sessions", self.sessions_page),
            ("suricata", self.suricata_page),
            ("detection", self.detection_page),
            ("whitelist", self.whitelist_page),
            ("container_firewall", self.container_firewall_page),
            ("honeypot_targets", self.honeypot_targets_page),
            ("pool_scaling", self.pool_scaling_page),
            ("services", self.services_page),
            ("health", self.health_page),
            ("resources", self.resources_page),
            ("certificates", self.certs_page),
            ("redis", self.redis_page),
            ("backups", self.backups_page),
            ("kibana", self.kibana_page),
            ("patterns", self.patterns_page),
            ("pattern_database", self.pattern_database_page),
            ("signature_sim", self.signature_sim_page),
            ("account_persistence", self.account_persistence_page),
            ("pool_test", self.pool_test_page),
            ("breach_audit", self.breach_audit_page),
            ("log_search", self.log_search_page),
            ("extras", self.extras_page),
            ("wp_studio", self.wp_studio_page),
            ("wp_update", self.wp_update_page),
            ("targeted_access", self.targeted_access_page),
            ("settings", self.settings_page),
            ("learn", self.learn_page),
        ]:
            # Each page scrolls on its own when the window is smaller than
            # it, so no page dictates the window's minimum size.
            self.stack.addWidget(scrollable(widget))

        start_page = state.last_page if state.last_page in PAGES else NAV_ORDER[0]
        # First launch with this feature: open on Learn once, so a student
        # sees the orientation and labs before the control pages.
        if not state.learn_welcome_shown:
            start_page = "learn"
            state.learn_welcome_shown = True
            state.save()
        self.nav_list.currentItemChanged.connect(self._on_nav_changed)
        self._open_page(start_page)

        self.poller = StatusPoller(self._get_targets, interval_ms=state.poll_interval_ms)
        self.poller.results_ready.connect(self._on_status_results)
        # Pages that want fresh status when opened ask the poller thread
        # instead of running `docker compose ps` on the GUI thread.
        self.health_page.refresh_requested.connect(self.poller.poll_now)
        self.patterns_page.refresh_requested.connect(self.poller.poll_now)
        self.wp_studio_page.refresh_requested.connect(self.poller.poll_now)
        self.wp_update_page.refresh_requested.connect(self.poller.poll_now)
        self.poller.start()

        # Previous poll's classified status per (target_key, service), used
        # to detect NEW unhealthy/exited-with-error transitions rather than
        # re-notifying on every single poll tick while a container just sits
        # unhealthy.
        self._last_status: dict[tuple[str, str], str] = {}

        self._build_tray_icon()

        # Security alerting (core/alert_policy.py): every parsed proxy event
        # is checked against the user's policy.
        self._alerts_sent: dict[str, float] = {}
        self._webhook_jobs: set = set()
        self._last_webhook_error = ""
        self._last_webhook_warn_at = 0.0
        self.security_feed.event_parsed.connect(self._on_security_event)

        # A required tool going missing is recorded into the same
        # persisted security-events history as everything else the feed
        # tracks, not just this banner's own standing warning.
        self.dependency_banner.required_missing_detected.connect(self.security_feed.add_dependency_event)

        self._build_shortcuts()

    # ---- navigation / target plumbing ----

    def _grab_health_screenshot(self, target_key: str | None = None,
                                containers: list[dict] | None = None) -> str:
        """Bring the Global Visualization page on-screen briefly, grab it, and return a PNG
        path for the Extras thesis export. Restores the previous page. Returns
        "" if the grab fails -- the export tolerates a missing screenshot.

        With ``target_key`` (the Services report) it instead draws just that
        target's tiles from ``containers``, a `ps` result the caller already
        has (HealthPage.snapshot_target()) -- no page switch, no poll wait."""
        import os
        import tempfile
        from PyQt6.QtCore import QEventLoop, QTimer

        if target_key is not None:
            try:
                image = self.health_page.snapshot_target(target_key, containers or [])
                if image is None or image.isNull():
                    return ""
                path = os.path.join(tempfile.mkdtemp(prefix="services_health_"), "health.png")
                image.save(path)
                return path
            except Exception:  # noqa: BLE001 -- best-effort screenshot
                return ""

        prev = self.stack.currentIndex()
        try:
            self.stack.setCurrentIndex(PAGES.index("health"))
            # Let it lay out and paint before grabbing.
            loop = QEventLoop()
            QTimer.singleShot(700, loop.quit)
            loop.exec()
            pixmap = self.health_page.grab()
        except Exception:  # noqa: BLE001 -- best-effort screenshot
            return ""
        finally:
            self.stack.setCurrentIndex(prev)
        if pixmap.isNull():
            return ""
        try:
            path = os.path.join(tempfile.mkdtemp(prefix="thesis_health_"), "health.png")
            image = pixmap.toImage()
            image.setDevicePixelRatio(1.0)
            image.save(path)
            return path
        except Exception:  # noqa: BLE001
            return ""

    def _get_targets(self):
        return all_targets(self.state)

    def _edge_target(self):
        """The reverse_proxy target the security feed tails -- the same one
        the Attack Simulation page's score badge uses (target_for picks remote when
        configured, else local)."""
        return target_for("edge", self.state)

    def _build_nav_rail(self) -> QWidget:
        """One non-selectable header per NAV_GROUPS
        section followed by the rows currently in that section's visible
        list. Page items carry their page id in PAGE_ROLE; header items
        carry only GROUP_ROLE."""
        rail = QFrame()
        rail.setObjectName("NavRail")
        rail.setFixedWidth(236)
        layout = QVBoxLayout(rail)
        layout.setContentsMargins(0, 6, 0, 12)
        layout.setSpacing(0)

        self.nav_list = NavSidebarList()
        self.nav_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.nav_list.setToolTip(
            "Drag pages to reorder, or into a category's ⋮ panel to hide them")
        self._nav_items: dict[str, QListWidgetItem] = {}
        self.nav_list.pageDropped.connect(
            self._on_page_dropped, Qt.ConnectionType.QueuedConnection)
        self._render_nav_list()
        layout.addWidget(self.nav_list, stretch=1)

        footer = QLabel("Edge + SIEM digital twin")
        footer.setObjectName("NavFooter")
        footer.setContentsMargins(20, 8, 16, 0)
        layout.addWidget(footer)

        # The persistent overflow side panel lives directly on the window
        # (not in a layout) so it can sit beside the rail without resizing
        # the content. It is shown on demand by each category's "⋮".
        self.overflow_panel = NavOverflowPanel(self)
        self.overflow_panel.pageActivated.connect(self._open_page)
        self.overflow_panel.pageDropped.connect(
            self._on_page_dropped, Qt.ConnectionType.QueuedConnection)
        self.overflow_panel.keep_open_when_clicking(rail)
        self.overflow_panel.set_rail(rail)

        theme.on_change(self._refresh_page_icons)
        return rail

    def _render_nav_list(self) -> None:
        """Rebuild the rail from _nav_layout, preserving the selected page.

        Rebuilding (rather than moving QListWidget rows in place) keeps the
        group headers and the user's ordering as the single source of truth,
        and makes a drop across the visible/overflow boundary one code path.
        """
        if not hasattr(self, "nav_list"):
            return
        scroll = self.nav_list.verticalScrollBar().value()
        self.nav_list.blockSignals(True)
        try:
            self.nav_list.clear()
            self._nav_items.clear()
            self._nav_more_buttons.clear()
            for group, _page_ids in NAV_GROUPS:
                header = QListWidgetItem()
                header.setData(GROUP_ROLE, group)
                header.setFlags(Qt.ItemFlag.NoItemFlags)
                header.setSizeHint(QSize(0, 40))
                self.nav_list.addItem(header)
                self.nav_list.setItemWidget(header, self._nav_group_header(group))
                for page_id in self._nav_layout[group]["visible"]:
                    guide = PAGE_GUIDES.get(page_id)
                    item = make_page_item(
                        page_id, PAGE_LABELS[page_id], group,
                        page_icons.page_icon(page_id),
                        guide.summary if guide else "", row_height=32,
                    )
                    self.nav_list.addItem(item)
                    self._nav_items[page_id] = item
            current_item = self._nav_items.get(self._current_page_id)
            if current_item is not None:
                self.nav_list.setCurrentItem(current_item)
            else:
                self.nav_list.setCurrentRow(-1)
            self.nav_list.verticalScrollBar().setValue(scroll)
        finally:
            self.nav_list.blockSignals(False)

    def _nav_group_header(self, group: str) -> QWidget:
        """A category label plus its "⋮" button. The button opens the
        category's persistent overflow panel -- the drop target that lets
        pages move between the rail and that panel. The header itself is
        also a drop target so a section with no visible rows can still
        receive a page back from overflow."""
        header = NavGroupHeader(group)
        header.moreClicked.connect(
            lambda name=group, button=header.more:
            self._show_nav_overflow_panel(button, name)
        )
        header.pageDropped.connect(
            self._on_page_dropped, Qt.ConnectionType.QueuedConnection)
        self._nav_more_buttons[group] = header.more
        return header

    def _show_nav_overflow_panel(self, button: QToolButton, group: str) -> None:
        """Open (or toggle) a category's overflow side panel beside the
        rail. The panel stays open during drags, unlike a QMenu."""
        if group not in self._nav_layout:
            return
        if self.overflow_panel.isVisible() and self.overflow_panel.group == group:
            self.overflow_panel.hide()
            return
        self._refresh_overflow_panel(group)
        self.overflow_panel.show_at(button)

    def _refresh_overflow_panel(self, group: str | None = None) -> None:
        group = group or self.overflow_panel.group
        if group not in self._nav_layout:
            return
        entries = []
        for page_id in self._nav_layout[group]["overflow"]:
            guide = PAGE_GUIDES.get(page_id)
            entries.append((
                page_id,
                PAGE_LABELS[page_id],
                page_icons.page_icon(page_id),
                guide.summary if guide else "",
            ))
        self.overflow_panel.set_pages(group, entries, self._current_page_id)
        if self.overflow_panel.isVisible():
            self.overflow_panel.keep_on_screen()

    def _on_page_dropped(self, page_id: str, source_group: str, target_group: str,
                         target_kind: str, target_index: int) -> None:
        """A page was dropped in the rail or the overflow panel.

        Cross-category drags are intentionally ignored: PAGE_GROUP and the
        breadcrumb treat a page's category as fixed.
        """
        if source_group != target_group:
            return
        self._move_page(page_id, target_group, target_kind, target_index)

    def _move_page(self, page_id: str, target_group: str, target_kind: str,
                   target_index: int) -> None:
        if target_kind not in ("visible", "overflow"):
            return
        if PAGE_GROUP.get(page_id) != target_group:
            return
        entry = self._nav_layout.get(target_group)
        if entry is None:
            return
        if page_id in entry["visible"]:
            source_kind = "visible"
        elif page_id in entry["overflow"]:
            source_kind = "overflow"
        else:
            return

        source_index = entry[source_kind].index(page_id)
        entry[source_kind].remove(page_id)
        target_list = entry[target_kind]
        if source_kind == target_kind and source_index < target_index:
            target_index -= 1
        target_index = max(0, min(target_index, len(target_list)))
        target_list.insert(target_index, page_id)
        self._apply_nav_layout()

    def _apply_nav_layout(self) -> None:
        self.state.nav_layout = self._nav_layout
        self.state.save()
        self._render_nav_list()
        if self.overflow_panel.isVisible():
            self._refresh_overflow_panel()

    def _visible_order(self) -> list[str]:
        return [
            page_id
            for group, _page_ids in NAV_GROUPS
            for page_id in self._nav_layout[group]["visible"]
        ]

    def _open_nth_visible(self, index: int) -> None:
        order = self._visible_order()
        if 0 <= index < len(order):
            self._open_page(order[index])

    def _refresh_page_icons(self) -> None:
        for page_id, item in getattr(self, "_nav_items", {}).items():
            item.setIcon(page_icons.page_icon(page_id))
        for action, page_id in self._page_actions:
            action.setIcon(page_icons.menu_icon(page_id))
        panel = getattr(self, "overflow_panel", None)
        if panel is not None and panel.isVisible():
            self._refresh_overflow_panel()

    def _build_header_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("HeaderBar")
        layout = QVBoxLayout(bar)
        layout.setContentsMargins(20, 14, 20, 12)
        layout.setSpacing(2)
        crumb_row = QHBoxLayout()
        crumb_row.setSpacing(10)
        self.nav_toggle = QPushButton("☰")
        self.nav_toggle.setObjectName("NavToggle")
        self.nav_toggle.setToolTip("Show or hide the navigation")
        self.nav_toggle.setProperty("compact", True)
        self.nav_toggle.setFixedWidth(34)
        self.nav_toggle.clicked.connect(lambda: self._set_nav_visible(not self.nav_rail.isVisible()))
        self.page_crumb = QLabel()
        self.page_crumb.setObjectName("PageCrumb")
        # Long labels must not set the window's minimum width.
        self.page_crumb.setMinimumWidth(1)
        self.page_title = QLabel()
        self.page_title.setObjectName("PageTitle")
        self.page_subtitle = QLabel()
        self.page_subtitle.setObjectName("PageSubtitle")
        self.page_subtitle.setWordWrap(True)
        # The command palette's always-visible entry point lives in the
        # title bar (TitleBar.search_btn), centred above every page.
        crumb_row.addWidget(self.nav_toggle)
        crumb_row.addWidget(self.page_crumb, stretch=1)
        layout.addLayout(crumb_row)
        layout.addWidget(self.page_title)
        layout.addWidget(self.page_subtitle)
        return bar

    def current_page(self) -> str:
        return self._current_page_id if self._current_page_id in PAGES else "learn"

    def _open_page(self, page_id: str) -> None:
        """Open a page whether it is currently a rail row, a category
        overflow page, or reached from the View menu / palette / a link."""
        if page_id not in PAGES:
            return
        item = self._nav_items.get(page_id)
        if item is not None:
            if self.nav_list.currentItem() is item:
                self._show_page(page_id)
            else:
                self.nav_list.setCurrentItem(item)
            return
        # An overflow page has no rail row to select. Clear the old
        # selection (without firing _on_nav_changed) and display it
        # directly; _current_page_id is the source of truth for "where am I".
        self.nav_list.blockSignals(True)
        try:
            self.nav_list.setCurrentRow(-1)
            self.nav_list.clearSelection()
        finally:
            self.nav_list.blockSignals(False)
        self._show_page(page_id)

    def _on_nav_changed(self, current: QListWidgetItem | None, _previous=None) -> None:
        page_id = current.data(PAGE_ROLE) if current is not None else None
        if page_id in PAGES:
            self._show_page(page_id)

    def _show_page(self, page_id: str) -> None:
        self._current_page_id = page_id
        self.stack.setCurrentIndex(PAGES.index(page_id))
        self.page_crumb.setText(f"{PAGE_GROUP[page_id].upper()}  ›  {PAGE_LABELS[page_id].upper()}")
        self.page_title.setText(PAGE_LABELS[page_id])
        guide = PAGE_GUIDES.get(page_id)
        self.page_subtitle.setText(guide.summary if guide else "")
        self.page_subtitle.setVisible(bool(guide) and not self._short)
        # Narrow window: the rail is a drawer, closed again once a page is picked.
        if self._narrow:
            self._set_nav_visible(False)
        panel = getattr(self, "overflow_panel", None)
        if panel is not None:
            panel.hide()
        self.state.last_page = page_id
        self.state.save()

    def _on_remote_settings_changed(self) -> None:
        self.host_settings_banner.refresh()
        self.services_page.rebuild_panels()
        # Global Visualization page rebuilds its diagram automatically on the next poll
        # tick (it always calls _get_targets() fresh in apply_status()).
        self.redis_page.rebuild_targets()
        self.pipeline_page.rebuild_targets()
        self.sessions_page.rebuild_targets()
        self.suricata_page.rebuild_targets()
        self.detection_page.rebuild_targets()
        self.whitelist_page.rebuild_targets()
        self.container_firewall_page.rebuild_targets()
        self.honeypot_targets_page.rebuild_targets()
        self.pool_scaling_page.rebuild_targets()
        self.breach_audit_page.rebuild_targets()
        self.backups_page.rebuild_targets()
        self.patterns_page.rebuild_targets()
        self.log_search_page.rebuild_targets()
        self.resources_page.rebuild_targets()
        self.security_feed.start(self._edge_target())

    def _on_layer_set_elsewhere(self, layer_id: str) -> None:
        """Settings → Deployment or the wizard switched the honeypot layer
        (only possible while the ids stack is stopped): show it on the
        Workloads page too, then the same rebuild as a switch made there."""
        self.services_page._select_layer(layer_id)
        self._on_honeypot_layer_changed(layer_id)

    def _on_honeypot_layer_changed(self, _layer_id: str) -> None:
        """Workloads page switched the ids stack's honeypot layer: rebuild
        every page's targets (their compose file and labels changed), let the
        Attack Simulation page re-grey its presets and the Segmentation
        Validation page offer only the patterns the layer isolates, and re-poll
        right away."""
        self._on_remote_settings_changed()
        self.patterns_page.set_honeypot_layer()
        self.pool_test_page.set_honeypot_layer()
        self.poller.poll_now()

    def _on_pattern_registry_changed(self) -> None:
        """The Pattern Database page enabled/disabled/added/removed a pattern:
        the Attack Simulation battery and the Segmentation Validation preset
        list both re-read the registry so they only ever run patterns that are
        currently enabled."""
        self.patterns_page.reload_patterns()
        self.pool_test_page.reload_patterns()
        self.honeypot_targets_page.reload()

    def _on_target_registry_changed(self) -> None:
        """Honeypot Targets enabled/disabled a CVE target: same registry, so
        the simulation pages and the Pattern Database view re-read it."""
        self.patterns_page.reload_patterns()
        self.pool_test_page.reload_patterns()
        self.pattern_database_page.reload()

    def set_poll_interval(self, interval_ms: int) -> None:
        self.state.poll_interval_ms = interval_ms
        self.state.save()
        self.poller.set_interval(interval_ms)

    def _on_lifecycle_requested(self, action: str) -> None:
        """Overview page's Start/Restart/Stop all: drive every Workloads
        panel (both stacks, local + remote) at once, reusing their progress
        bars and the quit-while-mutating guard. Stop asks first."""
        if action == "stop" and not confirm(
                self, "Stop all stacks",
                "Run 'docker compose down' on the ids and siem stacks (every configured target)? "
                "Containers are removed; data volumes are kept."):
            return
        self._open_page("services")   # so the user sees the live output/progress
        {"start": self.services_page.start_all, "restart": self.services_page.restart_all,
         "stop": self.services_page.stop_all}[action]()

    def _on_status_results(self, results: dict) -> None:
        self.overview_page.apply_status(results)
        self.services_page.apply_status(results)
        self.health_page.apply_status(results)
        self.patterns_page.apply_status(results)
        self._notify_new_problems(results)

    # ---- system tray ----

    def _build_tray_icon(self) -> None:
        self.tray_icon = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            # Headless/offscreen environments and some minimal window
            # managers have no tray at all -- notifications are simply
            # unavailable there, not an error.
            return

        icon = QIcon(str(_APP_ICON_PATH)) if _APP_ICON_PATH.exists() else QIcon()
        if icon.isNull():
            icon = QIcon.fromTheme("utilities-system-monitor")
        if icon.isNull():
            icon = self.windowIcon()

        self.tray_icon = QSystemTrayIcon(icon, self)
        self.tray_icon.setToolTip(APP_TITLE)

        menu = QMenu()
        show_action = menu.addAction("Show dashboard")
        show_action.triggered.connect(self._show_and_raise)
        quit_action = menu.addAction("Quit")
        quit_action.triggered.connect(self.close)
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self._on_tray_activated)

        self.tray_icon.show()

    def _on_tray_activated(self, reason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._show_and_raise()

    def _show_and_raise(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _notify_new_problems(self, results: dict) -> None:
        if not self.tray_icon or not self.state.tray_notifications_enabled:
            self._last_status = self._classify_all(results)
            return

        current = self._classify_all(results)
        for key, status in current.items():
            if status in _NOTIFY_ON_STATUSES and self._last_status.get(key) != status:
                target_key, service = key
                label = "unhealthy" if status == "unhealthy" else "exited with an error"
                self.tray_icon.showMessage(
                    "Container problem",
                    f"{service} ({target_key}) is {label}",
                    QSystemTrayIcon.MessageIcon.Warning,
                    8000,
                )
        self._last_status = current

    def _on_security_event(self, event, ts: int) -> None:
        policy = alert_policy.AlertPolicy.from_dict(self.state.alert_policy)
        if alert_policy.should_alert(policy, event.kind, event.label, event.color, event.score,
                                     self._alerts_sent, time.time()):
            self._deliver_alert(policy, event.label, event.detail, live_events.severity(event.color),
                                event.score, ts)

    def _test_alert(self) -> None:
        policy = alert_policy.AlertPolicy.from_dict(self.state.alert_policy)
        self._deliver_alert(policy, "Test alert", "from the dashboard", "high", None, int(time.time()),
                            webhook=False)

    def _deliver_alert(self, policy, label: str, detail: str, severity: str, score, ts: int,
                       webhook: bool = True) -> None:
        if policy.desktop and self.tray_icon:
            self.tray_icon.showMessage(f"Security alert ({severity})", alert_policy.message(label, detail),
                                       QSystemTrayIcon.MessageIcon.Critical, 10000)
        if webhook and policy.webhook_url:
            payload = alert_policy.webhook_payload(label, detail, severity, score, ts)
            # Via a tracked Job (not a fire-and-forget daemon thread) so a
            # failing webhook is reported instead of silently dropping every
            # alert -- a misconfigured endpoint should be visible.
            job = Job(lambda u=policy.webhook_url, p=payload: alert_policy.send_webhook(u, p), self)
            self._webhook_jobs.add(job)

            def finished(result, error):
                self._webhook_jobs.discard(job)
                job.deleteLater()
                self._on_webhook_result(result or error or "")
            job.done.connect(finished)
            job.start()

    def _on_webhook_result(self, error: str) -> None:
        """Surface a webhook delivery failure once per cooldown, so a broken
        endpoint doesn't drop alerts unnoticed; a later success clears it."""
        if not error:
            self._last_webhook_error = ""
            return
        now = time.time()
        if now - self._last_webhook_warn_at < 300:
            self._last_webhook_error = error
            return
        self._last_webhook_warn_at = now
        self._last_webhook_error = error
        if self.tray_icon:
            self.tray_icon.showMessage("Alert webhook failed",
                                       f"A security alert could not be delivered: {error[:160]}",
                                       QSystemTrayIcon.MessageIcon.Warning, 10000)

    @staticmethod
    def _classify_all(results: dict) -> dict[tuple[str, str], str]:
        classified = {}
        for target_key, containers in results.items():
            for container in containers:
                service = container.get("Service")
                if service:
                    classified[(target_key, service)] = classify(container)
        return classified

    # ---- menu ----

    def _build_menu(self) -> None:
        # Not self.menuBar(): that would replace the title bar set as the
        # menu widget with a fresh QMenuBar.
        menu_bar: QMenuBar = self.title_bar.menu_bar

        settings_menu = menu_bar.addMenu("&Settings")
        open_settings_action = settings_menu.addAction("Open " + _menu_text(PAGE_LABELS["settings"]))
        open_settings_action.setIcon(page_icons.menu_icon("settings"))
        open_settings_action.triggered.connect(lambda: self._open_page("settings"))
        self._page_actions.append((open_settings_action, "settings"))
        rerun_wizard_action = settings_menu.addAction("Re-run setup wizard…")
        rerun_wizard_action.triggered.connect(self._rerun_wizard)

        view_menu = menu_bar.addMenu("&View")
        palette_action = view_menu.addAction("Command palette…")
        palette_action.setShortcut(QKeySequence("Ctrl+K"))
        palette_action.triggered.connect(self._show_palette)
        for group, page_ids in NAV_GROUPS:
            view_menu.addSection(group)
            for page_id in page_ids:
                action = view_menu.addAction(_menu_text(PAGE_LABELS[page_id]))
                action.setIcon(page_icons.menu_icon(page_id))
                action.triggered.connect(lambda _checked, pid=page_id: self._open_page(pid))
                self._page_actions.append((action, page_id))

        help_menu = menu_bar.addMenu("&Help")
        page_help_action = help_menu.addAction("Help for this page")
        page_help_action.setShortcut(QKeySequence("F1"))
        page_help_action.triggered.connect(self._show_page_help)
        learn_action = help_menu.addAction(f"{PAGE_LABELS['learn']}: labs, glossary, attack lessons")
        learn_action.setIcon(page_icons.menu_icon("learn"))
        learn_action.triggered.connect(lambda: self._open_page("learn"))
        self._page_actions.append((learn_action, "learn"))

    def palette_commands(self) -> list[palette.Command]:
        """Every page (grouped as in the rail, searchable by its summary)
        plus a few actions."""
        commands = []
        for group, page_ids in NAV_GROUPS:
            for page_id in page_ids:
                guide = PAGE_GUIDES.get(page_id)
                commands.append(palette.Command(
                    f"page:{page_id}", PAGE_LABELS[page_id], group,
                    guide.summary if guide else "", icon=page_id))
        commands += [
            palette.Command("lifecycle:start", "Start all stacks", "Actions",
                            "bring up docker compose ids siem run"),
            palette.Command("lifecycle:restart", "Restart all stacks", "Actions", "recreate docker compose"),
            palette.Command("lifecycle:stop", "Stop all stacks", "Actions", "bring down halt docker compose"),
            palette.Command("action:help", "Help for this page", "Actions", "F1 what is this page for"),
            palette.Command("action:wizard", "Re-run setup wizard…", "Actions", "first run configuration"),
            palette.Command("action:find", "Search all logs", "Actions", "Ctrl+F forensics grep"),
        ]
        return commands

    def _run_palette_command(self, command: palette.Command) -> None:
        kind, _, name = command.id.partition(":")
        if kind == "page":
            self._open_page(name)
        elif kind == "lifecycle":
            self._on_lifecycle_requested(name)
        elif name == "help":
            self._show_page_help()
        elif name == "wizard":
            self._rerun_wizard()
        elif name == "find":
            self._on_find_shortcut()

    def _show_palette(self) -> None:
        dialog = CommandPalette(self.palette_commands(), self._run_palette_command, self)
        # Drop it down from the title bar's search, so it reads as that
        # field opening rather than a dialog appearing somewhere else.
        search = self.title_bar.search_btn
        width = max(dialog.width(), search.width() + 160)
        anchor = search.mapToGlobal(search.rect().center())
        dialog.resize(width, dialog.height())
        dialog.move(anchor.x() - width // 2, search.mapToGlobal(search.rect().topLeft()).y() - 4)
        dialog.exec()

    def _show_page_help(self) -> None:
        """F1: what the current page is for, what to try, what to notice
        (core/learning.PAGE_GUIDES), with a jump to the Knowledge Base."""
        page_id = self.current_page()
        box = QMessageBox(self)
        box.setWindowTitle(f"Help: {PAGE_LABELS[page_id]}")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(page_guide_html(page_id, PAGE_LABELS[page_id]))
        learn_btn = box.addButton(f"Open {PAGE_LABELS['learn']}", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Close)
        box.exec()
        if box.clickedButton() is learn_btn:
            self._open_page("learn")

    # ---- keyboard shortcuts ----

    def _build_shortcuts(self) -> None:
        # Ctrl+1..9: jump straight to the Nth page visible in the rail.
        # Resolve the order when the shortcut fires, not here, so reordering
        # or hiding pages keeps the numbers matching the rows on screen.
        for i in range(1, 10):
            shortcut = QShortcut(QKeySequence(f"Ctrl+{i}"), self)
            shortcut.activated.connect(lambda idx=i - 1: self._open_nth_visible(idx))

        # Ctrl+R: refresh whatever the current page can meaningfully
        # refresh on demand -- an embedded browser reload, an immediate
        # re-search, Redis's own Refresh button. Services/Health are
        # poll-driven already (a few seconds' staleness at most) so
        # there's no separate "refresh now" plumbing for those.
        refresh_shortcut = QShortcut(QKeySequence("Ctrl+R"), self)
        refresh_shortcut.activated.connect(self._on_refresh_shortcut)

        # Ctrl+F: jump to and focus the Forensics Analysis page's search box --
        # the one "find" surface in this app, so Ctrl+F behaves the way
        # it's expected to everywhere else.
        find_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        find_shortcut.activated.connect(self._on_find_shortcut)

    def _on_refresh_shortcut(self) -> None:
        page = self.current_page()
        if page == "kibana":
            self.kibana_page.browser.view.reload()
        elif page == "patterns":
            self.patterns_page.browser.view.reload()
        elif page == "log_search":
            self.log_search_page.run_search()
        elif page == "redis":
            self.redis_page.refresh()
        elif page == "backups":
            self.backups_page.refresh()
        elif page == "certificates" and hasattr(self.certs_page, "refresh"):
            self.certs_page.refresh()

    def _on_find_shortcut(self) -> None:
        self._open_page("log_search")
        self.log_search_page.focus_search_box()

    # ---- menu ----

    def _rerun_wizard(self) -> None:
        layer_before = honeypot_layer.active().id
        wizard = SetupWizard(self.state, self, edge_running=self.services_page._edge_running,
                             on_test_alert=self._test_alert)
        accepted = wizard.exec() == SetupWizard.DialogCode.Accepted
        if honeypot_layer.active().id != layer_before:
            self._on_layer_set_elsewhere(honeypot_layer.active().id)
        # Connectors & Config page holds its own EnvFile/RemoteConfigWidget instances
        # loaded at construction time -- rebuild it so it reflects whatever
        # the wizard just wrote, instead of showing stale pre-wizard values.
        self._reload_settings_page()
        self.services_page.rebuild_panels()
        self.redis_page.rebuild_targets()
        self.pipeline_page.rebuild_targets()
        self.sessions_page.rebuild_targets()
        self.suricata_page.rebuild_targets()
        self.detection_page.rebuild_targets()
        self.whitelist_page.rebuild_targets()
        self.container_firewall_page.rebuild_targets()
        self.honeypot_targets_page.rebuild_targets()
        self.pool_scaling_page.rebuild_targets()
        self.breach_audit_page.rebuild_targets()
        self.backups_page.rebuild_targets()
        self.patterns_page.rebuild_targets()
        self.log_search_page.rebuild_targets()
        self.resources_page.rebuild_targets()
        self.security_feed.start(self._edge_target())
        if accepted and wizard.start_stacks:
            self.services_page.start_all()

    def _reload_settings_page(self) -> None:
        area = self.stack.widget(PAGES.index("settings"))
        area.takeWidget()
        self.settings_page.deleteLater()
        self.settings_page = SettingsPage(self.state, self._on_remote_settings_changed, self.set_poll_interval,
                                      on_test_alert=self._test_alert,
                                      edge_running=self.services_page._edge_running,
                                      on_layer_changed=self._on_layer_set_elsewhere)
        area.setWidget(self.settings_page)

    # ---- responsive layout ----

    def _set_nav_visible(self, visible: bool) -> None:
        self.nav_rail.setVisible(visible)
        self.nav_toggle.setToolTip("Hide the navigation" if visible else "Show the navigation")
        if not visible:
            panel = getattr(self, "overflow_panel", None)
            if panel is not None:
                panel.hide()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._resize_grips.update_geometry()
        self._border.update_geometry()
        # The panel is an overlay anchored to a "⋮" button; a resize can
        # move that anchor, so close it rather than leave it floating.
        panel = getattr(self, "overflow_panel", None)
        if panel is not None and panel.isVisible():
            panel.hide()
        size = event.size()
        narrow = size.width() < NARROW_WIDTH
        if narrow != self._narrow:
            # Only on crossing the breakpoint, so a rail the user opened
            # by hand stays open while they resize within one range.
            self._narrow = narrow
            self._set_nav_visible(not narrow)
        short = size.height() < SHORT_HEIGHT
        if short != self._short:
            self._short = short
            self.page_subtitle.setVisible(not short and bool(PAGE_GUIDES.get(self.current_page())))
            self.dependency_banner.set_compact(short)
            self.host_settings_banner.set_compact(short)

    # ---- geometry persistence ----

    def _restore_geometry(self) -> None:
        if self.state.window_geometry_b64:
            try:
                data = QByteArray(base64.b64decode(self.state.window_geometry_b64))
                self.restoreGeometry(data)
            except Exception:
                pass

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        # Edge grips and the outline hide while maximized.
        if event.type() == event.Type.WindowStateChange:
            self._resize_grips.update_geometry()
            self._border.update_geometry()

    def closeEvent(self, event) -> None:
        if self.services_page.any_mutating_action_running():
            reply = QMessageBox.warning(
                self, "Command still running",
                "A docker compose command (start/restart/stop/purge) is "
                "still running for at least one target. Closing now will "
                "kill it mid-operation.\n\nClose anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

        # A by-hand maximize (no window manager) is just a big geometry to
        # Qt; put the normal one back so the next launch isn't full-screen.
        self.title_bar.host.restore()
        data = bytes(self.saveGeometry())
        self.state.window_geometry_b64 = base64.b64encode(data).decode("ascii")
        self.state.save()
        self.poller.stop()
        self.poller.wait(2000)
        self.security_feed.stop()
        # The telemetry worker runs for the app's lifetime now (to keep ~5
        # min of history warm); retire it cleanly so its QThread isn't
        # destroyed mid-run on exit.
        self.resources_page.stop()
        if self.tray_icon:
            self.tray_icon.hide()
        super().closeEvent(event)
