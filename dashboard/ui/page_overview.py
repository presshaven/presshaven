"""Overview page: the dashboard's landing screen -- a security-operations
summary assembled from data the app already collects but never showed in
one place before.

Two live sources feed it, with no new background work of its own:
  - the shared StatusPoller's per-target `docker compose ps` results
    (pushed in via apply_status(), exactly like Workloads/Global
    Visualization), aggregated per project into one health line each; and
  - the app-lifetime SecurityEventFeed (ui/security_feed.py), whose
    `score_changed`/`event_added` signals drive the headline risk score
    and the notable-events count cards.

Below the cards is a directory of every dashboard page -- one clickable
card each (icon, name, one-line description from core/learning.py's
PAGE_GUIDES) -- so the landing screen doubles as a map of the whole app.
MainWindow owns the page list, so it hands it in via set_page_directory().

Pure presentation: all the counting lives in core/overview_stats.py
(Qt-free, unit-tested). Clicking a page card jumps there via
open_page_requested, the same mechanism the Knowledge Base page uses.
"""
from __future__ import annotations

import time

from PyQt6.QtCore import QRect, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QVBoxLayout, QWidget,
)

from core import learning, overview_stats, pool_view, session_view
from core.colors import GREEN, GREY, ORANGE, RED
from core.docker_ctl import target_for
from core.pattern_log_parser import PatternEvent
from core.redis_inspect import list_sessions, pool_snapshot
from core.state import AppState
from ui import page_icons, theme
from ui.common import Job
from ui.flow_layout import FlowLayout
from ui.security_feed import SecurityEventFeed

# How often the landing-page stats refresh while the page is visible, so the
# decayed score, the "(1h)" windows and the live redis-backed cards don't go
# stale just because the user is sitting on the page. Kept brisk (3s) so the
# decaying risk score visibly ticks down; the redis-backed cards self-
# throttle via _redis_busy if a fetch is slower than one interval.
REFRESH_MS = 3000

# Risk-score colour bands -- the honeypot routing threshold is 80 (see the
# Knowledge Base glossary / init.lua), so a score at or above it is the
# danger colour, an elevated score the warning colour.
_HONEYPOT_THRESHOLD = 80
_ELEVATED = 40


def _score_color(score: int | None) -> str:
    if score is None:
        return GREY
    if score >= _HONEYPOT_THRESHOLD:
        return RED
    if score >= _ELEVATED:
        return ORANGE
    return GREEN


def _ago(ts: float | None) -> str:
    if not ts:
        return "never"
    delta = max(0, int(time.time() - ts))
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


class StatCard(QFrame):
    """A titled value tile -- big value, small caption, accent bar in a
    status colour. Recoloured on theme change via set_value()'s cached
    args, so it follows light/dark like the rest of the app."""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        self.setMinimumWidth(190)
        self._value = "—"
        self._accent = GREY
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)
        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("StatCardTitle")
        self.value_label = QLabel(self._value)
        self.value_label.setObjectName("StatCardValue")
        self.caption_label = QLabel("")
        self.caption_label.setObjectName("StatCardCaption")
        self.caption_label.setWordWrap(True)
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.caption_label)
        theme.on_change(self._restyle)
        self._restyle()

    def set_value(self, value: str, caption: str = "", accent: str | None = None) -> None:
        self._value = value
        if accent is not None:
            self._accent = accent
        self.value_label.setText(value)
        self.caption_label.setText(caption)
        self.caption_label.setVisible(bool(caption))
        self._restyle()

    def _restyle(self) -> None:
        c = theme.scheme_colors()
        self.setStyleSheet(
            f"#StatCard {{ background: {c['surface']}; border: 1px solid {c['border']};"
            f" border-left: 4px solid {self._accent};"
            f" border-radius: {theme.corner_radius_css(8)}; }}"
            f"#StatCardTitle {{ color: {c['fg_muted']}; font-size: 8pt; font-weight: 700;"
            " letter-spacing: 1px; }"
            f"#StatCardValue {{ color: {self._accent}; font-size: 22pt; font-weight: 800; }}"
            f"#StatCardCaption {{ color: {c['fg_muted']}; font-size: 8pt; }}")


class PageCard(QFrame):
    """A clickable tile linking to a dashboard page: its themed SVG icon, its
    name and a one-line description. Emits clicked(page_id) when pressed and
    recolors on theme change like the rest of the app."""

    clicked = pyqtSignal(str)

    # Every directory card is the same width; the FlowLayout tiles them and a
    # uniform height is applied across the set once they are all built (see
    # natural_height / OverviewPage.set_page_directory), so cards with longer
    # descriptions don't come out taller than their neighbours.
    WIDTH = 300
    _MARGINS = (12, 11, 12, 11)   # left, top, right, bottom (matches row below)
    _ICON = 26
    _ROW_SPACING = 11
    _TEXT_SPACING = 2

    def __init__(self, page_id: str, title: str, description: str, parent=None):
        super().__init__(parent)
        self.page_id = page_id
        self.setObjectName("PageCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedWidth(self.WIDTH)
        row = QHBoxLayout(self)
        row.setContentsMargins(*self._MARGINS)
        row.setSpacing(self._ROW_SPACING)
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(self._ICON, self._ICON)
        row.addWidget(self.icon_label, alignment=Qt.AlignmentFlag.AlignTop)
        text = QVBoxLayout()
        text.setSpacing(self._TEXT_SPACING)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("PageCardTitle")
        self.desc_label = QLabel(description)
        self.desc_label.setObjectName("PageCardDesc")
        self.desc_label.setWordWrap(True)
        self.desc_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        # Fonts set explicitly (not only via the stylesheet) so fontMetrics are
        # reliable for natural_height() before the widget is ever shown.
        tf = self.title_label.font(); tf.setPointSize(10); tf.setBold(True)
        self.title_label.setFont(tf)
        df = self.desc_label.font(); df.setPointSize(8)
        self.desc_label.setFont(df)
        text.addWidget(self.title_label)
        text.addWidget(self.desc_label)
        text.addStretch(1)
        row.addLayout(text, stretch=1)
        theme.on_change(self._restyle)
        self._restyle()

    def natural_height(self) -> int:
        """Full card height needed to show this card's title and (wrapped)
        description at WIDTH, with no clipping. The tallest value across a set
        of cards is applied to all of them so they end up uniform."""
        left, top, right, bottom = self._MARGINS
        inner = self.WIDTH - left - right - self._ICON - self._ROW_SPACING
        title_h = self.title_label.fontMetrics().height()
        desc_rect = self.desc_label.fontMetrics().boundingRect(
            QRect(0, 0, inner, 100000),
            int(Qt.TextFlag.TextWordWrap), self.desc_label.text())
        body = max(title_h + self._TEXT_SPACING + desc_rect.height(), self._ICON)
        return top + body + bottom

    def _restyle(self) -> None:
        c = theme.scheme_colors()
        self.icon_label.setPixmap(page_icons.page_pixmap(self.page_id, 26))
        self.setStyleSheet(
            f"#PageCard {{ background: {c['surface']}; border: 1px solid {c['border']};"
            f" border-radius: {theme.corner_radius_css(8)}; }}"
            f"#PageCard:hover {{ border-color: {c['accent']}; background: {c['bg_alt']}; }}"
            f"#PageCardTitle {{ color: {c['fg']}; }}"
            f"#PageCardDesc {{ color: {c['fg_muted']}; }}")

    def mouseReleaseEvent(self, event) -> None:
        if (event.button() == Qt.MouseButton.LeftButton
                and self.rect().contains(event.position().toPoint())):
            self.clicked.emit(self.page_id)
        super().mouseReleaseEvent(event)


class OverviewPage(QWidget):
    open_page_requested = pyqtSignal(str)
    lifecycle_requested = pyqtSignal(str)   # "start" | "stop" | "restart", for both stacks

    def __init__(self, state: AppState, security_feed: SecurityEventFeed, parent=None):
        super().__init__(parent)
        self.state = state
        self.feed = security_feed
        self._last_results: dict = {}
        self._redis_busy = False
        self._jobs: set[Job] = set()

        root = QVBoxLayout(self)
        root.setSpacing(12)

        # ---- stat cards ----
        cards_host = QWidget()
        self._cards = FlowLayout(cards_host, margin=0, h_spacing=10, v_spacing=10)
        self.card_score = StatCard("Current risk score")
        self.card_health = StatCard("System health")
        self.card_diverted = StatCard("Adversary IPs diverted")
        self.card_pools = StatCard("Honeypot pools")
        self.card_events = StatCard("Notable events (1h)")
        for card in (self.card_score, self.card_health, self.card_diverted,
                     self.card_pools, self.card_events):
            self._cards.addWidget(card)
        root.addWidget(cards_host)

        # ---- per-stack health lines + lifecycle controls ----
        stacks_row = QHBoxLayout()
        self.stacks_label = QLabel("Bring the stacks up to see live health.")
        self.stacks_label.setWordWrap(True)
        self.stacks_label.setStyleSheet(f"color: {GREY};")
        stacks_row.addWidget(self.stacks_label, stretch=1)
        self.start_btn = QPushButton("▶ Start all")
        self.start_btn.setToolTip("docker compose up -d on the ids and siem stacks (every configured target)")
        self.start_btn.clicked.connect(lambda: self.lifecycle_requested.emit("start"))
        self.restart_all_btn = QPushButton("⟳ Restart all")
        self.restart_all_btn.clicked.connect(lambda: self.lifecycle_requested.emit("restart"))
        self.stop_btn = QPushButton("■ Stop all")
        self.stop_btn.setToolTip("docker compose stop on the ids and siem stacks")
        self.stop_btn.clicked.connect(lambda: self.lifecycle_requested.emit("stop"))
        for b in (self.start_btn, self.restart_all_btn, self.stop_btn):
            stacks_row.addWidget(b)
        root.addLayout(stacks_row)

        # ---- directory: a card per dashboard page ----
        header = QHBoxLayout()
        title = QLabel("All dashboard pages")
        title.setStyleSheet("font-weight: 700; font-size: 11pt;")
        header.addWidget(title)
        header.addStretch()
        self.nav_hint = QLabel("every page, with what it is for — click to open")
        self.nav_hint.setStyleSheet(f"color: {GREY}; font-size: 8pt;")
        header.addWidget(self.nav_hint)
        root.addLayout(header)

        self._cards_container = QWidget()
        self._page_cards = FlowLayout(self._cards_container, margin=0, h_spacing=10, v_spacing=10)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self._cards_container)
        root.addWidget(scroll, stretch=1)

        self._refresh_score()
        self._refresh_counts()
        self.card_diverted.set_value("—", "bring the edge stack up", GREY)
        self.card_pools.set_value("—", "bring the edge stack up", GREY)

        self.feed.event_added.connect(self._on_event_added)
        self.feed.score_changed.connect(self._on_score_changed)

        # Auto-refresh while visible: time-based cards and the decayed score
        # recomputed locally, the diverted-adversary and pool cards re-fetched
        # from the session store off the GUI thread.
        self.timer = QTimer(self)
        self.timer.setInterval(REFRESH_MS)
        self.timer.timeout.connect(self._tick)

    # ---- live updates ----

    def apply_status(self, results: dict) -> None:
        """Called from MainWindow on every poll tick with the same results
        dict the other pages get."""
        self._last_results = results
        healths = [overview_stats.project_health(results, "edge", "Edge (IDS honeypot)"),
                   overview_stats.project_health(results, "siem", "SIEM (ELK)")]
        lines = [f"<b>{h.label}:</b> <span style='color:{h.color};'>{h.text}</span>" for h in healths]
        self.stacks_label.setText("&nbsp;&nbsp;·&nbsp;&nbsp;".join(lines))
        self.stacks_label.setTextFormat(Qt.TextFormat.RichText)
        headline, color, caption = overview_stats.system_summary(healths)
        self.card_health.set_value(headline, caption, color)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        # Time-based captions ("3m ago", last-hour counts) and the decayed
        # risk score drift while the page is hidden -- recompute on re-entry,
        # then keep them fresh on a timer.
        self._tick()
        self.timer.start()

    def hideEvent(self, event) -> None:
        self.timer.stop()
        super().hideEvent(event)

    def _tick(self) -> None:
        self._refresh_counts()
        self._refresh_score()
        if self._last_results:
            self.apply_status(self._last_results)
        self._fetch_redis()

    def _fetch_redis(self) -> None:
        """One off-thread round-trip to the edge session store for the two
        live cards (adversaries diverted, pool state). Silently leaves the
        cards on their last value if the store is unreachable -- the page is
        a glanceable summary, not a place to surface redis errors."""
        if self._redis_busy:
            return
        self._redis_busy = True
        remote = target_for("edge", self.state).remote

        def work():
            return list_sessions(remote), pool_snapshot(remote)

        job = Job(work, self)
        self._jobs.add(job)

        def done(result, error):
            self._redis_busy = False
            self._jobs.discard(job)
            job.deleteLater()
            if error or result is None:
                self.card_diverted.set_value("—", "session store unreachable", GREY)
                self.card_pools.set_value("—", "session store unreachable", GREY)
                return
            sessions_text, pools_text = result
            self._render_diverted(session_view.parse_snapshot(sessions_text))
            self._render_pools(pool_view.parse_snapshot(pools_text))
        job.done.connect(done)
        job.start()

    def _render_diverted(self, sessions) -> None:
        n = overview_stats.unique_diverted_ips(sessions)
        self.card_diverted.set_value(
            str(n), f"{len(sessions)} active session(s)", RED if n else GREEN)

    def _render_pools(self, o: pool_view.PoolOverview) -> None:
        used = max(0, o.ready - o.free)
        preparing = len(o.building)
        self.card_pools.set_value(
            str(used), f"{o.free} available · {preparing} preparing",
            ORANGE if (used or preparing) else GREEN)

    def set_page_directory(self, pages: list[tuple[str, str]]) -> None:
        """Populate the page-link cards from (page_id, label) pairs in sidebar
        order; each card's one-line description is the page's learning-guide
        summary. MainWindow owns the page list, so it calls this once after
        construction."""
        while self._page_cards.count():
            item = self._page_cards.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        cards = []
        for page_id, label in pages:
            guide = learning.PAGE_GUIDES.get(page_id)
            card = PageCard(page_id, label, guide.summary if guide else "", self._cards_container)
            card.clicked.connect(self.open_page_requested)
            cards.append(card)
        # Size every card to the tallest one so the grid is uniform in both
        # width (fixed per card) and height, regardless of description length.
        if cards:
            height = max(card.natural_height() for card in cards)
            for card in cards:
                card.setFixedHeight(height)
                self._page_cards.addWidget(card)

    def _on_event_added(self, event: PatternEvent, ts: int) -> None:
        self._refresh_counts()
        self._refresh_score()

    def _on_score_changed(self, _score) -> None:
        # A fresh per-request score just landed; recompute the decayed
        # posture (which now includes it via the persisted history).
        self._refresh_score()

    def _refresh_score(self) -> None:
        """The headline risk is a decayed aggregate of recent notable
        activity (core/overview_stats.posture_score), not just the last
        request's raw score -- so it fades as attacks stop and climbs again
        when they resume. The latest raw request score is the caption."""
        score = overview_stats.posture_score(self.state.security_events)
        latest = self.feed.latest_score
        if score is None:
            caption = f"latest request: {latest}" if latest is not None else "no requests scored yet"
            self.card_score.set_value("—", caption, GREY)
            return
        band = ("honeypot threshold reached" if score >= _HONEYPOT_THRESHOLD
                else "elevated" if score >= _ELEVATED else "benign")
        caption = f"{band} · decayed from recent activity"
        if latest is not None:
            caption = f"{band} · latest request {latest}"
        self.card_score.set_value(str(score), caption, _score_color(score))

    def _refresh_counts(self) -> None:
        counts = overview_stats.event_window_counts(self.state.security_events)
        self.card_events.set_value(
            str(counts["window_total"]),
            f"last event {_ago(counts['last_timestamp'])}",
            ORANGE if counts["window_total"] else GREY)

