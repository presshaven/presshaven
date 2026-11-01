"""WordPress Studio -- edit the real shop, push changes to every honeypot.

Embeds the production wp-admin panel and, on demand, fans the editor's changes
out to every honeypot pool with a staged progress bar. The point of the page:
a single place to manage the WordPress + WooCommerce shop so that pages, posts,
products and safe settings stay identical between production and the decoys an
adversary lands in -- without ever copying user accounts, orders or any secret
(API keys, passwords, payment-gateway config).

Two moving parts keep the editing session safe:

  * The embedded browser injects X-Studio-Backend + the internal-test secret on
    every request, so nginx force-routes wp-admin to production and never
    diverts a live edit into a honeypot (see core.wp_studio.studio_headers and
    router_rules.is_studio_passthrough).
  * Propagation reuses the honeypot_content_sync service's replication script
    in `--once N` mode, so the dashboard runs the exact same allow-listed sync
    the periodic loop runs -- the "what is safe to copy" policy lives in one
    place (the script), not duplicated here.

Qt-free logic (which pools, the sync command, the URL/headers, the policy
text) lives in core.wp_studio and is unit-tested; this module is the thin Qt
adapter around it.
"""
from __future__ import annotations

import subprocess
import time

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtWebEngineCore import QWebEngineUrlRequestInterceptor
from PyQt6.QtWidgets import (QCheckBox, QFrame, QHBoxLayout, QLabel, QLineEdit,
                             QProgressBar, QPushButton, QVBoxLayout, QWidget)

from core import prod_egress
from core import redis_inspect
from core import wp_studio
from core.detection_policy import HONEYPOT_THRESHOLD
from core.docker_ctl import target_for
from core.env_upload import EnvUploadError, load_project_env
from core.eta import EtaTracker, format_eta
from core.state import AppState
from ui import theme
from ui.browser_widget import BrowserWidget
from ui.common import ErrorBanner, Job, muted_label, set_status

# A pool sync is a single scoped mysqldump+apply; generous ceiling so a slow
# disk or SSH link doesn't cut a legitimate sync short, but it never hangs the
# worker thread forever.
_SYNC_TIMEOUT_S = 180


def _edge_host(state: AppState) -> str:
    return state.remote_edge.host if state.remote_edge.is_configured() else "localhost"


class _StudioInterceptor(QWebEngineUrlRequestInterceptor):
    """Injects the studio passthrough headers on every request from the
    embedded admin browser, so nginx keeps it pinned to production. The secret
    can be refreshed (set_secret) once the edge .env has been read."""

    def __init__(self, secret: str, parent=None):
        super().__init__(parent)
        self._secret = secret or ""

    def set_secret(self, secret: str) -> None:
        self._secret = secret or ""

    def interceptRequest(self, info) -> None:  # noqa: N802 (Qt override)
        for name, value in wp_studio.studio_headers(self._secret).items():
            info.setHttpHeader(name.encode(), value.encode())


class _PoolRow(QWidget):
    """One pool's propagation status: a glyph + label, with an optional detail
    line (error text) when it fails. States: pending | active | done | failed."""

    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 1, 0, 1)
        outer.setSpacing(1)
        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(6)
        self.glyph = QLabel("○")
        self.glyph.setFixedWidth(16)
        self.glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label = QLabel(label)
        head.addWidget(self.glyph)
        head.addWidget(self.label)
        head.addStretch(1)
        outer.addLayout(head)
        self.detail = QLabel("")
        self.detail.setWordWrap(True)
        self.detail.setVisible(False)
        outer.addWidget(self.detail)
        self.set_state("pending")

    def set_state(self, state: str, detail: str = "") -> None:
        c = theme.scheme_colors()
        if state == "done":
            self.glyph.setText("✓")
            color, weight = c["success"], "600"
        elif state == "failed":
            self.glyph.setText("✗")
            color, weight = c["danger"], "600"
        elif state == "active":
            self.glyph.setText("▸")
            color, weight = c["accent"], "600"
        else:
            self.glyph.setText("○")
            color, weight = c["fg_muted"], "400"
        self.glyph.setStyleSheet(f"color: {color};")
        self.label.setStyleSheet(f"color: {color}; font-weight: {weight};")
        self.detail.setVisible(bool(detail))
        if detail:
            self.detail.setText(detail)
            self.detail.setStyleSheet(f"color: {c['fg_muted']}; font-size: 11px; padding-left: 22px;")


class _PropagationJob(QThread):
    """Runs the per-pool sync sequentially off the GUI thread. Emits a signal
    as each pool starts and finishes, plus one when the whole run is done, so
    the page can advance the progress bar and the per-pool rows live."""

    pool_started = pyqtSignal(int, int, int)       # pool, index (0-based), total
    pool_finished = pyqtSignal(int, int, bool, str)  # pool, index, ok, detail
    run_finished = pyqtSignal(int, int)            # succeeded, total

    def __init__(self, target, steps, parent=None):
        super().__init__(parent)
        self._target = target
        self._steps = steps

    def run(self) -> None:
        total = len(self._steps)
        succeeded = 0
        for i, step in enumerate(self._steps):
            self.pool_started.emit(step.pool, i, total)
            ok, detail = self._sync_one(step.pool)
            if ok:
                succeeded += 1
            self.pool_finished.emit(step.pool, i, ok, detail)
        self.run_finished.emit(succeeded, total)

    def _sync_one(self, pool: int) -> tuple[bool, str]:
        argv, cwd = wp_studio.sync_argv(self._target, pool)
        try:
            proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                                  timeout=_SYNC_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            return False, f"timed out after {_SYNC_TIMEOUT_S}s"
        except Exception as e:  # noqa: BLE001 -- surfaced to the GUI as text
            return False, str(e)
        if proc.returncode == 0:
            return True, ""
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return False, (detail[-1] if detail else f"exit {proc.returncode}")


class WpStudioPage(QWidget):
    """The WordPress Studio page: embedded production wp-admin + propagate."""

    # Ask MainWindow to trigger an immediate status poll once a run finishes.
    refresh_requested = pyqtSignal()

    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._job: _PropagationJob | None = None
        self._egress_job: Job | None = None
        self._score_job: Job | None = None
        self._unpoison_job: Job | None = None
        self._chrome_collapsed = False
        self._propagating = False
        self._pool_rows: list[_PoolRow] = []
        self._run_t0 = 0.0
        self._eta = EtaTracker()
        self._env_cache = None
        # One automatic sign-in per visit to the login form: set when the
        # form is submitted, cleared once any other page loads.
        self._autologin_pending = False

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # Everything above the browser frame lives in one collapsible container,
        # so the "focus mode" toggle can hand the whole window to the editor.
        self._chrome = QWidget()
        chrome = QVBoxLayout(self._chrome)
        chrome.setContentsMargins(0, 0, 0, 0)
        chrome.setSpacing(8)

        title = QLabel("WordPress Studio")
        title.setStyleSheet("font-size: 17px; font-weight: 700;")
        chrome.addWidget(title)
        chrome.addWidget(muted_label(
            "Edit the real shop below. Changes land in production; press "
            "“Propagate to honeypot pools” to mirror them into every decoy at "
            "once, so adversaries always see the same catalog your customers do."))

        chrome.addWidget(self._build_policy_panel())
        chrome.addWidget(self._build_egress_panel())

        # Toolbar: propagate button + status.
        bar = QHBoxLayout()
        self.propagate_btn = QPushButton("Propagate to honeypot pools")
        self.propagate_btn.setToolTip(
            "Mirror production's pages, posts, products and safe settings into "
            "every ready honeypot pool, right now.")
        self.propagate_btn.clicked.connect(self._start_propagation)
        bar.addWidget(self.propagate_btn)
        self.status_label = muted_label("")
        bar.addWidget(self.status_label, stretch=1)
        self.eta_label = muted_label("")
        bar.addWidget(self.eta_label)
        chrome.addLayout(bar)

        # Progress area (hidden until a run). Overall bar + per-pool rows.
        self.progress_box = QFrame()
        self.progress_box.setObjectName("studioProgress")
        pbl = QVBoxLayout(self.progress_box)
        pbl.setContentsMargins(8, 6, 8, 6)
        pbl.setSpacing(2)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        pbl.addWidget(self.progress_bar)
        self.pool_rows_box = QVBoxLayout()
        self.pool_rows_box.setContentsMargins(0, 0, 0, 0)
        self.pool_rows_box.setSpacing(0)
        pbl.addLayout(self.pool_rows_box)
        self.progress_box.setVisible(False)
        chrome.addWidget(self.progress_box)

        root.addWidget(self._chrome)

        # Error banner stays outside the collapsible chrome so an alert (e.g. a
        # rejected sign-in) is still seen in focus mode.
        self.error_banner = ErrorBanner()
        root.addWidget(self.error_banner)

        # Always-visible strip right above the browser: the focus toggle plus a
        # live routing/score readout and the un-poison button (built below).
        root.addWidget(self._build_studio_bar())

        # The embedded admin browser, pinned to production via header injection.
        self._interceptor = _StudioInterceptor(self._internal_secret())
        self.browser = BrowserWidget(wp_studio.studio_url(_edge_host(self.state)),
                                     profile_name="wp-studio")
        self.browser.profile.setUrlRequestInterceptor(self._interceptor)
        self.browser.view.loadFinished.connect(self._maybe_autologin)
        root.addWidget(self.browser, stretch=1)

        if not self._internal_secret():
            self.error_banner.show_message(
                "INTERNAL_TEST_SECRET is not set on the edge stack, so the admin "
                "panel cannot be pinned to production and may be diverted into a "
                "honeypot while editing. Propagation still works.")

        self._eta_timer = QTimer(self)
        self._eta_timer.setInterval(1000)
        self._eta_timer.timeout.connect(self._tick_eta)

        # Live routing/score poll (only while this page is on screen).
        self._score_timer = QTimer(self)
        self._score_timer.setInterval(6000)
        self._score_timer.timeout.connect(self._poll_score)

    # ---- helpers ----

    def _target(self):
        return target_for("edge", self.state)

    def _edge_env(self):
        """The edge stack's .env (cached; anything with .get). Empty if unreadable."""
        if self._env_cache is None:
            try:
                self._env_cache = load_project_env("edge", self._target().remote)
            except EnvUploadError:
                self._env_cache = {}
        return self._env_cache

    def _internal_secret(self) -> str:
        """The edge INTERNAL_TEST_SECRET. Empty string if unreadable -- the
        page degrades to an un-pinned admin panel and warns."""
        return (self._edge_env().get("INTERNAL_TEST_SECRET", "") or "").strip()

    def _maybe_autologin(self, ok: bool) -> None:
        """Sign in with the production admin account (WP_ADMIN_USER /
        WP_ADMIN_PASSWORD from the edge .env) when wp-login.php shows up.
        Only while the browser is pinned to production: unpinned, the edge may
        route the login into a honeypot, which would record the real password."""
        url = self.browser.view.url().toString()
        home = wp_studio.studio_url(_edge_host(self.state))
        if not ok or not wp_studio.is_login_form(url, home):
            self._autologin_pending = False
            return
        login = wp_studio.admin_login(self._edge_env())
        if login is None or not self._internal_secret():
            return
        if self._autologin_pending:
            # Back on the form after our submit: report a rejection, never retry.
            self.browser.page.runJavaScript(wp_studio.AUTOLOGIN_ERROR_PROBE,
                                            self._on_autologin_result)
            return
        self._autologin_pending = True
        self.browser.page.runJavaScript(wp_studio.autologin_script(login),
                                        self._on_autologin_result)

    def _on_autologin_result(self, result) -> None:
        if result == wp_studio.AUTOLOGIN_REJECTED:
            self.error_banner.show_message(
                "Automatic sign-in was rejected: WP_ADMIN_USER / WP_ADMIN_PASSWORD "
                "in the edge .env don't match production. Sign in by hand, or run "
                "production_db_seed to re-apply the account.")

    def _build_policy_panel(self) -> QWidget:
        """Two columns: what an edit carries to every pool, and what never
        leaves production. Mirrors core.wp_studio's allow/deny constants."""
        frame = QFrame()
        frame.setObjectName("studioPolicy")
        cols = QHBoxLayout(frame)
        cols.setContentsMargins(8, 6, 8, 6)
        cols.setSpacing(16)
        c = theme.scheme_colors()

        def column(heading: str, items, color: str) -> QWidget:
            box = QWidget()
            lay = QVBoxLayout(box)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(1)
            head = QLabel(heading)
            head.setStyleSheet(f"color: {color}; font-weight: 700; font-size: 12px;")
            lay.addWidget(head)
            for it in items:
                row = QLabel(f"•  {it}")
                row.setWordWrap(True)
                row.setStyleSheet(f"color: {c['fg_muted']}; font-size: 12px;")
                lay.addWidget(row)
            lay.addStretch(1)
            return box

        cols.addWidget(column("Propagates to production + all pools",
                              wp_studio.PROPAGATES, c["success"]), stretch=1)
        cols.addWidget(column("Never leaves production",
                              wp_studio.NEVER_PROPAGATES, c["danger"]), stretch=1)
        return frame

    # ---- internet egress ----

    def _build_egress_panel(self) -> QWidget:
        """Production internet-egress controls. Production is default-deny:
        a compromised plugin cannot phone home, so it can never become a path
        around the honeypots. These two knobs loosen it deliberately and
        persist to the edge .env (surviving restarts and `down -v`):

          * a TEMPORARY all-internet HTTPS bypass, for installing/updating a
            plugin or theme, and
          * a persistent allow-list of specific outbound-443 domains.

        Applying also pushes the matching ruleset to the running production
        firewall, so it takes effect on the fly (core.prod_egress)."""
        c = theme.scheme_colors()
        frame = QFrame()
        frame.setObjectName("studioEgress")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(8, 6, 8, 6)
        lay.setSpacing(4)

        head = QLabel("Production internet egress")
        head.setStyleSheet("font-weight: 700; font-size: 12px;")
        lay.addWidget(head)
        lay.addWidget(muted_label(
            "Production normally reaches nothing on the public internet, so a "
            "hijacked plugin cannot phone home or pull a payload. Loosen it "
            "only while you install or update plugins/themes, then turn it off."))

        self.egress_bypass = QCheckBox(
            "Temporarily allow all outbound HTTPS (plugin / theme installs)")
        self.egress_bypass.setToolTip(
            "Opens outbound 443 from production to the whole internet. Leave off "
            "in normal operation; turn on only while installing, then off again.")
        lay.addWidget(self.egress_bypass)

        self.egress_domains = QLineEdit()
        self.egress_domains.setPlaceholderText(
            "Trusted domains, comma-separated (e.g. downloads.wordpress.org, "
            "api.wordpress.org)")
        self.egress_domains.setToolTip(
            "Persistent outbound-443 allow-list. Each stays reachable even when "
            f"the temporary bypass is off. Up to {prod_egress.MAX_DOMAINS}.")
        lay.addWidget(self.egress_domains)

        bar = QHBoxLayout()
        self.egress_apply_btn = QPushButton("Apply egress policy")
        self.egress_apply_btn.setToolTip(
            "Save to the edge .env and push the ruleset to the running "
            "production firewall now.")
        self.egress_apply_btn.clicked.connect(self._apply_egress)
        bar.addWidget(self.egress_apply_btn)
        self.egress_status = muted_label("")
        bar.addWidget(self.egress_status, stretch=1)
        lay.addLayout(bar)

        self._load_egress_policy()
        return frame

    def _load_egress_policy(self) -> None:
        """Prefill the controls from the edge .env (shipped default: deny)."""
        try:
            policy = prod_egress.read_policy()
        except Exception as e:  # noqa: BLE001 -- unreadable .env is non-fatal
            set_status(self.egress_status, f"could not read the egress policy: {e}",
                       color=theme.scheme_colors()["warning"])
            return
        self.egress_bypass.setChecked(policy.internet_bypass)
        self.egress_domains.setText(policy.domains_text())

    def _apply_egress(self) -> None:
        accepted, rejected = prod_egress.parse_domains(self.egress_domains.text())
        if rejected:
            self.error_banner.show_message(
                "These trusted-domain entries were ignored (not a domain, or past "
                f"the {prod_egress.MAX_DOMAINS}-domain limit): " + ", ".join(rejected))
        else:
            self.error_banner.hide()
        # Reflect the cleaned, deduplicated list back to the operator.
        self.egress_domains.setText(", ".join(accepted))
        policy = prod_egress.EgressPolicy(
            internet_bypass=self.egress_bypass.isChecked(), domains=accepted)
        remote = self._target().remote
        self.egress_apply_btn.setEnabled(False)
        set_status(self.egress_status, "applying…")

        def done(result, error: str) -> None:
            self._egress_job = None
            self.egress_apply_btn.setEnabled(True)
            if error:
                set_status(self.egress_status, "")
                self.error_banner.show_message(
                    "Could not apply the production egress policy "
                    f"(it is saved to the .env and will apply on redeploy): {error}")
                return
            c = theme.scheme_colors()
            if policy.internet_bypass:
                msg = "applied: all outbound HTTPS open (remember to turn it off)"
                color = c["warning"]
            elif accepted:
                msg = f"applied: {len(accepted)} trusted domain(s), internet otherwise denied"
                color = c["success"]
            else:
                msg = "applied: production internet egress denied"
                color = c["success"]
            set_status(self.egress_status, msg, color=color)

        self._egress_job = Job(
            lambda: prod_egress.apply_policy(remote, policy), self)
        self._egress_job.done.connect(done)
        self._egress_job.start()

    # ---- focus toggle + live routing score ----

    def _build_studio_bar(self) -> QWidget:
        """The always-visible strip above the browser: a focus-mode toggle that
        collapses all the chrome, a live routing/score readout for the admin's
        own session, and an un-poison button. The score matters because the
        admin edits through the same edge that diverts attackers: if this
        browser is ever scored up and mis-routed into a honeypot, the readout
        goes red and un-poisoning clears the admin host's score + sticky pool
        assignment so the next request lands back on production."""
        c = theme.scheme_colors()
        frame = QFrame()
        frame.setObjectName("studioBar")
        lay = QHBoxLayout(frame)
        lay.setContentsMargins(8, 4, 8, 4)
        lay.setSpacing(8)

        self.collapse_btn = QPushButton("▸ Focus mode (hide controls)")
        self.collapse_btn.setToolTip(
            "Collapse everything above the browser to edit full-screen. The "
            "routing readout and un-poison button stay visible.")
        self.collapse_btn.clicked.connect(self._toggle_chrome)
        lay.addWidget(self.collapse_btn)

        self.score_label = muted_label("checking routing…")
        self.score_label.setToolTip(
            "The worst threat score the edge currently holds against your "
            "admin host. At or above the honeypot threshold (80) your edits "
            "may be diverted into a decoy instead of reaching production.")
        lay.addWidget(self.score_label, stretch=1)

        self.unpoison_btn = QPushButton("Un-poison my session")
        self.unpoison_btn.setToolTip(
            "Clear your admin host's threat score, scored sessions and sticky "
            "honeypot assignment so the next request is routed to production. "
            "Only affects private/local IPs -- never a real attacker's.")
        self.unpoison_btn.clicked.connect(self._unpoison)
        lay.addWidget(self.unpoison_btn)
        return frame

    def _toggle_chrome(self) -> None:
        self._chrome_collapsed = not self._chrome_collapsed
        self._chrome.setVisible(not self._chrome_collapsed)
        self.collapse_btn.setText("▾ Show controls" if self._chrome_collapsed
                                  else "▸ Focus mode (hide controls)")

    def _poll_score(self) -> None:
        """Fetch the admin host's worst threat score off the GUI thread."""
        if self._score_job is not None:
            return  # a fetch is already in flight
        remote = self._target().remote
        self._score_job = Job(lambda: redis_inspect.local_threat_score(remote), self)
        self._score_job.done.connect(self._on_score)
        self._score_job.start()

    def _on_score(self, score, error: str) -> None:
        self._score_job = None
        c = theme.scheme_colors()
        if error:
            # Redis unreachable (stack down, SSH hiccup): don't cry wolf.
            set_status(self.score_label, "routing score unavailable", color=c["fg_muted"])
            return
        score = int(score or 0)
        if score >= HONEYPOT_THRESHOLD:
            set_status(self.score_label,
                       f"⚠ DIVERTED RISK: admin host scored {score}/100 "
                       f"(≥ {HONEYPOT_THRESHOLD}) — edits may hit a honeypot. Un-poison now.",
                       color=c["danger"])
        elif score > 0:
            set_status(self.score_label,
                       f"admin host scored {score}/100 (below the {HONEYPOT_THRESHOLD} "
                       "honeypot threshold) — still routed to production",
                       color=c["warning"])
        else:
            set_status(self.score_label, "routing clean (score 0) — pinned to production",
                       color=c["success"])

    def _unpoison(self) -> None:
        if self._unpoison_job is not None:
            return
        remote = self._target().remote
        self.unpoison_btn.setEnabled(False)
        set_status(self.score_label, "un-poisoning…")

        def done(result, error: str) -> None:
            self._unpoison_job = None
            self.unpoison_btn.setEnabled(True)
            if error:
                self.error_banner.show_message(f"Could not un-poison the session: {error}")
                return
            summary = result or {}
            n_sess = summary.get("sessions_removed", 0)
            n_ips = len(summary.get("threat_ips_removed", []) or [])
            self.error_banner.hide()
            c = theme.scheme_colors()
            set_status(self.score_label,
                       f"un-poisoned: cleared {n_sess} session(s), {n_ips} IP score(s) "
                       "— reload the admin to route to production",
                       color=c["success"])
            self._poll_score()

        self._unpoison_job = Job(
            lambda: redis_inspect.clear_local_threat_state(remote), self)
        self._unpoison_job.done.connect(done)
        self._unpoison_job.start()

    def showEvent(self, event) -> None:  # noqa: N802 -- Qt override
        super().showEvent(event)
        self._poll_score()
        self._score_timer.start()

    def hideEvent(self, event) -> None:  # noqa: N802 -- Qt override
        super().hideEvent(event)
        self._score_timer.stop()

    # ---- propagation ----

    def _start_propagation(self) -> None:
        if self._propagating:
            return
        self.error_banner.hide()
        pools = wp_studio.ready_pools(self._target().remote)
        steps = wp_studio.propagation_steps(pools)
        if not steps:
            self.error_banner.show_message("No honeypot pools to propagate to.")
            return

        # Build the per-pool rows fresh.
        for row in self._pool_rows:
            row.setParent(None)
        self._pool_rows = []
        for step in steps:
            row = _PoolRow(step.label)
            self._pool_rows.append(row)
            self.pool_rows_box.addWidget(row)

        self._propagating = True
        self.propagate_btn.setEnabled(False)
        self.progress_box.setVisible(True)
        self.progress_bar.setRange(0, len(steps))
        self.progress_bar.setValue(0)
        self.browser.set_dimmed(True, "Propagating to honeypot pools…")
        self.status_label.setText(f"Propagating to {len(steps)} pool(s)…")
        self._run_t0 = time.monotonic()
        self._eta.reset()
        self._eta_timer.start()

        self._job = _PropagationJob(self._target(), steps, self)
        self._job.pool_started.connect(self._on_pool_started)
        self._job.pool_finished.connect(self._on_pool_finished)
        self._job.run_finished.connect(self._on_run_finished)
        self._job.start()

    def _on_pool_started(self, pool: int, index: int, total: int) -> None:
        if 0 <= index < len(self._pool_rows):
            self._pool_rows[index].set_state("active")
        self.status_label.setText(f"Syncing honeypot pool {pool} ({index + 1} of {total})…")

    def _on_pool_finished(self, pool: int, index: int, ok: bool, detail: str) -> None:
        if 0 <= index < len(self._pool_rows):
            self._pool_rows[index].set_state("done" if ok else "failed", detail)
        done = index + 1
        self.progress_bar.setValue(done)
        total = self.progress_bar.maximum() or 1
        self._eta.update(time.monotonic() - self._run_t0, done / total)
        self._tick_eta()

    def _on_run_finished(self, succeeded: int, total: int) -> None:
        self._propagating = False
        self._eta_timer.stop()
        self.eta_label.setText("")
        self.propagate_btn.setEnabled(True)
        self.browser.set_dimmed(False)
        failed = total - succeeded
        if failed:
            self.status_label.setText(f"Propagated to {succeeded} of {total} pool(s) — {failed} failed.")
            self.error_banner.show_message(
                f"{failed} pool(s) did not sync. See the rows above for details.")
        else:
            self.status_label.setText(f"Propagated to all {total} pool(s).")
        self.refresh_requested.emit()

    def _tick_eta(self) -> None:
        if not self._propagating:
            return
        remaining = self._eta.remaining_at(time.monotonic() - self._run_t0)
        self.eta_label.setText(f"~ {format_eta(remaining)} left")
