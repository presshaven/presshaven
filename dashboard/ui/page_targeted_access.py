"""Targeted Access -- jump an embedded wp-admin browser straight to
production or to any one honeypot pool, on demand.

The main use case is verifying propagation: after WordPress Studio pushes
a change out, this page lets an operator open pool 2's admin panel directly
and see for themselves that it actually landed, rather than trusting the
"Propagated to all N pool(s)" status line. It is also useful while
investigating a session -- looking at exactly what a given pool is serving
an adversary right now.

Both "Production" and "Honeypot pool N" use the same secret-gated edge
passthrough WordPress Studio uses for production (see core.wp_studio /
core.targeted_access and router_rules.lua's is_studio_passthrough /
studio_honeypot_target): the embedded browser injects X-Studio-Backend (+
X-Studio-Pool for a honeypot target) and the internal-test secret on every
request, so nginx force-routes it to the chosen backend and skips
scoring/session-routing entirely. That cuts both ways on purpose -- the
check can never be diverted off its target, AND it never poisons the
operator's own IP reputation, no matter which pool is opened.

Qt-free logic (which pools are reachable this way, the headers, which
account to sign in with) lives in core.targeted_access and is unit-tested;
this module is the thin Qt adapter around it.
"""
from __future__ import annotations

from PyQt6.QtWebEngineCore import QWebEngineUrlRequestInterceptor
from PyQt6.QtWidgets import QComboBox, QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from core import targeted_access as ta
from core import wp_studio
from core.docker_ctl import target_for
from core.env_upload import EnvUploadError, load_project_env
from core.state import AppState
from ui import theme
from ui.browser_widget import BrowserWidget
from ui.common import ErrorBanner, muted_label, set_status


def _edge_host(state: AppState) -> str:
    return state.remote_edge.host if state.remote_edge.is_configured() else "localhost"


class _TargetedAccessInterceptor(QWebEngineUrlRequestInterceptor):
    """Injects whatever headers pin the embedded browser to the currently
    selected target. set_headers swaps them when the operator switches."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._headers: dict[str, str] = {}

    def set_headers(self, headers: dict[str, str]) -> None:
        self._headers = dict(headers or {})

    def interceptRequest(self, info) -> None:  # noqa: N802 (Qt override)
        for name, value in self._headers.items():
            info.setHttpHeader(name.encode(), value.encode())


class TargetedAccessPage(QWidget):
    """Lets the operator pin the embedded admin browser to production or to
    any one statically-declared honeypot pool, and sign in to it directly."""

    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._env_cache = None
        self._targets = ta.targets()
        self._current_target = self._targets[0]  # Production, until Open is pressed
        # One automatic sign-in per visit to the login form: set when the
        # form is submitted, cleared once another page loads or the target
        # is switched.
        self._autologin_pending = False

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        title = QLabel("Targeted Access")
        title.setStyleSheet("font-size: 17px; font-weight: 700;")
        root.addWidget(title)
        root.addWidget(muted_label(
            "Open the real wp-admin panel on production or on any honeypot pool, "
            "right now -- e.g. to confirm a WordPress Studio propagation actually "
            "landed on a pool. Pinned the same way WordPress Studio pins to "
            "production: scoring and session routing are skipped entirely for "
            "this browser, so the check can't be diverted off its target and "
            "never affects your own IP's threat score."))

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Target:"))
        self.target_combo = QComboBox()
        for t in self._targets:
            self.target_combo.addItem(t.label)
        bar.addWidget(self.target_combo)
        self.open_btn = QPushButton("Open")
        self.open_btn.setToolTip("Pin the browser below to the selected target and sign in.")
        self.open_btn.clicked.connect(self._open_selected_target)
        bar.addWidget(self.open_btn)
        self.status_label = muted_label("")
        bar.addWidget(self.status_label, stretch=1)
        root.addLayout(bar)

        only_static = QFrame()
        only_static_lay = QHBoxLayout(only_static)
        only_static_lay.setContentsMargins(0, 0, 0, 0)
        only_static_lay.addWidget(muted_label(
            f"Only pools 1-{wp_studio.STATIC_POOLS} (declared in docker-compose.yml) can be "
            "reached this way -- a pool created later at runtime by pool_manager has no "
            "static route to force-target it with."))
        root.addWidget(only_static)

        self.error_banner = ErrorBanner()
        root.addWidget(self.error_banner)

        self._interceptor = _TargetedAccessInterceptor(self)
        self.browser = BrowserWidget(wp_studio.studio_url(_edge_host(self.state)),
                                     profile_name="targeted-access")
        self.browser.profile.setUrlRequestInterceptor(self._interceptor)
        self.browser.view.loadFinished.connect(self._maybe_autologin)
        root.addWidget(self.browser, stretch=1)

        if not self._internal_secret():
            self.error_banner.show_message(
                "INTERNAL_TEST_SECRET is not set on the edge stack, so this browser cannot "
                "be pinned to a target and requests are routed/scored normally instead.")

        self._pin_to(self._current_target)

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
        return (self._edge_env().get("INTERNAL_TEST_SECRET", "") or "").strip()

    def _pin_to(self, target: ta.AccessTarget) -> None:
        self._current_target = target
        self._autologin_pending = False
        self._interceptor.set_headers(ta.target_headers(self._internal_secret(), target))
        url = wp_studio.studio_url(_edge_host(self.state))
        self.browser.set_home_url(url)
        self.browser.navigate(url)
        c = theme.scheme_colors()
        if self._internal_secret():
            set_status(self.status_label, f"pinned to {target.label}", color=c["success"])
        else:
            set_status(self.status_label,
                       f"not pinned (no secret configured) -- {target.label} may not be reached",
                       color=c["warning"])

    def _open_selected_target(self) -> None:
        idx = self.target_combo.currentIndex()
        if 0 <= idx < len(self._targets):
            self._pin_to(self._targets[idx])

    def _maybe_autologin(self, ok: bool) -> None:
        """Sign in with the account matching the currently pinned target.
        Only while pinned (a configured secret was presented): unpinned, the
        edge may route the login elsewhere, which would leak the password to
        the wrong backend."""
        url = self.browser.view.url().toString()
        home = wp_studio.studio_url(_edge_host(self.state))
        if not ok or not wp_studio.is_login_form(url, home):
            self._autologin_pending = False
            return
        login = ta.target_login(self._edge_env(), self._current_target)
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
                f"Automatic sign-in to {self._current_target.label} was rejected: check "
                "WP_ADMIN_USER / WP_ADMIN_PASSWORD / HONEYPOT_WP_ADMIN_PASSWORD in the "
                "edge .env. Sign in by hand instead.")
