"""Signature Simulation page: watch one browser characteristic become the
proxy's consent-gated one-way ``gdpr_signature``, end to end, against the
running reverse proxy.

The left half is a resizeable "visitor browser" window (a QMdiArea sub-window
the user can drag to any size). Its size IS the screen-size characteristic the
browser would report, so resizing it changes what gets signed. The right half
walks the flow in five stages -- the two client-side ones (collect
characteristics, RSA-encrypt into a gdpr_token) are reproduced locally and
shown in full; the server-side ones (the proxy appends the client IP, hashes
the canonical form with a secret salt) are shown as process, because by design
only their output -- the signature -- ever leaves the proxy. A run sends one
real request carrying the token and reads the derived signature back from the
proxy log (core/signature_sim.py).

Resize the window and re-run to see the signature change; return it to a
previous size and the signature comes back identical -- the deterministic
re-recognition the whole subsystem exists for. The reset buttons restore the
default window size and revoke consent (which clears the flow, mirroring how a
visitor dropping the token simply stops producing a signature).
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QMdiArea, QMdiSubWindow, QPushButton,
    QSizePolicy, QVBoxLayout, QWidget,
)

from core import signature_sim
from core.colors import BLUE, GREEN, GREY, ORANGE, RED
from core.docker_ctl import target_for
from core.state import AppState
from ui import theme
from ui.common import ErrorBanner, Job, muted_label

# Default content size of the "visitor browser" window, and the floor a drag
# can shrink it to. These are the screen-size characteristic the demo signs.
DEFAULT_W, DEFAULT_H = 1024, 660
MIN_W, MIN_H = 360, 260

_MONO = "font-family: 'DejaVu Sans Mono','Consolas',monospace;"


def _base_url(state: AppState) -> str:
    """Same edge URL the Attack Simulation page browses: the remote edge host
    when one is configured, else localhost."""
    host = state.primary_remote_host("edge")
    return f"https://{host}"


class _BrowserView(QFrame):
    """The mock web page shown inside the resizeable window: a browser chrome
    bar over a consent banner and a big live read-out of the current size (the
    screen-size characteristic). Its own size tracks the window, so resizing
    the window resizes this."""

    def __init__(self, url: str, parent=None):
        super().__init__(parent)
        self.setObjectName("SimBrowserView")
        self.setMinimumSize(MIN_W, MIN_H)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        chrome = QFrame()
        chrome.setObjectName("SimChrome")
        chrome_row = QHBoxLayout(chrome)
        chrome_row.setContentsMargins(10, 7, 10, 7)
        chrome_row.setSpacing(8)
        dots = QLabel("●  ●  ●")
        dots.setStyleSheet("color: #d9534f; letter-spacing: -2px;")
        self.address = QLabel(url + "/")
        self.address.setObjectName("SimAddress")
        chrome_row.addWidget(dots)
        chrome_row.addWidget(self.address, stretch=1)
        outer.addWidget(chrome)

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(22, 20, 22, 22)
        body_layout.setSpacing(14)
        banner = QLabel("\U0001f36a  This site derives a privacy-preserving signature from your "
                        "browser. Agreeing lets it recognise this browser again without storing "
                        "anything that identifies you.")
        banner.setObjectName("SimConsentBanner")
        banner.setWordWrap(True)
        body_layout.addWidget(banner)

        hint = QLabel("Drag this window's edge or corner to resize it — its size is the "
                      "screen size your browser reports.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {GREY};")
        body_layout.addWidget(hint)

        body_layout.addStretch(1)
        self.size_read = QLabel()
        self.size_read.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.size_read.setStyleSheet(f"{_MONO} font-size: 20pt; font-weight: bold;")
        caption = QLabel("reported screen size")
        caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
        caption.setStyleSheet(f"color: {GREY}; font-size: 8pt; letter-spacing: 1px;")
        body_layout.addWidget(self.size_read)
        body_layout.addWidget(caption)
        body_layout.addStretch(2)
        outer.addWidget(body, stretch=1)

        self._refresh_readout()
        theme.on_change(self._apply_theme)
        self._apply_theme()

    def _apply_theme(self) -> None:
        c = theme.scheme_colors()
        self.setStyleSheet(
            f"#SimBrowserView {{ background: {c['bg']}; border: 1px solid {c['border']}; }}"
            f"#SimChrome {{ background: {c['bg_alt']}; border-bottom: 1px solid {c['border']}; }}"
            f"#SimAddress {{ {_MONO} color: {c['fg_muted']}; background: {c['bg']}; "
            f"  border: 1px solid {c['border']}; border-radius: {theme.corner_radius_css(10)}; "
            f"  padding: 3px 10px; }}"
            f"#SimConsentBanner {{ color: {c['fg']}; background: {c['bg_alt']}; "
            f"  border: 1px solid {c['border']}; border-left: 3px solid {BLUE}; padding: 9px 11px; }}"
            f"#SimBrowserView QLabel {{ color: {c['fg']}; }}")
        self._refresh_readout()

    def _refresh_readout(self) -> None:
        self.size_read.setText(self.screen_string().replace("x", "  ×  "))

    def screen_string(self) -> str:
        """The ``"WxH"`` characteristic for the browser's current size."""
        return f"{self.width()}x{self.height()}"

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._refresh_readout()


class _BrowserWindow(QMdiSubWindow):
    """A resizeable MDI sub-window that reports every resize, so the page can
    keep the characteristic read-out and flow state in step with its size."""
    resized = pyqtSignal()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.resized.emit()


class _Stage(QFrame):
    """One step in the flow: a numbered, role-coloured card with a title, a
    short descriptive line and a (usually monospace) value area filled once the
    step has run."""

    def __init__(self, number: int, title: str, role: str, accent: str,
                 description: str, parent=None):
        super().__init__(parent)
        self.setObjectName("SimStage")
        self._accent = accent
        self._placeholder = "—"
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 11)
        layout.setSpacing(6)

        head = QHBoxLayout()
        head.setSpacing(9)
        self.badge = QLabel(str(number))
        self.badge.setFixedSize(22, 22)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge.setStyleSheet(
            f"background: {accent}; color: #10151f; "
            f"border-radius: {theme.corner_radius_css(11)}; font-weight: bold;")
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-weight: bold;")
        tag = QLabel(role.upper())
        tag.setStyleSheet(f"color: {accent}; font-size: 7.5pt; letter-spacing: 1px;")
        head.addWidget(self.badge)
        head.addWidget(title_lbl, stretch=1)
        head.addWidget(tag)
        layout.addLayout(head)

        desc = QLabel(description)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {GREY}; font-size: 8pt;")
        layout.addWidget(desc)

        self.value = QLabel(self._placeholder)
        self.value.setWordWrap(True)
        self.value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.value.setStyleSheet(f"{_MONO} color: {GREY};")
        layout.addWidget(self.value)

        theme.on_change(self._apply_theme)
        self._apply_theme()

    def _apply_theme(self) -> None:
        c = theme.scheme_colors()
        self.setStyleSheet(
            f"#SimStage {{ background: {c['bg_alt']}; border: 1px solid {c['border']}; "
            f"  border-left: 3px solid {self._accent}; }}")

    def set_value(self, text: str, color: str | None = None, tooltip: str = "") -> None:
        self.value.setText(text or self._placeholder)
        self.value.setStyleSheet(f"{_MONO} color: {color or theme.scheme_colors()['fg']};")
        self.value.setToolTip(tooltip)

    def reset(self) -> None:
        self.value.setText(self._placeholder)
        self.value.setStyleSheet(f"{_MONO} color: {GREY};")
        self.value.setToolTip("")


def _ellipsize(text: str, head: int = 44, tail: int = 10) -> str:
    if len(text) <= head + tail + 1:
        return text
    return f"{text[:head]}…{text[-tail:]}"


class SignatureSimPage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._busy = False
        self._jobs: set[Job] = set()
        # (screen, signature) of recent runs, newest last -- the re-recognition story.
        self._history: list[tuple[str, str]] = []

        root = QVBoxLayout(self)
        intro = QLabel(
            "Watch one browser characteristic become the proxy's consent-gated, one-way "
            "<b>gdpr_signature</b>. Resize the visitor browser on the left — its size is the "
            "screen size the browser reports — then click <b>Agree &amp; derive signature</b> to "
            "mint a real <code>gdpr_token</code>, send it to the proxy, and read back the signature "
            "it derives. Resize and run again to see it change; return to a previous size and the "
            "same signature comes back.")
        intro.setWordWrap(True)
        root.addWidget(intro)

        self.error_banner = ErrorBanner()
        root.addWidget(self.error_banner)

        main = QHBoxLayout()
        main.setSpacing(14)
        main.addLayout(self._build_browser_column(), stretch=3)
        main.addLayout(self._build_flow_column(), stretch=2)
        root.addLayout(main, stretch=1)

        note = muted_label(
            "The client half (stages 1–2) is reproduced here from Python exactly as "
            "reverse_proxy_enhanced/gdpr_client.js does it in a real browser. The server half "
            "(stages 3–4) runs only inside the proxy: it appends the client IP it sees, strips "
            "the timestamp, hashes the sorted characteristics with a deployment-local salt, and "
            "emits just the signature — the raw characteristics and the salt never leave it. "
            "See ids/GDPR.md.")
        root.addWidget(note)

    # ---- construction ----

    def _build_browser_column(self):
        col = QVBoxLayout()
        col.setSpacing(8)
        header = QLabel("<b>Visitor browser</b>")
        col.addWidget(header)

        self.mdi = QMdiArea()
        self.mdi.setMinimumHeight(420)
        self.mdi.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.mdi.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.mdi.setBackground(QBrush(QColor(theme.scheme_colors()["bg"])))
        theme.on_change(lambda: self.mdi.setBackground(QBrush(QColor(theme.scheme_colors()["bg"]))))

        self.view = _BrowserView(_base_url(self.state))
        self.win = _BrowserWindow()
        self.win.setWidget(self.view)
        self.win.setWindowTitle("https://…  —  visitor browser")
        # A clean, resizeable frame: a title bar for grabbing, but none of the
        # minimise/maximise/close/system-menu buttons an MDI window shows by
        # default (there is only ever this one window).
        self.win.setWindowFlags(Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)
        self.mdi.addSubWindow(self.win)
        self.win.resize(DEFAULT_W, DEFAULT_H)
        self.win.move(18, 14)
        self.win.resized.connect(self._on_window_resized)
        col.addWidget(self.mdi, stretch=1)

        row = QHBoxLayout()
        self.screen_lbl = QLabel()
        self.screen_lbl.setStyleSheet(f"{_MONO}")
        self.reset_size_btn = QPushButton("Reset window size")
        self.reset_size_btn.setToolTip(f"Restore the window to {DEFAULT_W}×{DEFAULT_H}.")
        self.reset_size_btn.clicked.connect(self._reset_size)
        row.addWidget(self.screen_lbl, stretch=1)
        row.addWidget(self.reset_size_btn)
        col.addLayout(row)
        self._update_screen_label()
        return col

    def _build_flow_column(self):
        col = QVBoxLayout()
        col.setSpacing(8)
        col.addWidget(QLabel("<b>gdpr_token → gdpr_signature</b>"))

        self.stage_chars = _Stage(
            1, "Collect characteristics", "client", BLUE,
            "The browser reads its screen size and stamps the current time.")
        self.stage_token = _Stage(
            2, "Encrypt → gdpr_token", "client", BLUE,
            "RSA-OAEP(SHA-256) with the proxy's public key, base64-encoded into the cookie.")
        self.stage_ip = _Stage(
            3, "Proxy appends client IP", "server", ORANGE,
            "The proxy decrypts in memory and adds the IP it sees — the browser can't supply it.")
        self.stage_hash = _Stage(
            4, "Hash → one-way signature", "server", ORANGE,
            "Timestamp stripped, characteristics sorted, SHA-256 with a deployment-local salt.")
        self.stage_sig = _Stage(
            5, "gdpr_signature", "result", GREEN,
            "The only value that leaves the proxy. Bound to a honeypot in Redis when matched.")
        self._stages = [self.stage_chars, self.stage_token, self.stage_ip, self.stage_hash, self.stage_sig]
        for s in self._stages:
            col.addWidget(s)

        btns = QHBoxLayout()
        self.run_btn = QPushButton("Agree && derive signature")
        self.run_btn.clicked.connect(self._run)
        self.revoke_btn = QPushButton("Revoke consent && reset")
        self.revoke_btn.setToolTip("Clear the token and signature — as if the visitor withdrew "
                                   "consent, so the browser simply stops sending the token.")
        self.revoke_btn.clicked.connect(self._revoke)
        btns.addWidget(self.run_btn, stretch=1)
        btns.addWidget(self.revoke_btn)
        col.addLayout(btns)

        self.status_lbl = QLabel("")
        self.status_lbl.setWordWrap(True)
        self.status_lbl.setStyleSheet(f"color: {GREY};")
        col.addWidget(self.status_lbl)

        self.history_lbl = QLabel("")
        self.history_lbl.setWordWrap(True)
        self.history_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.history_lbl.setStyleSheet(f"{_MONO} font-size: 8pt; color: {GREY};")
        col.addWidget(self.history_lbl)

        col.addStretch(1)
        self._fill_characteristics()  # stage 1 is known from the window at rest
        return col

    # ---- window size <-> characteristic ----

    def _on_window_resized(self) -> None:
        self._update_screen_label()
        self._fill_characteristics()
        if self.stage_sig.value.text() not in ("—", ""):
            self.status_lbl.setText("Window resized — derive again to see the signature for the "
                                    "new screen size.")
            self.status_lbl.setStyleSheet(f"color: {ORANGE};")

    def _update_screen_label(self) -> None:
        self.screen_lbl.setText(f"screen = {self.view.screen_string()}")

    def _reset_size(self) -> None:
        self.win.resize(DEFAULT_W, DEFAULT_H)

    def _fill_characteristics(self) -> None:
        """Stage 1 is purely client-side, so it can show the live payload even
        before (and between) runs."""
        screen = self.view.screen_string()
        self.stage_chars.set_value(f'screen = {screen}\n{{"s":"{screen}","t":<now>}}',
                                   color=theme.scheme_colors()["fg"])

    # ---- run / reset ----

    def _revoke(self) -> None:
        for s in self._stages:
            s.reset()
        self._fill_characteristics()
        self.status_lbl.setText("Consent revoked — with no token sent, the proxy can derive no "
                                "signature, and there is nothing stored to erase.")
        self.status_lbl.setStyleSheet(f"color: {GREY};")

    def _run(self) -> None:
        if self._busy:
            return
        self._busy = True
        self.run_btn.setEnabled(False)
        self.run_btn.setText("Deriving…")
        self.error_banner.set_error(None)
        self.status_lbl.setText("Minting a gdpr_token and sending it to the proxy…")
        self.status_lbl.setStyleSheet(f"color: {GREY};")
        self.stage_sig.reset()

        screen = self.view.screen_string()
        base = _base_url(self.state)
        target = target_for("edge", self.state)
        job = Job(lambda: signature_sim.run_flow(base, target, screen), self)
        self._jobs.add(job)

        def finished(result, error):
            self._busy = False
            self.run_btn.setEnabled(True)
            self.run_btn.setText("Agree && derive signature")
            self._jobs.discard(job)
            job.deleteLater()
            if error or result is None:
                self.error_banner.set_error(error or "no result", prefix="⚠ ")
                self.status_lbl.setText("")
                return
            self._apply_result(result)
        job.done.connect(finished)
        job.start()

    def _apply_result(self, r: signature_sim.FlowResult) -> None:
        fg = theme.scheme_colors()["fg"]
        # Stage 1: the exact payload that was encrypted (timestamp and all).
        if r.payload_json:
            self.stage_chars.set_value(f"screen = {r.screen}\n{r.payload_json}", color=fg)
        # Stage 2: the gdpr_token cookie value.
        if r.token_b64:
            self.stage_token.set_value(_ellipsize(r.token_b64), color=fg,
                                       tooltip=r.token_b64)
        else:
            self.stage_token.reset()

        if not r.ok:
            # Server stages couldn't be observed; say why on the result stage.
            self.stage_ip.reset()
            self.stage_hash.reset()
            self.stage_sig.set_value("no signature", color=RED)
            self.error_banner.set_error(r.error, prefix="⚠ ")
            self.status_lbl.setText("")
            return

        # Server half observed: show it as process (its inputs never leave the proxy).
        self.stage_ip.set_value("payload.ip = <client IP the proxy sees>   (server-side)", color=fg)
        self.stage_hash.set_value("SHA256( deployment-salt | sorted characteristics incl. ip )",
                                  color=fg)
        self.stage_sig.set_value(r.signature, color=GREEN,
                                 tooltip=f"Session {r.session_id}" if r.session_id else "")

        self.error_banner.set_error(None)
        repeat = any(sig == r.signature and scr == r.screen for scr, sig in self._history)
        status = f"Proxy response {r.http_status}."
        if r.session_id:
            status += f" Session {r.session_id}."
        if repeat:
            status += "  Same size as a previous run → identical signature (re-recognition)."
        self.status_lbl.setText(status)
        self.status_lbl.setStyleSheet(f"color: {GREEN};")
        self._record_history(r.screen, r.signature)

    def _record_history(self, screen: str, signature: str) -> None:
        self._history.append((screen, signature))
        self._history = self._history[-5:]
        lines = [f"{scr:>11}  →  {sig[:16]}…" for scr, sig in reversed(self._history)]
        self.history_lbl.setText("recent runs\n" + "\n".join(lines))
