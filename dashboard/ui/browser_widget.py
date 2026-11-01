"""Embedded browser widget with an address bar -- shared by the SIEM Analytics page
and the Attack Simulation page's production-eshop view.

Uses a dedicated QWebEngineProfile per widget instance rather than the
shared default profile: every site this app points a browser at (Kibana,
the eshop) uses a self-signed certificate, and keeping cookies/site-data
isolated per-widget is what makes "reset local score + cookies"
(page_patterns.py) actually mean something -- clearing cookies here can't
accidentally also log the user out of Kibana or anything else running in
the same process.

By default that profile is off-the-record (in-memory, unnamed) -- this is
a testing tool, not something that should accumulate browsing history/
cache between runs. Pass profile_name to get a NAMED profile instead,
which Qt persists to disk (cookies survive app restarts) -- see the Kibana
page's "Remember credentials" toggle, the one place in this app where
staying logged in across restarts is actually wanted.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtWebEngineCore import QWebEngineCertificateError, QWebEnginePage, QWebEngineProfile
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QProgressBar, QPushButton, QVBoxLayout, QWidget,
)


class _DimOverlay(QWidget):
    """A translucent "idle" veil drawn over the whole browser while it is not
    in use (during a PDF export, between screenshot captures). It also eats
    mouse input, so the browser really is inert while dimmed. Hidden by
    default; sized to cover its parent. It is a sibling of the QWebEngineView
    raised above it -- Qt6 WebEngine composites the web layer with the widget
    stack, so a raised overlay sits on top, and because capture un-dims it
    first (see page_patterns), it never lands in a screenshot."""

    # Side margin kept between the caption pill and the overlay edges, so the
    # label gets a real width to wrap into rather than overflowing (the old
    # fixed-size pill clipped a one-line caption on a narrow browser).
    _MARGIN = 20

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setVisible(False)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(self._MARGIN, self._MARGIN, self._MARGIN, self._MARGIN)
        self.label = QLabel("")
        self.label.setWordWrap(True)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet(
            "color: #e6e6e6; font-size: 14px; "
            "background: rgba(0,0,0,150); padding: 14px 20px; border-radius: 8px;")
        layout.addStretch(1)
        layout.addWidget(self.label, alignment=Qt.AlignmentFlag.AlignHCenter)
        layout.addStretch(1)
        # A dark, semi-transparent wash over the live page -- clearly "not
        # now" without fully hiding what the browser last showed.
        self.setStyleSheet("_DimOverlay { background: rgba(18,18,18,150); }")

    def set_message(self, message: str) -> None:
        self.label.setText(message)
        self.label.setVisible(bool(message))

    def resizeEvent(self, event) -> None:  # noqa: N802 (Qt override)
        super().resizeEvent(event)
        # Cap the caption's width to the overlay (minus margins, and never
        # absurdly wide on a big browser) so word-wrap actually kicks in and
        # the pill grows downward to fit instead of being clipped.
        avail = max(120, self.width() - 2 * self._MARGIN)
        self.label.setMaximumWidth(min(avail, 460))


class BrowserWidget(QWidget):
    def __init__(self, home_url: str = "about:blank", profile_name: str | None = None, parent=None):
        super().__init__(parent)
        self._home_url = home_url

        # A named profile gets Qt's own on-disk storage (cookies/cache
        # persisted, survives app restarts, AllowPersistentCookies by
        # default); no name keeps everything off-the-record/in-memory,
        # same as before.
        self.profile = QWebEngineProfile(profile_name, self) if profile_name else QWebEngineProfile(self)
        self.page = QWebEnginePage(self.profile, self)
        self.page.certificateError.connect(self._on_certificate_error)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        nav_row = QHBoxLayout()
        self.back_btn = QPushButton("←")
        self.back_btn.setFixedWidth(32)
        self.back_btn.setToolTip("Back")
        self.forward_btn = QPushButton("→")
        self.forward_btn.setFixedWidth(32)
        self.forward_btn.setToolTip("Forward")
        self.reload_btn = QPushButton("↻")
        self.reload_btn.setFixedWidth(32)
        self.reload_btn.setToolTip("Reload")
        self.home_btn = QPushButton("⌂")
        self.home_btn.setFixedWidth(32)
        self.home_btn.setToolTip("Home (back to the starting address)")
        for btn in (self.back_btn, self.forward_btn, self.reload_btn, self.home_btn):
            btn.setProperty("compact", True)
        self.address_bar = QLineEdit()
        self.address_bar.setPlaceholderText("Enter a URL and press Enter")
        go_btn = QPushButton("Go")
        go_btn.setFixedWidth(40)
        go_btn.setProperty("compact", True)

        nav_row.addWidget(self.back_btn)
        nav_row.addWidget(self.forward_btn)
        nav_row.addWidget(self.reload_btn)
        nav_row.addWidget(self.home_btn)
        nav_row.addWidget(self.address_bar, stretch=1)
        nav_row.addWidget(go_btn)
        layout.addLayout(nav_row)

        self.progress = QProgressBar()
        self.progress.setMaximumHeight(4)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.view = QWebEngineView()
        self.view.setPage(self.page)
        layout.addWidget(self.view, stretch=1)

        # Idle veil for the PDF export (see set_dimmed). Not in the layout --
        # a free child kept sized to the whole widget and raised on top.
        self._overlay = _DimOverlay(self)

        self.back_btn.clicked.connect(self.view.back)
        self.forward_btn.clicked.connect(self.view.forward)
        self.reload_btn.clicked.connect(self.view.reload)
        self.home_btn.clicked.connect(self.reload_home)
        go_btn.clicked.connect(self._navigate_to_address_bar)
        self.address_bar.returnPressed.connect(self._navigate_to_address_bar)

        self.view.urlChanged.connect(self._on_url_changed)
        self.view.loadStarted.connect(lambda: self.progress.setVisible(True))
        self.view.loadProgress.connect(self.progress.setValue)
        self.view.loadFinished.connect(lambda _ok: self.progress.setVisible(False))

        if home_url and home_url != "about:blank":
            self.navigate(home_url)

    def set_dimmed(self, dimmed: bool, message: str = "") -> None:
        """Show (or hide) the idle veil over the browser. `message` is the
        centered caption shown while dimmed."""
        self._overlay.set_message(message)
        self._overlay.setGeometry(self.rect())
        self._overlay.setVisible(dimmed)
        if dimmed:
            self._overlay.raise_()

    def resizeEvent(self, event) -> None:  # noqa: N802 (Qt override)
        super().resizeEvent(event)
        if self._overlay.isVisible():
            self._overlay.setGeometry(self.rect())

    def navigate(self, url_str: str) -> None:
        url = QUrl(url_str)
        if url.scheme() == "":
            url = QUrl("https://" + url_str)
        self.view.load(url)

    def reload_home(self) -> None:
        self.navigate(self._home_url)

    def set_home_url(self, url: str) -> None:
        """Change what the "⌂" button / reload_home() returns to -- used by
        pages that re-point one browser at a different backend (e.g.
        Targeted Access switching between production and a honeypot pool)
        instead of creating a fresh widget per target."""
        self._home_url = url

    def clear_cookies(self) -> None:
        self.profile.cookieStore().deleteAllCookies()

    def _navigate_to_address_bar(self) -> None:
        self.navigate(self.address_bar.text().strip())

    def _on_url_changed(self, url: QUrl) -> None:
        self.address_bar.setText(url.toString())

    def _on_certificate_error(self, error: QWebEngineCertificateError) -> None:
        # Every site this app points a browser at (Kibana, the eshop) uses
        # a self-signed cert generated by this repo's own gen_elk_certs.sh
        # / cert pages -- there's no real CA to trust, so treat cert errors
        # for these known-self-signed local/test targets as expected
        # rather than blocking navigation on them.
        error.acceptCertificate()
