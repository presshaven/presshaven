"""Per-page SVG icons, recolored for the active theme.

The files under ``resources/page_icons/`` use the literal placeholder
``currentColor`` for their stroke. Qt's SVG renderer does not resolve CSS
``currentColor`` in a QIcon, so each icon is rendered to a small pixmap with
that placeholder replaced by the theme's muted/selected-text/foreground
color. Rendering per color (and caching the pixmaps) means a theme switch is
just a fresh lookup, with no second set of hand-maintained light/dark assets.
"""
from __future__ import annotations

from PyQt6.QtCore import QByteArray, QSize, Qt
from PyQt6.QtGui import QIcon, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer

from core.paths import DASHBOARD_DIR
from ui import theme

ICON_DIR = DASHBOARD_DIR / "resources" / "page_icons"

# Logical icon size in the rail and overflow panel. Rendering at 2x keeps
# the strokes crisp on HiDPI displays.
_ICON_SIZE = 18
_SCALE = 2
_pixmap_cache: dict[tuple[str, str, int], QPixmap] = {}


def _pixmap(page_id: str, color: str, size: int = _ICON_SIZE) -> QPixmap:
    key = (page_id, color, size)
    cached = _pixmap_cache.get(key)
    if cached is not None:
        return cached

    path = ICON_DIR / f"{page_id}.svg"
    if not path.exists():
        return QPixmap()
    svg = path.read_text(encoding="utf-8").replace("currentColor", color)
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    if not renderer.isValid():
        return QPixmap()

    pixmap = QPixmap(size * _SCALE, size * _SCALE)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    renderer.render(painter)
    painter.end()
    pixmap.setDevicePixelRatio(float(_SCALE))
    _pixmap_cache[key] = pixmap
    return pixmap


def _icon(page_id: str, normal_color: str, active_color: str,
          selected_color: str, size: int) -> QIcon:
    muted = _pixmap(page_id, normal_color, size)
    if muted.isNull():
        return QIcon()
    normal = muted
    active = _pixmap(page_id, active_color, size)
    selected = _pixmap(page_id, selected_color, size)

    icon = QIcon()
    for state in (QIcon.State.Off, QIcon.State.On):
        icon.addPixmap(normal, QIcon.Mode.Normal, state)
        icon.addPixmap(active, QIcon.Mode.Active, state)
        icon.addPixmap(selected, QIcon.Mode.Selected, state)
        icon.addPixmap(muted, QIcon.Mode.Disabled, state)
    return icon


def page_icon(page_id: str, size: int = _ICON_SIZE) -> QIcon:
    """A theme-aware QIcon for the navigation rail / overflow panel.

    Normal items use the muted nav color, hovered/active items the regular
    foreground, and selected items the rail's selected-text color -- matching
    the rest of the navigation rail. Missing assets return an empty QIcon
    rather than raising, so a stale page id can never stop the window from
    opening.
    """
    c = theme.scheme_colors()
    return _icon(page_id, c["fg_muted"], c["fg"], c["nav_selected_fg"], size)


def menu_icon(page_id: str, size: int = _ICON_SIZE) -> QIcon:
    """Like page_icon(), but for menus and the command palette, whose
    selected rows use the global selection colors rather than the rail's
    nav-specific ones."""
    c = theme.scheme_colors()
    return _icon(page_id, c["fg_muted"], c["fg"], c["selection_fg"], size)


def page_pixmap(page_id: str, size: int = _ICON_SIZE, color: str | None = None) -> QPixmap:
    """A single theme-colored pixmap of a page's icon, for places that show it
    as a plain image (e.g. the Overview page-link cards) rather than as a QIcon
    with hover/selected states. Defaults to the theme foreground color."""
    c = theme.scheme_colors()
    return _pixmap(page_id, color or c["fg"], size)


def clear_cache() -> None:
    """Drop rendered pixmaps (used by tests after switching themes)."""
    _pixmap_cache.clear()


def icon_size() -> QSize:
    """The logical size the rail and overflow panel use for page icons."""
    return QSize(_ICON_SIZE, _ICON_SIZE)
