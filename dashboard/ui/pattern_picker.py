"""A scrollable pattern picker that replaces the tall pattern dropdowns.

A plain ``QComboBox`` holding 30+ grouped presets opens a popup as tall as the
list, which on the Attack Simulation and Segmentation Validation pages ran off
the bottom of the window.  ``PatternPickerButton`` is a drop-in替代: a button
that opens its own small popup -- searchable, grouped, and never taller than
half the window -- instead of a native combo list.

Two modes:

* ``"single"`` -- click a row to pick one preset and close (what a combo did:
  the manual request builder and the Segmentation Validation run each act on
  one pattern).
* ``"multi"`` -- each row has a checkbox; the *checked* set is the batch the
  Attack Simulation Multi-run and the PDF report cover, while the *highlighted*
  row (click the row, not the box) is the one a single run targets.

The picker only ever shows the presets it is given, so the caller filters out
registry-disabled patterns before populating it (see
``core.pattern_registry.active_presets``): a pattern switched off in the Pattern
Database never appears here.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import (
    QButtonGroup, QCheckBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QScrollArea, QSizePolicy, QToolButton, QVBoxLayout, QWidget,
)

from ui import theme


def preset_key(preset) -> str:
    """A stable identity for a preset across repopulates (so checked/current
    state survives a category-filter change). ``None`` is the blank request."""
    if preset is None:
        return "\x00blank"
    return "|".join(str(getattr(preset, f, "")) for f in ("cve", "method", "path", "name"))


class _PickerRow(QWidget):
    """One preset row: an optional checkbox plus a label. Clicking the row
    (anywhere but the checkbox) highlights it; the checkbox toggles batch
    membership on its own."""

    row_clicked = pyqtSignal(str)
    check_toggled = pyqtSignal(str, bool)

    def __init__(self, key: str, text: str, *, checkable: bool, selectable: bool,
                 tooltip: str = "", marker: str = "", parent=None):
        super().__init__(parent)
        self.key = key
        self._selectable = selectable
        # A bare QWidget subclass ignores a stylesheet background without this.
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setToolTip(tooltip)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 3, 8, 3)
        layout.setSpacing(6)
        self.check: QCheckBox | None = None
        if checkable:
            self.check = QCheckBox()
            self.check.setEnabled(selectable)
            self.check.toggled.connect(lambda state: self.check_toggled.emit(self.key, state))
            layout.addWidget(self.check)
        elif marker:
            # A row with no checkbox in a checkbox list reads as broken, so a
            # batch-excluded row (single-run only) gets a glyph in the checkbox
            # column instead of an empty gap, aligned with the real checkboxes.
            dot = QLabel(marker)
            dot.setFixedWidth(18)
            dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
            dot.setStyleSheet(f"color: {theme.scheme_colors()['fg_muted']};")
            layout.addWidget(dot)
        self.label = QLabel(text)
        self.label.setEnabled(selectable)
        self.label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        layout.addWidget(self.label, stretch=1)
        self._current = False
        self._apply_style()

    def set_checked(self, state: bool) -> None:
        if self.check is not None:
            self.check.blockSignals(True)
            self.check.setChecked(state)
            self.check.blockSignals(False)

    def is_checked(self) -> bool:
        return bool(self.check and self.check.isChecked())

    def set_current(self, current: bool) -> None:
        self._current = current
        self._apply_style()

    def _apply_style(self) -> None:
        c = theme.scheme_colors()
        if self._current:
            self.setStyleSheet(
                f"_PickerRow {{ background: {c['accent']}; }} "
                f"QLabel {{ color: {c['accent_text']}; }}")
        else:
            self.setStyleSheet(f"_PickerRow:hover {{ background: {c['bg_alt']}; }}")

    def mousePressEvent(self, event) -> None:  # noqa: N802 (Qt override)
        if self._selectable:
            self.row_clicked.emit(self.key)
        super().mousePressEvent(event)


class _CategorySegment(QWidget):
    """One test-category filter rendered as an inline segmented control --
    "All | <opt> | <opt>" -- rather than a QComboBox. A combo's own dropdown
    is itself a popup, which inside this frame's Qt.Popup fights the parent
    for the grab and dismisses it; a row of exclusive buttons has no nested
    popup, so it lives happily inside the picker."""

    changed = pyqtSignal(str, str)   # (attr, value)

    def __init__(self, attr: str, title: str, options: dict, tip: str, parent=None):
        super().__init__(parent)
        self.attr = attr
        self.setToolTip(tip)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(4)
        label = QLabel(f"{title}:")
        label.setFixedWidth(58)
        c = theme.scheme_colors()
        label.setStyleSheet(f"color: {c['fg_muted']}; font-size: 11px;")
        row.addWidget(label)
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._buttons: dict[str, QPushButton] = {}
        self.setStyleSheet(
            "QPushButton { padding: 2px 9px; font-size: 11px; border: 1px solid "
            f"{c['border']}; border-radius: {theme.corner_radius_css(4)}; "
            f"background: {c['bg']}; color: {c['fg_muted']}; }} "
            f"QPushButton:checked {{ background: {c['accent']}; color: {c['accent_text']}; "
            "border-color: transparent; font-weight: 600; }")
        for value, text in [("", "All")] + list(options.items()):
            btn = QPushButton(text)
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            if value == "":
                btn.setChecked(True)
            self._group.addButton(btn)
            btn.toggled.connect(lambda on, v=value: on and self.changed.emit(self.attr, v))
            self._buttons[value] = btn
            row.addWidget(btn)
        row.addStretch(1)

    def value(self) -> str:
        for value, btn in self._buttons.items():
            if btn.isChecked():
                return value
        return ""


class _Popup(QFrame):
    """The frameless list that drops below the button. Closes on an outside
    click (Qt.Popup) and caps its own height at half the top-level window."""

    def __init__(self, owner: "PatternPickerButton"):
        super().__init__(owner, Qt.WindowType.Popup)
        self._owner = owner
        self.setFrameShape(QFrame.Shape.StyledPanel)
        c = theme.scheme_colors()
        self.setStyleSheet(
            f"_Popup {{ background: {c['bg']}; border: 1px solid {c['border']}; }}")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(5)

        # Filled by owner.add_category_filters() -- the test-category filters,
        # which used to sit in a toolbar row of their own on the page. Kept at
        # the very top of the popup so narrowing the list lives with the list.
        self.category_heading = QLabel("Filter the list")
        self.category_heading.setStyleSheet(
            f"color: {c['accent']}; font-size: 8pt; font-weight: 700; letter-spacing: 1px;")
        self.category_heading.setVisible(False)
        outer.addWidget(self.category_heading)
        self.category_container = QVBoxLayout()
        self.category_container.setContentsMargins(0, 0, 0, 0)
        self.category_container.setSpacing(3)
        outer.addLayout(self.category_container)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search patterns…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(owner._filter_rows)
        outer.addWidget(self.search)

        if owner._mode == "multi":
            tools = QHBoxLayout()
            tools.setContentsMargins(0, 0, 0, 0)
            all_btn = QPushButton("Select all")
            none_btn = QPushButton("Select none")
            all_btn.setFlat(True)
            none_btn.setFlat(True)
            all_btn.clicked.connect(lambda: owner._set_all_visible(True))
            none_btn.clicked.connect(lambda: owner._set_all_visible(False))
            tools.addWidget(all_btn)
            tools.addWidget(none_btn)
            tools.addStretch(1)
            outer.addLayout(tools)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.body = QWidget()
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(0, 0, 0, 0)
        self.body_layout.setSpacing(0)
        self.scroll.setWidget(self.body)
        outer.addWidget(self.scroll)

        # Footer reminder: the list only ever shows registry-enabled patterns
        # (the caller filters via core.pattern_registry.active_presets), so tell
        # the user where more come from -- enabling them in the Pattern Database.
        self.footer = QLabel(
            "Need more? Enable patterns on the Pattern Database page and they "
            "appear here automatically.")
        self.footer.setWordWrap(True)
        self.footer.setStyleSheet(
            f"color: {c['fg_muted']}; font-size: 8pt; padding: 4px 2px 0 2px; "
            f"border-top: 1px solid {c['border']};")
        outer.addWidget(self.footer)


class PatternPickerButton(QToolButton):
    selection_changed = pyqtSignal()   # the checked batch changed (multi mode)
    current_changed = pyqtSignal()     # the highlighted / picked preset changed
    category_changed = pyqtSignal()    # a test-category filter changed (see add_category_filters)

    def __init__(self, mode: str = "multi", parent=None):
        super().__init__(parent)
        assert mode in ("single", "multi")
        self._mode = mode
        self._rows: dict[str, _PickerRow] = {}
        self._order: list[str] = []
        self._presets: dict[str, object] = {}
        self._checked: set[str] = set()
        self._current: str | None = None
        self._category_segments: dict[str, _CategorySegment] = {}
        # Default (DelayedPopup) mode with no QMenu set behaves as a plain
        # button that fires clicked -- we drive our own popup off that. (An
        # InstantPopup button swallows clicked, so don't use it here.)
        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self._popup = _Popup(self)
        self.clicked.connect(self._open_popup)
        self._update_text()

    # ------------------------------------------------------------------
    # test-category filters (shown at the top of the popup)
    # ------------------------------------------------------------------
    def add_category_filters(self, specs) -> None:
        """Add inline category filters to the popup. `specs` is a list of
        ``(attr, title, options_dict, tooltip)``; the chosen value per attr is
        read back with category_value(), and category_changed fires on a
        change (the page re-runs its filtering off that)."""
        for attr, title, options, tip in specs:
            seg = _CategorySegment(attr, title, options, tip)
            seg.changed.connect(self._on_category_changed)
            self._popup.category_container.addWidget(seg)
            self._category_segments[attr] = seg
        self._popup.category_heading.setVisible(bool(self._category_segments))

    def _on_category_changed(self, _attr: str, _value: str) -> None:
        self.category_changed.emit()

    def category_value(self, attr: str) -> str:
        """The selected value for category `attr` ("" = all / unset)."""
        seg = self._category_segments.get(attr)
        return seg.value() if seg else ""

    def set_categories_enabled(self, enabled: bool) -> None:
        for seg in self._category_segments.values():
            seg.setEnabled(enabled)

    # ------------------------------------------------------------------
    # population
    # ------------------------------------------------------------------
    def set_groups(self, groups, *, greyed=(), blank_label: str = "",
                   batch_excluded=()) -> None:
        """Repopulate from ``groups`` -- a list of ``(heading, [preset, ...])``.

        ``greyed`` presets are shown disabled (not pickable); ``batch_excluded``
        presets are pickable for a single run but never get a checkbox (the
        GDPR session-restore demo, which is a browser action, not an attack).
        ``blank_label`` adds a leading "no preset" row (the manual builder)."""
        prev_checked = set(self._checked)
        prev_current = self._current
        first_population = not self._order
        greyed_keys = {preset_key(p) for p in greyed}
        excluded_keys = {preset_key(p) for p in batch_excluded}

        for row in self._rows.values():
            row.setParent(None)
            row.deleteLater()
        self._rows.clear()
        self._order.clear()
        self._presets.clear()
        # Clear the body layout's heading labels too.
        while self._popup.body_layout.count():
            item = self._popup.body_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

        if blank_label:
            self._add_row(None, blank_label, selectable=True,
                          checkable=False, tooltip="Send a request with no preset payload.")

        for heading, presets in groups:
            if heading:
                self._add_heading(heading)
            for preset in presets:
                key = preset_key(preset)
                selectable = key not in greyed_keys
                excluded = key in excluded_keys
                checkable = self._mode == "multi" and not excluded
                tooltip = getattr(preset, "description", "")
                if not selectable:
                    tooltip = ("Not isolated by the database honeypot layer — "
                               "switch layer on the Workloads page to run it.\n" + tooltip)
                marker = ""
                if self._mode == "multi" and excluded:
                    marker = "▸"
                    tooltip = ("Highlight to target it; not part of the checked "
                               "batch.\n" + tooltip)
                self._add_row(preset, self._row_text(preset), selectable=selectable,
                              checkable=checkable, tooltip=tooltip, marker=marker)

        # Restore the batch: on the first population check every selectable
        # row (so Multi-run covers the whole list out of the box, as the old
        # category selector did); afterwards keep prior checks by identity so a
        # category-filter change doesn't silently wipe the user's unchecks.
        self._checked.clear()
        for key, row in self._rows.items():
            if row.check is None:
                continue
            keep = row._selectable and (first_population or key in prev_checked)
            row.set_checked(keep)
            if keep:
                self._checked.add(key)

        # Restore / choose the highlighted row.
        if prev_current in self._rows:
            self._set_current(prev_current)
        else:
            self._set_current(self._first_selectable_key())
        self._update_text()

    def _add_heading(self, text: str) -> None:
        label = QLabel(text)
        c = theme.scheme_colors()
        label.setStyleSheet(
            f"color: {c['accent']}; font-size: 8pt; font-weight: 700; "
            f"letter-spacing: 1px; padding: 6px 8px 2px 8px;")
        label.setProperty("_heading", True)
        self._popup.body_layout.addWidget(label)

    def _add_row(self, preset, text, *, selectable, checkable, tooltip, marker="") -> None:
        key = preset_key(preset)
        row = _PickerRow(key, text, checkable=checkable, selectable=selectable,
                         tooltip=tooltip, marker=marker)
        row.row_clicked.connect(self._on_row_clicked)
        row.check_toggled.connect(self._on_check_toggled)
        self._popup.body_layout.addWidget(row)
        self._rows[key] = row
        self._order.append(key)
        self._presets[key] = preset

    @staticmethod
    def _row_text(preset) -> str:
        cve = getattr(preset, "cve", "")
        name = getattr(preset, "name", "")
        return f"{cve} — {name}" if cve else name

    # ------------------------------------------------------------------
    # interaction
    # ------------------------------------------------------------------
    def _open_popup(self) -> None:
        if not self._order:
            return
        # Cap the list at half the window height BEFORE sizing, so the frame
        # shrinks to the cap instead of opening full-length then clipping.
        window = self.window()
        half = max(220, (window.height() // 2) if window else 400)
        self._popup.scroll.setMaximumHeight(half)
        self._popup.setMinimumWidth(max(self.width(), 360))
        self._popup.adjustSize()
        below = self.mapToGlobal(self.rect().bottomLeft())
        self._popup.move(below)
        self._popup.show()
        self._popup.search.clear()
        self._popup.search.setFocus()

    def _on_row_clicked(self, key: str) -> None:
        self._set_current(key)
        self._update_text()
        if self._mode == "single":
            self._popup.hide()

    def _on_check_toggled(self, key: str, state: bool) -> None:
        if state:
            self._checked.add(key)
        else:
            self._checked.discard(key)
        self._update_text()
        self.selection_changed.emit()

    def _set_current(self, key: str | None) -> None:
        if self._current == key:
            return
        if self._current in self._rows:
            self._rows[self._current].set_current(False)
        self._current = key
        if key in self._rows:
            self._rows[key].set_current(True)
        self.current_changed.emit()

    def _first_selectable_key(self) -> str | None:
        # The first pickable row -- the blank request included, so the manual
        # builder defaults to "(blank request)" the way its combo did.
        for key in self._order:
            if self._rows[key]._selectable:
                return key
        return self._order[0] if self._order else None

    def _set_all_visible(self, state: bool) -> None:
        for key in self._order:
            row = self._rows[key]
            if row.check is None or row.isHidden() or not row._selectable:
                continue
            row.set_checked(state)
            if state:
                self._checked.add(key)
            else:
                self._checked.discard(key)
        self._update_text()
        self.selection_changed.emit()

    def _filter_rows(self, text: str) -> None:
        needle = text.strip().lower()
        # Walk the body layout so headings hide when their whole group does.
        layout = self._popup.body_layout
        pending_heading: QLabel | None = None
        heading_has_visible = False
        for i in range(layout.count()):
            widget = layout.itemAt(i).widget()
            if widget is None:
                continue
            if widget.property("_heading"):
                if pending_heading is not None:
                    pending_heading.setVisible(heading_has_visible)
                pending_heading = widget
                heading_has_visible = False
                continue
            row = widget
            visible = (not needle) or needle in (row.toolTip() + " " + row.label.text()).lower()
            row.setVisible(visible)
            heading_has_visible = heading_has_visible or visible
        if pending_heading is not None:
            pending_heading.setVisible(heading_has_visible)

    def _update_text(self) -> None:
        if self._mode == "multi":
            batch = sum(1 for k in self._order
                        if self._rows[k].check is not None and self._rows[k]._selectable)
            text = f"{len(self._checked)} of {batch} patterns"
            cur = self._presets.get(self._current) if self._current else None
            if cur is not None:
                text += f"  ·  run: {getattr(cur, 'name', '')}"
        else:
            cur = self._presets.get(self._current) if self._current else None
            text = self._row_text(cur) if cur is not None else "(none)"
        metrics = QFontMetrics(self.font())
        avail = max(80, self.width() - 44)  # room for the caret + padding
        self.setText(metrics.elidedText(text, Qt.TextElideMode.ElideRight, avail) + "  ▾")
        self.setToolTip(text)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._update_text()

    # ------------------------------------------------------------------
    # public accessors (the combo API the pages used)
    # ------------------------------------------------------------------
    def current_preset(self):
        """The highlighted (single-run) preset, or None for the blank row."""
        return self._presets.get(self._current) if self._current else None

    def set_current_preset(self, preset) -> None:
        self._set_current(preset_key(preset))
        self._update_text()

    def checked_presets(self) -> list:
        """The checked batch (multi mode), in list order; excludes the blank
        and non-selectable rows."""
        return [self._presets[k] for k in self._order
                if k in self._checked and self._presets[k] is not None]

    def has_entries(self) -> bool:
        return bool(self._order)
