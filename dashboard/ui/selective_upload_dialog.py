"""Checklist of the files a selective upload would send: the result of an
rsync dry run against the remote, every file ticked by default so the common
case is one click, with Select all / none and a filter for the odd one out."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QPushButton, QVBoxLayout, QWidget,
)


class SelectiveUploadDialog(QDialog):
    def __init__(self, files: list[str], destination: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Selective upload")
        self.resize(640, 480)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            f"{len(files)} file(s) differ from {destination} (new, or a different "
            "size / modification time). Tick the ones to upload:"))

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by path…")
        self.filter_edit.textChanged.connect(self._apply_filter)
        layout.addWidget(self.filter_edit)

        self.list = QListWidget()
        for path in files:
            item = QListWidgetItem(path)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            self.list.addItem(item)
        self.list.itemChanged.connect(self._update_count)
        layout.addWidget(self.list, stretch=1)

        row = QHBoxLayout()
        all_btn = QPushButton("Select all")
        all_btn.clicked.connect(lambda: self._set_visible(Qt.CheckState.Checked))
        none_btn = QPushButton("Select none")
        none_btn.clicked.connect(lambda: self._set_visible(Qt.CheckState.Unchecked))
        self.count_label = QLabel()
        row.addWidget(all_btn)
        row.addWidget(none_btn)
        row.addStretch()
        row.addWidget(self.count_label)
        layout.addLayout(row)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.upload_btn = self.buttons.addButton(
            "Upload selected", QDialogButtonBox.ButtonRole.AcceptRole)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self._update_count()

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        for i in range(self.list.count()):
            item = self.list.item(i)
            item.setHidden(bool(needle) and needle not in item.text().lower())

    def _set_visible(self, state: Qt.CheckState) -> None:
        """Select all / none apply to what the filter currently shows."""
        for i in range(self.list.count()):
            item = self.list.item(i)
            if not item.isHidden():
                item.setCheckState(state)

    def selected(self) -> list[str]:
        return [self.list.item(i).text() for i in range(self.list.count())
                if self.list.item(i).checkState() == Qt.CheckState.Checked]

    def _update_count(self, *_args) -> None:
        n = len(self.selected())
        self.count_label.setText(f"{n} of {self.list.count()} selected")
        self.upload_btn.setEnabled(n > 0)
