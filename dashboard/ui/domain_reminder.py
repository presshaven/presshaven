"""Connectors-page reminder that an uploaded .env still has localhost domain
settings. Uploaders call notify_env_uploaded(); the SettingsPage banner listens."""
from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton

from core.domain_check import localhost_domain_vars

_LABELS = {"edge": "ids", "siem": "siem"}


class _Notifier(QObject):
    uploaded = pyqtSignal(str, str)   # project, env text


_notifier = _Notifier()


def notify_env_uploaded(project: str, text: str) -> None:
    _notifier.uploaded.emit(project, text)


class DomainReminderBanner(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            "QFrame { background: #4a3b10; border: 1px solid #b8860b; border-radius: 4px; }"
            "QLabel { color: #ffd966; border: none; }")
        row = QHBoxLayout(self)
        self.label = QLabel("")
        self.label.setWordWrap(True)
        row.addWidget(self.label, 1)
        dismiss = QPushButton("Dismiss")
        dismiss.clicked.connect(self.hide)
        row.addWidget(dismiss)
        self.hide()
        _notifier.uploaded.connect(self.on_uploaded)

    def on_uploaded(self, project: str, text: str) -> None:
        names = localhost_domain_vars(text, project)
        if not names:
            self.hide()
            return
        self.label.setText(
            f"⚠ The {_LABELS.get(project, project)} .env was uploaded to a remote host, but "
            f"these domain settings are still localhost: {', '.join(names)}. "
            "Set them to the remote's real domain/address and upload again.")
        self.show()
