"""Connectors & Config page tab for one project's .env: a Local/Remote toggle that
swaps the SOURCE of the same EnvEditorWidget between the real local file
and the one fetched live from the configured remote host over SSH. Save
writes back to whichever source is currently selected. Companion to the
wizard's RemoteAwareEnvPage (same underlying core.env_upload functions),
but reachable anytime afterward rather than only during first-run setup,
and switchable back and forth without leaving the page.

Secret hygiene (generate weak secrets, restore a backup, back up on a
local save that changes a secret, placeholder warnings) is the shared
ui.setup_sections.SecretTools, also used by the wizard's ids .env page.
"""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget,
)

from core.docker_ctl import Target
from core.env_file import EnvFile, merge_example_keys, seed_from_example
from core.env_upload import EnvUploadError, download_env_text, upload_env_text
from core.state import RemoteConfig
from ui.domain_reminder import notify_env_uploaded
from ui.env_editor import EnvEditorWidget
from ui.setup_sections import SecretTools

_SOURCE_LOCAL = "local"
_SOURCE_REMOTE = "remote"


class EnvSourceTab(QWidget):
    def __init__(
        self, project: str, local_path: Path, local_example: Path,
        get_remote_config, parent=None,
    ):
        super().__init__(parent)
        self.project = project
        self.local_path = local_path
        self.local_example = local_example
        self._get_remote_config = get_remote_config  # callable -> RemoteConfig, read fresh each time

        self.env_file: EnvFile | None = None
        self.editor: EnvEditorWidget | None = None
        self._source_is_remote = False

        layout = QVBoxLayout(self)

        toggle_row = QHBoxLayout()
        toggle_row.addWidget(QLabel("Editing:"))
        self.source_combo = QComboBox()
        self.source_combo.addItem("Local .env", _SOURCE_LOCAL)
        self.source_combo.addItem("Remote .env (fetched live via SSH)", _SOURCE_REMOTE)
        self.source_combo.currentIndexChanged.connect(self._on_source_changed)
        toggle_row.addWidget(self.source_combo)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setToolTip("Re-fetch from the current source, discarding unsaved edits here.")
        self.refresh_btn.clicked.connect(self._reload_current_source)
        toggle_row.addWidget(self.refresh_btn)
        toggle_row.addStretch()

        layout.addLayout(toggle_row)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("color: #888888;")
        layout.addWidget(self.status_label)

        self.secret_tools = SecretTools(
            project, local_path, local_example,
            get_env_file=lambda: self.env_file,
            apply_form=lambda: self.editor.apply_to_env_file(),
            rebuild=self._show_editor, reload_local=self._load_local)
        layout.addWidget(self.secret_tools)

        self._editor_slot = QVBoxLayout()
        layout.addLayout(self._editor_slot, stretch=1)

        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self._save)
        layout.addWidget(self.save_btn)

        self._load_local()
        self.refresh_remote_availability()

    def refresh_remote_availability(self) -> None:
        """Call after remote settings change elsewhere (Settings' own
        remote tabs) so the Remote option's availability -- and the
        currently-shown content, if it's already on Remote -- stays
        correct without needing to reopen this tab."""
        remote = self._get_remote_config()
        configured = remote.is_configured()

        model = self.source_combo.model()
        remote_item = model.item(1)
        if remote_item:
            remote_item.setEnabled(configured)

        if not configured and self.source_combo.currentData() == _SOURCE_REMOTE:
            self.source_combo.setCurrentIndex(0)  # falls back to Local via the signal

    def _clear_editor(self) -> None:
        while self._editor_slot.count():
            item = self._editor_slot.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _on_source_changed(self, _index: int) -> None:
        if self.source_combo.currentData() == _SOURCE_REMOTE:
            self._load_remote()
        else:
            self._load_local()

    def _reload_current_source(self) -> None:
        if self.source_combo.currentData() == _SOURCE_REMOTE:
            self._load_remote()
        else:
            self._load_local()

    def _show_editor(self) -> None:
        self._clear_editor()
        self.editor = EnvEditorWidget(self.env_file)
        self._editor_slot.addWidget(self.editor)
        self.secret_tools.set_remote(self._source_is_remote)
        self.secret_tools.update_warnings()

    def _load_local(self) -> None:
        self._source_is_remote = False
        self.env_file = seed_from_example(self.local_path, self.local_example)
        self._show_editor()
        self.status_label.setText(
            f"Editing local file: {self.local_path}" + self._added_keys_note()
        )
        self.status_label.setStyleSheet("color: #888888;")

    def _added_keys_note(self) -> str:
        """Suffix for the status line naming keys that .env.example has
        but the loaded file doesn't (they're in the form with template
        defaults, and get written on Save)."""
        added = self.env_file.added_keys if self.env_file else []
        if not added:
            return ""
        return (
            f"\nNot in this file yet, added from .env.example (saved on Save): "
            + ", ".join(added)
        )

    def _load_remote(self) -> None:
        remote = self._get_remote_config()
        if not remote.is_configured():
            QMessageBox.warning(
                self, "Remote not configured",
                "Configure and test this project's remote connection "
                "first (Settings → remote tab, or the wizard).",
            )
            self.source_combo.blockSignals(True)
            self.source_combo.setCurrentIndex(0)
            self.source_combo.blockSignals(False)
            self._load_local()
            return

        self._clear_editor()
        remote_env_path = Target(project=self.project, remote=remote).remote_env_path()
        self.status_label.setText(f"Fetching {remote_env_path} from {remote.user}@{remote.host}…")
        self.status_label.setStyleSheet("color: #888888;")
        self.repaint()

        try:
            text = download_env_text(self.project, remote)
        except EnvUploadError as e:
            QMessageBox.warning(self, "Fetch failed", str(e))
            self.source_combo.blockSignals(True)
            self.source_combo.setCurrentIndex(0)
            self.source_combo.blockSignals(False)
            self._load_local()
            return

        self._source_is_remote = True
        display_path = Path(f"{remote.user}@{remote.host}:{remote_env_path}")
        self.env_file = EnvFile.from_text(text, display_path)
        # The template is part of this repo, so it describes what the
        # remote deployment of the same code needs too -- an empty remote
        # file becomes the full template, an old one gains new keys.
        self.env_file.added_keys = merge_example_keys(self.env_file, self.local_example)
        self._show_editor()

        if text:
            self.status_label.setText(
                f"Editing REMOTE file: {remote.user}@{remote.host}:{remote_env_path}"
                + self._added_keys_note()
            )
        else:
            self.status_label.setText(
                f"No .env found yet at {remote.user}@{remote.host}:"
                f"{remote_env_path} -- starting from the .env.example "
                "template; Save will create it there."
            )
        self.status_label.setStyleSheet("color: #5cb85c;")

    def _save(self) -> None:
        self.editor.apply_to_env_file()
        if self._source_is_remote:
            remote = self._get_remote_config()
            try:
                upload_env_text(self.env_file.render(), self.project, remote)
            except EnvUploadError as e:
                QMessageBox.warning(self, "Save to remote failed", str(e))
                return
            remote_env_path = Target(project=self.project, remote=remote).remote_env_path()
            notify_env_uploaded(self.project, self.env_file.render())
            QMessageBox.information(
                self, "Saved",
                f"Saved to {remote.user}@{remote.host}:{remote_env_path}",
            )
        else:
            note = self.secret_tools.save_local()
            if note is None:
                return
            QMessageBox.information(self, "Saved", f"Saved {self.local_path}" + note)
        self.secret_tools.update_warnings()

