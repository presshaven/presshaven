"""Form for a single project's remote (SSH) connection settings, plus Test
Connection, "upload just the .env", and "sync the whole project" actions.
Shared by the wizard and the Connectors & Config page."""
from __future__ import annotations

import shutil

from PyQt6.QtCore import QProcess
from PyQt6.QtWidgets import (
    QCheckBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QProgressBar, QPushButton, QSpinBox, QVBoxLayout,
    QWidget,
)

from core.docker_ctl import Target
from core.env_upload import EnvUploadError, upload_env
from core.paths import EDGE_DIR, EDGE_ENV_FILE, SIEM_DIR, SIEM_ENV_FILE
from core.project_upload import (
    ProjectUploadError, build_rsync_argv, parse_progress_percent,
    remote_dir_has_content,
)
from core.state import RemoteConfig

_LOCAL_ENV_FILES = {"edge": EDGE_ENV_FILE, "siem": SIEM_ENV_FILE}
_PROJECT_ENV_LABELS = {"edge": "ids/.env", "siem": "siem/docker/.env"}
_LOCAL_PROJECT_DIRS = {"edge": EDGE_DIR, "siem": SIEM_DIR}
_PROJECT_DIR_LABELS = {"edge": "ids", "siem": "siem"}


class RemoteConfigWidget(QWidget):
    def __init__(self, project: str, config: RemoteConfig, parent=None):
        super().__init__(parent)
        self.project = project

        layout = QVBoxLayout(self)

        self.enabled_check = QCheckBox("Enable this remote host")
        self.enabled_check.setChecked(config.enabled)
        layout.addWidget(self.enabled_check)

        form = QFormLayout()
        self.name_edit = QLineEdit(config.name)
        self.name_edit.setPlaceholderText("optional label, e.g. \"staging\" or \"vm-02\"")
        form.addRow("Name:", self.name_edit)

        self.host_edit = QLineEdit(config.host)
        form.addRow("Host / IP:", self.host_edit)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(config.port or 22)
        form.addRow("SSH port:", self.port_spin)

        self.user_edit = QLineEdit(config.user)
        form.addRow("SSH user:", self.user_edit)

        key_row = QHBoxLayout()
        self.key_edit = QLineEdit(config.key_path)
        key_browse = QPushButton("Browse…")
        key_browse.clicked.connect(self._browse_key)
        key_row.addWidget(self.key_edit)
        key_row.addWidget(key_browse)
        form.addRow("SSH private key:", key_row)

        self.remote_path_edit = QLineEdit(config.remote_path)
        self.remote_path_edit.setPlaceholderText(
            "e.g. /home/user/DP_Repository/ids "
            "(or .../siem -- same idea, the "
            "project root either way; this app finds SIEM's "
            "docker-compose.yml in the docker/ subdirectory automatically, "
            "same as it does locally)"
        )
        form.addRow("Remote project path:", self.remote_path_edit)

        layout.addLayout(form)

        test_row = QHBoxLayout()
        self.test_btn = QPushButton("Test connection")
        self.test_btn.clicked.connect(self._test_connection)
        self.test_result = QLabel("")
        test_row.addWidget(self.test_btn)
        test_row.addWidget(self.test_result)
        test_row.addStretch()
        layout.addLayout(test_row)

        # Only enabled after a successful Test connection -- clearly names
        # which project's .env it would send (ids vs.
        # siem), since a remote target's own .env otherwise
        # has to be placed there by hand.
        upload_row = QHBoxLayout()
        self.upload_btn = QPushButton(f"Upload {_PROJECT_ENV_LABELS[project]} to remote…")
        self.upload_btn.setEnabled(False)
        self.upload_btn.clicked.connect(self._upload_env)
        self.upload_result = QLabel("")
        upload_row.addWidget(self.upload_btn)
        upload_row.addWidget(self.upload_result)
        upload_row.addStretch()
        layout.addLayout(upload_row)

        # Whole-project sync (code + config, not just .env) via rsync --
        # also only enabled after a successful Test connection. Separate
        # from the .env-only upload above so a quick config tweak doesn't
        # have to wait on a full project sync, and vice versa.
        sync_row = QHBoxLayout()
        self.sync_btn = QPushButton(f"Upload entire {_PROJECT_DIR_LABELS[project]} to remote…")
        self.sync_btn.setEnabled(False)
        self.sync_btn.clicked.connect(self._sync_project)
        self.sync_result = QLabel("")
        sync_row.addWidget(self.sync_btn)
        sync_row.addWidget(self.sync_result)
        sync_row.addStretch()
        layout.addLayout(sync_row)

        self.sync_progress = QProgressBar()
        self.sync_progress.setRange(0, 100)
        self.sync_progress.setVisible(False)
        layout.addWidget(self.sync_progress)

        self._sync_process: QProcess | None = None

    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select SSH private key")
        if path:
            self.key_edit.setText(path)

    def to_config(self) -> RemoteConfig:
        return RemoteConfig(
            enabled=self.enabled_check.isChecked(),
            host=self.host_edit.text().strip(),
            port=self.port_spin.value(),
            user=self.user_edit.text().strip(),
            key_path=self.key_edit.text().strip(),
            remote_path=self.remote_path_edit.text().strip(),
            name=self.name_edit.text().strip(),
        )

    def _test_connection(self) -> None:
        config = self.to_config()
        if not config.is_configured():
            self.test_result.setText("Fill in host, user, and key path first.")
            self.test_result.setStyleSheet("color: #f0ad4e;")
            self.upload_btn.setEnabled(False)
            self.sync_btn.setEnabled(False)
            return
        target = Target(project=self.project, remote=config)
        self.test_result.setText("Testing…")
        self.test_result.setStyleSheet("color: #888888;")
        self.upload_btn.setEnabled(False)
        self.sync_btn.setEnabled(False)
        self.repaint()
        ok = target.is_reachable()
        if ok:
            # Purely informational -- never blocks the upload/sync buttons
            # below, since a brand new remote host legitimately has no
            # compose file yet until "Upload entire project to remote"
            # puts one there. remote_compose_file_exists() already knows
            # to look in remote_path + "/docker" for SIEM (same as
            # everything else here) -- Remote project path is just the
            # project root either way, not something that needs a manual
            # "/docker" suffix.
            if target.remote_compose_file_exists():
                self.test_result.setText("✓ Reachable (compose file found)")
                self.test_result.setStyleSheet("color: #5cb85c;")
            else:
                self.test_result.setText(
                    "✓ Reachable, but no docker-compose.yml found there yet "
                    "-- upload the project first (below), or double-check "
                    "Remote project path if you expected one already."
                )
                self.test_result.setStyleSheet("color: #f0ad4e;")
            self.upload_result.setText("")
            self.upload_btn.setEnabled(True)
            self.sync_result.setText("")
            self.sync_btn.setEnabled(True)
        else:
            self.test_result.setText("✗ Could not connect")
            self.test_result.setStyleSheet("color: #d9534f;")

    def _upload_env(self) -> None:
        config = self.to_config()
        local_path = _LOCAL_ENV_FILES[self.project]
        env_label = _PROJECT_ENV_LABELS[self.project]
        remote_env_path = Target(project=self.project, remote=config).remote_env_path()

        reply = QMessageBox.warning(
            self, "Confirm upload",
            f"This will overwrite {remote_env_path} on "
            f"{config.user}@{config.host} with the LOCAL {env_label} file "
            "(sent as-is, including secrets, over the SSH connection just "
            "tested).\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.upload_result.setText("Uploading…")
        self.upload_result.setStyleSheet("color: #888888;")
        self.repaint()

        try:
            upload_env(local_path, self.project, config)
        except EnvUploadError as e:
            self.upload_result.setText("✗ Upload failed")
            self.upload_result.setStyleSheet("color: #d9534f;")
            QMessageBox.warning(self, "Upload failed", str(e))
            return

        self.upload_result.setText("✓ Uploaded")
        self.upload_result.setStyleSheet("color: #5cb85c;")
        QMessageBox.information(
            self, "Uploaded",
            f"{env_label} uploaded to {config.host}:{remote_env_path}",
        )

    def _sync_project(self) -> None:
        config = self.to_config()
        dir_label = _PROJECT_DIR_LABELS[self.project]

        if shutil.which("rsync") is None:
            QMessageBox.warning(
                self, "rsync not found",
                "This feature needs the 'rsync' command installed on this "
                "machine (not the remote host).",
            )
            return

        self.sync_result.setText("Checking remote directory…")
        self.sync_result.setStyleSheet("color: #888888;")
        self.repaint()
        try:
            already_has_content = remote_dir_has_content(config)
        except ProjectUploadError as e:
            self.sync_result.setText("✗ Check failed")
            self.sync_result.setStyleSheet("color: #d9534f;")
            QMessageBox.warning(self, "Connection check failed", str(e))
            return

        if already_has_content:
            reply = QMessageBox.warning(
                self, "Remote directory not empty",
                f"{config.remote_path} on {config.host} already has files "
                f"in it. Syncing entire {dir_label} there will overwrite "
                "any file that differs (runtime data -- logs, backups, "
                "database volumes -- is excluded and left alone either "
                "way, but this can still overwrite manual changes made "
                "directly on the remote host).\n\nRewrite it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if reply != QMessageBox.StandardButton.Yes:
                self.sync_result.setText("")
                return

        local_dir = _LOCAL_PROJECT_DIRS[self.project]
        argv = build_rsync_argv(local_dir, config)

        self.sync_btn.setEnabled(False)
        self.sync_progress.setVisible(True)
        self.sync_progress.setValue(0)
        self.sync_result.setText("Syncing…")
        self.sync_result.setStyleSheet("color: #888888;")

        self._sync_process = QProcess(self)
        self._sync_process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._sync_process.readyReadStandardOutput.connect(self._on_sync_output)
        self._sync_process.finished.connect(self._on_sync_finished)
        self._sync_process.start(argv[0], argv[1:])

    def _on_sync_output(self) -> None:
        if self._sync_process is None:
            return
        data = bytes(self._sync_process.readAllStandardOutput()).decode(errors="replace")
        percent = parse_progress_percent(data)
        if percent is not None:
            self.sync_progress.setValue(percent)

    def _on_sync_finished(self, exit_code: int, _exit_status) -> None:
        self.sync_btn.setEnabled(True)
        if exit_code == 0:
            self.sync_progress.setValue(100)
            self.sync_result.setText("✓ Synced")
            self.sync_result.setStyleSheet("color: #5cb85c;")
        else:
            self.sync_result.setText(f"✗ Sync failed (rsync exit code {exit_code})")
            self.sync_result.setStyleSheet("color: #d9534f;")
        self._sync_process = None


class RemoteHostsWidget(QWidget):
    """A project's whole list of remote (SSH) hosts: zero or more
    RemoteConfigWidget forms, each boxed with its own "Remove host" button,
    plus an "Add host" button. Replaces the old single-remote-per-project
    form -- targets_for(project) drives the local stack plus every enabled
    host collected here."""

    def __init__(self, project: str, configs: list[RemoteConfig], parent=None):
        super().__init__(parent)
        self.project = project

        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)

        self._hosts_layout = QVBoxLayout()
        self._hosts_layout.setContentsMargins(0, 0, 0, 0)
        self._layout.addLayout(self._hosts_layout)

        self._empty_label = QLabel(
            "No remote hosts configured — this project runs on the local "
            "Docker stack only. Add one to drive it on another machine over "
            "SSH.")
        self._empty_label.setWordWrap(True)
        self._layout.addWidget(self._empty_label)

        add_row = QHBoxLayout()
        self.add_btn = QPushButton("Add host")
        self.add_btn.clicked.connect(lambda: self._add_host(RemoteConfig()))
        add_row.addWidget(self.add_btn)
        add_row.addStretch()
        self._layout.addLayout(add_row)

        # (group box, its form) pairs, in display/persist order.
        self._boxes: list[tuple[QGroupBox, RemoteConfigWidget]] = []
        for config in configs:
            self._add_host(config)

    def _add_host(self, config: RemoteConfig) -> None:
        box = QGroupBox()
        box_layout = QVBoxLayout(box)
        widget = RemoteConfigWidget(self.project, config, box)
        box_layout.addWidget(widget)

        remove_row = QHBoxLayout()
        remove_row.addStretch()
        remove_btn = QPushButton("Remove host")
        remove_btn.clicked.connect(lambda: self._remove_host(box))
        remove_row.addWidget(remove_btn)
        box_layout.addLayout(remove_row)

        # Keep the box title following whatever identifies the host, so a
        # list of several stays readable while being edited.
        def retitle(_=None) -> None:
            box.setTitle(widget.to_config().display_name)
        retitle()
        widget.name_edit.textChanged.connect(retitle)
        widget.host_edit.textChanged.connect(retitle)

        self._hosts_layout.addWidget(box)
        self._boxes.append((box, widget))
        self._update_empty()

    def _remove_host(self, box: QGroupBox) -> None:
        self._boxes = [(b, w) for (b, w) in self._boxes if b is not box]
        self._hosts_layout.removeWidget(box)
        box.setParent(None)
        box.deleteLater()
        self._update_empty()

    def _update_empty(self) -> None:
        self._empty_label.setVisible(not self._boxes)

    def to_configs(self) -> list[RemoteConfig]:
        """Every non-blank host row, in display order. A row the user added
        but left untouched is dropped rather than persisted as a phantom
        host (see RemoteConfig.is_empty)."""
        configs = [w.to_config() for (_b, w) in self._boxes]
        return [c for c in configs if not c.is_empty()]
