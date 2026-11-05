"""Connectors & Config page: every first-run wizard step, reachable anytime
-- either project's real .env file, remote (SSH) control, the deployment
choices (honeypot layer, honeypot-target routing, Apply to edge), host
kernel checks, security alerts, certificates -- plus export/import of the
whole configuration as one JSON bundle. The wizard's later steps and these
tabs are the same widgets (ui/setup_sections.py)."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFormLayout, QLabel, QMessageBox,
    QPushButton, QScrollArea, QSpinBox, QTabWidget, QVBoxLayout, QWidget,
)

from core.paths import (
    EDGE_ENV_EXAMPLE, EDGE_ENV_FILE, SIEM_ENV_EXAMPLE, SIEM_ENV_FILE,
)
from core.settings_bundle import BundleError, apply_bundle, export_bundle, read_bundle, write_bundle
from core.state import AppState, RemoteConfig
from ui import theme
from ui.common import set_status
from ui.edge_policy_bar import EdgePolicyBar, current_document
from ui.env_source_tab import EnvSourceTab
from ui.remote_config_widget import RemoteHostsWidget
from ui.setup_sections import (
    AlertsSection, CertsSection, DeploymentSection, HostChecksSection,
)

from ui.domain_reminder import DomainReminderBanner


class SettingsPage(QWidget):
    def __init__(self, state: AppState, on_state_changed, on_poll_interval_changed=None,
                 on_test_alert=None, edge_running=None, on_layer_changed=None, parent=None):
        super().__init__(parent)
        self.state = state
        self._on_state_changed = on_state_changed
        self._on_poll_interval_changed = on_poll_interval_changed
        self._on_test_alert = on_test_alert
        self._edge_running = edge_running          # callable -> bool (Workloads page)
        self._on_layer_changed = on_layer_changed  # callable(layer_id)

        layout = QVBoxLayout(self)
        self.domain_banner = DomainReminderBanner()
        layout.addWidget(self.domain_banner)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self._build_tabs()
        self.tabs.currentChanged.connect(self._on_tab_shown)

    def _on_tab_shown(self, index: int) -> None:
        widget = self.tabs.widget(index)
        if widget is self._deployment_tab:
            # The layer lock follows the Workloads page; the routing values
            # are also edited on the Honeypot Targets / URL Whitelist pages.
            self.deployment.reload()
        elif widget is self._host_checks_tab and not self._host_checked:
            self._host_checked = True
            self.host_checks.check()

    def _build_tabs(self) -> None:
        """(Re)builds every tab from scratch, reading .env files fresh
        from disk. Called from __init__ and again after a successful
        Import, since the previously-displayed editors/widgets would
        otherwise keep showing pre-import values."""
        self.tabs.clear()

        self.tabs.addTab(self._build_general_tab(), "General")
        self._deployment_tab = self._build_deployment_tab()
        self.tabs.addTab(self._deployment_tab, "Deployment")
        self.alerts_section = AlertsSection(self.state, self._on_test_alert)
        self.tabs.addTab(self._scrolled(self.alerts_section), "Alerts")

        # Each .env tab has its own Local/Remote toggle (only enabled once
        # that project's remote connection is configured) -- get_remote_config
        # is a callable, not a snapshot, so it always reflects whatever the
        # remote tabs below currently hold, including after they're saved.
        self.edge_env_tab = EnvSourceTab(
            "edge", EDGE_ENV_FILE, EDGE_ENV_EXAMPLE,
            lambda: self.state.primary_remote("edge") or RemoteConfig(),
        )
        self.tabs.addTab(self.edge_env_tab, "ids .env")

        self.siem_env_tab = EnvSourceTab(
            "siem", SIEM_ENV_FILE, SIEM_ENV_EXAMPLE,
            lambda: self.state.primary_remote("siem") or RemoteConfig(),
        )
        self.tabs.addTab(self.siem_env_tab, "siem .env")

        self.edge_remote_widget = RemoteHostsWidget("edge", self.state.remotes_for("edge"))
        edge_remote_tab = self._wrap_with_save(self._scrolled(self.edge_remote_widget), self._save_edge_remote)
        self.tabs.addTab(edge_remote_tab, "ids remote (SSH)")

        self.siem_remote_widget = RemoteHostsWidget("siem", self.state.remotes_for("siem"))
        siem_remote_tab = self._wrap_with_save(self._scrolled(self.siem_remote_widget), self._save_siem_remote)
        self.tabs.addTab(siem_remote_tab, "siem remote (SSH)")

        self.host_checks = HostChecksSection(self.state)
        self._host_checks_tab = self._scrolled(self.host_checks)
        self._host_checked = False
        self.tabs.addTab(self._host_checks_tab, "Host checks")
        self.certs_section = CertsSection()
        self.tabs.addTab(self._scrolled(self.certs_section), "Certificates")

        self.tabs.addTab(self._build_export_import_tab(), "Export / Import")

    def _build_general_tab(self) -> QWidget:
        container = QWidget()
        form = QFormLayout(container)

        self.theme_combo = QComboBox()
        for value in theme.THEMES:
            self.theme_combo.addItem(theme.THEME_LABELS[value], value)
        self.theme_combo.setCurrentIndex(max(0, theme.THEMES.index(self.state.theme)))
        self.theme_combo.currentIndexChanged.connect(self._on_theme_combo_changed)
        form.addRow("Theme:", self.theme_combo)

        self.poll_interval_spin = QSpinBox()
        self.poll_interval_spin.setRange(1, 300)
        self.poll_interval_spin.setSuffix(" s")
        self.poll_interval_spin.setValue(max(1, round(self.state.poll_interval_ms / 1000)))
        self.poll_interval_spin.valueChanged.connect(self._on_poll_interval_spin_changed)
        form.addRow("Status refresh interval:", self.poll_interval_spin)

        self.tray_notif_check = QCheckBox(
            "Notify when a container errors (unhealthy / exited with an error)")
        self.tray_notif_check.setChecked(self.state.tray_notifications_enabled)
        self.tray_notif_check.toggled.connect(self._on_tray_notif_toggled)
        form.addRow("Desktop notifications:", self.tray_notif_check)

        self.honeypot_notif_check = QCheckBox(
            "Notify when the honeypot receives a visitor")
        self.honeypot_notif_check.setChecked(self.state.honeypot_notifications_enabled)
        self.honeypot_notif_check.toggled.connect(self._on_honeypot_notif_toggled)
        form.addRow("", self.honeypot_notif_check)

        notif_note = QLabel(
            "Desktop notifications use the operating system's tray/notification "
            "area, so they appear even when this window is in the background. "
            "They are silently unavailable on a host without a system tray. "
            "Richer security alerting (severity thresholds, cooldown, webhook) "
            "lives on the Alerts tab."
        )
        notif_note.setWordWrap(True)
        form.addRow("", notif_note)

        note = QLabel(
            "Lower the refresh interval for a snappier topology map; "
            "raise it to reduce SSH round-trips against a remote target on "
            "a slow link. Takes effect immediately, no restart needed."
        )
        note.setWordWrap(True)
        form.addRow(note)

        return container

    @staticmethod
    def _scrolled(widget: QWidget) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        v = QVBoxLayout(body)
        v.addWidget(widget)
        v.addStretch(1)
        scroll.setWidget(body)
        return scroll

    def _build_deployment_tab(self) -> QWidget:
        container = QWidget()
        v = QVBoxLayout(container)
        self.deployment = DeploymentSection(self.state, self._edge_running)
        if self._on_layer_changed:
            self.deployment.layer_changed.connect(self._on_layer_changed)
        v.addWidget(self.deployment)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self._save_deployment)
        v.addWidget(save_btn)
        self.deployment_status = QLabel("")
        self.deployment_status.setWordWrap(True)
        v.addWidget(self.deployment_status)
        self.policy_bar = EdgePolicyBar(self.state, current_document)
        v.addWidget(self.policy_bar)
        v.addWidget(self.policy_bar.error_banner)
        v.addStretch(1)
        return self._scrolled(container)

    def _save_deployment(self) -> None:
        try:
            summary = self.deployment.save()
        except OSError as e:
            QMessageBox.warning(self, "Save failed", f"Could not save the edge policy: {e}")
            return
        set_status(self.deployment_status,
                   f"Saved ({summary}). Apply to edge to push the routing to a running edge; "
                   "a freshly started edge without a policy gets it automatically.")
        self.policy_bar.refresh_sync()

    def _on_poll_interval_spin_changed(self, seconds: int) -> None:
        interval_ms = seconds * 1000
        if self._on_poll_interval_changed:
            self._on_poll_interval_changed(interval_ms)
        else:
            self.state.poll_interval_ms = interval_ms
            self.state.save()

    def _on_tray_notif_toggled(self, checked: bool) -> None:
        self.state.tray_notifications_enabled = checked
        self.state.save()

    def _on_honeypot_notif_toggled(self, checked: bool) -> None:
        self.state.honeypot_notifications_enabled = checked
        self.state.save()

    def _on_theme_combo_changed(self, index: int) -> None:
        value = self.theme_combo.itemData(index)
        self.state.theme = value
        self.state.save()
        theme.apply_theme(value)

    def _wrap_with_save(self, widget: QWidget, save_fn) -> QWidget:
        container = QWidget()
        v = QVBoxLayout(container)
        v.addWidget(widget, stretch=1)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(save_fn)
        v.addWidget(save_btn)
        return container

    def _save_edge_remote(self) -> None:
        self.state.set_remotes("edge", self.edge_remote_widget.to_configs())
        self.state.save()
        self._on_state_changed()
        self.edge_env_tab.refresh_remote_availability()
        n = len(self.state.remotes_for("edge"))
        QMessageBox.information(self, "Saved", f"{n} remote host(s) saved for ids.")

    def _save_siem_remote(self) -> None:
        self.state.set_remotes("siem", self.siem_remote_widget.to_configs())
        self.state.save()
        self._on_state_changed()
        self.siem_env_tab.refresh_remote_availability()
        n = len(self.state.remotes_for("siem"))
        QMessageBox.information(self, "Saved", f"{n} remote host(s) saved for siem.")

    # ---- Export / Import ----

    def _build_export_import_tab(self) -> QWidget:
        container = QWidget()
        v = QVBoxLayout(container)

        info = QLabel(
            "Back up or restore both projects' .env values, remote (SSH) "
            "target settings and the deployment choices (honeypot layer, alert "
            "policy, honeypot-target routing and URL whitelist) as a single JSON file -- useful before a "
            "risky change, or to move this setup to a fresh checkout of "
            "the repo instead of re-typing everything by hand.\n\n"
            "⚠ The exported file contains real secrets in plaintext "
            "(database/Redis passwords, API keys, the remote SSH key "
            "path -- not the key file's contents, just its path). Store "
            "it securely and never commit it to version control.\n\n"
            "Import only changes keys present in the file -- other "
            "existing .env keys and all comments are left exactly as "
            "they are (same comment-preserving editor this whole app "
            "uses). Remote (SSH) settings for each project present in "
            "the file are replaced entirely."
        )
        info.setWordWrap(True)
        v.addWidget(info)

        export_btn = QPushButton("Export settings…")
        export_btn.clicked.connect(self._export_settings)
        v.addWidget(export_btn)

        import_btn = QPushButton("Import settings…")
        import_btn.clicked.connect(self._import_settings)
        v.addWidget(import_btn)

        v.addStretch()
        return container

    def _export_settings(self) -> None:
        default_name = f"honeypot-dashboard-export-{datetime.now():%Y%m%d_%H%M%S}.json"
        path_str, _ = QFileDialog.getSaveFileName(self, "Export settings", default_name, "JSON files (*.json)")
        if not path_str:
            return

        try:
            bundle = export_bundle(self.state)
            write_bundle(Path(path_str), bundle)
        except OSError as e:
            QMessageBox.warning(self, "Export failed", str(e))
            return

        QMessageBox.information(
            self, "Exported",
            f"Settings exported to:\n\n{path_str}\n\n"
            "Remember: this file contains real secrets in plaintext -- "
            "store it securely.",
        )

    def _import_settings(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(self, "Import settings", "", "JSON files (*.json)")
        if not path_str:
            return

        reply = QMessageBox.warning(
            self, "Confirm import",
            "This will overwrite matching keys in both projects' real "
            ".env files and replace both remote (SSH) settings, the honeypot "
            "layer, alert policy and edge policy with whatever is in this file.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            bundle = read_bundle(Path(path_str))
            notes = apply_bundle(bundle, self.state)
        except BundleError as e:
            QMessageBox.warning(self, "Import failed", str(e))
            return

        self._on_state_changed()
        self._build_tabs()
        QMessageBox.information(self, "Imported", "\n".join(notes))
