"""Setup sections shared by the first-run wizard (ui/wizard.py) and the
Settings page (ui/page_settings.py), so every setting a user needs to set up
the platform is reachable in both places from ONE implementation:

  SecretTools        -- bulk-generate weak secrets, restore a .env backup,
                        warn about placeholders, back up on save (.env editors)
  DeploymentSection  -- honeypot layer, what a honeypot-target hit does, the
                        unlisted-path score
  HostChecksSection  -- kernel settings the stacks need on their hosts
  AlertsSection      -- security alerts (desktop / webhook)
  CertsSection       -- generate the SIEM CA + service certs and the edge cert
  setup_summary()    -- what is still unfinished, for the wizard's last page

The bigger security pages (URL Whitelist, Honeypot Targets, Container
Firewall, Detection Policy) keep their own pages; they start from safe
defaults and the sections here point to them.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QButtonGroup, QCheckBox, QComboBox, QFormLayout, QHBoxLayout, QInputDialog, QLabel,
    QLineEdit, QMessageBox, QPushButton, QRadioButton, QSpinBox, QVBoxLayout, QWidget,
)

from core import alert_policy, edge_policy, env_secrets, honeypot_layer
from core.detection_policy import HONEYPOT_THRESHOLD
from core.env_file import EnvFile
from core.state import AppState
from ui.common import muted_label, set_status
from ui.env_editor import looks_like_secret


# ---- .env secret hygiene ---------------------------------------------------

class SecretTools(QWidget):
    """Buttons + warning line under a .env editor. The host (EnvSourceTab or
    the wizard's .env page) supplies callables, so this never holds a stale
    EnvFile: get_env_file() -> the EnvFile being edited, apply_form() copies
    the form into it, rebuild() redraws the form from it, reload_local()
    re-reads the local file. Secret values are never shown: messages name
    keys only."""

    def __init__(self, project: str, local_path: Path, example: Path,
                 get_env_file: Callable[[], EnvFile | None], apply_form: Callable[[], None],
                 rebuild: Callable[[], None], reload_local: Callable[[], None], parent=None):
        super().__init__(parent)
        self.project = project
        self.local_path = local_path
        self.example = example
        self._get_env_file = get_env_file
        self._apply_form = apply_form
        self._rebuild = rebuild
        self._reload_local = reload_local
        # The generation rules know the ids stack's secrets only.
        self.generates = project == "edge"
        self._remote = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.generate_btn = QPushButton("Generate weak secrets")
        self.generate_btn.setToolTip(
            "Fill every secret that is missing, a placeholder, the .env.example value "
            "or too short with a strong random value (database passwords, Redis, salts, "
            "signing keys, admin passwords, GDPR key). Values stay hidden; save to "
            "write them, then Redeploy on the Workloads page.")
        self.generate_btn.clicked.connect(self.generate)
        self.generate_btn.setVisible(self.generates)
        row.addWidget(self.generate_btn)
        self.restore_btn = QPushButton("Restore backup…")
        self.restore_btn.setToolTip(
            "Put a .env.bak.* backup back as the local .env (the current file is "
            "backed up first).")
        self.restore_btn.clicked.connect(self.restore)
        row.addWidget(self.restore_btn)
        row.addStretch()
        layout.addLayout(row)

        self.warning_label = QLabel("")
        self.warning_label.setWordWrap(True)
        self.warning_label.setStyleSheet("color: #e0a800;")
        self.warning_label.setVisible(False)
        layout.addWidget(self.warning_label)

    def set_remote(self, remote: bool) -> None:
        """Backups exist for the local file only."""
        self._remote = remote
        self.restore_btn.setEnabled(not remote)

    def warnings(self) -> list[str]:
        env = self._get_env_file()
        if not self.generates or env is None:
            return []
        return env_secrets.config_warnings(env, self.example)

    def update_warnings(self) -> None:
        warnings = self.warnings()
        self.warning_label.setText("\n".join(f"⚠ {w}" for w in warnings))
        self.warning_label.setVisible(bool(warnings))

    def generate(self) -> None:
        """Replace every weak secret in the form (not on disk until saved)."""
        self._apply_form()
        env = self._get_env_file()
        try:
            plan = env_secrets.secret_plan(env, self.example)
        except Exception as e:  # noqa: BLE001 -- e.g. openssl missing for the GDPR key
            QMessageBox.warning(self, "Generate weak secrets", f"Could not generate secrets: {e}")
            return
        if not plan:
            QMessageBox.information(self, "Generate weak secrets",
                                    "Every secret is already strong -- nothing to change.")
            return
        for key, value in plan.items():
            env.set(key, value)
        self._rebuild()
        generated = [k for k, v in plan.items() if v]
        cleared = [k for k, v in plan.items() if not v]
        text = ""
        if generated:
            text += "Generated: " + ", ".join(generated) + "\n\n"
        if cleared:
            text += ("Cleared (placeholder external credential, that integration is "
                     "now off until you enter a real one): " + ", ".join(cleared) + "\n\n")
        QMessageBox.information(
            self, "Generate weak secrets",
            text + "Not written yet: save to write them (the current file is backed up "
            "first). On a running stack, then use Redeploy on the Workloads page so every "
            "container -- databases included -- switches to the new values. Everyone gets "
            "logged out.")

    def restore(self) -> None:
        backups = env_secrets.list_backups(self.local_path)
        if not backups:
            QMessageBox.information(self, "Restore backup",
                                    f"No .env.bak.* backups next to {self.local_path}.")
            return
        name, ok = QInputDialog.getItem(
            self, "Restore backup", f"Replace {self.local_path} with (newest first):",
            [b.name for b in backups], 0, False)
        if not ok:
            return
        try:
            previous = env_secrets.restore(self.local_path, self.local_path.parent / name)
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Restore backup", f"Restore failed: {e}")
            return
        self._reload_local()
        QMessageBox.information(
            self, "Restore backup",
            f"Restored {name}."
            + (f" The file it replaced was saved as {previous.name}." if previous else "")
            + "\n\nRunning containers still use whatever they were started with: "
              "Redeploy on the Workloads page to apply it.")

    def changed_secrets(self) -> list[str]:
        """Secret keys whose value in the edited file differs from the local file."""
        env = self._get_env_file()
        if env is None or not self.local_path.exists():
            return []
        disk = EnvFile.load(self.local_path)
        return [k for k in env.keys()
                if looks_like_secret(k) and k in disk.keys() and disk.get(k) != env.get(k)]

    def save_local(self) -> str | None:
        """Write the edited file locally (0600), backing the old one up first
        when a secret changed. Returns a note for the user, or None when the
        user cancelled after a failed backup."""
        changed = self.changed_secrets()
        note = ""
        if changed:
            try:
                note = f"\n\nPrevious file backed up as {env_secrets.backup(self.local_path).name}."
            except OSError as e:
                if QMessageBox.question(
                        self, "Backup failed",
                        f"Could not back up the current .env ({e}). Save anyway?",
                ) != QMessageBox.StandardButton.Yes:
                    return None
            note += (f"\nChanged secrets: {', '.join(changed)}. If the stack is running, "
                     "Redeploy on the Workloads page to apply them (databases switch their "
                     "passwords on that restart).")
        env = self._get_env_file()
        env.save()
        os.chmod(self.local_path, 0o600)   # it holds every credential of the stack
        self.update_warnings()
        return note

    def confirm_weak(self) -> bool:
        """Before leaving the wizard page: True to go on. Weak secrets get one
        chance to be generated; any other warning is only shown."""
        self._apply_form()
        warnings = self.warnings()
        if not warnings:
            return True
        env = self._get_env_file()
        if env is not None and env_secrets.weak_secrets(env, self.example):
            answer = QMessageBox.question(
                self, "Weak secrets",
                "\n\n".join(warnings) + "\n\nGenerate strong values for the weak secrets now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                | QMessageBox.StandardButton.Cancel)
            if answer == QMessageBox.StandardButton.Cancel:
                return False
            if answer == QMessageBox.StandardButton.Yes:
                self.generate()
            return True
        return QMessageBox.question(
            self, "Unfinished settings",
            "\n\n".join(warnings) + "\n\nContinue anyway? (They stay listed here and in "
            "Settings → ids .env.)") == QMessageBox.StandardButton.Yes


# ---- deployment ------------------------------------------------------------

class DeploymentSection(QWidget):
    """Honeypot layer + honeypot-target routing. save() writes both; the
    layer goes to AppState (and core.honeypot_layer), the routing to
    patterns/edge_policy.json -- the same file the Honeypot Targets and URL
    Whitelist pages edit."""
    layer_changed = pyqtSignal(str)

    def __init__(self, state: AppState, edge_running: Callable[[], bool] | None = None, parent=None):
        super().__init__(parent)
        self.state = state
        self._edge_running = edge_running or (lambda: False)
        form = QFormLayout(self)

        self.layer_combo = QComboBox()
        for layer in honeypot_layer.LAYERS.values():
            self.layer_combo.addItem(layer.label, layer.id)
        form.addRow("Honeypot layer:", self.layer_combo)
        self.layer_note = muted_label(
            "WordPress proxy level: suspicious sessions are routed to separate honeypot "
            "WordPress containers (recommended). Database proxy level: one eshop serves "
            "everything and only the database is switched per request (isolates "
            "database-layer attacks only, see ids/db_proxy/COVERAGE.md).")
        form.addRow(self.layer_note)

        self.direct_radio = QRadioButton("Auto-send to honeypot (scoring bypassed)")
        self.score_radio = QRadioButton("Score it first, divert at the threshold")
        group = QButtonGroup(self)
        group.addButton(self.direct_radio)
        group.addButton(self.score_radio)
        mode_box = QVBoxLayout()
        mode_box.addWidget(self.direct_radio)
        mode_box.addWidget(self.score_radio)
        form.addRow("Honeypot-target hit:", mode_box)

        self.target_score = QSpinBox()
        self.target_score.setRange(0, edge_policy.MAX_SCORE)
        self.target_score.setSuffix(" pts")
        form.addRow("Target score:", self.target_score)

        self.unlisted_score = QSpinBox()
        self.unlisted_score.setRange(0, edge_policy.MAX_SCORE)
        self.unlisted_score.setSuffix(" pts")
        self.unlisted_score.setSpecialValueText("0 (inventory only)")
        form.addRow("Unlisted-path score:", self.unlisted_score)

        form.addRow(muted_label(
            f"A request is diverted to a honeypot once its score reaches {HONEYPOT_THRESHOLD}. "
            "Target score is added per CVE match / vulnerable-plugin hit in score-first mode; "
            "unlisted-path score is added for any path not on the URL whitelist. Which CVE "
            "targets and whitelist entries are on (generic exploits only by default) is set "
            "on the Honeypot Targets and URL Whitelist pages; the container firewall and "
            "detection thresholds on their own pages. The edge picks this up when the policy "
            "is applied -- automatically on its first start, or with Apply to edge."))

        self.direct_radio.toggled.connect(lambda checked: self.target_score.setEnabled(not checked))
        self.reload()

    def reload(self) -> None:
        # From state: the first-run wizard runs before MainWindow activates it.
        self.layer_combo.setCurrentIndex(max(0, self.layer_combo.findData(self.state.honeypot_layer)))
        running = self._edge_running()
        self.layer_combo.setEnabled(not running)
        self.layer_combo.setToolTip("Stop the ids stack to change the layer" if running else "")
        settings = edge_policy.EdgePolicySettings.load()
        self.direct_radio.setChecked(settings.mode == "direct")
        self.score_radio.setChecked(settings.mode != "direct")
        self.target_score.setValue(settings.target_score)
        self.target_score.setEnabled(settings.mode != "direct")
        self.unlisted_score.setValue(settings.unlisted_score)

    def save(self) -> str:
        """Returns a one-line summary. Raises OSError when the policy file
        can't be written."""
        settings = edge_policy.EdgePolicySettings.load()
        settings.mode = "direct" if self.direct_radio.isChecked() else "score"
        settings.target_score = self.target_score.value()
        settings.unlisted_score = self.unlisted_score.value()
        settings.save()
        new_layer = self.layer_combo.currentData()
        if new_layer != self.state.honeypot_layer or new_layer != honeypot_layer.active().id:
            honeypot_layer.set_active(new_layer)
            self.state.honeypot_layer = new_layer
            self.state.save()
            self.layer_changed.emit(new_layer)
        return (f"{honeypot_layer.layer(new_layer).short_label}, "
                + ("auto-send" if settings.mode == "direct" else "score-first")
                + " for honeypot targets")


# ---- host kernel settings --------------------------------------------------

class HostChecksSection(QWidget):
    """Runs the same check as the main window's host-settings banner on
    demand and always says the outcome (the banner only appears on a
    problem)."""

    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        from ui.host_settings_banner import HostSettingsBanner
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.status = QLabel("")
        self.status.setWordWrap(True)
        row.addWidget(self.status, stretch=1)
        self.check_btn = QPushButton("Check host settings")
        self.check_btn.setToolTip(
            "Redis needs vm.overcommit_memory=1 on the ids host, Elasticsearch "
            "vm.max_map_count ≥ 262144 on the SIEM host (checked over SSH for remote hosts).")
        self.check_btn.clicked.connect(self.check)
        row.addWidget(self.check_btn)
        layout.addLayout(row)
        self.banner = HostSettingsBanner(state, auto=False)
        self.banner.checked.connect(self._on_checked)
        layout.addWidget(self.banner)

    def check(self) -> None:
        set_status(self.status, "checking…")
        self.banner.refresh()

    def _on_checked(self, problem_hosts: int) -> None:
        if problem_hosts:
            set_status(self.status, f"{problem_hosts} host(s) need a kernel setting -- see below.",
                       color="#e0a800")
        else:
            set_status(self.status, "Host kernel settings OK on every host in use.", color="#5cb85c")


# ---- alerts ----------------------------------------------------------------

class AlertsSection(QWidget):
    """Security-alert policy (core/alert_policy.py); every change saves at once."""

    def __init__(self, state: AppState, on_test_alert: Callable[[], None] | None = None, parent=None):
        super().__init__(parent)
        self.state = state
        self._on_test_alert = on_test_alert
        policy = alert_policy.AlertPolicy.from_dict(state.alert_policy)
        form = QFormLayout(self)

        self.alert_enabled = QCheckBox("Raise alerts for security events")
        self.alert_enabled.setChecked(policy.enabled)
        form.addRow("", self.alert_enabled)

        self.alert_severity = QComboBox()
        self.alert_severity.addItem("Medium and above", "medium")
        self.alert_severity.addItem("High only", "high")
        self.alert_severity.setCurrentIndex(alert_policy.MIN_SEVERITIES.index(policy.min_severity))
        form.addRow("Minimum severity:", self.alert_severity)

        self.alert_diversion = QCheckBox("Always alert when a session is diverted to the honeypot")
        self.alert_diversion.setChecked(policy.on_diversion)
        form.addRow("", self.alert_diversion)

        self.alert_score = QSpinBox()
        self.alert_score.setRange(0, 100)
        self.alert_score.setSpecialValueText("off")
        self.alert_score.setValue(policy.score_threshold)
        form.addRow("Alert at risk score ≥:", self.alert_score)

        self.alert_cooldown = QSpinBox()
        self.alert_cooldown.setRange(0, 3600)
        self.alert_cooldown.setSuffix(" s")
        self.alert_cooldown.setValue(policy.cooldown_seconds)
        form.addRow("Repeat suppression:", self.alert_cooldown)

        self.alert_desktop = QCheckBox("Desktop notification (system tray)")
        self.alert_desktop.setChecked(policy.desktop)
        form.addRow("", self.alert_desktop)

        self.alert_webhook = QLineEdit(policy.webhook_url)
        self.alert_webhook.setPlaceholderText("https://hooks.slack.com/… or any endpoint accepting a JSON POST")
        form.addRow("Webhook URL:", self.alert_webhook)

        test_btn = QPushButton("Send test alert")
        test_btn.clicked.connect(self._send_test_alert)
        form.addRow("", test_btn)

        form.addRow(muted_label(
            "Container-health notifications are separate (Settings → General). "
            "Changes apply immediately."))

        for widget, signal in ((self.alert_enabled, "toggled"), (self.alert_severity, "currentIndexChanged"),
                               (self.alert_diversion, "toggled"), (self.alert_score, "valueChanged"),
                               (self.alert_cooldown, "valueChanged"), (self.alert_desktop, "toggled"),
                               (self.alert_webhook, "editingFinished")):
            getattr(widget, signal).connect(self.save)

    def save(self, *_args) -> None:
        self.state.alert_policy = alert_policy.AlertPolicy(
            enabled=self.alert_enabled.isChecked(), min_severity=self.alert_severity.currentData(),
            on_diversion=self.alert_diversion.isChecked(), score_threshold=self.alert_score.value(),
            cooldown_seconds=self.alert_cooldown.value(), desktop=self.alert_desktop.isChecked(),
            webhook_url=self.alert_webhook.text().strip()).to_dict()
        self.state.save()

    def _send_test_alert(self) -> None:
        self.save()
        if self._on_test_alert:
            self._on_test_alert()
        url = self.state.alert_policy.get("webhook_url", "")
        if url:
            error = alert_policy.send_webhook(
                url, alert_policy.webhook_payload("Test alert", "from the dashboard", "high", None, 0))
            QMessageBox.information(self, "Webhook test", "Webhook delivered." if not error
                                    else f"Webhook failed: {error}")


# ---- certificates ----------------------------------------------------------

class CertsSection(QWidget):
    """"Generate all certificates" (SIEM CA + service certs, edge nginx cert).
    Runs through CertWorker (a QThread): RSA key generation can block on
    entropy long enough to look like a hang if run on the GUI thread."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(muted_label(
            "Generate the SIEM CA + service certs and the edge nginx SSL cert. The PKI & "
            "Certificates page shows each certificate and regenerates them one at a time."))
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.generate_btn = QPushButton("Generate all certificates now")
        self.generate_btn.clicked.connect(self.generate_all)
        layout.addWidget(self.generate_btn)
        layout.addStretch()
        self._queue: list[str] = []
        self._worker = None
        self._lines: list[str] = []

    def generate_all(self) -> None:
        self.generate_btn.setEnabled(False)
        self._lines = []
        self.status_label.setText("Generating…")
        self._queue = ["siem-all", "edge-nginx"]
        self._run_next_in_queue()

    def _run_next_in_queue(self) -> None:
        from ui.page_certs import CertWorker
        if not self._queue:
            self.status_label.setText("\n".join(self._lines) + "\n\nDone.")
            self.generate_btn.setEnabled(True)
            return
        self._worker = CertWorker(self._queue.pop(0))
        self._worker.line.connect(self._on_line)
        self._worker.done.connect(self._on_step_done)
        self._worker.start()

    def _on_line(self, msg: str) -> None:
        self._lines.append(msg.rstrip("\n"))
        self.status_label.setText("\n".join(self._lines))

    def _on_step_done(self, success: bool, message: str) -> None:
        if not success:
            self._lines.append(f"Failed: {message}")
            self.status_label.setText("\n".join(self._lines))
            self.generate_btn.setEnabled(True)
            self._queue.clear()
            QMessageBox.warning(self, "Certificate generation failed", message)
            return
        self._run_next_in_queue()


# ---- summary ---------------------------------------------------------------

def setup_summary(state: AppState) -> list[str]:
    """What is still unfinished, for the wizard's last page: the ids .env
    warnings (read over SSH when the ids stack is remote) and missing
    certificates. Key names only, never values."""
    from core.env_upload import EnvUploadError, load_project_env
    from core.paths import EDGE_ENV_EXAMPLE, EDGE_SSL_CERT_DIR
    remote = state.primary_remote("edge")
    out = []
    try:
        env = load_project_env("edge", remote, timeout=10.0)
        out += [f"ids .env: {w}" for w in env_secrets.config_warnings(env, EDGE_ENV_EXAMPLE)]
    except EnvUploadError as e:
        out.append(f"Could not read the remote ids .env to check it: {e}")
    if remote is None and not any(EDGE_SSL_CERT_DIR.glob("*.crt")) and not any(EDGE_SSL_CERT_DIR.glob("*.pem")):
        out.append("No edge SSL certificate yet: generate one on the Certificates step "
                   "(or Settings → Certificates).")
    return out
