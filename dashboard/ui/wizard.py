"""First-run setup wizard: everything a user needs to set the platform up,
in order -- dependencies, remote SSH control, both projects' .env files
(with weak-secret generation and backups for the ids one), the deployment
choices (honeypot layer, what a honeypot-target hit does, host kernel
settings), security alerts and certificates -- then a summary of anything
still unfinished and an option to start the stacks. Re-runnable anytime
from the menu; it loads existing values rather than blanking them. Every
step after the .env pages is the same widget as its Settings tab
(ui/setup_sections.py), so the two can't drift apart.
"""
from __future__ import annotations

from pathlib import Path

from typing import Callable

from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QMessageBox, QScrollArea, QVBoxLayout,
    QWidget,
    QWizard, QWizardPage,
)

from core.docker_ctl import Target
from core.env_file import EnvFile, merge_example_keys, seed_from_example
from core.env_upload import EnvUploadError, download_env_text, upload_env_text
from core.paths import (
    EDGE_ENV_EXAMPLE, EDGE_ENV_FILE, SIEM_ENV_EXAMPLE, SIEM_ENV_FILE,
)
from core.state import AppState, RemoteConfig
from ui.dependency_banner import DependencyBanner
from ui.env_editor import EnvEditorWidget
from ui.remote_config_widget import RemoteHostsWidget
from ui.setup_sections import (
    AlertsSection, CertsSection, DeploymentSection, HostChecksSection, SecretTools,
    setup_summary,
)

# Page IDs, module-level (not SetupWizard class attributes) so both the
# wizard itself and WizardTimeline's step list can reference them without
# an import-order/forward-reference problem.
(PAGE_WELCOME, PAGE_REMOTE, PAGE_EDGE_ENV, PAGE_SIEM_ENV, PAGE_DEPLOYMENT, PAGE_ALERTS,
 PAGE_CERTS, PAGE_FINISH) = range(8)

# Fixed step labels, in wizard order. Every run visits every page, in this
# order -- a project marked remote no longer skips its .env page; that
# page instead fetches and edits the .env directly on the remote host
# (see RemoteAwareEnvPage). WizardTimeline appends "(remote)" to the
# Edge/SIEM .env labels when that project is remote-enabled.
_STEP_LABELS = {
    PAGE_WELCOME: "Welcome",
    PAGE_REMOTE: "Remote/Local",
    PAGE_EDGE_ENV: "Edge .env",
    PAGE_SIEM_ENV: "SIEM .env",
    PAGE_DEPLOYMENT: "Deployment",
    PAGE_ALERTS: "Alerts",
    PAGE_CERTS: "Certificates",
    PAGE_FINISH: "Done",
}
_STEP_ORDER = (PAGE_WELCOME, PAGE_REMOTE, PAGE_EDGE_ENV, PAGE_SIEM_ENV, PAGE_DEPLOYMENT,
               PAGE_ALERTS, PAGE_CERTS, PAGE_FINISH)


def visible_steps() -> list[tuple[int, str]]:
    """The full, fixed step list -- every wizard run visits every page."""
    return [(pid, _STEP_LABELS[pid]) for pid in _STEP_ORDER]


class WizardTimeline(QWidget):
    """Step-indicator row shown at the top of every wizard page: all steps
    that will actually be visited (see visible_steps()), with completed
    steps checked off, the current one highlighted, and remaining ones
    dimmed. Rebuilt via refresh() on every page show (TimelineMixin calls
    this from initializePage(), which Qt calls on every visit including
    Back navigation) since the skip-aware step list can change mid-run.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._row = QHBoxLayout(self)
        self._row.setContentsMargins(0, 0, 0, 10)

    def refresh(self, state: AppState, current_id: int) -> None:
        while self._row.count():
            item = self._row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        steps = visible_steps()
        current_index = next((i for i, (pid, _label) in enumerate(steps) if pid == current_id), None)

        for i, (pid, label) in enumerate(steps):
            if pid == PAGE_EDGE_ENV and state.primary_remote("edge") is not None:
                label = f"{label} (remote)"
            elif pid == PAGE_SIEM_ENV and state.primary_remote("siem") is not None:
                label = f"{label} (remote)"

            if current_index is not None and i < current_index:
                text, style = f"✓ {label}", "color: #5cb85c;"
            elif pid == current_id:
                text, style = f"● {label}", f"color: {self._current_step_text_color()}; font-weight: bold;"
            else:
                text, style = label, "color: #888888;"

            lbl = QLabel(text)
            lbl.setStyleSheet(style)
            self._row.addWidget(lbl)

            if i < len(steps) - 1:
                arrow = QLabel("→")
                arrow.setStyleSheet("color: #555555;")
                self._row.addWidget(arrow)

        self._row.addStretch()

    def _current_step_text_color(self) -> str:
        """Black on a light background, white on a dark one. Was hardcoded
        white -- unreadable (white-on-light) on a light system/Qt theme,
        confirmed live. Reads the widget's own actual effective palette
        rather than assuming either theme, so it's correct regardless of
        OS light/dark mode or a custom app stylesheet."""
        bg = self.palette().color(QPalette.ColorRole.Window)
        # Perceived-brightness formula (ITU-R BT.601), 0-255 scale.
        brightness = (bg.red() * 299 + bg.green() * 587 + bg.blue() * 114) / 1000
        return "#000000" if brightness > 128 else "#ffffff"


class TimelineMixin:
    """Mixed into every QWizardPage below. _init_timeline() inserts a
    WizardTimeline as the first item in the page's own layout; Qt calls
    initializePage() every time a page is shown (including via Back
    navigation), which is what keeps the highlighted step correct if the
    user goes back and changes the remote/local choice."""

    def _init_timeline(self, layout: QVBoxLayout) -> None:
        self._timeline = WizardTimeline()
        layout.addWidget(self._timeline)

    def initializePage(self) -> None:
        wiz = self.wizard()
        timeline = getattr(self, "_timeline", None)
        if wiz is not None and timeline is not None:
            timeline.refresh(wiz.state, wiz.currentId())
        super().initializePage()


class WelcomePage(TimelineMixin, QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Welcome")
        layout = QVBoxLayout(self)
        self._init_timeline(layout)

        # Checked here first, before the user sinks time into filling out
        # .env forms, since nothing past this page works without docker/
        # docker compose -- also shown persistently in the main window
        # (see MainWindow's own DependencyBanner) for anyone who skips or
        # re-runs just part of the wizard.
        self.dependency_banner = DependencyBanner()
        layout.addWidget(self.dependency_banner)

        label = QLabel(
            "This wizard walks through everything the platform needs: remote "
            "SSH control (optional), the .env files of both compose projects "
            "(ids and siem) with strong generated secrets, the deployment "
            "choices (honeypot layer, how honeypot-target traffic is handled, "
            "host kernel settings), security alerts and certificates. The "
            "last step lists anything still unfinished and can start the stacks.\n\n"
            "Every step is also a tab under Settings.\n\n"
            "Re-running this wizard later loads your existing .env values "
            "instead of blanking them -- it's also reachable anytime from "
            "the menu."
        )
        label.setWordWrap(True)
        layout.addWidget(label)


class RemotePage(TimelineMixin, QWizardPage):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self.setTitle("Remote hosts (optional)")
        layout = QVBoxLayout(self)
        self._init_timeline(layout)

        # Scrolls instead of letting the stacked widgets' inputs get
        # squeezed vertically when the window is short.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        layout.addWidget(scroll, stretch=1)
        body = QWidget()
        scroll.setWidget(body)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(0, 0, 0, 0)

        info = QLabel(
            "If either project runs on one or more separate hosts (the real "
            "multi-host deployment this project is designed for -- see "
            "ARCHITECTURE.md), add each over SSH here with \"Add host\". Add "
            "none to control only the local stack.\n\n"
            "When a project has at least one configured host, its .env is "
            "fetched live from the FIRST such host on the next step "
            "(prefilling the same form you'd see for a local .env) instead "
            "of a local file -- Next there saves it straight back to that "
            "remote host, not here."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.edge_widget = RemoteHostsWidget("edge", state.remotes_for("edge"))
        layout.addWidget(QLabel("<b>ids</b>"))
        layout.addWidget(self.edge_widget)

        self.siem_widget = RemoteHostsWidget("siem", state.remotes_for("siem"))
        layout.addWidget(QLabel("<b>siem</b>"))
        layout.addWidget(self.siem_widget)
        layout.addStretch(1)

    def validatePage(self) -> bool:
        self.state.set_remotes("edge", self.edge_widget.to_configs())
        self.state.set_remotes("siem", self.siem_widget.to_configs())
        self.state.save()
        return True


class RemoteAwareEnvPage(TimelineMixin, QWizardPage):
    """Base for EdgeEnvPage/SiemEnvPage. Shows and edits a project's .env
    in the same EnvEditorWidget either way, but the SOURCE depends on the
    live remote/local choice from RemotePage, re-checked every time this
    page is shown (initializePage(), same mechanism the timeline already
    uses -- so going Back and toggling remote then Next again picks it up
    correctly):
      - local (default): seeded from .env.example if the real file doesn't
        exist yet, same as before.
      - remote (that project marked remote AND configured): fetched live
        over SSH via download_env_text() and prefilled -- an empty/missing
        remote .env prefills an empty form rather than failing, matching
        how a missing local file behaves. A fetch failure (bad connection)
        falls back to showing the local file instead, with an explanation.

    validatePage() saves back to whichever source was actually shown --
    upload_env_text() for remote, EnvFile.save() for local.
    """

    def __init__(
        self, state: AppState, project: str, title: str,
        local_path: Path, local_example: Path,
        parent=None,
    ):
        super().__init__(parent)
        self.state = state
        self.project = project
        self.local_path = local_path
        self.local_example = local_example
        self.setTitle(title)

        layout = QVBoxLayout(self)
        self._init_timeline(layout)

        self.info = QLabel("")
        self.info.setWordWrap(True)
        layout.addWidget(self.info)

        self.secret_tools = SecretTools(
            project, local_path, local_example,
            get_env_file=lambda: self.env_file,
            apply_form=lambda: self.editor.apply_to_env_file(),
            rebuild=self._show_editor, reload_local=self._load_source)
        layout.addWidget(self.secret_tools)

        self._editor_slot = QVBoxLayout()
        layout.addLayout(self._editor_slot, stretch=1)

        self.env_file: EnvFile | None = None
        self.editor: EnvEditorWidget | None = None
        self._source_is_remote = False

    def _remote_config(self):
        return self.state.primary_remote(self.project) or RemoteConfig()

    def initializePage(self) -> None:
        super().initializePage()  # TimelineMixin's refresh, then QWizardPage's
        self._load_source()

    def _clear_editor(self) -> None:
        while self._editor_slot.count():
            item = self._editor_slot.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _load_source(self) -> None:
        self._clear_editor()
        remote = self._remote_config()

        if remote.enabled and remote.is_configured():
            remote_env_path = Target(project=self.project, remote=remote).remote_env_path()
            self.info.setText(f"Fetching {remote_env_path} from {remote.user}@{remote.host}…")
            self.repaint()
            try:
                text = download_env_text(self.project, remote)
            except EnvUploadError as e:
                self._source_is_remote = False
                self.env_file = seed_from_example(self.local_path, self.local_example)
                self.info.setText(
                    f"Could not fetch the remote .env ({e}) -- showing the "
                    f"LOCAL file instead ({self.local_path}). Fix the "
                    "connection on the previous page and come back, or "
                    "Next will just save locally."
                )
            else:
                self._source_is_remote = True
                display_path = Path(f"{remote.user}@{remote.host}:{remote_env_path}")
                self.env_file = EnvFile.from_text(text, display_path)
                self.env_file.added_keys = merge_example_keys(self.env_file, self.local_example)
                if text:
                    self.info.setText(
                        f"Writes to REMOTE {remote.user}@{remote.host}:"
                        f"{remote_env_path} (fetched live just now, "
                        "shown below). Password/secret fields have a "
                        "Generate button for a random value."
                    )
                else:
                    self.info.setText(
                        f"No .env found yet at {remote.user}@{remote.host}:"
                        f"{remote_env_path} -- starting from an "
                        "empty form; Next creates it there."
                    )
        else:
            self._source_is_remote = False
            self.env_file = seed_from_example(self.local_path, self.local_example)
            self.info.setText(
                f"Writes to {self.local_path}. Password/secret fields have "
                "a Generate button for a random value -- recommended over "
                "the placeholder defaults."
            )

        self._show_editor()

    def _show_editor(self) -> None:
        # Show every key in the file (.env.example keys already merged in),
        # same as the Settings .env editor.
        self._clear_editor()
        self.editor = EnvEditorWidget(self.env_file)
        self._editor_slot.addWidget(self.editor)
        self.secret_tools.set_remote(self._source_is_remote)
        self.secret_tools.update_warnings()

    def validatePage(self) -> bool:
        # Weak secrets get one offer to be generated before they are written.
        if not self.secret_tools.confirm_weak():
            return False
        self.editor.apply_to_env_file()
        if self._source_is_remote:
            remote = self._remote_config()
            try:
                upload_env_text(self.env_file.render(), self.project, remote)
            except EnvUploadError as e:
                remote_env_path = Target(project=self.project, remote=remote).remote_env_path()
                QMessageBox.warning(
                    self, "Save to remote failed",
                    f"Could not write to {remote.user}@{remote.host}:"
                    f"{remote_env_path}:\n\n{e}\n\n"
                    "Go back and fix the connection, or disable remote for "
                    "this project to save locally instead.",
                )
                return False
        else:
            note = self.secret_tools.save_local()
            if note is None:
                return False
            if note:
                QMessageBox.information(self, "Saved", f"Saved {self.local_path}" + note)
        return True


class EdgeEnvPage(RemoteAwareEnvPage):
    def __init__(self, state: AppState, parent=None):
        super().__init__(
            state, "edge", "ids (edge honeypot) — .env",
            EDGE_ENV_FILE, EDGE_ENV_EXAMPLE, parent,
        )


class SiemEnvPage(RemoteAwareEnvPage):
    def __init__(self, state: AppState, parent=None):
        super().__init__(
            state, "siem", "siem (SIEM) — .env",
            SIEM_ENV_FILE, SIEM_ENV_EXAMPLE, parent,
        )


class _SectionPage(TimelineMixin, QWizardPage):
    """A wizard page around setup sections, scrolling when the window is short."""

    def __init__(self, title: str, intro: str, parent=None):
        super().__init__(parent)
        self.setTitle(title)
        outer = QVBoxLayout(self)
        self._init_timeline(outer)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(scroll, stretch=1)
        body = QWidget()
        scroll.setWidget(body)
        self.body = QVBoxLayout(body)
        self.body.setContentsMargins(0, 0, 0, 0)
        info = QLabel(intro)
        info.setWordWrap(True)
        self.body.addWidget(info)

    def finish_body(self) -> None:
        self.body.addStretch(1)


class DeploymentPage(_SectionPage):
    def __init__(self, state: AppState, edge_running: Callable[[], bool] | None = None, parent=None):
        super().__init__(
            "Deployment",
            "How suspicious traffic is handled. All of it can be changed later under "
            "Settings → Deployment (the layer only while the ids stack is stopped).", parent)
        self.deployment = DeploymentSection(state, edge_running)
        self.body.addWidget(self.deployment)
        self.body.addWidget(QLabel("<b>Host kernel settings</b>"))
        self.host_checks = HostChecksSection(state)
        self.body.addWidget(self.host_checks)
        self.finish_body()
        self._checked_once = False

    def initializePage(self) -> None:
        super().initializePage()
        self.deployment.reload()
        if not self._checked_once:   # remote hosts were just set on an earlier page
            self._checked_once = True
            self.host_checks.check()

    def validatePage(self) -> bool:
        try:
            self.deployment.save()
        except OSError as e:
            QMessageBox.warning(self, "Save failed", f"Could not save the edge policy: {e}")
            return False
        return True


class AlertsPage(_SectionPage):
    def __init__(self, state: AppState, on_test_alert: Callable[[], None] | None = None, parent=None):
        super().__init__(
            "Security alerts",
            "When to raise an alert for what the IDS sees, and where to send it. "
            "Saved as you change it (also under Settings → Alerts).", parent)
        self.alerts = AlertsSection(state, on_test_alert)
        self.body.addWidget(self.alerts)
        self.finish_body()


class CertsPage(_SectionPage):
    def __init__(self, parent=None):
        super().__init__(
            "Certificates",
            "The SIEM stack needs its CA and service certificates and the edge nginx "
            "an SSL certificate before they start. Skip this if they already exist "
            "(also under Settings → Certificates).", parent)
        self.certs = CertsSection()
        self.body.addWidget(self.certs)
        self.finish_body()


class FinishPage(_SectionPage):
    def __init__(self, state: AppState, parent=None):
        super().__init__("Done", "", parent)
        self.state = state
        self.summary = QLabel("")
        self.summary.setWordWrap(True)
        self.body.addWidget(self.summary)
        self.body.addWidget(QLabel(
            "The rest has safe defaults and its own page, to review when you like:\n"
            "  •  Honeypot Targets / URL Whitelist -- which CVE targets and legitimate "
            "URLs are on (generic exploits only by default)\n"
            "  •  Container Firewall -- which sensitive endpoints only established "
            "connections may reach\n"
            "  •  Detection Policy -- scoring thresholds and decay\n\n"
            "Health shows container status; Settings has every step of this wizard."))
        self.start_check = QCheckBox("Start the stacks now (Workloads → Start all)")
        self.start_check.setChecked(True)
        self.body.addWidget(self.start_check)
        self.finish_body()

    def initializePage(self) -> None:
        super().initializePage()
        self.summary.setText("Checking what is still unfinished…")
        self.repaint()
        remaining = setup_summary(self.state)
        if remaining:
            self.summary.setStyleSheet("color: #e0a800;")
            self.summary.setText("Still unfinished (go Back to fix, or later in Settings):\n"
                                 + "\n".join(f"⚠ {r}" for r in remaining))
        else:
            self.summary.setStyleSheet("color: #5cb85c;")
            self.summary.setText("✓ Setup complete -- no placeholder secrets or settings left.")


class SetupWizard(QWizard):
    def __init__(self, state: AppState, parent=None,
                 edge_running: Callable[[], bool] | None = None,
                 on_test_alert: Callable[[], None] | None = None):
        super().__init__(parent)
        self.state = state
        self.setWindowTitle("PressHaven.io — Setup")
        self.setMinimumSize(760, 660)

        # Remote/local choice comes first so the .env pages that follow
        # know whether to fetch from the remote host instead of a local file.
        self.setPage(PAGE_WELCOME, WelcomePage())
        self.setPage(PAGE_REMOTE, RemotePage(state))
        self.setPage(PAGE_EDGE_ENV, EdgeEnvPage(state))
        self.setPage(PAGE_SIEM_ENV, SiemEnvPage(state))
        self.setPage(PAGE_DEPLOYMENT, DeploymentPage(state, edge_running))
        self.setPage(PAGE_ALERTS, AlertsPage(state, on_test_alert))
        self.setPage(PAGE_CERTS, CertsPage())
        self.setPage(PAGE_FINISH, FinishPage(state))

    @property
    def start_stacks(self) -> bool:
        """The Done page's "Start the stacks now", read after exec()."""
        return self.page(PAGE_FINISH).start_check.isChecked()

    def accept(self) -> None:
        self.state.first_run_complete = True
        self.state.save()
        super().accept()
