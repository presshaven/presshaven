"""Account Persistence page: walk, step by step, the proof that an adversary
who is logged in on production keeps their OWN account -- role, profile, the
lot -- when the edge diverts them to a honeypot pool, so nothing about the move
hints they have been dropped into a honeypot (request 26). Export the walk as a
PDF.

Where Signature Simulation shows one browser characteristic becoming the
proxy's one-way signature, this page shows what happens to a LOGGED-IN visitor
behind that signature: the username rides the gdpr_token as metadata (a live
proof, step 2, that it never changes the signature), production publishes the
real authenticated identity, the edge keys the account copy off that verified
identity rather than the spoofable token value, a worker copies the account into
the pool, and a secret-gated plugin logs them in there.

The run happens off the GUI thread (docker exec / HTTP can be slow, especially
over SSH); each step streams into a list as it completes, and "Export report
(PDF)" renders the same data through core.account_persistence_pdf.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog, QFrame, QHBoxLayout, QLabel, QMessageBox, QProgressBar,
    QPushButton, QVBoxLayout, QWidget,
)

from core import account_persistence
from core.account_persistence import (ERROR, FAIL, INFO, PASS, SKIP, WARN,
                                      AccountPersistenceReport, StepOutcome)
from core.colors import BLUE, GREEN, GREY, ORANGE, RED
from core.docker_ctl import target_for
from core.state import AppState
from ui import theme
from ui.common import muted_label

_STATUS_COLOR = {PASS: GREEN, FAIL: RED, WARN: ORANGE, INFO: BLUE, SKIP: GREY, ERROR: GREY}
_STATUS_TEXT = {PASS: "PASS", FAIL: "FAIL", WARN: "WARN", INFO: "INFO", SKIP: "SKIP", ERROR: "ERROR"}

_MONO = "font-family: 'DejaVu Sans Mono','Consolas',monospace;"


def _base_url(state: AppState) -> str:
    host = state.primary_remote_host("edge")
    return f"https://{host}"


class _ReportJob(QThread):
    """Runs the (blocking) walk-through off the GUI thread, emitting a progress
    line per step and the finished report (or an error) at the end."""
    progress = pyqtSignal(str)
    done = pyqtSignal(object, str)

    def __init__(self, target, base_url, parent=None):
        super().__init__(parent)
        self._target = target
        self._base_url = base_url

    def run(self) -> None:
        try:
            report = account_persistence.run_report(
                self._target, self._base_url,
                target_label=getattr(self._target, "label", ""),
                log=lambda s: self.progress.emit(s))
            self.done.emit(report, "")
        except Exception as e:  # noqa: BLE001 -- surfaced to the GUI as text
            self.done.emit(None, str(e))


class _StepCard(QFrame):
    """One step shown as a numbered, verdict-coloured card: a badge, the step
    name and one-line summary, then its evidence and detail lines once run."""

    def __init__(self, step: StepOutcome, parent=None):
        super().__init__(parent)
        self.setObjectName("ApStepCard")
        self._accent = _STATUS_COLOR.get(step.status, GREY)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 11)
        layout.setSpacing(6)

        head = QHBoxLayout()
        head.setSpacing(9)
        self.badge = QLabel(_STATUS_TEXT.get(step.status, step.status.upper()))
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge.setFixedWidth(54)
        self.badge.setStyleSheet(
            f"background: {self._accent}; color: #10151f; "
            f"border-radius: {theme.corner_radius_css(6)}; font-weight: bold; padding: 2px 0;")
        title = QLabel(f"{step.number}. {step.name}")
        title.setWordWrap(True)
        title.setStyleSheet("font-weight: bold;")
        head.addWidget(self.badge)
        head.addWidget(title, stretch=1)
        layout.addLayout(head)

        summ = QLabel(step.summary)
        summ.setWordWrap(True)
        summ.setStyleSheet(f"color: {GREY}; font-size: 8.5pt;")
        layout.addWidget(summ)

        if step.evidence:
            ev = QLabel("→ " + step.evidence)
            ev.setWordWrap(True)
            ev.setStyleSheet(f"color: {self._accent}; font-size: 9pt;")
            layout.addWidget(ev)

        if step.details:
            det = QLabel("\n".join(step.details))
            det.setWordWrap(True)
            det.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            det.setStyleSheet(f"{_MONO} color: {theme.scheme_colors()['fg_muted']}; font-size: 8.5pt;")
            layout.addWidget(det)

        theme.on_change(self._apply_theme)
        self._apply_theme()

    def _apply_theme(self) -> None:
        c = theme.scheme_colors()
        self.setStyleSheet(
            f"#ApStepCard {{ background: {c['bg_alt']}; border: 1px solid {c['border']}; "
            f"  border-left: 3px solid {self._accent}; }}"
            f"#ApStepCard QLabel {{ background: transparent; }}")


class AccountPersistencePage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._job: _ReportJob | None = None
        self._report: AccountPersistenceReport | None = None

        root = QVBoxLayout(self)

        intro = QLabel(
            "<b>Account Persistence.</b> When a logged-in visitor's "
            "<code>gdpr_signature</code> turns suspicious and the edge diverts them to a "
            "honeypot pool, their own production account — role, profile, password hash and "
            "all — is copied into that pool and they are silently logged in there, so nothing "
            "hints they have been moved into a honeypot. This page walks that chain one step at "
            "a time: a <b>live proof</b> that the username rides the token as metadata and never "
            "changes the signature, then read-only inspection that production publishes the "
            "authenticated identity, the edge keys the copy off that verified identity (never the "
            "spoofable token value) and strips the identity/autologin headers, the replication "
            "worker is up, and the pool autologin plugin is secret-gated. Every check is "
            "read-only — no account is actually copied.")
        intro.setWordWrap(True)
        root.addWidget(intro)

        controls = QHBoxLayout()
        self.run_btn = QPushButton("Run step-by-step test")
        self.run_btn.clicked.connect(self._run)
        controls.addWidget(self.run_btn)
        self.export_btn = QPushButton("Export report (PDF)")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export)
        controls.addWidget(self.export_btn)
        controls.addStretch()
        root.addLayout(controls)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)   # busy indicator
        self.progress.hide()
        root.addWidget(self.progress)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)

        self.steps_box = QVBoxLayout()
        self.steps_box.setSpacing(8)
        steps_holder = QWidget()
        steps_holder.setLayout(self.steps_box)
        root.addWidget(steps_holder, stretch=1)

        root.addWidget(muted_label(
            "Step 2 sends two real consented requests and reads the two signatures the proxy "
            "derives back from its own log. Steps 3–6 inspect the deployed config and running "
            "services read-only (docker exec test/grep, docker ps). The only secret involved, "
            "INTERNAL_TEST_SECRET, is never read or printed — the gating checks look only for the "
            "presence of the guards. See ids/GDPR.md."))

    # -- target -------------------------------------------------------------

    def rebuild_targets(self) -> None:
        """main_window calls this on every page when remote settings change;
        this page always uses the single edge target, so there is nothing to
        rebuild."""

    def _target(self):
        return target_for("edge", self.state)

    # -- run ----------------------------------------------------------------

    def _run(self) -> None:
        if self._job is not None:
            return
        self._clear_steps()
        self._report = None
        self.export_btn.setEnabled(False)
        self.run_btn.setEnabled(False)
        self.progress.show()
        self.status_label.setText("Starting the account-persistence walk-through …")
        self.status_label.setStyleSheet(f"color: {GREY};")

        self._job = _ReportJob(self._target(), _base_url(self.state), self)
        self._job.progress.connect(self._on_progress)
        self._job.done.connect(self._on_done)
        self._job.start()

    def _on_progress(self, line: str) -> None:
        self.status_label.setText(line)

    def _on_done(self, report, error: str) -> None:
        self.progress.hide()
        self.run_btn.setEnabled(True)
        self._job = None
        if error or report is None:
            self.status_label.setText(f"✗ Account persistence test failed: {error}")
            self.status_label.setStyleSheet(f"color: {RED};")
            return

        self._report = report
        self._fill_steps(report)
        self.export_btn.setEnabled(True)
        status, summary = report.headline()
        color = RED if status.startswith("NOT") else (
            ORANGE if "warning" in status.lower() else (
                GREY if status.startswith("INCONCLUSIVE") else GREEN))
        self.status_label.setText(f"{status}: {summary}")
        self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def _clear_steps(self) -> None:
        while self.steps_box.count():
            item = self.steps_box.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _fill_steps(self, report: AccountPersistenceReport) -> None:
        self._clear_steps()
        for step in report.steps:
            self.steps_box.addWidget(_StepCard(step))
        self.steps_box.addStretch(1)

    # -- export -------------------------------------------------------------

    def _export(self) -> None:
        if self._report is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save account persistence report", "account_persistence_report.pdf",
            "PDF files (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        try:
            from core.account_persistence_pdf import render_pdf
            render_pdf(self._report, path)
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "Export failed", str(e))
            return
        QMessageBox.information(self, "Exported", f"Saved {path}")
