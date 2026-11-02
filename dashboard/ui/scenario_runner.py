"""Attack Simulation page tab that runs the ids/testing/scenario_*.sh pentest
scripts with live output. The scripts read INTERNAL_TEST_SECRET from ids/.env
themselves (lib/scenario_common.sh), so it is never put on a command line
here -- the LogPanel echoes the argv it runs."""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget,
)

from core.paths import EDGE_DIR
from core.state import AppState
from ui.common import muted_label
from ui.process_runner import LogPanel

SCENARIO_DIR = EDGE_DIR / "testing"


def scenario_scripts() -> list[str]:
    return sorted(p.name for p in SCENARIO_DIR.glob("scenario_*.sh"))


def scenario_argv(script: str, host: str, port: str) -> list[str]:
    if script not in scenario_scripts():
        raise ValueError(f"unknown scenario {script!r}")
    return ["bash", str(SCENARIO_DIR / script), host.strip() or "127.0.0.1", port.strip() or "80"]


class ScenarioScriptsTab(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        row = QHBoxLayout()
        row.addWidget(QLabel("Scenario:"))
        self.script_combo = QComboBox()
        self.script_combo.addItems(scenario_scripts())
        row.addWidget(self.script_combo, stretch=1)
        row.addWidget(QLabel("Host:"))
        self.host_edit = QLineEdit(state.primary_remote_host("edge", "127.0.0.1"))
        self.host_edit.setMaximumWidth(180)
        row.addWidget(self.host_edit)
        row.addWidget(QLabel("Port:"))
        self.port_edit = QLineEdit("80")
        self.port_edit.setMaximumWidth(60)
        row.addWidget(self.port_edit)
        self.run_btn = QPushButton("Run")
        self.run_btn.clicked.connect(self._run)
        row.addWidget(self.run_btn)
        layout.addLayout(row)

        layout.addWidget(muted_label(
            "Runs ids/testing/<scenario> against the reverse proxy at Host:Port. The "
            "script reads INTERNAL_TEST_SECRET from the local ids/.env, so routing "
            "headers only come back from a deployment that uses the same .env."))

        self.log_panel = LogPanel()
        layout.addWidget(self.log_panel, stretch=1)

    def _run(self) -> None:
        script = self.script_combo.currentText()
        if not script:
            return
        self.log_panel.run(
            scenario_argv(script, self.host_edit.text(), self.port_edit.text()),
            str(SCENARIO_DIR))
