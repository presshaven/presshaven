"""Suricata page: the network-IDS half of the stack, natively. Two tabs:

  - Alerts: the most recent alerts from eve.json with headline counts (by
    severity, top signatures, top source IPs), searchable, one row per alert.
  - Rules: every rule in local.rules with its sid, message, class and
    state; rules can be switched off/on (commented in the file) and saved
    back, after which Suricata is restarted to load the edited file.

All container access goes through core/suricata_ctl.py (docker compose exec,
local or SSH) on a background thread so a slow remote never freezes the UI."""
from __future__ import annotations

import time

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QPushButton, QSplitter, QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core import suricata_ctl
from core.colors import GREY, ORANGE, RED
from core.docker_ctl import targets_for
from core.state import AppState
from ui.common import ErrorBanner, Job, TargetSelector, confirm, copy_logs, export_logs

_SEV_COLOR = {"critical": RED, "high": ORANGE}
REFRESH_MS = 8000
# Severity filters: label -> set of severity labels to keep (None = all).
_SEV_FILTERS = [("All severities", None), ("Critical", {"critical"}),
                ("Critical + high", {"critical", "high"}), ("Medium", {"medium"})]


class SuricataPage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._alerts: list[suricata_ctl.SuricataAlert] = []
        self._shown_alerts: list[suricata_ctl.SuricataAlert] = []
        self._ip_names: dict[str, str] = {}
        self._rules_text = ""
        self._rules: list[suricata_ctl.Rule] = []
        self._jobs: set[Job] = set()
        self._busy = False

        layout = QVBoxLayout(self)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Target:"))
        self.target_combo = TargetSelector(lambda: targets_for("edge", self.state))
        bar.addWidget(self.target_combo)
        self.refresh_btn = QPushButton("Refresh")
        bar.addWidget(self.refresh_btn)
        self.copy_btn = QPushButton("Copy logs")
        self.copy_btn.setToolTip("Copy the alerts currently shown (after any filter) to the clipboard")
        bar.addWidget(self.copy_btn)
        self.export_btn = QPushButton("Export logs…")
        self.export_btn.setToolTip("Save the alerts currently shown (after any filter) to a file")
        bar.addWidget(self.export_btn)
        self.clear_btn = QPushButton("Clear logs")
        self.clear_btn.setToolTip("Empty Suricata's eve.json alert log in the container, "
                                  "discarding every recorded alert")
        bar.addWidget(self.clear_btn)
        self.status = QLabel("")
        bar.addWidget(self.status, stretch=1)
        layout.addLayout(bar)
        self.error_banner = ErrorBanner()
        layout.addWidget(self.error_banner)

        tabs = QTabWidget()
        layout.addWidget(tabs, stretch=1)

        # ---- alerts tab ----
        alerts_tab = QWidget()
        al = QVBoxLayout(alerts_tab)
        self.summary = QLabel("")
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.TextFormat.RichText)
        al.addWidget(self.summary)
        filter_row = QHBoxLayout()
        self.alert_filter = QLineEdit()
        self.alert_filter.setPlaceholderText("Filter by signature, IP, URL or category…")
        self.alert_filter.setClearButtonEnabled(True)
        filter_row.addWidget(self.alert_filter, stretch=1)
        self.sev_combo = QComboBox()
        for label, _keep in _SEV_FILTERS:
            self.sev_combo.addItem(label)
        filter_row.addWidget(self.sev_combo)
        al.addLayout(filter_row)
        alert_split = QSplitter(Qt.Orientation.Vertical)
        al.addWidget(alert_split, stretch=1)
        self.alert_table = QTableWidget(0, 6)
        self.alert_table.setHorizontalHeaderLabels(["Time", "Severity", "Signature", "Source", "Target", "URL"])
        self.alert_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.alert_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.alert_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.alert_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.alert_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.alert_table.verticalHeader().setVisible(False)
        self.alert_table.itemSelectionChanged.connect(self._on_alert_selected)
        alert_split.addWidget(self.alert_table)
        self.alert_detail = QPlainTextEdit(readOnly=True)
        self.alert_detail.setPlaceholderText("Select an alert to see its full detail.")
        self.alert_detail.setMaximumHeight(170)
        alert_split.addWidget(self.alert_detail)
        alert_split.setSizes([400, 150])
        tabs.addTab(alerts_tab, "Alerts")

        # ---- rules tab ----
        rules_tab = QWidget()
        rl = QVBoxLayout(rules_tab)
        rbar = QHBoxLayout()
        self.rule_filter = QLineEdit()
        self.rule_filter.setPlaceholderText("Filter by sid, message or class…")
        self.rule_filter.setClearButtonEnabled(True)
        rbar.addWidget(self.rule_filter, stretch=1)
        self.apply_btn = QPushButton("Save && restart Suricata")
        self.apply_btn.setEnabled(False)
        rbar.addWidget(self.apply_btn)
        rl.addLayout(rbar)
        self.rule_table = QTableWidget(0, 5)
        self.rule_table.setHorizontalHeaderLabels(["Enabled", "SID", "Message", "Class", "Rev"])
        self.rule_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.rule_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.rule_table.verticalHeader().setVisible(False)
        rl.addWidget(self.rule_table, stretch=1)
        tabs.addTab(rules_tab, "Rules")

        self.refresh_btn.clicked.connect(self.refresh)
        self.copy_btn.clicked.connect(self._copy_logs)
        self.export_btn.clicked.connect(self._export_logs)
        self.clear_btn.clicked.connect(self._clear_logs)
        self.target_combo.currentIndexChanged.connect(self.refresh)
        self.alert_filter.textChanged.connect(self._render_alerts)
        self.sev_combo.currentIndexChanged.connect(self._render_alerts)
        self.rule_filter.textChanged.connect(self._render_rules)
        self.rule_table.itemChanged.connect(self._on_rule_toggled)
        self.apply_btn.clicked.connect(self._apply)

        self.timer = QTimer(self)
        self.timer.setInterval(REFRESH_MS)
        self.timer.timeout.connect(self._tick)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.refresh()
        self.timer.start()

    def hideEvent(self, event) -> None:
        self.timer.stop()
        super().hideEvent(event)

    def rebuild_targets(self) -> None:
        self.target_combo.rebuild()

    def _tick(self) -> None:
        # Don't clobber unsaved rule edits, and don't stack fetches.
        if not self._busy and not self.apply_btn.isEnabled():
            self.refresh()

    def _run(self, fn, on_done) -> None:
        job = Job(fn, self)
        self._jobs.add(job)

        def finished(result, error):
            self._jobs.discard(job)
            job.deleteLater()
            on_done(result, error)
        job.done.connect(finished)
        job.start()

    def refresh(self) -> None:
        if self._busy:
            return
        self._busy = True
        remote = self.target_combo.current_remote()
        self.status.setText("loading…")
        self._run(lambda: (suricata_ctl.fetch_alerts(remote), suricata_ctl.fetch_rules_text(remote),
                           suricata_ctl.container_ip_map(remote)),
                  self._loaded)

    def _loaded(self, result, error: str) -> None:
        self._busy = False
        if error or result is None:
            self.status.setText("")
            self.error_banner.set_error(error or "no data", prefix="⚠ Suricata unreachable: ")
            return
        self.error_banner.set_error(None)
        self._alerts, self._rules_text, self._ip_names = result
        self._rules = suricata_ctl.parse_rules(self._rules_text)
        self.status.setText(f"{len(self._alerts)} recent alerts · {len(self._rules)} rules")
        self.apply_btn.setEnabled(False)
        self._render_alerts()
        self._render_rules()

    def _render_alerts(self) -> None:
        s = suricata_ctl.summarize(self._alerts)
        sev = " · ".join(f"{k}: {v}" for k, v in s["by_severity"].items()) or "none"
        sigs = ", ".join(f"{n} ({c})" for n, c in s["top_signatures"]) or "—"
        ips = ", ".join(f"{n} ({c})" for n, c in s["top_sources"]) or "—"
        self.summary.setText(f"<b>{s['total']}</b> alerts &nbsp; ({sev})<br>"
                             f"<b>Top signatures:</b> {sigs}<br><b>Top sources:</b> {ips}")
        needle = self.alert_filter.text().strip().lower()
        keep = _SEV_FILTERS[self.sev_combo.currentIndex()][1]
        self._shown_alerts = [a for a in reversed(self._alerts)
                              if (keep is None or a.severity_label in keep)
                              and (not needle
                                   or needle in f"{a.signature} {a.src_ip} {a.url} {a.category}".lower())]
        self.alert_table.setRowCount(len(self._shown_alerts))
        for r, a in enumerate(self._shown_alerts):
            cells = [a.timestamp[:19].replace("T", " "), a.severity_label, a.signature,
                     self._endpoint(a.src_ip, a.src_port), self._endpoint(a.dest_ip, a.dest_port), a.url]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 1:
                    item.setForeground(QColor(_SEV_COLOR.get(a.severity_label, GREY)))
                self.alert_table.setItem(r, c, item)

    def _endpoint(self, ip: str, port: int) -> str:
        """`name (ip:port)` when the IP belongs to a known container, else the
        bare `ip:port` -- so the Alerts tab shows which container an alert's
        source/target is, not just a bare Docker bridge address."""
        base = f"{ip}:{port}" if port else ip
        name = self._ip_names.get(ip)
        return f"{name} ({base})" if name else base

    def _on_alert_selected(self) -> None:
        rows = self.alert_table.selectionModel().selectedRows()
        if not rows or rows[0].row() >= len(self._shown_alerts):
            return
        a = self._shown_alerts[rows[0].row()]
        lines = []
        for label, value in a.detail_lines():
            if label == "Source":
                value = self._endpoint(a.src_ip, a.src_port)
            elif label == "Target":
                value = self._endpoint(a.dest_ip, a.dest_port)
            lines.append(f"{label}: {value}")
        self.alert_detail.setPlainText("\n".join(lines))

    def _alerts_as_text(self) -> str:
        """The alerts currently shown (respecting the filter and severity
        selector), as a tab-separated table -- what Copy/Export logs act on.
        Empty string when nothing is shown, so the helpers can say so."""
        if not self._shown_alerts:
            return ""
        header = ["Time", "Severity", "Signature", "SID", "Category", "Source", "Target", "URL"]
        rows = ["\t".join(header)]
        for a in self._shown_alerts:
            rows.append("\t".join((
                a.timestamp[:19].replace("T", " "), a.severity_label, a.signature,
                str(a.sid), a.category, self._endpoint(a.src_ip, a.src_port),
                self._endpoint(a.dest_ip, a.dest_port), a.url)))
        return "\n".join(rows)

    def _copy_logs(self) -> None:
        if copy_logs(self, self._alerts_as_text(), "alerts"):
            self.status.setText(f"{len(self._shown_alerts)} alert(s) copied")

    def _export_logs(self) -> None:
        name = f"suricata_alerts_{time.strftime('%Y%m%d_%H%M%S')}.tsv"
        if export_logs(self, self._alerts_as_text(), name, "alerts",
                       "Tab-separated (*.tsv);;Text files (*.txt);;All files (*)"):
            self.status.setText(f"{len(self._shown_alerts)} alert(s) exported")

    def _clear_logs(self) -> None:
        if not confirm(self, "Clear Suricata alerts",
                       "This empties eve.json in the suricata_ids container, permanently "
                       "discarding every recorded alert. The rule set is not touched and "
                       "Suricata keeps running. Continue?"):
            return
        remote = self.target_combo.current_remote()
        self.clear_btn.setEnabled(False)
        self.status.setText("clearing alerts…")

        def done(_result, error):
            self.clear_btn.setEnabled(True)
            if error:
                self.error_banner.set_error(error, prefix="⚠ Could not clear alerts: ")
                self.status.setText("")
            else:
                self.status.setText("alerts cleared")
                self.refresh()
        self._run(lambda: suricata_ctl.clear_alerts(remote), done)

    def _render_rules(self) -> None:
        needle = self.rule_filter.text().strip().lower()
        rules = [r for r in self._rules
                 if not needle or needle in f"{r.sid} {r.msg} {r.classtype}".lower()]
        self.rule_table.blockSignals(True)
        self.rule_table.setRowCount(len(rules))
        for row, r in enumerate(rules):
            check = QTableWidgetItem()
            check.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            check.setCheckState(Qt.CheckState.Checked if r.enabled else Qt.CheckState.Unchecked)
            check.setData(Qt.ItemDataRole.UserRole, r.sid)
            self.rule_table.setItem(row, 0, check)
            for col, text in enumerate((str(r.sid), r.msg, r.classtype, str(r.rev)), start=1):
                self.rule_table.setItem(row, col, QTableWidgetItem(text))
        self.rule_table.blockSignals(False)

    def _on_rule_toggled(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        sid = item.data(Qt.ItemDataRole.UserRole)
        enabled = item.checkState() == Qt.CheckState.Checked
        try:
            self._rules_text = suricata_ctl.set_rule_enabled(self._rules_text, sid, enabled)
        except suricata_ctl.SuricataError as e:
            QMessageBox.warning(self, "Rule", str(e))
            return
        self._rules = suricata_ctl.parse_rules(self._rules_text)
        self.apply_btn.setEnabled(True)

    def _apply(self) -> None:
        if not confirm(self, "Apply rule changes",
                       "This writes local.rules in the suricata_ids container and restarts Suricata "
                       "(a few seconds without network detection). Continue?"):
            return
        remote = self.target_combo.current_remote()
        text = self._rules_text
        self.apply_btn.setEnabled(False)
        self.status.setText("saving and restarting…")

        def work():
            suricata_ctl.save_rules_text(remote, text)
            suricata_ctl.restart(remote)

        def done(_result, error):
            if error:
                self.error_banner.set_error(error, prefix="⚠ Could not apply rules: ")
                self.apply_btn.setEnabled(True)
                self.status.setText("")
            else:
                self.refresh()
        self._run(work, done)
