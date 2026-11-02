"""Log Pipeline page: is the edge's Vector shipper actually delivering logs
to the SIEM? The Global Visualization shows vector_outbound as a green box
whenever its container runs, even when the mTLS channel to the aggregator is
failing -- the exact situation ARCHITECTURE.md documents twice. This page
combines four checks: shipping configured (ELK_ENABLED / VECTOR_HOST), the
shipper container running, its log tail (delivery errors vs. the last
healthcheck pass, core/shipper_health.py) and the SIEM-side vector_inbound
container. Refreshed every 15 s while visible, off the GUI thread."""
from __future__ import annotations

import subprocess
import time

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QMessageBox, QPushButton,
    QVBoxLayout, QWidget,
)
from PyQt6.QtGui import QColor

from core import shipper_health as sh
from core.colors import GREEN, GREY, ORANGE, RED
from core.docker_ctl import Target, targets_for
from core.kibana_credentials import get_elastic_credentials
from core.state import AppState
from ui.common import ErrorBanner, Job, TargetSelector, confirm, copy_logs, danger_button, export_logs
from ui.flow_layout import FlowLayout
from ui.page_overview import StatCard

REFRESH_MS = 15000
_AGG_COLOR = {"healthy": GREEN, "running": GREEN, "unhealthy": RED, "exited_bad": RED, "down": RED,
              "starting": ORANGE, "created": ORANGE, "unknown": GREY}


def _run(argv, cwd) -> str:
    try:
        return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=30).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def _check(edge: Target, siem_targets: list[Target], state):
    """(ShipperHealth, aggregator state, index stats or None, raw shipper log
    tail) -- runs docker/ssh, so off-thread. The raw tail is kept for the
    Copy/Export logs buttons; the health view above only surfaces the relevant
    lines from it."""
    enabled, why = edge.siem_shipping()
    shipper = next((c for c in edge.ps() if c.get("Service") == sh.SHIPPER_SERVICE), None)
    logs = ""
    if enabled and shipper is not None:
        argv, cwd = edge.build("logs", "--tail=300", "--timestamps", sh.SHIPPER_SERVICE)
        logs = _run(argv, cwd)
    agg, agg_target = "unknown", None
    for t in siem_targets:
        agg = sh.aggregator_state(t.ps())
        if agg != "unknown":
            agg_target = t
            break
    # Direct end-to-end confirmation: ask Elasticsearch (inside es01, same
    # path the SIEM healthcheck uses) how many honeypot-* docs it holds.
    index_stats = None
    if agg_target is not None and agg in ("healthy", "running"):
        creds = get_elastic_credentials(state)
        if creds is not None:
            argv, cwd = agg_target.build("exec", "-T", "es01", "sh", "-c",
                                         sh.ES_INDEX_CURL.format(password=creds[1]))
            index_stats = sh.parse_index_stats(_run(argv, cwd))
    return sh.combine(enabled, why, shipper, logs), agg, index_stats, logs


class PipelinePage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._busy = False
        self._jobs: set[Job] = set()
        self._last_docs: int | None = None
        self._log_tail = ""   # raw shipper log tail from the last check, for Copy/Export

        layout = QVBoxLayout(self)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Edge target:"))
        self.target_combo = TargetSelector(lambda: targets_for("edge", self.state))
        bar.addWidget(self.target_combo)
        self.refresh_btn = QPushButton("Check now")
        bar.addWidget(self.refresh_btn)
        self.copy_btn = QPushButton("Copy logs")
        self.copy_btn.setToolTip("Copy the shipper's log tail (the lines summarised below) to the clipboard")
        bar.addWidget(self.copy_btn)
        self.export_btn = QPushButton("Export logs…")
        self.export_btn.setToolTip("Save the shipper's log tail to a file")
        bar.addWidget(self.export_btn)
        self.updated = QLabel("")
        bar.addWidget(self.updated, stretch=1)
        self.clear_btn = danger_button("Clear all documents in SIEM", self._clear_siem)
        self.clear_btn.setToolTip(
            "Permanently delete every honeypot-* document stored in Elasticsearch. "
            "The indices stay and Vector keeps shipping new logs, but everything "
            "already in the SIEM (and the Kibana history built from it) is gone.")
        bar.addWidget(self.clear_btn)
        layout.addLayout(bar)
        self.error_banner = ErrorBanner()
        layout.addWidget(self.error_banner)

        cards_host = QWidget()
        cards = FlowLayout(cards_host, margin=0, h_spacing=10, v_spacing=10)
        self.card_agg = StatCard("SIEM aggregator")
        self.card_docs = StatCard("Documents in SIEM")
        self.card_errors = StatCard("Delivery errors (log tail)")
        self.card_ok = StatCard("Last healthcheck pass")
        for c in (self.card_agg, self.card_docs, self.card_errors, self.card_ok):
            cards.addWidget(c)
        layout.addWidget(cards_host)

        self.detail = QLabel("")
        self.detail.setWordWrap(True)
        layout.addWidget(self.detail)
        note = QLabel("The Documents card is the direct end-to-end check: it queries Elasticsearch for the "
                      "honeypot-* indices and shows whether they are growing. The delivery-error and "
                      "last-healthcheck cards (and the log lines below) are the shipper's own indirect "
                      "signals — Vector does not log every batch, so a quiet log alone does not prove delivery.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {GREY}; font-size: 8pt;")
        layout.addWidget(note)

        layout.addWidget(QLabel("<b>Relevant shipper log lines</b>"))
        self.evidence = QListWidget()
        self.evidence.setWordWrap(True)
        layout.addWidget(self.evidence, stretch=1)

        self.timer = QTimer(self)
        self.timer.setInterval(REFRESH_MS)
        self.timer.timeout.connect(self.refresh)
        self.refresh_btn.clicked.connect(self.refresh)
        self.copy_btn.clicked.connect(self._copy_logs)
        self.export_btn.clicked.connect(self._export_logs)
        self.target_combo.currentIndexChanged.connect(self.refresh)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.refresh()
        self.timer.start()

    def hideEvent(self, event) -> None:
        self.timer.stop()
        super().hideEvent(event)

    def rebuild_targets(self) -> None:
        self.target_combo.rebuild()

    def refresh(self) -> None:
        edge = self.target_combo.current_target()
        if self._busy or edge is None:
            return
        self._busy = True
        siem = targets_for("siem", self.state)
        job = Job(lambda: _check(edge, siem, self.state), self)
        self._jobs.add(job)

        def finished(result, error):
            self._busy = False
            self._jobs.discard(job)
            job.deleteLater()
            if error or result is None:
                self.error_banner.set_error(error or "no data", prefix="⚠ Pipeline check failed: ")
                return
            self.error_banner.set_error(None)
            health, agg, index_stats, log_tail = result
            self._log_tail = log_tail or ""
            self._render(health, agg, index_stats)
        job.done.connect(finished)
        job.start()

    def _copy_logs(self) -> None:
        if copy_logs(self, self._log_tail, "shipper logs"):
            self.updated.setText(f"logs copied {time.strftime('%H:%M:%S')}")

    def _export_logs(self) -> None:
        name = f"vector_outbound_{time.strftime('%Y%m%d_%H%M%S')}.log"
        if export_logs(self, self._log_tail, name, "shipper logs"):
            self.updated.setText(f"logs exported {time.strftime('%H:%M:%S')}")

    def _clear_siem(self) -> None:
        if self._busy:
            return
        if not confirm(
            self, "Clear all documents in SIEM",
            "This permanently deletes every honeypot-* document currently stored in "
            "Elasticsearch — all shipped logs, alerts and events, and the Kibana history "
            "built from them.\n\n"
            "The indices themselves stay and Vector keeps shipping new logs, so the "
            "pipeline is unaffected, but the data already in the SIEM cannot be recovered.\n\n"
            "Delete all documents now?",
        ):
            return
        # Hold off the periodic re-check (and a second click) while the wipe runs.
        self._busy = True
        self.clear_btn.setEnabled(False)
        self.clear_btn.setText("Clearing…")
        siem = targets_for("siem", self.state)
        job = Job(lambda: sh.clear_all_documents(siem, self.state), self)
        self._jobs.add(job)

        def finished(result, error):
            self._busy = False
            self.clear_btn.setEnabled(True)
            self.clear_btn.setText("Clear all documents in SIEM")
            self._jobs.discard(job)
            job.deleteLater()
            if error or result is None:
                QMessageBox.warning(self, "Clear all documents failed", error or "no data")
                return
            deleted, derr = result
            if derr:
                QMessageBox.warning(self, "Clear all documents failed", derr)
            else:
                QMessageBox.information(
                    self, "Documents cleared",
                    f"Deleted {deleted:,} document(s) from the SIEM.")
                self._last_docs = None  # forget the previous count so growth re-baselines
            self.refresh()
        job.done.connect(finished)
        job.start()

    def _render(self, h: sh.ShipperHealth, agg: str, index_stats: dict | None) -> None:
        self.updated.setText(f"checked {time.strftime('%H:%M:%S')}")
        self.card_agg.set_value(agg.replace("_", " "), "vector_inbound", _AGG_COLOR.get(agg, GREY))
        self._render_docs(index_stats)
        self.card_errors.set_value(str(h.error_count), "none in the tail" if not h.error_count else
                                   f"latest {h.last_error or 'unknown time'}", RED if h.error_count else GREEN)
        self.card_ok.set_value(h.last_ok[11:19] if h.last_ok else "—",
                               h.last_ok[:10] if h.last_ok else "none in the tail", GREEN if h.last_ok else GREY)
        self.detail.setText(h.detail)
        self.evidence.clear()
        for e in h.evidence:
            item = QListWidgetItem(("✓ " if e.ok else "✗ ") + e.text)
            item.setForeground(QColor(GREEN if e.ok else RED))
            self.evidence.addItem(item)

    def _render_docs(self, index_stats: dict | None) -> None:
        """The direct end-to-end check: honeypot-* document count in ES, and
        whether it grew since the previous poll."""
        if index_stats is None:
            self.card_docs.set_value("—", "SIEM not reachable / no auth", GREY)
            self._last_docs = None
            return
        total = index_stats["total_docs"]
        if self._last_docs is None:
            caption = f"{index_stats['index_count']} honeypot-* indices"
            color = GREEN if total else ORANGE
        else:
            delta = total - self._last_docs
            if delta > 0:
                caption, color = f"+{delta} since last check — growing", GREEN
            elif total == 0:
                caption, color = "no documents yet", ORANGE
            else:
                caption, color = "no change since last check", ORANGE
        self.card_docs.set_value(f"{total:,}", caption, color)
        self._last_docs = total
