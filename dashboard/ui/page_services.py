"""Workloads page: start/restart/stop/purge for each project, local and
(if configured) remote, with live status shown next to the buttons and
live command output below."""
from __future__ import annotations

import subprocess
import threading

import os

from PyQt6.QtCore import Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QLabel, QMessageBox, QPushButton,
    QScrollArea, QTabWidget, QVBoxLayout, QWidget,
)

from core.container_status import finished_ok, summarize
from core import honeypot_layer
from core.docker_ctl import Target
from core import services_report
from ui.common import Job, confirm, danger_button, muted_label, set_status
from ui.error_monitor import ErrorLogMonitor
from ui.log_export import LogExporter
from ui.process_runner import LogPanel


class TargetPanel(QGroupBox):
    def __init__(self, target: Target, error_monitor: ErrorLogMonitor | None = None,
                 health_screenshot_provider=None, parent=None):
        super().__init__(target.label, parent)
        self.target = target
        self._error_monitor = error_monitor
        # Callable returning a PNG path of the Global Visualization page (or "" on failure),
        # supplied by MainWindow -- used by the "…with PDF graph export" buttons
        # to embed Health-page screenshots in the report.
        self._health_screenshot_provider = health_screenshot_provider
        self._svc_worker: services_report.ServicesReportWorker | None = None
        self._remove_finished_after_report = False
        self._svc_out_path = ""
        self._svc_render_error = ""
        # Whether the LogPanel's current process is a mutating compose
        # command (up/down/restart) vs. the harmless auto-tail (logs -f) --
        # used to warn before quitting mid-operation without nagging the
        # user every time (the auto-tail is running almost constantly), and
        # to know whether to auto-resume the tail once it finishes (see
        # _on_log_finished).
        self._mutating_action = False
        self._seed_jobs: set = set()
        self._log_exporter = LogExporter(self)

        layout = QVBoxLayout(self)

        status_row = QHBoxLayout()
        self.status_label = QLabel("checking…")
        status_row.addWidget(QLabel("Status:"))
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        layout.addLayout(status_row)

        button_row = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.restart_btn = QPushButton("Restart")
        self.stop_btn = QPushButton("Stop")
        self.redeploy_btn = QPushButton("Redeploy")
        self.redeploy_btn.setToolTip(
            "Apply changed .env values and images: rebuild every image, then take the "
            "stack down and up again (networks recreated, data volumes kept)"
            + ("; the runtime honeypot pools are removed so pool_manager rebuilds them "
               "with the current passwords." if target.project == "edge" else "."))
        self.purge_btn = danger_button("Purge (⚠ deletes volumes)")
        self.download_btn = QPushButton("Download logs…")
        for b in (self.start_btn, self.restart_btn, self.stop_btn, self.redeploy_btn,
                  self.purge_btn, self.download_btn):
            button_row.addWidget(b)
        layout.addLayout(button_row)

        self.start_btn.clicked.connect(self._start)
        self.restart_btn.clicked.connect(self._restart)
        self.stop_btn.clicked.connect(self._stop)
        self.redeploy_btn.clicked.connect(self._redeploy)
        self.purge_btn.clicked.connect(self._purge)
        self.download_btn.clicked.connect(self._download_logs)

        # Second row: start/stop that ALSO record a PDF of resource graphs
        # (host CPU/RAM + per-container) with event markers and Health-page
        # screenshots, the same style as the Attack Simulation page's report export.
        export_row = QHBoxLayout()
        self.start_export_btn = QPushButton("Start with PDF graph export")
        self.stop_export_btn = QPushButton("Stop with PDF graph export")
        self.start_export_btn.setToolTip(
            "Start this stack and export a PDF of host + per-container resource "
            "graphs (event markers, peak explanations, Health-page screenshots).")
        self.stop_export_btn.setToolTip(
            "Stop this stack and export the same resource-graph PDF for the shutdown.")
        self.start_export_btn.clicked.connect(lambda: self._run_with_export("start"))
        self.stop_export_btn.clicked.connect(lambda: self._run_with_export("stop"))
        export_row.addWidget(self.start_export_btn)
        export_row.addWidget(self.stop_export_btn)
        export_row.addStretch()
        layout.addLayout(export_row)

        layout.addWidget(muted_label(
            "Logs (auto-tailing -- Start/Restart/Stop/Redeploy/Purge takes over this "
            "panel, then returns to auto-tailing once the command finishes):"
        ))

        # No Stop button on this LogPanel -- Start/Restart/Stop/Purge above
        # already cover stopping/controlling this target, a second "Stop"
        # here would just be redundant (and ambiguous about what it stops).
        # reload_action overrides Reload to always switch to tailing logs
        # rather than replaying whatever command last ran here -- that's
        # frequently a mutating one (up -d/restart/down), and naively
        # replaying it would re-trigger it instead of showing logs;
        # confirmed live this could loop indefinitely if Reload was
        # clicked again before the mutating command finished (each click
        # kills the in-flight one and restarts it, so it never reaches
        # the point where _on_log_finished would auto-resume the tail).
        self.log_panel = LogPanel(show_stop_button=False, reload_action=self._reload_logs)
        self.log_panel.setMinimumHeight(160)
        self.log_panel.finished.connect(self._on_log_finished)
        if self._error_monitor is not None:
            self.log_panel.line_received.connect(self._on_log_line)
        layout.addWidget(self.log_panel)

        # Auto-show logs immediately rather than waiting for a button click
        # -- for a remote target with bad SSH config this also surfaces the
        # connectivity problem right away instead of only on the next
        # manual action.
        self._run("logs", "--tail=50", "-f", mutating=False)

    def update_status(self, containers: list[dict]) -> None:
        text, color = summarize(containers)
        set_status(self.status_label, text, color, bold=True)

    def is_mutating_action_running(self) -> bool:
        return self._mutating_action and self.log_panel.is_running()

    def _run(self, *compose_args: str, mutating: bool = True, keep_output: bool = False) -> None:
        self._mutating_action = mutating
        self._last_mutating_args = compose_args if mutating else ()
        # A fresh `logs -f` tail replays its own `--tail=50` scrollback --
        # reset this target's error counts so that scrollback isn't
        # double-counted on top of whatever it already contributed the
        # last time this same tail started (see ErrorLogMonitor.reset()).
        if compose_args and compose_args[0] == "logs" and self._error_monitor is not None:
            self._error_monitor.reset(self.target.key)
        # Deploy hook: before bringing the stack up, prune host iptables rules
        # orphaned by a previous teardown (a dead-bridge `! -i` DROP left by
        # Docker blackholes the reused container IP -- production_db_seed could
        # not reach production_database). Local + non-fatal; see
        # Target.prune_orphan_rules() / scripts/prune_orphan_iptables.sh.
        if compose_args[:1] == ("up",):
            out = self.target.prune_orphan_rules()
            if out:
                self.log_panel.append(out)
        argv, cwd = self.target.build(*compose_args)
        self.log_panel.run(argv, cwd, keep_output=keep_output)

    def _on_log_line(self, text: str) -> None:
        self._error_monitor.process_chunk(self.target.key, text)

    def _on_log_finished(self, _exit_code: int) -> None:
        # `docker compose up -d` (and restart/down/down -v) exit as soon as
        # the command completes -- with -d, that's almost immediately, so
        # the panel would otherwise just sit there showing "process exited
        # with code 0" instead of going back to showing what the containers
        # are actually doing. Resume the live tail once a mutating action
        # finishes; don't do this for the tail itself finishing (would only
        # happen on a genuine failure/all-containers-gone, and retrying
        # immediately in a loop isn't useful there). The log panel's own
        # "[process exited with code N]" banner (ui/process_runner.py)
        # already surfaces success/failure -- no separate indicator needed
        # here.
        if self._mutating_action:
            self._mutating_action = False
            if _exit_code == 0 and getattr(self, "_last_mutating_args", ())[:1] == ("up",):
                # While a report records this start, leave finished jobs in
                # place until it is done: removing them took their logs with
                # them, so the report's warnings missed the seed jobs' error
                # lines that their tiles' badges were showing.
                if self._svc_worker is None:
                    self._remove_finished_containers()
                else:
                    self._remove_finished_after_report = True
                if self.target.project == "edge":
                    self._seed_edge_policy()
            # If a "…with PDF graph export" is recording, let it know the
            # compose command has now exited (with this code) so a stop is
            # recorded right up to the down command finishing, not just until
            # the containers vanish from `ps`.
            if self._svc_worker is not None:
                self._svc_worker.notify_operation_finished(_exit_code)
            # A failed up/down leaves its output on screen: resuming the tail
            # would only bury the error that explains why services are missing.
            if _exit_code != 0:
                return
            # Resume the tail below the finished command's output, not over it.
            self._run("logs", "--tail=50", "-f", mutating=False, keep_output=True)

    def _seed_edge_policy(self) -> None:
        """A freshly started edge with no policy in Redis gets the one saved
        in the dashboard (URL Whitelist / Honeypot Targets / Settings →
        Deployment), off the GUI thread."""
        from ui.edge_policy_bar import seed_if_missing
        remote = self.target.remote

        def done(applied, error: str) -> None:
            self._seed_jobs.discard(job)
            if error:
                self.log_panel.append(f"[edge policy not applied: {error} -- use Apply to edge "
                                      "on the Honeypot Targets page]\n")
            elif applied:
                self.log_panel.append("[applied the saved edge policy (whitelist + honeypot "
                                      "targets) to this fresh edge]\n")
        job = Job(lambda: seed_if_missing(remote), self)
        self._seed_jobs.add(job)
        job.done.connect(done)
        job.start()

    def _remove_finished_containers(self) -> None:
        """`up` leaves every one-shot service (init_setup, the db seed and
        migration jobs, the Kibana/ES setup jobs) behind as an "Exited (0)"
        container, which clutters `docker container ls -a`. Their work is done and
        the next `up` re-runs them anyway, so remove those. Only jobs that
        exited 0 go: a failed one (e.g. kibana_dashboards_setup when the import
        never went through) stays, with its logs, so the failure is visible
        instead of silently vanishing. Runs off the GUI thread (`ps` + `rm`)."""
        target = self.target

        def work() -> None:
            done = sorted({c.get("Service", "") for c in finished_ok(target.ps())} - {""})
            if not done:
                return
            argv, cwd = target.build("rm", "-f", *done)
            try:
                subprocess.run(argv, cwd=cwd, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=60)
            except (OSError, subprocess.TimeoutExpired):
                pass
        threading.Thread(target=work, daemon=True).start()

    def _reload_logs(self) -> None:
        self._run("logs", "--tail=50", "-f", mutating=False)

    def _download_logs(self) -> None:
        self._log_exporter.export(self.target, self.target.key, None, self.target.label)

    def _start(self) -> None:
        self._run("up", "-d")

    def _restart(self) -> None:
        # `docker compose restart` only acts on containers that already
        # exist and are running -- after a Purge (down -v), a Stop, or a
        # partially-created state it silently does nothing, so "Restart"
        # appeared broken (nothing came up). `up -d --force-recreate`
        # (with --remove-orphans appended by Target._augment_args) cycles
        # every service from ANY prior state -- down, created, or running
        # -- so Restart reliably lands the stack in a fresh running state.
        self._run("up", "-d", "--force-recreate")

    def _stop(self) -> None:
        self._run("down")

    def _redeploy(self) -> None:
        edge = self.target.project == "edge"
        if confirm(
            self, "Confirm redeploy",
            f"Rebuild every image of {self.target.label} and recreate all of its "
            "containers and networks from the current .env and compose files. Data "
            "volumes are kept"
            + (" -- except the honeypot pools added at runtime, which pool_manager "
               "rebuilds with the current design and passwords" if edge else "") + ".\n\n"
            "The stack is down for the duration."
            + ("\n\nIf secrets changed, every database switches to its new passwords "
               "on this start, and everyone is logged out (WordPress salts and the "
               "session signing key)." if edge else "") + "\n\nContinue?",
        ):
            self._mutating_action = True
            # Ends in `up`, so the finished jobs get cleaned up as after Start.
            self._last_mutating_args = ("up",)
            # Same orphaned-iptables prune as Start (see _run()): redeploy does
            # its own down+up, so the dead-bridge DROPs must go first here too.
            out = self.target.prune_orphan_rules()
            if out:
                self.log_panel.append(out)
            argv, cwd = self.target.build_redeploy()
            self.log_panel.run(argv, cwd)

    def _purge(self) -> None:
        if confirm(
            self, "Confirm purge",
            f"This will run 'docker compose down -v' for {self.target.label}, "
            "permanently deleting all named volumes (databases, Redis data, "
            "Elasticsearch indices, everything) for this stack"
            + (", including the honeypot pools added at runtime" if self.target.project == "edge"
               else "") + ".\n\n"
            "This cannot be undone. Continue?",
        ):
            self._mutating_action = True
            self._last_mutating_args = ("down", "-v")
            argv, cwd = self.target.build_purge()
            self.log_panel.run(argv, cwd)

    # ---- start/stop with PDF graph export ----

    def _run_with_export(self, operation: str) -> None:
        if self._svc_worker is not None:
            return  # an export is already running for this target
        # Named like the target the report says it is ("ids (local)" ->
        # ids-local), not by the internal project key ("edge-local").
        where = "remote" if self.target.is_remote else "local"
        default_name = f"services_{operation}_{self.target.spec.label}-{where}.pdf"
        path, _ = QFileDialog.getSaveFileName(
            self, f"Save {operation} graph report", default_name, "PDF files (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        self._svc_out_path = path
        self._svc_render_error = ""

        worker = services_report.ServicesReportWorker(self.target, operation)
        worker.health_shot_request.connect(self._on_svc_health_shot)
        worker.finished_ok.connect(self._on_svc_finished)
        worker.failed.connect(self._on_svc_failed)
        worker.finished.connect(self._on_svc_thread_done)
        self._svc_worker = worker

        self.start_export_btn.setEnabled(False)
        self.stop_export_btn.setEnabled(False)
        set_status(self.status_label, f"recording {operation} graphs…", "#e08a00", bold=True)

        # The worker takes its idle "before" shot first, then signals; the real
        # compose command is launched on that signal so elapsed starts at 0.
        worker.ready_to_run.connect(
            lambda: self._run("up", "-d") if operation == "start" else self._run("down"))
        worker.start()

    def _on_svc_health_shot(self, key: str) -> None:
        """GUI-thread: draw this target's tiles from the worker's own `ps`
        result and hand the path back to the worker (which is blocked waiting
        for it), with the error-badge counts the tiles show."""
        path = ""
        worker = self._svc_worker
        if self._health_screenshot_provider is not None and worker is not None:
            try:
                path = self._health_screenshot_provider(self.target.key, worker.shot_containers) or ""
            except Exception:  # noqa: BLE001
                path = ""
        badges = {}
        if self._error_monitor is not None and worker is not None:
            names = {c.get("Service", "") for c in worker.shot_containers} - {""}
            badges = {svc: n for svc in names if (n := self._error_monitor.count_for(self.target.key, svc))}
        if worker is not None:
            worker.provide_health_shot(key, path, badges)

    def _on_svc_finished(self, data) -> None:
        # Render on the GUI thread (QPrinter/QtGui); teardown reads the error.
        try:
            services_report.render_services_pdf(data, self._svc_out_path)
        except Exception as e:  # noqa: BLE001
            self._svc_render_error = str(e)

    def _on_svc_failed(self, message: str) -> None:
        self._svc_render_error = message

    def _on_svc_thread_done(self) -> None:
        out_path = self._svc_out_path
        error = self._svc_render_error
        if self._svc_worker is not None:
            self._svc_worker.deleteLater()
            self._svc_worker = None
        if self._remove_finished_after_report:
            self._remove_finished_after_report = False
            self._remove_finished_containers()
        self.start_export_btn.setEnabled(True)
        self.stop_export_btn.setEnabled(True)
        if error:
            QMessageBox.warning(self, "Graph export failed", error)
            return
        if out_path and os.path.exists(out_path) and QMessageBox.question(
            self, "Report saved",
            f"Saved the resource-graph report to:\n{out_path}\n\nOpen it now?",
        ) == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(out_path)))


class ServicesPage(QWidget):
    # Emitted with the new layer id after the user switches "Honeypot layer"
    # (state already saved, core.honeypot_layer already updated).
    layer_changed = pyqtSignal(str)

    def __init__(self, get_targets, error_monitor: ErrorLogMonitor | None = None,
                 health_screenshot_provider=None, state=None, parent=None):
        super().__init__(parent)
        self._get_targets = get_targets
        self._error_monitor = error_monitor
        self._health_screenshot_provider = health_screenshot_provider
        self._state = state
        self.panels: dict[str, TargetPanel] = {}
        # Stack view by default: show every target's panel at once. The tab
        # view is the opt-in for when there are enough targets that scrolling
        # the stack is tedious.
        self._tab_view = False
        self._last_status: dict[str, list[dict]] = {}

        outer = QVBoxLayout(self)

        # Which honeypot layer the ids stack runs (see core/honeypot_layer.py
        # and ids/db_proxy/README.md). Applies to every ids target, local and
        # remote; the siem stack is unaffected.
        layer_row = QHBoxLayout()
        layer_row.addWidget(QLabel("Honeypot layer:"))
        self.layer_combo = QComboBox()
        for layer in honeypot_layer.LAYERS.values():
            self.layer_combo.addItem(layer.label, layer.id)
        self.layer_combo.setItemData(
            0, "Suspicious sessions are routed to separate honeypot WordPress "
               "containers (ids/docker-compose.yml).", Qt.ItemDataRole.ToolTipRole)
        self.layer_combo.setItemData(
            1, "One eshop serves everything; the database is switched per request "
               "(ids/docker-compose.db-proxy.yml). Isolates database-layer attacks "
               "only -- see ids/db_proxy/COVERAGE.md.", Qt.ItemDataRole.ToolTipRole)
        self.layer_combo.setCurrentIndex(
            self.layer_combo.findData(honeypot_layer.active().id))
        self.layer_combo.currentIndexChanged.connect(self._on_layer_selected)
        layer_row.addWidget(self.layer_combo)
        # The layer is a compose-file choice: switching it only makes sense
        # while the ids stack is down, so the dropdown is disabled (with this
        # note) whenever any edge target is running -- see _apply_layer_lock().
        self.layer_note = QLabel("")
        self.layer_note.setStyleSheet("color: #888888;")
        self.layer_note.setWordWrap(True)
        layer_row.addWidget(self.layer_note)
        layer_row.addStretch()
        outer.addLayout(layer_row)

        toggle_row = QHBoxLayout()
        toggle_row.addStretch()
        self.view_toggle_btn = QPushButton("Switch to tab view" if not self._tab_view else "Switch to stack view")
        self.view_toggle_btn.clicked.connect(self._toggle_view)
        toggle_row.addWidget(self.view_toggle_btn)
        outer.addLayout(toggle_row)

        # Stack view (toggle): every target's panel one below another in a
        # scroll area -- see everything at once, scroll to find one.
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        outer.addWidget(self.scroll)

        inner = QWidget()
        self.inner_layout = QVBoxLayout(inner)
        self.inner_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(inner)

        # Tab view (default): one tab per target -- only one panel's log
        # tail/controls visible at a time, useful once there are enough
        # targets (local + remote x2 projects) that the stack view means
        # a lot of scrolling to reach the one you want.
        self.tab_widget = QTabWidget()
        self.tab_widget.setVisible(True)
        outer.addWidget(self.tab_widget)

        self.rebuild_panels()

    def _toggle_view(self) -> None:
        self._tab_view = not self._tab_view
        self.view_toggle_btn.setText("Switch to stack view" if self._tab_view else "Switch to tab view")
        self._populate_current_view()

    def rebuild_panels(self) -> None:
        """Call after remote settings change, so newly-configured remote
        targets get their own panel without restarting the app."""
        for panel in self.panels.values():
            panel.deleteLater()
        self.panels.clear()

        for target in self._get_targets():
            self.panels[target.key] = TargetPanel(
                target, self._error_monitor, self._health_screenshot_provider)

        self._populate_current_view()

    def _populate_current_view(self) -> None:
        # Detach every panel from whichever container currently holds it
        # -- removeTab()/takeAt() detach the widget without deleting it,
        # and addTab()/addWidget() below reparents it into the other
        # container. Panels themselves are constructed once (rebuild_
        # panels()) and just move between the two views on toggle, so
        # each one's auto-tailing log process keeps running uninterrupted
        # regardless of which view is currently shown.
        while self.inner_layout.count():
            self.inner_layout.takeAt(0)
        while self.tab_widget.count():
            self.tab_widget.removeTab(0)

        for target in self._get_targets():
            panel = self.panels.get(target.key)
            if panel is None:
                continue
            if self._tab_view:
                self.tab_widget.addTab(panel, target.label)
            else:
                self.inner_layout.addWidget(panel)
                # QTabWidget hides every tab page except the currently
                # selected one, and removeTab() doesn't restore visibility
                # on the way out -- confirmed live: switching back to
                # stack view left every panel that wasn't the active tab
                # invisible (a blank-looking page), since addWidget()
                # alone doesn't undo that hidden state.
                panel.setVisible(True)

        self.scroll.setVisible(not self._tab_view)
        self.tab_widget.setVisible(self._tab_view)

    def any_mutating_action_running(self) -> bool:
        """True if any panel has an in-flight up/down/restart/purge --
        used to warn before quitting mid-operation. Deliberately excludes
        the auto-tail log stream, which is always running and harmless to
        interrupt."""
        return any(p.is_mutating_action_running() for p in self.panels.values())

    def start_all(self) -> None:
        """`docker compose up -d` on every target (both stacks) -- the
        Overview page's "Start all". Each panel shows its own progress."""
        for panel in self.panels.values():
            panel._start()

    def restart_all(self) -> None:
        for panel in self.panels.values():
            panel._restart()

    def stop_all(self) -> None:
        for panel in self.panels.values():
            panel._stop()

    def _on_layer_selected(self, _index: int) -> None:
        new_id = self.layer_combo.currentData()
        old = honeypot_layer.active()
        if new_id == old.id:
            return
        if self.any_mutating_action_running():
            QMessageBox.information(
                self, "Honeypot layer",
                "A start/stop is still running. Switch the layer once it finishes.")
            self._select_layer(old.id)
            return

        edge_keys = [t.key for t in self._get_targets() if t.project == "edge"]
        running = [k for k in edge_keys
                   if any(c.get("State") == "running" for c in self._last_status.get(k, []))]
        new = honeypot_layer.layer(new_id)
        apply_now = False
        if running:
            answer = QMessageBox.question(
                self, "Switch honeypot layer",
                f"The ids stack is running as the {old.short_label}.\n\n"
                f"Recreate it now as the {new.short_label}? This runs "
                "'docker compose up -d --remove-orphans' with the new compose file: "
                "services that differ are replaced and the other layer's extra "
                "services are removed. Data volumes are kept.\n\n"
                "No = switch anyway and apply on the next Start.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                | QMessageBox.StandardButton.Cancel,
            )
            if answer == QMessageBox.StandardButton.Cancel:
                self._select_layer(old.id)
                return
            apply_now = answer == QMessageBox.StandardButton.Yes

        honeypot_layer.set_active(new.id)
        if self._state is not None:
            self._state.honeypot_layer = new.id
            self._state.save()
        # Owners rebuild their targets (panel titles and every compose call
        # now carry the new layer), this page included.
        self.layer_changed.emit(new.id)
        if apply_now:
            for key in running:
                panel = self.panels.get(key)
                if panel is not None:
                    panel._start()

    def _select_layer(self, layer_id: str) -> None:
        self.layer_combo.blockSignals(True)
        self.layer_combo.setCurrentIndex(self.layer_combo.findData(layer_id))
        self.layer_combo.blockSignals(False)

    def apply_status(self, results: dict[str, list[dict]]) -> None:
        self._last_status.update(results)
        for key, containers in results.items():
            if key in self.panels:
                self.panels[key].update_status(containers)
        self._apply_layer_lock()

    def _edge_running(self) -> bool:
        """Any edge (ids) target with at least one running container."""
        edge_keys = [t.key for t in self._get_targets() if t.project == "edge"]
        return any(any(c.get("State") == "running" for c in self._last_status.get(k, []))
                   for k in edge_keys)

    def _apply_layer_lock(self) -> None:
        """The honeypot layer is a compose-file choice; only let it change
        while the ids stack is down, so a reconfiguration can't race a
        running stack. While up, disable the dropdown and say why."""
        running = self._edge_running()
        self.layer_combo.setEnabled(not running)
        self.layer_note.setText("stop the ids stack to change the layer" if running else "")
