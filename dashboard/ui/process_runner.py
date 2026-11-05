"""Runs a command via QProcess and streams its output into a QPlainTextEdit
-- shared by the Workloads page (start/stop/restart/purge), the Global Visualization page
(per-service restart/logs), and the PKI & Certificates page (regenerate).

One LogPanel = one QProcess at a time. Starting a new command while one is
already running kills the previous one first (there's no legitimate reason
to have two `docker compose` invocations racing against the same project
from this app).
"""
from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import QProcess, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from core.line_buffer import LineBuffer
from ui import ansi_render, theme


# Rendering is throttled: a remote `logs --tail=all` (or any chatty service)
# can deliver megabytes in a burst, and inserting each chunk into the
# QPlainTextEdit synchronously (one styled insertText per ANSI segment) starves
# the event loop -- the whole window freezes until the flood is rendered. Output
# is queued instead and drawn in bounded slices from a timer, so the UI keeps
# repainting and responding between slices.
_RENDER_INTERVAL_MS = 40
_RENDER_SLICE_CHARS = 32_000
# The view keeps only the last 5000 blocks anyway, so when the backlog outgrows
# this the oldest queued text could never be seen -- drop it rather than
# spending seconds drawing text that is scrolled off immediately.
_BACKLOG_MAX_CHARS = 600_000
_PENDING_MAX_CHUNKS = 20_000   # same bound for text held back by Pause


class LogPanel(QWidget):
    finished = pyqtSignal(int)  # exit code
    # Raw stdout chunks, emitted independent of pause state -- unlike
    # append()/_emit(), this never buffers or holds anything back, so a
    # consumer that wants to react to output as it happens (e.g.
    # page_patterns.py's pattern-event parser) isn't at the mercy of the
    # log tail's own Pause button.
    line_received = pyqtSignal(str)

    def __init__(self, parent=None, show_stop_button: bool = True, reload_action=None):
        super().__init__(parent)
        self.process: QProcess | None = None
        # Set only while run() is killing the PREVIOUS process to start a
        # new one -- see run()/_on_finished. Suppresses that killed
        # process's finished/error signals so they don't re-enter the
        # consumer's finished handler mid-run (QProcess delivers finished
        # synchronously inside waitForFinished(), so without this the
        # `finished` from the auto-tail this app kills on every Start/
        # Restart fires reentrantly -- corrupting TargetPanel's
        # mutating-action guard, leaking the resumed log tail, and leaving
        # the panel stuck on "[process exited]" instead of tailing again.
        self._suppress_finish = False
        self._paused = False
        self._pending: list[str] = []
        self._backlog = ""     # accepted output awaiting throttled rendering
        self._dropped = False  # backlog was trimmed since the last render
        self._render_timer = QTimer(self)
        self._render_timer.setInterval(_RENDER_INTERVAL_MS)
        self._render_timer.timeout.connect(self._render_slice)
        self._default_text_color = ansi_render.panel_colors()[1]
        self._ansi = ansi_render.make_parser()
        self._last_argv: list[str] | None = None
        self._last_cwd: str | None = None
        self._last_line_filter: Callable[[str], bool] | None = None
        # Overrides what the Reload button does, instead of blindly
        # replaying the last command run() was given. Needed by the
        # Workloads page: its LogPanel's "last command" is often a
        # mutating one (up -d/restart/down) that the panel only runs
        # once before auto-resuming a `logs -f` tail (see
        # page_services.py's TargetPanel) -- naively replaying THAT would
        # re-trigger the mutating command instead of showing logs, and
        # confirmed live this can loop indefinitely if Reload gets clicked
        # again before the mutating command finishes (each click kills
        # the in-flight one and starts a fresh one, so it can never reach
        # the point where it would auto-resume tailing on its own).
        self._reload_action = reload_action
        # Set per-run() (not constructor-only) so the same panel instance
        # can switch between an unfiltered full tail and a filtered view
        # across separate run() calls -- see page_health.py's error-badge
        # click, which reuses its one LogPanel for both. None means "show
        # everything" (unchanged default behavior for every other caller).
        self._line_filter: Callable[[str], bool] | None = None
        self._filter_buffer = LineBuffer()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.text = QPlainTextEdit(readOnly=True)
        self.text.setMaximumBlockCount(5000)
        layout.addWidget(self.text)
        self._apply_theme_colors()
        theme.on_change(self._apply_theme_colors)

        button_row = QHBoxLayout()

        self.pause_button = QPushButton("Pause")
        self.pause_button.clicked.connect(self._toggle_pause)
        button_row.addWidget(self.pause_button)

        self.catchup_button = QPushButton("Catch up (0)")
        self.catchup_button.clicked.connect(self._catch_up)
        self.catchup_button.setEnabled(False)
        button_row.addWidget(self.catchup_button)

        # Re-runs the last run() command from scratch (fresh process, fresh
        # output) -- only ever enabled once run() has actually been called,
        # since pages that only ever push lines in via append() (e.g. the
        # PKI & Certificates page's worker-thread output) have no command to
        # replay.
        self.reload_button = QPushButton("Reload")
        self.reload_button.clicked.connect(self._reload)
        self.reload_button.setEnabled(False)
        button_row.addWidget(self.reload_button)

        # The Workloads page already has its own Start/Restart/Stop/Purge
        # buttons directly above this panel -- a second "Stop" button here
        # would be redundant (and ambiguous: stopping WHAT, the compose
        # command or the containers?). Health/PKI & Certificates pages have no
        # such buttons of their own, so they keep it.
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop)
        self.stop_button.setEnabled(False)
        self.stop_button.setVisible(show_stop_button)
        button_row.addWidget(self.stop_button)

        layout.addLayout(button_row)

    def _apply_theme_colors(self) -> None:
        self._default_text_color = ansi_render.panel_colors()[1]
        self.text.setStyleSheet(ansi_render.panel_stylesheet())
        # Only the parser's DEFAULT palette (used for un-styled text and
        # future ESC[...m codes) needs to change -- already-rendered
        # scrollback keeps whatever explicit colors it was drawn with,
        # same as any terminal emulator's own theme switch.
        self._ansi = ansi_render.make_parser()

    def append(self, text: str) -> None:
        """text may contain raw ANSI SGR escape codes (e.g. from `docker
        compose --ansi always logs`) -- self._ansi turns those into styled
        segments instead of literal escape-code garbage. Plain text with no
        codes in it (worker-thread lines, the "$ ..." command echo below,
        "[process exited...]" banners) just comes back as one segment in
        the default color, unchanged from before."""
        ansi_render.append(self.text, self._ansi, text, self._default_text_color)

    def clear(self) -> None:
        self.text.clear()
        self._ansi = ansi_render.make_parser()

    def run(
        self, argv: list[str], cwd: str | None = None,
        line_filter: Callable[[str], bool] | None = None,
        keep_output: bool = False,
    ) -> None:
        # keep_output: append to what is already shown instead of clearing it
        # (the log tail that resumes after a Start must not erase the `up`
        # output, including any build/start error in it).
        # Kill any in-flight process WITHOUT letting its finished/error
        # signal reach our consumers -- that stale "the thing I just killed
        # exited" event is not a real completion of anything the caller
        # cares about (see self._suppress_finish).
        self._suppress_finish = True
        self.stop()
        self._suppress_finish = False
        if keep_output:
            self.append("\n")
        else:
            self.clear()
        self._paused = False
        self.pause_button.setText("Pause")
        self._pending.clear()
        self._backlog = ""
        self._dropped = False
        self._render_timer.stop()
        self.catchup_button.setEnabled(False)
        self.catchup_button.setText("Catch up (0)")
        self._last_argv = argv
        self._last_cwd = cwd
        self._last_line_filter = line_filter
        self._line_filter = line_filter
        self._filter_buffer = LineBuffer()
        self.reload_button.setEnabled(True)
        self.append(f"$ {' '.join(argv)}\n\n")

        self.process = QProcess(self)
        if cwd:
            self.process.setWorkingDirectory(cwd)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._on_output)
        self.process.finished.connect(self._on_finished)
        self.process.errorOccurred.connect(self._on_error)

        program, args = argv[0], argv[1:]
        self.process.start(program, args)
        self.stop_button.setEnabled(True)

    def _reload(self) -> None:
        if self._reload_action is not None:
            self._reload_action()
        elif self._last_argv is not None:
            self.run(self._last_argv, self._last_cwd, self._last_line_filter)

    def is_running(self) -> bool:
        return self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning

    def stop(self) -> None:
        if self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.kill()
            self.process.waitForFinished(2000)
        self.process = None
        self.stop_button.setEnabled(False)

    # ---- pause / catch-up ----
    #
    # Pausing does NOT stop the underlying process -- it keeps running and
    # producing output, which is buffered here instead of being appended to
    # the visible text, so a fast-scrolling live tail can be held still to
    # read without losing anything. "Catch up" flushes that buffer without
    # necessarily leaving pause mode, so you can jump to the latest output
    # and then keep reading from there without it immediately scrolling
    # away again.

    def _toggle_pause(self) -> None:
        self._paused = not self._paused
        self.pause_button.setText("Resume" if self._paused else "Pause")
        if not self._paused:
            self._flush_pending()

    def _catch_up(self) -> None:
        self._flush_pending()

    def _flush_pending(self) -> None:
        if self._pending:
            self._drain_backlog()
            self.append("".join(self._pending))
            self._pending.clear()
        self.catchup_button.setEnabled(False)
        self.catchup_button.setText("Catch up (0)")

    def _emit(self, text: str) -> None:
        """Routes all output -- live stdout AND the finished/error banners
        below -- through the same pause-aware path, so pausing genuinely
        holds the view still with nothing slipping through, and catch-up
        reveals everything (including "process exited") in order."""
        if self._paused:
            self._pending.append(text)
            if len(self._pending) > _PENDING_MAX_CHUNKS:
                del self._pending[:len(self._pending) - _PENDING_MAX_CHUNKS]
            self.catchup_button.setEnabled(True)
            buffered_lines = sum(chunk.count("\n") for chunk in self._pending)
            self.catchup_button.setText(f"Catch up ({buffered_lines})")
        else:
            self._enqueue(text)

    def _enqueue(self, text: str) -> None:
        self._backlog += text
        if len(self._backlog) > _BACKLOG_MAX_CHARS:
            self._backlog = self._backlog[-_BACKLOG_MAX_CHARS:]
            self._dropped = True
        if not self._render_timer.isActive():
            self._render_timer.start()

    def _render_slice(self) -> None:
        if not self._backlog:
            self._render_timer.stop()
            return
        if self._dropped:
            self._dropped = False
            self.append("\n[... output too fast to display; older lines skipped ...]\n")
        chunk, self._backlog = (self._backlog[:_RENDER_SLICE_CHARS],
                                self._backlog[_RENDER_SLICE_CHARS:])
        self.append(chunk)
        if not self._backlog:
            self._render_timer.stop()

    def _drain_backlog(self) -> None:
        """Render whatever is queued now (bounded by _BACKLOG_MAX_CHARS), so
        a banner emitted next lands after all the output, in order."""
        self._render_timer.stop()
        if self._backlog:
            if self._dropped:
                self._dropped = False
                self.append("\n[... output too fast to display; older lines skipped ...]\n")
            chunk, self._backlog = self._backlog, ""
            self.append(chunk)

    def _on_output(self) -> None:
        if self.process is None:
            return
        data = self.process.readAllStandardOutput().data().decode(errors="replace")
        # line_received always gets the full, unfiltered chunk -- other
        # consumers (e.g. page_health.py's content-sync activity parser)
        # want everything regardless of what the visible panel is
        # currently filtered down to.
        self.line_received.emit(data)
        if self._line_filter is not None:
            data = self._filter_lines(data)
            if not data:
                return
        self._emit(data)

    def _filter_lines(self, chunk: str) -> str:
        """Keeps only whole lines that pass self._line_filter (see
        core.line_buffer for the chunk-boundary handling)."""
        kept = [line for line in self._filter_buffer.feed(chunk) if self._line_filter(line)]
        return "\n".join(kept) + "\n" if kept else ""

    def _on_finished(self, exit_code: int, _exit_status) -> None:
        if self._suppress_finish:
            return  # a process we killed to start a new one -- not a real completion
        self._drain_backlog()
        self._emit(f"\n\n[process exited with code {exit_code}]\n")
        self.stop_button.setEnabled(False)
        self.finished.emit(exit_code)

    def _on_error(self, error) -> None:
        if self._suppress_finish:
            return
        self._drain_backlog()
        self._emit(f"\n[process error: {error}]\n")
        self.stop_button.setEnabled(False)
