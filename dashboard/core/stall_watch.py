"""Opt-in UI-freeze diagnostics (DASHBOARD_STALL_WATCH=1).

A QTimer on the GUI thread stamps a heartbeat; a plain Python thread checks the
stamp. If the GUI thread has not run its timer for `threshold` seconds, the GUI
thread's stack is written to logs/stall-<time>.txt -- the exact line the window
was stuck in. Off by default (no thread, no timer) so normal use pays nothing."""
from __future__ import annotations

import sys
import threading
import time
import traceback
from pathlib import Path

HEARTBEAT_MS = 100


class StallWatch:
    def __init__(self, gui_thread_id: int, log_dir: Path, threshold: float = 1.0):
        self._gui_id = gui_thread_id
        self._dir = log_dir
        self._threshold = threshold
        self._beat = time.monotonic()
        self._stop = threading.Event()
        self._reported_for = 0.0
        self.reports: list[Path] = []

    def beat(self) -> None:
        self._beat = time.monotonic()

    def start(self) -> None:
        threading.Thread(target=self._run, name="stall-watch", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def check_once(self) -> Path | None:
        """Writes a report if the GUI thread is currently stalled (one report
        per stall, not one per check). Returns the file, else None."""
        stalled = time.monotonic() - self._beat
        if stalled < self._threshold or self._reported_for == self._beat:
            return None
        frame = sys._current_frames().get(self._gui_id)
        if frame is None:
            return None
        self._reported_for = self._beat
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / f"stall-{time.strftime('%Y%m%d-%H%M%S')}.txt"
        path.write_text(f"GUI thread unresponsive for {stalled:.1f}s; stack:\n\n"
                        + "".join(traceback.format_stack(frame)))
        self.reports.append(path)
        return path

    def _run(self) -> None:
        while not self._stop.wait(0.25):
            self.check_once()
