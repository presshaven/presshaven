"""Ship the pool manager's live state to the edge log pipeline as JSONL.

The manager already keeps the whole picture of the pool system -- how many
pools are ready/free, who is waiting, what is building, the host's headroom --
in Redis, plus a latency event log (builds with per-phase timings, hand-offs
with wait times). The SIEM's Vector shipper can't reach Redis (there is no
redis client in the timberio/vector image) and runs on the edge, so instead of
the SIEM pulling this state, the manager pushes it: one JSON object per line
into two files on a shared volume that a Vector `file` source tails into
Elasticsearch (honeypot-pool_state-* for the periodic snapshot, and
honeypot-pool_events-* for the latency/lifecycle events). It is the same state
the dashboard app's Pool page shows, made queryable without the app running.

Design rules:
  * Writes NEVER raise into the manager's reconcile loop -- a broken exporter
    must not stop pools from scaling, so every write swallows its own errors.
  * Disabled (a pure no-op) unless a directory is given, so the manager's unit
    tests and any setup that doesn't ship pool state are entirely unaffected.
  * Non-scalar field values are stored as compact JSON strings, so a nested
    field (e.g. a build's phase timings) can never lock or conflict an
    Elasticsearch index mapping.
  * The snapshot file is throttled (the reconcile loop runs every few seconds,
    far more often than the state is worth sampling) and both files are capped
    in size, resetting when they grow too large -- Vector notices the file
    shrink and re-reads from the new start.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone


def _iso(epoch: float | None = None) -> str:
    """RFC 3339 / ISO 8601 UTC timestamp, matching the "%+" parse in the edge
    Vector config so the SIEM's time field is when the state was observed."""
    when = datetime.fromtimestamp(epoch if epoch is not None else time.time(), timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _scalarize(doc: dict) -> dict:
    """Return a copy with every list/dict value turned into a compact JSON
    string, so Elasticsearch only ever sees flat, unambiguous scalar fields."""
    return {k: (json.dumps(v, separators=(",", ":")) if isinstance(v, (list, dict)) else v)
            for k, v in doc.items()}


class StateExporter:
    SNAPSHOT_FILE = "pool_state.jsonl"
    EVENTS_FILE = "pool_events.jsonl"

    def __init__(self, directory: str | None, snapshot_interval: float = 30.0,
                 max_bytes: int = 20 * 1024 * 1024, log=lambda _m: None) -> None:
        self.directory = directory or ""
        self.snapshot_interval = max(0.0, snapshot_interval)
        self.max_bytes = max(0, max_bytes)
        self._log = log
        self._lock = threading.Lock()
        self._last_snapshot = 0.0
        if self.directory:
            try:
                os.makedirs(self.directory, exist_ok=True)
            except OSError as e:
                self._log(f"state export dir {self.directory!r} unusable: {e}")
                self.directory = ""

    @property
    def enabled(self) -> bool:
        return bool(self.directory)

    def _write(self, filename: str, doc: dict) -> None:
        if not self.directory:
            return
        line = json.dumps(_scalarize(doc), separators=(",", ":")) + "\n"
        path = os.path.join(self.directory, filename)
        try:
            with self._lock:
                # Cap the file: when it would grow past max_bytes, start it over.
                # Vector detects the truncation (the file is now smaller than its
                # last read offset) and resumes from the new beginning.
                mode = "a"
                if self.max_bytes and os.path.exists(path) \
                        and os.path.getsize(path) >= self.max_bytes:
                    mode = "w"
                with open(path, mode, encoding="utf-8") as fh:
                    fh.write(line)
        except OSError as e:
            self._log(f"state export write to {filename} failed: {e}")

    def snapshot(self, doc: dict, *, force: bool = False) -> bool:
        """Write one pool-state snapshot, at most once per snapshot_interval
        (``force`` bypasses the throttle). Returns whether it wrote a line."""
        if not self.directory:
            return False
        now = time.time()
        if not force and now - self._last_snapshot < self.snapshot_interval:
            return False
        self._last_snapshot = now
        self._write(self.SNAPSHOT_FILE, {"ts": _iso(now), "kind": "pool_state", **doc})
        return True

    def event(self, doc: dict) -> None:
        """Write one latency / lifecycle event (build, handoff, scaledown, ...);
        called for every event the manager logs, so each lands exactly once."""
        if not self.directory:
            return
        at = doc.get("at")
        self._write(self.EVENTS_FILE,
                    {"ts": _iso(at if isinstance(at, (int, float)) else None),
                     "kind": "pool_event", **doc})
