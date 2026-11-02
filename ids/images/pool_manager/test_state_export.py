"""Unit tests for state_export.StateExporter (dependency-free, runs anywhere).

It ships the pool manager's live state to the edge log pipeline as JSONL; these
check it is a safe no-op when disabled, throttles snapshots, writes every event,
flattens non-scalar fields so Elasticsearch mappings stay clean, caps file size,
and never raises on a bad directory.
"""
import json
import os
import tempfile
import time
import unittest

import state_export


class Disabled(unittest.TestCase):
    def test_no_directory_is_a_noop(self):
        exp = state_export.StateExporter(None)
        self.assertFalse(exp.enabled)
        self.assertFalse(exp.snapshot({"pools": 1}))
        exp.event({"type": "build"})   # must not raise

    def test_unusable_directory_disables_quietly(self):
        msgs = []
        # A path under a file (not a dir) can't be created -> disabled, logged.
        with tempfile.NamedTemporaryFile() as f:
            exp = state_export.StateExporter(os.path.join(f.name, "sub"),
                                             log=msgs.append)
        self.assertFalse(exp.enabled)
        self.assertTrue(msgs)


class Snapshots(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pfwtest_state_")
        self.exp = state_export.StateExporter(self.dir, snapshot_interval=1000.0)

    def _lines(self, name):
        path = os.path.join(self.dir, name)
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [json.loads(l) for l in fh if l.strip()]

    def test_snapshot_writes_a_tagged_line(self):
        self.assertTrue(self.exp.snapshot({"pools": 3, "ready": 2}))
        lines = self._lines(state_export.StateExporter.SNAPSHOT_FILE)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["kind"], "pool_state")
        self.assertEqual(lines[0]["pools"], 3)
        self.assertIn("ts", lines[0])

    def test_snapshot_is_throttled_but_force_bypasses(self):
        self.assertTrue(self.exp.snapshot({"pools": 1}))
        self.assertFalse(self.exp.snapshot({"pools": 2}))   # within the interval
        self.assertTrue(self.exp.snapshot({"pools": 3}, force=True))
        pools = [l["pools"] for l in self._lines(state_export.StateExporter.SNAPSHOT_FILE)]
        self.assertEqual(pools, [1, 3])

    def test_short_interval_allows_successive_snapshots(self):
        exp = state_export.StateExporter(self.dir, snapshot_interval=0.0)
        self.assertTrue(exp.snapshot({"n": 1}))
        self.assertTrue(exp.snapshot({"n": 2}))
        self.assertEqual(len(self._lines(state_export.StateExporter.SNAPSHOT_FILE)), 2)

    def test_event_written_every_time_and_scalarized(self):
        self.exp.event({"type": "build", "at": 1700000000.5, "pool": 4,
                        "phases": [["db", 1.2], ["wp", 3.4]]})
        self.exp.event({"type": "handoff", "at": 1700000001.0, "pool": 4, "waited": 2.5})
        lines = self._lines(state_export.StateExporter.EVENTS_FILE)
        self.assertEqual([l["type"] for l in lines], ["build", "handoff"])
        self.assertEqual(lines[0]["kind"], "pool_event")
        # The nested phases list must be stored as a JSON string, not an array,
        # so it can't lock/conflict an Elasticsearch mapping.
        self.assertIsInstance(lines[0]["phases"], str)
        self.assertEqual(json.loads(lines[0]["phases"]), [["db", 1.2], ["wp", 3.4]])
        self.assertEqual(lines[1]["waited"], 2.5)

    def test_event_ts_matches_the_event_time(self):
        self.exp.event({"type": "build", "at": 1700000000.0})
        line = self._lines(state_export.StateExporter.EVENTS_FILE)[0]
        # ts is derived from .at, so it is the 2023 event time, not "now".
        self.assertTrue(line["ts"].startswith("2023-11-14T"), line["ts"])

    def test_size_cap_resets_the_file(self):
        exp = state_export.StateExporter(self.dir, snapshot_interval=0.0, max_bytes=200)
        for i in range(50):
            exp.snapshot({"i": i, "pad": "x" * 50})
        size = os.path.getsize(os.path.join(self.dir, state_export.StateExporter.SNAPSHOT_FILE))
        # The file was reset at least once instead of growing unbounded, so it
        # is far below what 50 un-capped lines would be.
        self.assertLess(size, 50 * 70)

    def test_ts_is_iso_utc(self):
        self.exp.snapshot({"pools": 1})
        ts = self._lines(state_export.StateExporter.SNAPSHOT_FILE)[0]["ts"]
        self.assertTrue(ts.endswith("Z"))
        self.assertEqual(ts[10], "T")


if __name__ == "__main__":
    unittest.main()
