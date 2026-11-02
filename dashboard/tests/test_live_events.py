"""Unit tests for core.live_events (Qt-free)."""
from __future__ import annotations

import csv
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import live_events  # noqa: E402
from core.pattern_log_parser import (  # noqa: E402
    COLOR_HIGH, COLOR_INFO, COLOR_LOW, COLOR_MED, PatternEvent,
)


class SeverityTests(unittest.TestCase):
    def test_colour_mapping(self):
        self.assertEqual(live_events.severity(COLOR_HIGH), "high")
        self.assertEqual(live_events.severity(COLOR_MED), "medium")
        self.assertEqual(live_events.severity(COLOR_LOW), "low")
        self.assertEqual(live_events.severity(COLOR_INFO), "info")
        self.assertEqual(live_events.severity("#123456"), "info")

    def test_rank_orders_severities(self):
        self.assertLess(live_events.severity_rank(COLOR_LOW), live_events.severity_rank(COLOR_HIGH))


class HoneypotDiversionTests(unittest.TestCase):
    def test_outcome_with_honeypot_label_is_a_visit(self):
        self.assertTrue(live_events.is_honeypot_diversion("outcome", "Routed to HONEYPOT"))
        self.assertTrue(live_events.is_honeypot_diversion("outcome", "routed to honeypot pool 2"))

    def test_non_outcome_or_non_honeypot_is_not(self):
        self.assertFalse(live_events.is_honeypot_diversion("signal", "Routed to HONEYPOT"))
        self.assertFalse(live_events.is_honeypot_diversion("outcome", "Served normally"))
        self.assertFalse(live_events.is_honeypot_diversion("outcome", None))
        self.assertFalse(live_events.is_honeypot_diversion("outcome", ""))


class FilterTests(unittest.TestCase):
    def test_all_passes_everything(self):
        self.assertTrue(live_events.matches("all", "signal", "x", COLOR_INFO))

    def test_medium_and_high(self):
        self.assertFalse(live_events.matches("medium", "signal", "x", COLOR_LOW))
        self.assertTrue(live_events.matches("medium", "signal", "x", COLOR_MED))
        self.assertTrue(live_events.matches("medium", "signal", "x", COLOR_HIGH))
        self.assertFalse(live_events.matches("high", "signal", "x", COLOR_MED))

    def test_diversions_and_outcomes(self):
        self.assertTrue(live_events.matches("diversions", "outcome", "Routed to HONEYPOT", COLOR_HIGH))
        self.assertFalse(live_events.matches("diversions", "outcome", "Routed to PRODUCTION", COLOR_LOW))
        self.assertTrue(live_events.matches("outcomes", "outcome", "x", COLOR_LOW))
        self.assertFalse(live_events.matches("outcomes", "signal", "x", COLOR_LOW))

    def test_text_match(self):
        self.assertTrue(live_events.text_matches("", "anything"))
        self.assertTrue(live_events.text_matches("SQL", "sql injection", "d"))
        self.assertFalse(live_events.text_matches("xss", "sql injection", "d"))


class BackfillTests(unittest.TestCase):
    def test_rfc3339_to_epoch(self):
        import calendar
        self.assertEqual(live_events.rfc3339_to_epoch("2026-10-17T07:22:59.885Z"),
                         calendar.timegm((2026, 10, 17, 7, 22, 59, 0, 0, 0)))
        self.assertEqual(live_events.rfc3339_to_epoch(None), 0)
        self.assertEqual(live_events.rfc3339_to_epoch("nonsense"), 0)

    def test_parse_backfill_uses_log_timestamps_and_skips_noise(self):
        text = (
            "reverse_proxy-1  | 2026-10-17T07:22:59.100Z [LOCATION / HEADER] route_decision='honeypot' risk_score='90'\n"
            "reverse_proxy-1  | 2026-10-17T07:23:00.000Z SESSION DEBUG nothing to see\n"
        )
        rows = live_events.parse_backfill(text)
        self.assertEqual(len(rows), 1)
        ts, event = rows[0]
        self.assertEqual(ts, live_events.rfc3339_to_epoch("2026-10-17T07:22:59Z"))
        self.assertEqual(event.kind, "outcome")

    def test_parse_backfill_empty(self):
        self.assertEqual(live_events.parse_backfill(""), [])


class CsvTests(unittest.TestCase):
    def test_csv_round_trip(self):
        text = live_events.to_csv([(0, "high", "outcome", "Routed, to HONEYPOT", 'a "b"')])
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(rows[0], ["time", "severity", "kind", "label", "detail"])
        self.assertEqual(rows[1], ["", "high", "outcome", "Routed, to HONEYPOT", 'a "b"'])


def _sig(label, color, ts=None):
    return PatternEvent("signal", label, "", color, timestamp=ts)


def _outcome(label, score, color, ts=None):
    return PatternEvent("outcome", label, f"Score: {score}", color, score=score, timestamp=ts)


class GroupingTests(unittest.TestCase):
    def test_epoch_float_keeps_fraction(self):
        self.assertAlmostEqual(
            live_events.rfc3339_to_epoch_float("2026-10-17T07:22:59.885Z"),
            live_events.rfc3339_to_epoch("2026-10-17T07:22:59Z") + 0.885, places=3)
        self.assertEqual(live_events.rfc3339_to_epoch_float(None), 0.0)
        self.assertEqual(live_events.rfc3339_to_epoch_float("nope"), 0.0)

    def test_group_events_splits_on_outcome(self):
        stream = [
            (1, _sig("SQLi (+40)", COLOR_HIGH)),
            (1, _sig("Automation (+10)", COLOR_MED)),
            (1, _outcome("Routed to HONEYPOT", 50, COLOR_HIGH)),
            (2, _sig("UA (+5)", COLOR_LOW)),
            (2, _outcome("Routed to PRODUCTION", 5, COLOR_LOW)),
        ]
        groups = live_events.group_events(stream)
        self.assertEqual(len(groups), 2)
        g0 = groups[0]
        self.assertEqual(g0.title, "Routed to HONEYPOT")
        self.assertEqual(g0.score, 50)
        self.assertTrue(g0.has_outcome)
        self.assertEqual(g0.color, COLOR_HIGH)       # worst severity in the burst
        self.assertIn("SQLi (+40)", g0.signals)
        self.assertIn("Automation (+10)", g0.signals)

    def test_trailing_burst_is_open_group(self):
        stream = [
            (1, _outcome("Routed to PRODUCTION", 0, COLOR_LOW)),
            (2, _sig("CVE match (+30)", COLOR_HIGH)),
        ]
        groups = live_events.group_events(stream)
        self.assertEqual(len(groups), 2)
        self.assertFalse(groups[1].has_outcome)
        self.assertEqual(groups[1].title, "CVE match (+30)")  # worst-so-far headline

    def test_latency_from_log_timestamps(self):
        stream = [
            (0, _sig("A (+10)", COLOR_LOW, ts="2026-10-17T07:22:59.100Z")),
            (0, _sig("B (+10)", COLOR_LOW, ts="2026-10-17T07:22:59.112Z")),
            (0, _outcome("Routed to HONEYPOT", 50, COLOR_HIGH, ts="2026-10-17T07:22:59.137Z")),
        ]
        g = live_events.group_events(stream)[0]
        self.assertEqual(g.latency_ms, 37)   # 137ms - 100ms

    def test_latency_none_without_timestamps(self):
        g = live_events.group_events([(1, _outcome("Routed to HONEYPOT", 50, COLOR_HIGH))])[0]
        self.assertIsNone(g.latency_ms)

    def test_group_matches_filters(self):
        hp = live_events.group_events([(1, _outcome("Routed to HONEYPOT", 90, COLOR_HIGH))])[0]
        prod = live_events.group_events([(1, _outcome("Routed to PRODUCTION", 0, COLOR_LOW))])[0]
        self.assertTrue(live_events.group_matches("high", hp))
        self.assertFalse(live_events.group_matches("high", prod))
        self.assertTrue(live_events.group_matches("diversions", hp))
        self.assertFalse(live_events.group_matches("diversions", prod))
        open_group = live_events.group_events([(1, _sig("x (+1)", COLOR_LOW))])[0]
        self.assertFalse(live_events.group_matches("outcomes", open_group))
        self.assertTrue(live_events.group_matches("outcomes", prod))

    def test_groups_to_csv(self):
        g = live_events.group_events([
            (0, _sig("SQLi (+40)", COLOR_HIGH, ts="2026-10-17T07:22:59.100Z")),
            (0, _outcome("Routed to HONEYPOT", 50, COLOR_HIGH, ts="2026-10-17T07:22:59.150Z")),
        ])
        text = live_events.groups_to_csv(g)
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(rows[0], ["time", "severity", "request", "score", "latency_ms", "signals", "detail"])
        self.assertEqual(rows[1][1], "high")
        self.assertEqual(rows[1][2], "Routed to HONEYPOT")
        self.assertEqual(rows[1][3], "50")
        self.assertEqual(rows[1][4], "50")


if __name__ == "__main__":
    unittest.main()
