"""Tests for the pure-logic bits of core.redis_inspect -- specifically the
admin-host threat-score readout that the WordPress Studio page polls so
administrators are warned if their editing session gets mis-routed into a
honeypot."""
from __future__ import annotations

import unittest
from unittest import mock

from core import redis_inspect as ri


class IsPrivateIpTests(unittest.TestCase):
    def test_private_ranges(self):
        for ip in ("10.0.0.5", "127.0.0.1", "172.16.0.1", "172.31.255.254",
                   "192.168.1.1"):
            self.assertTrue(ri._is_private_ip(ip), ip)

    def test_public_and_junk(self):
        for ip in ("8.8.8.8", "172.15.0.1", "172.32.0.1", "193.168.1.1",
                   "", "not-an-ip", "::1"):
            self.assertFalse(ri._is_private_ip(ip), ip)


class LocalThreatScoreTests(unittest.TestCase):
    def _patch(self, scores):
        return mock.patch.object(ri, "get_risk_scores", return_value=scores)

    def test_zero_when_no_local_ip(self):
        with self._patch({"8.8.8.8": 95, "1.1.1.1": 40}):
            self.assertEqual(ri.local_threat_score(None), 0)

    def test_zero_when_empty(self):
        with self._patch({}):
            self.assertEqual(ri.local_threat_score(None), 0)

    def test_worst_local_score_wins(self):
        with self._patch({"10.0.0.5": 30, "192.168.1.9": 82, "8.8.8.8": 100}):
            # the public 100 is ignored; the worst *local* score is reported
            self.assertEqual(ri.local_threat_score(None), 82)


if __name__ == "__main__":
    unittest.main()
