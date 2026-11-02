"""Unit tests for core.shipper_health (Qt-free)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import shipper_health as sh  # noqa: E402

OK = "vector_outbound-1  | 2026-10-17T08:00:01.100Z  INFO vector::topology::builder: Healthcheck passed.\n"
RETRY = ("vector_outbound-1  | 2026-10-17T08:05:00.000Z  WARN sink{component_id=siem}:request{request_id=1}: "
         "vector::sinks::util::retries: Retrying after error. error=Request failed: tls handshake eof "
         "internal_log_rate_limit=true\n")
NOISE = "vector_outbound-1  | 2026-10-17T08:00:00Z INFO vector: Vector has started.\n"


class AnalyseTests(unittest.TestCase):
    def test_healthy(self):
        h = sh.analyse_logs(NOISE + OK)
        self.assertEqual(h.verdict, sh.DELIVERING)
        self.assertEqual(h.last_ok, "2026-10-17T08:00:01.100Z")
        self.assertEqual(h.error_count, 0)

    def test_failing_after_ok(self):
        h = sh.analyse_logs(OK + RETRY)
        self.assertEqual(h.verdict, sh.FAILING)
        self.assertEqual(h.error_count, 1)
        self.assertIn("tls handshake eof", h.last_error_text)
        self.assertNotIn("internal_log_rate_limit", h.last_error_text)

    def test_recovered(self):
        h = sh.analyse_logs(RETRY + OK)
        self.assertEqual(h.verdict, sh.DELIVERING)
        self.assertIn("1 earlier error", h.detail)

    def test_unconfirmed_with_no_signal(self):
        self.assertEqual(sh.analyse_logs(NOISE).verdict, sh.UNCONFIRMED)
        self.assertEqual(sh.analyse_logs("").verdict, sh.UNCONFIRMED)

    def test_ansi_and_prefix_stripped(self):
        h = sh.analyse_logs("\x1b[36mvector_outbound-1  |\x1b[0m 2026-10-17T08:00:01Z Healthcheck passed.\n")
        self.assertEqual(h.verdict, sh.DELIVERING)

    def test_evidence_capped_newest_last(self):
        h = sh.analyse_logs(RETRY * 30 + OK)
        self.assertEqual(len(h.evidence), 12)
        self.assertTrue(h.evidence[-1].ok)


class CombineTests(unittest.TestCase):
    def test_disabled_wins(self):
        h = sh.combine(False, "ELK_ENABLED is not true", None, OK)
        self.assertEqual(h.verdict, sh.DISABLED)
        self.assertIn("ELK_ENABLED", h.detail)

    def test_container_down(self):
        self.assertEqual(sh.combine(True, "", None, OK).verdict, sh.STOPPED)
        exited = {"State": "exited", "ExitCode": "1"}
        self.assertEqual(sh.combine(True, "", exited, OK).verdict, sh.STOPPED)

    def test_running_uses_logs(self):
        running = {"State": "running", "Health": ""}
        self.assertEqual(sh.combine(True, "", running, OK + RETRY).verdict, sh.FAILING)

    def test_index_stats(self):
        text = ('[{"index":"honeypot-nginx_access-2026.10.17","docs.count":"166","store.size":"1mb"},'
                '{"index":"honeypot-suricata-2026.10.17","docs.count":"41","store.size":"300kb"}]')
        stats = sh.parse_index_stats(text)
        self.assertEqual(stats["total_docs"], 207)
        self.assertEqual(stats["index_count"], 2)
        self.assertEqual(stats["indices"][0][0], "honeypot-nginx_access-2026.10.17")

    def test_index_stats_bad_input(self):
        self.assertIsNone(sh.parse_index_stats("missing authentication credentials"))
        self.assertIsNone(sh.parse_index_stats('{"error":"x"}'))
        self.assertEqual(sh.parse_index_stats("[]")["total_docs"], 0)

    def test_aggregator_state(self):
        self.assertEqual(sh.aggregator_state([{"Service": "vector_inbound", "State": "running", "Health": "healthy"}]),
                         "healthy")
        self.assertEqual(sh.aggregator_state([{"Service": "es01", "State": "running"}]), "unknown")
        self.assertEqual(sh.aggregator_state([]), "unknown")


class _FakeTarget:
    """Minimal stand-in for docker_ctl.Target: aggregator_state reads .ps(),
    clear_all_documents reads .ps() and .build()."""
    def __init__(self, reachable: bool):
        self._reachable = reachable

    def ps(self):
        return [{"Service": "vector_inbound", "State": "running", "Health": "healthy"}] if self._reachable else []

    def build(self, *args):
        return (["docker", "compose", *args], "/cwd")


class ClearAllDocumentsTests(unittest.TestCase):
    """core.shipper_health.clear_all_documents -- the SIEM-wipe the Log
    Pipeline and SIEM Analytics pages both dispatch to."""

    def setUp(self):
        self._orig_creds = sh.get_elastic_credentials
        self._orig_exec = sh._es_exec
        sh.get_elastic_credentials = lambda state: ("elastic", "pw")

    def tearDown(self):
        sh.get_elastic_credentials = self._orig_creds
        sh._es_exec = self._orig_exec

    def test_unreachable_siem(self):
        deleted, err = sh.clear_all_documents([_FakeTarget(False)], state=None)
        self.assertIsNone(deleted)
        self.assertIn("not reachable", err)

    def test_missing_credentials(self):
        sh.get_elastic_credentials = lambda state: None
        deleted, err = sh.clear_all_documents([_FakeTarget(True)], state=None)
        self.assertIsNone(deleted)
        self.assertIn("credentials", err)

    def test_success_returns_deleted_count(self):
        sh._es_exec = lambda argv, cwd: '{"deleted": 1234, "total": 1234, "failures": []}'
        deleted, err = sh.clear_all_documents([_FakeTarget(True)], state=None)
        self.assertEqual(deleted, 1234)
        self.assertIsNone(err)

    def test_unexpected_response_is_surfaced(self):
        sh._es_exec = lambda argv, cwd: "missing authentication credentials"
        deleted, err = sh.clear_all_documents([_FakeTarget(True)], state=None)
        self.assertIsNone(deleted)
        self.assertIn("Unexpected response", err)

    def test_picks_the_reachable_target(self):
        captured = {}

        def fake_exec(argv, cwd):
            captured["argv"] = argv
            return '{"deleted": 0}'

        sh._es_exec = fake_exec
        # First target unreachable, second reachable -> must use the second.
        sh.clear_all_documents([_FakeTarget(False), _FakeTarget(True)], state=None)
        self.assertIn("_delete_by_query", " ".join(captured["argv"]))


if __name__ == "__main__":
    unittest.main()
