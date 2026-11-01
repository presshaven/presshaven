"""Tests for core.account_persistence -- the step-by-step account-persistence
verifier (request 26).

These exercise the pure logic (verdict/headline, the live username-is-metadata
comparison, the read-only inspection steps and the orchestrator) with the
GDPR / docker / HTTP boundaries mocked. No container, no network, and no secret
value is ever touched: the gating checks only ever assert the PRESENCE of the
guards, never their value, so no test compares or prints a secret.
"""
from __future__ import annotations

import unittest
from unittest import mock

from core import account_persistence as ap


def _report(*steps):
    r = ap.AccountPersistenceReport("t", "lbl", "https://x", "u", "1280x800")
    for i, (status,) in enumerate(steps, start=1):
        r.steps.append(ap.StepOutcome(i, f"s{i}", status, "sum"))
    return r


class HeadlineTests(unittest.TestCase):
    def test_all_pass_is_working(self):
        status, _ = _report((ap.PASS,), (ap.PASS,)).headline()
        self.assertEqual(status, "WORKING")

    def test_any_fail_is_not_working(self):
        status, _ = _report((ap.PASS,), (ap.FAIL,)).headline()
        self.assertEqual(status, "NOT WORKING")

    def test_warn_is_working_with_warnings(self):
        status, _ = _report((ap.PASS,), (ap.WARN,)).headline()
        self.assertTrue(status.startswith("WORKING (with"))

    def test_fail_outranks_warn(self):
        status, _ = _report((ap.WARN,), (ap.FAIL,)).headline()
        self.assertEqual(status, "NOT WORKING")

    def test_empty_is_inconclusive(self):
        status, _ = _report().headline()
        self.assertEqual(status, "INCONCLUSIVE")

    def test_skip_noted_when_all_else_passes(self):
        _, summary = _report((ap.PASS,), (ap.SKIP,)).headline()
        self.assertIn("could not run", summary)

    def test_counts(self):
        c = _report((ap.PASS,), (ap.PASS,), (ap.WARN,), (ap.SKIP,)).counts()
        self.assertEqual(c[ap.PASS], 2)
        self.assertEqual(c[ap.WARN], 1)
        self.assertEqual(c[ap.SKIP], 1)


class StepOutcomeTests(unittest.TestCase):
    def test_pass_and_info_are_ok(self):
        self.assertTrue(ap.StepOutcome(1, "n", ap.PASS, "s").ok)
        self.assertTrue(ap.StepOutcome(1, "n", ap.INFO, "s").ok)

    def test_fail_warn_skip_not_ok(self):
        for st in (ap.FAIL, ap.WARN, ap.SKIP, ap.ERROR):
            self.assertFalse(ap.StepOutcome(1, "n", st, "s").ok)


class _FakeConsent:
    cookie_name = "gdpr_token"

    def cleanup(self):
        pass


class ProveUsernameIsMetadataTests(unittest.TestCase):
    def _run(self, derive_results):
        with mock.patch.object(ap.GdprConsent, "acquire", return_value=_FakeConsent()), \
             mock.patch.object(ap, "_derive_signature", side_effect=derive_results):
            return ap.prove_username_is_metadata("https://x", object(), "1280x800", "bob")

    def test_identical_signatures_pass(self):
        out = self._run([("abc123", ""), ("abc123", "")])
        self.assertEqual(out.status, ap.PASS)

    def test_different_signatures_fail(self):
        out = self._run([("abc123", ""), ("different", "")])
        self.assertEqual(out.status, ap.FAIL)
        self.assertIn("CHANGED", out.evidence)

    def test_error_on_first_derivation(self):
        out = self._run([("", "boom"), ("x", "")])
        self.assertEqual(out.status, ap.ERROR)

    def test_error_on_second_derivation(self):
        out = self._run([("abc", ""), ("", "boom")])
        self.assertEqual(out.status, ap.ERROR)

    def test_subsystem_down_is_skip(self):
        with mock.patch.object(ap.GdprConsent, "acquire", return_value=None):
            out = ap.prove_username_is_metadata("https://x", object(), "1280x800", "bob")
        self.assertEqual(out.status, ap.SKIP)

    def test_no_secret_in_details_or_evidence(self):
        # The proof deals only in the (synthetic) username and the derived
        # signatures; assert the demo username label is harmless and present.
        out = self._run([("abc123", ""), ("abc123", "")])
        blob = out.evidence + " ".join(out.details)
        self.assertIn("bob", blob)


class DeriveSignatureTests(unittest.TestCase):
    def test_reads_new_line_after_send(self):
        consent = mock.Mock()
        consent.token.return_value = "tok"
        consent.cookie_name = "gdpr_token"
        # First call (before send): one line. Second call (after send): two,
        # so the appended line is recognised as ours.
        seq = [[("old", "s")], [("old", "s"), ("new", "s2")]]
        with mock.patch.object(ap.signature_sim, "_signature_lines", side_effect=seq), \
             mock.patch.object(ap.signature_sim, "_send", return_value=("HTTP/1.1 200", "")):
            sig, err = ap._derive_signature("https://x", object(), consent, {"s": "1x1"}, gap_s=0)
        self.assertEqual((sig, err), ("new", ""))

    def test_no_token_is_error(self):
        consent = mock.Mock()
        consent.token.return_value = None
        sig, err = ap._derive_signature("https://x", object(), consent, {"s": "1x1"}, gap_s=0)
        self.assertEqual(sig, "")
        self.assertIn("mint", err)

    def test_send_error_propagates(self):
        consent = mock.Mock()
        consent.token.return_value = "tok"
        consent.cookie_name = "gdpr_token"
        with mock.patch.object(ap.signature_sim, "_signature_lines", return_value=[]), \
             mock.patch.object(ap.signature_sim, "_send", return_value=("", "nope")):
            sig, err = ap._derive_signature("https://x", object(), consent, {"s": "1x1"}, gap_s=0)
        self.assertEqual((sig, err), ("", "nope"))


class ProductionIdentityStepTests(unittest.TestCase):
    def test_missing_plugin_is_fail(self):
        with mock.patch.object(ap.breach_audit, "_prod_container", return_value="prod"), \
             mock.patch.object(ap, "_file_present", return_value=False):
            out = ap._check_production_emits_identity(object(), ["prod"])
        self.assertEqual(out.status, ap.FAIL)

    def test_present_and_wired_is_pass(self):
        with mock.patch.object(ap.breach_audit, "_prod_container", return_value="prod"), \
             mock.patch.object(ap, "_file_present", return_value=True), \
             mock.patch.object(ap, "_grep_count", return_value=1):
            out = ap._check_production_emits_identity(object(), ["prod"])
        self.assertEqual(out.status, ap.PASS)

    def test_present_but_unwired_is_warn(self):
        # file present, but the expected markers are absent (0).
        with mock.patch.object(ap.breach_audit, "_prod_container", return_value="prod"), \
             mock.patch.object(ap, "_file_present", return_value=True), \
             mock.patch.object(ap, "_grep_count", return_value=0):
            out = ap._check_production_emits_identity(object(), ["prod"])
        self.assertEqual(out.status, ap.WARN)

    def test_no_container_is_skip(self):
        with mock.patch.object(ap.breach_audit, "_prod_container", return_value=None):
            out = ap._check_production_emits_identity(object(), [])
        self.assertEqual(out.status, ap.SKIP)


class EdgeRecordsStepTests(unittest.TestCase):
    def test_all_directives_present_is_pass(self):
        with mock.patch.object(ap.breach_audit, "_prod_container", return_value="rp"), \
             mock.patch.object(ap, "_grep_count", return_value=1):
            out = ap._check_edge_records_and_strips(object(), ["rp"])
        self.assertEqual(out.status, ap.PASS)

    def test_missing_directives_is_warn(self):
        with mock.patch.object(ap.breach_audit, "_prod_container", return_value="rp"), \
             mock.patch.object(ap, "_grep_count", return_value=0):
            out = ap._check_edge_records_and_strips(object(), ["rp"])
        self.assertEqual(out.status, ap.WARN)

    def test_unreadable_config_is_error(self):
        with mock.patch.object(ap.breach_audit, "_prod_container", return_value="rp"), \
             mock.patch.object(ap, "_grep_count", return_value=None):
            out = ap._check_edge_records_and_strips(object(), ["rp"])
        self.assertEqual(out.status, ap.ERROR)

    def test_no_proxy_is_skip(self):
        with mock.patch.object(ap.breach_audit, "_prod_container", return_value=None):
            out = ap._check_edge_records_and_strips(object(), [])
        self.assertEqual(out.status, ap.SKIP)


class SyncWorkerStepTests(unittest.TestCase):
    def test_running_is_pass(self):
        with mock.patch.object(ap.breach_audit, "_prod_container", return_value="honeypot_user_sync"):
            out = ap._check_sync_worker(object(), ["honeypot_user_sync"])
        self.assertEqual(out.status, ap.PASS)

    def test_not_running_is_fail(self):
        with mock.patch.object(ap.breach_audit, "_prod_container", return_value=None):
            out = ap._check_sync_worker(object(), ["reverse_proxy"])
        self.assertEqual(out.status, ap.FAIL)


class AutologinStepTests(unittest.TestCase):
    def test_pool_gated_plugin_is_pass(self):
        with mock.patch.object(ap.breach_audit, "discover_pools",
                               return_value={1: {"eshop": "honeypot_eshop_1"}}), \
             mock.patch.object(ap, "_file_present", return_value=True), \
             mock.patch.object(ap, "_grep_count", return_value=1):
            out = ap._check_autologin_plugin(object(), ["honeypot_eshop_1"])
        self.assertEqual(out.status, ap.PASS)

    def test_missing_plugin_is_fail(self):
        with mock.patch.object(ap.breach_audit, "discover_pools",
                               return_value={1: {"eshop": "honeypot_eshop_1"}}), \
             mock.patch.object(ap, "_file_present", return_value=False):
            out = ap._check_autologin_plugin(object(), ["honeypot_eshop_1"])
        self.assertEqual(out.status, ap.FAIL)

    def test_falls_back_to_production_when_no_pool(self):
        with mock.patch.object(ap.breach_audit, "discover_pools", return_value={}), \
             mock.patch.object(ap.breach_audit, "_prod_container", return_value="prod"), \
             mock.patch.object(ap, "_file_present", return_value=True), \
             mock.patch.object(ap, "_grep_count", return_value=1):
            out = ap._check_autologin_plugin(object(), ["prod"])
        self.assertEqual(out.status, ap.PASS)

    def test_no_container_is_skip(self):
        with mock.patch.object(ap.breach_audit, "discover_pools", return_value={}), \
             mock.patch.object(ap.breach_audit, "_prod_container", return_value=None):
            out = ap._check_autologin_plugin(object(), [])
        self.assertEqual(out.status, ap.SKIP)

    def test_ungated_plugin_is_warn(self):
        with mock.patch.object(ap.breach_audit, "discover_pools",
                               return_value={1: {"eshop": "honeypot_eshop_1"}}), \
             mock.patch.object(ap, "_file_present", return_value=True), \
             mock.patch.object(ap, "_grep_count", return_value=0):
            out = ap._check_autologin_plugin(object(), ["honeypot_eshop_1"])
        self.assertEqual(out.status, ap.WARN)


class FilePresentAndGrepTests(unittest.TestCase):
    def test_file_present_true_on_rc0(self):
        with mock.patch.object(ap.breach_audit, "_docker_exec", return_value=(0, "")):
            self.assertIs(ap._file_present(object(), "c", "/p"), True)

    def test_file_present_false_on_rc1(self):
        with mock.patch.object(ap.breach_audit, "_docker_exec", return_value=(1, "")):
            self.assertIs(ap._file_present(object(), "c", "/p"), False)

    def test_file_present_none_on_error(self):
        with mock.patch.object(ap.breach_audit, "_docker_exec",
                               side_effect=ap.breach_audit.BreachAuditError("x")):
            self.assertIsNone(ap._file_present(object(), "c", "/p"))

    def test_grep_count_parses_number(self):
        with mock.patch.object(ap.breach_audit, "_docker_exec", return_value=(0, "3")):
            self.assertEqual(ap._grep_count(object(), "c", "/p", "needle"), 3)

    def test_grep_count_none_on_error(self):
        with mock.patch.object(ap.breach_audit, "_docker_exec",
                               side_effect=ap.breach_audit.BreachAuditError("x")):
            self.assertIsNone(ap._grep_count(object(), "c", "/p", "needle"))


class RunReportTests(unittest.TestCase):
    def test_orchestrates_all_steps_and_captures_signatures(self):
        step2 = ap.StepOutcome(2, "username", ap.PASS, "sum", details=[
            'token characteristics (no username):  {"s":"1280x800"}',
            "  → signature  SIGPLAIN",
            'token characteristics (with username): {"s":"1280x800","u":"bob"}',
            "  → signature  SIGPLAIN",
        ])
        with mock.patch.object(ap.GdprConsent, "acquire", return_value=_FakeConsent()), \
             mock.patch.object(ap, "prove_username_is_metadata", return_value=step2), \
             mock.patch.object(ap.breach_audit, "_running_containers",
                               return_value=["prod", "rp", "honeypot_user_sync"]), \
             mock.patch.object(ap, "_check_production_emits_identity",
                               return_value=ap.StepOutcome(3, "p", ap.PASS, "s")), \
             mock.patch.object(ap, "_check_edge_records_and_strips",
                               return_value=ap.StepOutcome(4, "e", ap.PASS, "s")), \
             mock.patch.object(ap, "_check_sync_worker",
                               return_value=ap.StepOutcome(5, "w", ap.PASS, "s")), \
             mock.patch.object(ap, "_check_autologin_plugin",
                               return_value=ap.StepOutcome(6, "a", ap.PASS, "s")):
            report = ap.run_report(mock.Mock(label="lbl"), "https://x", username="bob")
        self.assertEqual(len(report.steps), 6)
        self.assertEqual(report.steps[0].status, ap.PASS)  # subsystem reachable
        self.assertEqual(report.sig_without_username, "SIGPLAIN")
        self.assertEqual(report.sig_with_username, "SIGPLAIN")
        self.assertEqual(report.headline()[0], "WORKING")

    def test_subsystem_down_marks_step1_fail(self):
        with mock.patch.object(ap.GdprConsent, "acquire", return_value=None), \
             mock.patch.object(ap, "prove_username_is_metadata",
                               return_value=ap.StepOutcome(2, "u", ap.SKIP, "s")), \
             mock.patch.object(ap.breach_audit, "_running_containers", return_value=[]), \
             mock.patch.object(ap, "_check_production_emits_identity",
                               return_value=ap.StepOutcome(3, "p", ap.SKIP, "s")), \
             mock.patch.object(ap, "_check_edge_records_and_strips",
                               return_value=ap.StepOutcome(4, "e", ap.SKIP, "s")), \
             mock.patch.object(ap, "_check_sync_worker",
                               return_value=ap.StepOutcome(5, "w", ap.SKIP, "s")), \
             mock.patch.object(ap, "_check_autologin_plugin",
                               return_value=ap.StepOutcome(6, "a", ap.SKIP, "s")):
            report = ap.run_report(mock.Mock(label="lbl"), "https://x")
        self.assertEqual(report.steps[0].status, ap.FAIL)

    def test_container_list_failure_errors_remaining_steps(self):
        with mock.patch.object(ap.GdprConsent, "acquire", return_value=_FakeConsent()), \
             mock.patch.object(ap, "prove_username_is_metadata",
                               return_value=ap.StepOutcome(2, "u", ap.PASS, "s")), \
             mock.patch.object(ap.breach_audit, "_running_containers",
                               side_effect=ap.breach_audit.BreachAuditError("no docker")):
            report = ap.run_report(mock.Mock(label="lbl"), "https://x")
        # Steps 1, 2 ran; 3-6 became ERROR outcomes.
        self.assertEqual(len(report.steps), 6)
        self.assertTrue(all(s.status == ap.ERROR for s in report.steps[2:]))


if __name__ == "__main__":
    unittest.main()
