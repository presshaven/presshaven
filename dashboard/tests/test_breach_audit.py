"""Tests for core.breach_audit -- the attacker-perspective hardening audit.

These exercise the pure logic (result classification, pool discovery, the
headline verdict, probe command shapes, the fail-closed secret handling) with
the docker/HTTP boundaries mocked. No container, no network, no secret value is
ever touched.
"""
from __future__ import annotations

import unittest
from unittest import mock

from core import breach_audit as ba


class DiscoverPoolsTests(unittest.TestCase):
    def test_compose_and_runtime_names(self):
        names = [
            "honeypot-ids-system-v1-honeypot_eshop_2-1",
            "honeypot-ids-system-v1-honeypot_database-1",   # pool 1 of db layer
            "honeypot_eshop_5",                             # runtime pool
            "honeypot_database_5",
            "production_eshop",
            "reverse_proxy",
        ]
        pools = ba.discover_pools(names)
        self.assertIn(2, pools)
        self.assertIn(5, pools)
        self.assertEqual(pools[5]["eshop"], "honeypot_eshop_5")
        self.assertEqual(pools[5]["database"], "honeypot_database_5")

    def test_ignores_non_pool_containers(self):
        pools = ba.discover_pools(["reverse_proxy", "session_store", "pool_manager"])
        self.assertEqual(pools, {})


class ReachResultTests(unittest.TestCase):
    def _d(self, **kw):
        return ba._Reach("dest", "1.2.3.4", 80, **kw)

    def test_blocked_is_pass(self):
        r = ba._reach_result(ba.CAT_BREAKOUT, "hp1", self._d(), 7, "BLOCKED")
        self.assertEqual(r.outcome, ba.PASS)

    def test_open_is_fail(self):
        r = ba._reach_result(ba.CAT_BREAKOUT, "hp1", self._d(), 0, "OPEN")
        self.assertEqual(r.outcome, ba.FAIL)

    def test_probe_unavailable_is_error(self):
        r = ba._reach_result(ba.CAT_BREAKOUT, "hp1", self._d(), 0, "PROBE_UNAVAILABLE")
        self.assertEqual(r.outcome, ba.ERROR)

    def test_udp_label(self):
        r = ba._reach_result(ba.CAT_BREAKOUT, "hp1", self._d(udp=True), 0, "BLOCKED")
        self.assertTrue(r.probe.startswith("UDP"))


class HeadlineTests(unittest.TestCase):
    def _data(self, *outcomes_sev):
        d = ba.BreachAuditData("t", "l", "u", "reverse_proxy", ba.ALL_CATEGORIES)
        for outcome, sev in outcomes_sev:
            d.results.append(ba.ProbeResult(ba.CAT_BREAKOUT, "p", "e", outcome, "", sev))
        return d

    def test_breach_when_any_fail(self):
        d = self._data((ba.PASS, ba.HIGH), (ba.FAIL, ba.CRITICAL))
        status, _ = d.headline()
        self.assertEqual(status, "BREACH")

    def test_breach_reports_worst_severity(self):
        d = self._data((ba.FAIL, ba.MEDIUM), (ba.FAIL, ba.CRITICAL))
        _, summary = d.headline()
        self.assertIn("critical", summary)

    def test_warnings_without_fail(self):
        d = self._data((ba.PASS, ba.HIGH), (ba.WARN, ba.MEDIUM))
        status, _ = d.headline()
        self.assertTrue(status.startswith("HARDENED"))
        self.assertIn("warning", status.lower())

    def test_all_pass(self):
        d = self._data((ba.PASS, ba.HIGH), (ba.PASS, ba.HIGH))
        status, _ = d.headline()
        self.assertEqual(status, "HARDENED")

    def test_nothing_ran(self):
        d = self._data()
        status, _ = d.headline()
        self.assertEqual(status, "INCONCLUSIVE")

    def test_counts(self):
        d = self._data((ba.PASS, ba.HIGH), (ba.FAIL, ba.HIGH), (ba.WARN, ba.MEDIUM))
        c = d.counts()
        self.assertEqual(c[ba.PASS], 1)
        self.assertEqual(c[ba.FAIL], 1)
        self.assertEqual(c[ba.WARN], 1)


class ProbeCommandTests(unittest.TestCase):
    def test_tcp_probe_reports_open_or_blocked(self):
        cmd = ba._tcp_probe_cmd("production_database", 3306)
        self.assertIn("fsockopen", cmd)
        self.assertIn("OPEN", cmd)
        self.assertIn("BLOCKED", cmd)
        self.assertIn("3306", cmd)

    def test_breakout_destinations_cover_production_and_internet(self):
        names = ["production_eshop", "production_database", "honeypot_eshop_1"]
        dests = ba._breakout_destinations(names, 1)
        labels = " ".join(d.label for d in dests)
        self.assertIn("production database", labels)
        self.assertIn("internet", labels)
        self.assertIn("metadata", labels)
        self.assertIn("Docker daemon", labels)

    def test_breakout_includes_peer_pools_not_self(self):
        names = ["honeypot_eshop_1", "honeypot_eshop_2", "honeypot_database_2"]
        dests = ba._breakout_destinations(names, 1)
        hosts = [d.host for d in dests]
        self.assertIn("honeypot_eshop_2", hosts)
        self.assertNotIn("honeypot_eshop_1", hosts)  # never probe ourselves


class SecretHandlingTests(unittest.TestCase):
    def test_whitelist_skips_without_secret(self):
        results = ba.run_whitelist("https://localhost", "", log=lambda s: None)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].outcome, ba.SKIP)

    def test_db_password_probe_compares_only_hashes(self):
        # Two different passwords -> different hashes -> PASS, and the probe
        # must never surface either value.
        def fake_exec(target, container, command, timeout=20.0):
            # command hashes $MYSQL_ROOT_PASSWORD; return a hash per container.
            h = "a" * 64 if "prod" in container else "b" * 64
            return 0, h
        with mock.patch.object(ba, "_docker_exec", side_effect=fake_exec):
            r = ba._db_password_shared_probe(
                mock.Mock(), ba.CAT_BREAKOUT, "honeypot_database_1", "production_database")
        self.assertEqual(r.outcome, ba.PASS)
        self.assertNotIn("a" * 64, r.evidence)
        self.assertNotIn("b" * 64, r.evidence)

    def test_db_password_probe_flags_shared(self):
        def fake_exec(target, container, command, timeout=20.0):
            return 0, "c" * 64  # same hash both sides == shared password
        with mock.patch.object(ba, "_docker_exec", side_effect=fake_exec):
            r = ba._db_password_shared_probe(
                mock.Mock(), ba.CAT_BREAKOUT, "honeypot_database_1", "production_database")
        self.assertEqual(r.outcome, ba.FAIL)
        self.assertEqual(r.severity, ba.CRITICAL)


class RoutingProbeTests(unittest.TestCase):
    def test_routes_to_honeypot(self):
        self.assertTrue(ba._routes_to_honeypot(ba._HttpResult(200, "honeypot", "80")))
        self.assertFalse(ba._routes_to_honeypot(ba._HttpResult(200, "production", "0")))

    def test_obfuscation_fail_when_served_production_unscored(self):
        # A crafted request that reaches production with score 0 is a real hole.
        def fake_req(base_url, path, secret, **kw):
            if path == ba._TARGET_PLUGIN:
                return ba._HttpResult(200, "honeypot", "80")       # baseline
            return ba._HttpResult(200, "production", "0")          # bypassed
        with mock.patch.object(ba, "_edge_request", side_effect=fake_req):
            results = ba.run_whitelist("https://localhost", "secret", log=lambda s: None)
        fails = [r for r in results if r.outcome == ba.FAIL]
        self.assertTrue(fails, "expected at least one bypass to be flagged FAIL")

    def test_obfuscation_pass_when_still_diverted(self):
        def fake_req(base_url, path, secret, **kw):
            return ba._HttpResult(200, "honeypot", "80")
        with mock.patch.object(ba, "_edge_request", side_effect=fake_req):
            results = ba.run_whitelist("https://localhost", "secret", log=lambda s: None)
        self.assertFalse([r for r in results if r.outcome == ba.FAIL])

    def test_edge_exposure_flags_leaked_header(self):
        # A wrong secret that still yields a routing header is a leak.
        def fake_req(base_url, path, secret, **kw):
            return ba._HttpResult(200, "honeypot", "80")
        with mock.patch.object(ba, "_edge_request", side_effect=fake_req):
            results = ba.run_edge_exposure("https://localhost", "secret", log=lambda s: None)
        leak = [r for r in results if "gated" in r.probe and r.outcome == ba.FAIL]
        self.assertTrue(leak)

    def test_edge_exposure_pass_when_header_withheld(self):
        def fake_req(base_url, path, secret, **kw):
            # No routing header for anyone, smuggling gets a 400.
            if kw.get("method") == "POST":
                return ba._HttpResult(400, None, None)
            return ba._HttpResult(200, None, None)
        with mock.patch.object(ba, "_edge_request", side_effect=fake_req):
            results = ba.run_edge_exposure("https://localhost", "secret", log=lambda s: None)
        self.assertFalse([r for r in results if r.outcome == ba.FAIL])


class EdgeProjectScopingTests(unittest.TestCase):
    def test_falls_back_to_default_when_env_missing(self):
        with mock.patch.object(ba, "load_project_env",
                               side_effect=ba.EnvUploadError("no env")):
            self.assertEqual(ba._edge_project(mock.Mock(remote=None)),
                             ba.EDGE_COMPOSE_PROJECT_DEFAULT)

    def test_rejects_unsafe_project_name(self):
        with mock.patch.object(ba, "load_project_env",
                               return_value={"COMPOSE_PROJECT_NAME": "bad; rm -rf"}):
            self.assertEqual(ba._edge_project(mock.Mock(remote=None)),
                             ba.EDGE_COMPOSE_PROJECT_DEFAULT)

    def test_uses_configured_project_name(self):
        with mock.patch.object(ba, "load_project_env",
                               return_value={"COMPOSE_PROJECT_NAME": "edge-stack_2"}):
            self.assertEqual(ba._edge_project(mock.Mock(remote=None)), "edge-stack_2")

    def test_running_containers_filters_by_project_label(self):
        captured = {}

        def fake_build_shell(cmd):
            captured["cmd"] = cmd
            return ["sh", "-c", cmd], None

        target = mock.Mock(remote=None)
        target.build_shell.side_effect = fake_build_shell
        with mock.patch.object(ba, "load_project_env",
                               return_value={"COMPOSE_PROJECT_NAME": "edgeproj"}), \
             mock.patch.object(ba, "run_checked",
                               return_value=mock.Mock(stdout="edgeproj-reverse_proxy-1\n")):
            names = ba._running_containers(target)
        self.assertIn("label=com.docker.compose.project=edgeproj", captured["cmd"])
        self.assertEqual(names, ["edgeproj-reverse_proxy-1"])


class CaughtBypassedTests(unittest.TestCase):
    def test_diverted_is_caught_not_bypassed(self):
        r = ba._HttpResult(404, "honeypot", "100")
        self.assertTrue(ba._caught(r))
        self.assertFalse(ba._bypassed(r))

    def test_scored_production_is_caught_not_bypassed(self):
        r = ba._HttpResult(200, "production", "40")
        self.assertTrue(ba._caught(r))
        self.assertFalse(ba._bypassed(r))

    def test_edge_block_is_caught(self):
        self.assertTrue(ba._caught(ba._HttpResult(403, None, None)))
        self.assertTrue(ba._caught(ba._HttpResult(400, None, None)))

    def test_production_unscored_served_is_bypassed(self):
        r = ba._HttpResult(200, "production", "0")
        self.assertFalse(ba._caught(r))
        self.assertTrue(ba._bypassed(r))

    def test_baseline_not_caught_skips_obfuscations(self):
        # Edge serves everything clean (no divert, no score, 200): the category
        # is not applicable -> one WARN baseline + one SKIP, never a pile of
        # WARN/FAIL obfuscation rows.
        def fake_req(base_url, path, secret, **kw):
            return ba._HttpResult(200, "production", "0")
        with mock.patch.object(ba, "_edge_request", side_effect=fake_req):
            results = ba.run_whitelist("https://localhost", "secret", log=lambda s: None)
        self.assertFalse([r for r in results if r.outcome == ba.FAIL])
        self.assertTrue([r for r in results if r.outcome == ba.SKIP])
        # obfuscation rows must not have run
        self.assertFalse([r for r in results if r.probe.startswith("obfuscation:")])


class ProductionHardeningTests(unittest.TestCase):
    """CAT_PROD_HARDENING: a production vulnerability must not bypass honeypots."""

    _VULN = [("woocommerce-payments", "CVE-2023-28121", "WooCommerce Payments"),
             ("wp-file-manager", "CVE-2020-25213", "File Manager")]

    def _run(self, fake_req, installed, names=("proj-production_eshop-1",),
             secret="s"):
        target = mock.Mock(remote=None)
        with mock.patch.object(ba, "_vulnerable_plugin_dirs", return_value=self._VULN), \
             mock.patch.object(ba, "_production_plugins", return_value=installed), \
             mock.patch.object(ba, "_prod_container",
                               return_value="proj-production_eshop-1"), \
             mock.patch.object(ba, "_docker_exec", return_value=(0, "BLOCKED")), \
             mock.patch.object(ba, "_internet_egress_allowed", return_value=False), \
             mock.patch.object(ba, "discover_pools", return_value={}), \
             mock.patch.object(ba, "_edge_request", side_effect=fake_req):
            return ba.run_production_hardening(
                target, list(names), "https://localhost", secret, log=lambda s: None)

    def _plugin_rows(self, results):
        return [r for r in results if r.probe.startswith("exploit of")]

    def test_diverted_vuln_plugin_is_pass(self):
        results = self._run(lambda *a, **k: ba._HttpResult(404, "honeypot", "100"),
                            installed={"woocommerce-payments"})
        rows = self._plugin_rows(results)
        self.assertTrue(rows)
        self.assertTrue(all(r.outcome == ba.PASS for r in rows))

    def test_bypassed_plugin_present_on_prod_is_critical_fail(self):
        # Served to production unscored AND the plugin is installed -> real bypass.
        def fake(base_url, path, secret, **kw):
            return ba._HttpResult(200, "production", "0")
        results = self._run(fake, installed={"woocommerce-payments"})
        wc = [r for r in self._plugin_rows(results) if "woocommerce-payments" in r.probe]
        self.assertEqual(len(wc), 1)
        self.assertEqual(wc[0].outcome, ba.FAIL)
        self.assertEqual(wc[0].severity, ba.CRITICAL)

    def test_bypassed_plugin_absent_is_warn(self):
        def fake(base_url, path, secret, **kw):
            return ba._HttpResult(200, "production", "0")
        results = self._run(fake, installed={"some-other-plugin"})
        wc = [r for r in self._plugin_rows(results) if "woocommerce-payments" in r.probe]
        self.assertEqual(wc[0].outcome, ba.WARN)

    def test_bypassed_inventory_unknown_is_warn(self):
        def fake(base_url, path, secret, **kw):
            return ba._HttpResult(200, "production", "0")
        results = self._run(fake, installed=None)
        wc = [r for r in self._plugin_rows(results) if "woocommerce-payments" in r.probe]
        self.assertEqual(wc[0].outcome, ba.WARN)

    def test_header_only_cve_probe_present(self):
        results = self._run(lambda *a, **k: ba._HttpResult(404, "honeypot", "100"),
                            installed={"woocommerce-payments"})
        hdr = [r for r in results if "header-only" in r.probe]
        self.assertEqual(len(hdr), 1)
        self.assertEqual(hdr[0].outcome, ba.PASS)

    def test_no_secret_skips_plugin_probes(self):
        results = self._run(lambda *a, **k: ba._HttpResult(404, "honeypot", "100"),
                            installed=None, secret="")
        self.assertFalse(self._plugin_rows(results))
        self.assertTrue([r for r in results if r.outcome == ba.SKIP])

    def test_missing_production_eshop_skips_egress(self):
        target = mock.Mock(remote=None)
        with mock.patch.object(ba, "_prod_container", return_value=None), \
             mock.patch.object(ba, "_vulnerable_plugin_dirs", return_value=self._VULN), \
             mock.patch.object(ba, "_edge_request",
                               side_effect=lambda *a, **k: ba._HttpResult(404, "honeypot", "100")):
            results = ba.run_production_hardening(
                target, [], "https://localhost", "s", log=lambda s: None)
        self.assertTrue([r for r in results if r.outcome == ba.SKIP
                         and "production shop present" in r.probe])

    def test_egress_open_docker_daemon_is_fail(self):
        dests = ba._production_egress_destinations([], internet_allowed=False)
        daemon = [d for d in dests if "Docker daemon" in d.label]
        self.assertTrue(daemon)
        self.assertTrue(all(d.open_outcome == ba.FAIL for d in daemon))

    def test_egress_open_internet_is_fail_by_default(self):
        # Default-deny: an open internet means the firewall is not enforcing.
        dests = ba._production_egress_destinations([], internet_allowed=False)
        inet = [d for d in dests if "internet" in d.label.lower()]
        self.assertTrue(inet)
        self.assertTrue(all(d.open_outcome == ba.FAIL for d in inet))

    def test_egress_open_internet_is_warn_when_bypass_on(self):
        # Temporary install bypass on: an open internet is expected -> WARN.
        dests = ba._production_egress_destinations([], internet_allowed=True)
        inet = [d for d in dests if "internet" in d.label.lower()]
        self.assertTrue(inet)
        self.assertTrue(all(d.open_outcome == ba.WARN for d in inet))

    def test_category_wired_into_maps(self):
        self.assertIn(ba.CAT_PROD_HARDENING, ba.ALL_CATEGORIES)
        self.assertIn(ba.CAT_PROD_HARDENING, ba.CATEGORY_LABELS)
        self.assertIn(ba.CAT_PROD_HARDENING, ba.CATEGORY_INTRO)


class SocketMountOwnershipTests(unittest.TestCase):
    def _run(self, names, inspect_map):
        def fake_inspect(target, container, fmt, timeout=15.0):
            if ".Mounts" in fmt and "Source" in fmt:
                return inspect_map.get(container, "")
            return ""
        target = mock.Mock(remote=None)
        target.build_shell.return_value = (["sh", "-c", "docker ps"], None)
        with mock.patch.object(ba, "_edge_project", return_value="proj"), \
             mock.patch.object(ba, "_prod_container", return_value=None), \
             mock.patch.object(ba, "run_checked",
                               return_value=mock.Mock(stdout="")), \
             mock.patch.object(ba, "_inspect", side_effect=fake_inspect):
            return ba.run_production_network(target, names, log=lambda s: None)

    def test_pool_manager_socket_is_pass(self):
        results = self._run(
            ["proj-pool_manager-1"],
            {"proj-pool_manager-1": "/var/run/docker.sock\n"})
        sock = [r for r in results if "Docker socket" in r.probe]
        self.assertEqual(len(sock), 1)
        self.assertEqual(sock[0].outcome, ba.PASS)

    def test_socket_proxy_is_pass(self):
        results = self._run(
            ["proj-docker_socket_proxy-1"],
            {"proj-docker_socket_proxy-1": "/var/run/docker.sock\n"})
        sock = [r for r in results if "Docker socket" in r.probe]
        self.assertEqual(len(sock), 1)
        self.assertEqual(sock[0].outcome, ba.PASS)

    def test_other_container_socket_is_fail(self):
        results = self._run(
            ["proj-vector_outbound-1"],
            {"proj-vector_outbound-1": "/var/run/docker.sock\n"})
        sock = [r for r in results if "Docker socket" in r.probe]
        self.assertEqual(len(sock), 1)
        self.assertEqual(sock[0].outcome, ba.FAIL)


class PrivilegeProbeTests(unittest.TestCase):
    def test_privileged_container_fails(self):
        def fake_inspect(target, container, fmt, timeout=15.0):
            if "Privileged" in fmt:
                return "true"
            return ""
        with mock.patch.object(ba, "_inspect", side_effect=fake_inspect):
            results = ba._privilege_probes(mock.Mock(), ba.CAT_BREAKOUT, "honeypot_eshop_1")
        priv = [r for r in results if "privileged" in r.probe]
        self.assertEqual(priv[0].outcome, ba.FAIL)

    def test_docker_sock_mount_fails(self):
        def fake_inspect(target, container, fmt, timeout=15.0):
            if ".Mounts" in fmt and "Source" in fmt:
                return "/var/run/docker.sock->/var/run/docker.sock"
            return ""
        with mock.patch.object(ba, "_inspect", side_effect=fake_inspect):
            results = ba._privilege_probes(mock.Mock(), ba.CAT_BREAKOUT, "honeypot_eshop_1")
        sock = [r for r in results if "Docker socket" in r.probe]
        self.assertEqual(sock[0].outcome, ba.FAIL)

    def test_clean_container_passes(self):
        def fake_inspect(target, container, fmt, timeout=15.0):
            if "SecurityOpt" in fmt:
                return "no-new-privileges:true"
            if "Privileged" in fmt:
                return "false"
            return ""
        with mock.patch.object(ba, "_inspect", side_effect=fake_inspect):
            results = ba._privilege_probes(mock.Mock(), ba.CAT_BREAKOUT, "honeypot_eshop_1")
        self.assertFalse([r for r in results if r.outcome == ba.FAIL])


if __name__ == "__main__":
    unittest.main()
