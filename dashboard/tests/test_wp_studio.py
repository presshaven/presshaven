"""Unit tests for core.wp_studio (Qt-free)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import wp_studio  # noqa: E402


class _FakeTarget:
    """Records the compose args wp_studio.sync_argv forwards to Target.build."""

    def __init__(self):
        self.calls: list[tuple] = []

    def build(self, *compose_args):
        self.calls.append(compose_args)
        return (["docker", "compose", *compose_args], "/edge")


class StudioUrlTests(unittest.TestCase):
    def test_bare_host_gets_https_and_wp_admin(self):
        self.assertEqual(wp_studio.studio_url("shop.example"), "https://shop.example/wp-admin/")

    def test_trailing_slash_and_whitespace_trimmed(self):
        self.assertEqual(wp_studio.studio_url("  shop.example/  "), "https://shop.example/wp-admin/")

    def test_full_url_is_tolerated(self):
        self.assertEqual(wp_studio.studio_url("http://10.0.0.5:8080"), "http://10.0.0.5:8080/wp-admin/")


class StudioHeadersTests(unittest.TestCase):
    def test_backend_header_always_sent(self):
        h = wp_studio.studio_headers("s3cret")
        self.assertEqual(h[wp_studio.STUDIO_BACKEND_HEADER], wp_studio.STUDIO_BACKEND_VALUE)
        self.assertEqual(h[wp_studio.INTERNAL_TEST_HEADER], "s3cret")

    def test_no_secret_omits_auth_header(self):
        for secret in (None, "", "   "):
            h = wp_studio.studio_headers(secret)
            self.assertIn(wp_studio.STUDIO_BACKEND_HEADER, h)
            self.assertNotIn(wp_studio.INTERNAL_TEST_HEADER, h)

    def test_secret_is_stripped(self):
        self.assertEqual(wp_studio.studio_headers("  tok  ")[wp_studio.INTERNAL_TEST_HEADER], "tok")


class ReadyPoolsTests(unittest.TestCase):
    def setUp(self):
        from core import redis_inspect
        self._ri = redis_inspect
        self._orig = redis_inspect.pool_state

    def tearDown(self):
        self._ri.pool_state = self._orig

    def test_uses_ready_pools_sorted_and_deduped(self):
        self._ri.pool_state = lambda remote, timeout=10.0: {"ready": ["3", "1", "2", "1"]}
        self.assertEqual(wp_studio.ready_pools(None), [1, 2, 3])

    def test_falls_back_to_static_pools_when_none_ready(self):
        self._ri.pool_state = lambda remote, timeout=10.0: {"ready": []}
        self.assertEqual(wp_studio.ready_pools(None), [1, 2, 3])

    def test_falls_back_when_redis_raises(self):
        def boom(remote, timeout=10.0):
            raise RuntimeError("no redis")
        self._ri.pool_state = boom
        self.assertEqual(wp_studio.ready_pools(None), [1, 2, 3])

    def test_ignores_bogus_pool_numbers(self):
        self._ri.pool_state = lambda remote, timeout=10.0: {"ready": ["0", "-1", "5", "2"]}
        self.assertEqual(wp_studio.ready_pools(None), [2, 5])


class PropagationStepsTests(unittest.TestCase):
    def test_one_step_per_pool_in_order(self):
        steps = wp_studio.propagation_steps([2, 5])
        self.assertEqual([(s.pool, s.label) for s in steps],
                         [(2, "Honeypot pool 2"), (5, "Honeypot pool 5")])


class SyncArgvTests(unittest.TestCase):
    def test_builds_once_exec_for_the_pool(self):
        target = _FakeTarget()
        argv, cwd = wp_studio.sync_argv(target, 2)
        self.assertEqual(cwd, "/edge")
        self.assertEqual(
            target.calls[0],
            ("exec", "-T", "honeypot_content_sync", "bash",
             "/replicate_content_to_honeypot.sh", "--once", "2"),
        )
        # The pool number is stringified and the script path is the mounted one.
        self.assertIn("--once", argv)
        self.assertEqual(argv[argv.index("--once") + 1], "2")


class PolicyConstantTests(unittest.TestCase):
    def test_propagation_lists_are_non_empty(self):
        self.assertTrue(wp_studio.PROPAGATES)
        self.assertTrue(wp_studio.NEVER_PROPAGATES)

    def test_secrets_are_on_the_never_list(self):
        joined = " ".join(wp_studio.NEVER_PROPAGATES).lower()
        for term in ("password", "api key", "secret", "token"):
            self.assertIn(term, joined)


if __name__ == "__main__":
    unittest.main()


class AdminLoginTests(unittest.TestCase):
    def test_reads_user_and_password(self):
        login = wp_studio.admin_login({"WP_ADMIN_USER": " admin ", "WP_ADMIN_PASSWORD": "pw"})
        self.assertEqual(login, wp_studio.AdminLogin("admin", "pw"))

    def test_missing_either_value_disables_autologin(self):
        self.assertIsNone(wp_studio.admin_login({"WP_ADMIN_USER": "admin"}))
        self.assertIsNone(wp_studio.admin_login({"WP_ADMIN_PASSWORD": "pw"}))
        self.assertIsNone(wp_studio.admin_login({}))

    def test_never_uses_the_honeypot_password(self):
        self.assertIsNone(wp_studio.admin_login(
            {"WP_ADMIN_USER": "admin", "HONEYPOT_WP_ADMIN_PASSWORD": "decoy"}))


class HoneypotAdminLoginTests(unittest.TestCase):
    def test_reads_shared_user_and_honeypot_password(self):
        login = wp_studio.honeypot_admin_login(
            {"WP_ADMIN_USER": " admin ", "WP_ADMIN_PASSWORD": "real",
             "HONEYPOT_WP_ADMIN_PASSWORD": "decoy"})
        self.assertEqual(login, wp_studio.AdminLogin("admin", "decoy"))

    def test_missing_either_value_disables_autologin(self):
        self.assertIsNone(wp_studio.honeypot_admin_login({"WP_ADMIN_USER": "admin"}))
        self.assertIsNone(wp_studio.honeypot_admin_login({"HONEYPOT_WP_ADMIN_PASSWORD": "decoy"}))
        self.assertIsNone(wp_studio.honeypot_admin_login({}))

    def test_never_uses_the_production_password(self):
        login = wp_studio.honeypot_admin_login(
            {"WP_ADMIN_USER": "admin", "WP_ADMIN_PASSWORD": "real",
             "HONEYPOT_WP_ADMIN_PASSWORD": "decoy"})
        self.assertNotEqual(login.password, "real")


class IsLoginFormTests(unittest.TestCase):
    HOME = "https://shop.example/wp-admin/"

    def test_login_redirect_on_studio_host(self):
        self.assertTrue(wp_studio.is_login_form(
            "https://shop.example/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1", self.HOME))

    def test_http_siteurl_redirect_on_same_host(self):
        self.assertTrue(wp_studio.is_login_form("http://shop.example/wp-login.php", self.HOME))

    def test_other_host_is_never_filled(self):
        self.assertFalse(wp_studio.is_login_form("https://evil.example/wp-login.php", self.HOME))
        self.assertFalse(wp_studio.is_login_form(
            "https://shop.example.evil.example/wp-login.php", self.HOME))

    def test_non_login_actions_and_explicit_logout_are_skipped(self):
        for q in ("action=logout", "action=lostpassword", "action=rp", "loggedout=true"):
            self.assertFalse(wp_studio.is_login_form(
                f"https://shop.example/wp-login.php?{q}", self.HOME), q)
        self.assertTrue(wp_studio.is_login_form(
            "https://shop.example/wp-login.php?action=login", self.HOME))

    def test_other_pages_are_not_login_forms(self):
        self.assertFalse(wp_studio.is_login_form("https://shop.example/wp-admin/", self.HOME))
        self.assertFalse(wp_studio.is_login_form("about:blank", self.HOME))


class AutologinScriptTests(unittest.TestCase):
    def test_values_are_json_escaped(self):
        js = wp_studio.autologin_script(wp_studio.AdminLogin("ad'min", 'p"w</script>\\'))
        self.assertIn('"ad\'min"', js)
        self.assertIn('"p\\"w</script>\\\\"', js)

    def test_does_not_resubmit_after_a_login_error(self):
        js = wp_studio.autologin_script(wp_studio.AdminLogin("a", "b"))
        self.assertLess(js.index("login_error"), js.index(".submit.call"))


class AutologinErrorProbeTests(unittest.TestCase):
    def test_probe_only_reads_the_page(self):
        probe = wp_studio.AUTOLOGIN_ERROR_PROBE
        self.assertIn("login_error", probe)
        self.assertNotIn("submit", probe)
        self.assertNotIn(".value", probe)
