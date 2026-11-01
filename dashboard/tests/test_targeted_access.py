"""Unit tests for core.targeted_access (Qt-free)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import targeted_access as ta  # noqa: E402
from core import wp_studio  # noqa: E402


class AvailablePoolsTests(unittest.TestCase):
    def test_matches_static_pool_count(self):
        self.assertEqual(ta.available_pools(), list(range(1, wp_studio.STATIC_POOLS + 1)))


class TargetsTests(unittest.TestCase):
    def test_production_first_then_pools_ascending(self):
        result = ta.targets([3, 1, 2])
        self.assertEqual([t.label for t in result],
                          ["Production", "Honeypot pool 1", "Honeypot pool 2", "Honeypot pool 3"])
        self.assertEqual([t.pool for t in result], [None, 1, 2, 3])

    def test_duplicates_collapsed(self):
        result = ta.targets([2, 2, 1])
        self.assertEqual([t.pool for t in result], [None, 1, 2])

    def test_defaults_to_available_pools(self):
        result = ta.targets()
        self.assertEqual([t.pool for t in result], [None, *ta.available_pools()])


class TargetHeadersTests(unittest.TestCase):
    def test_production_target_uses_studio_headers(self):
        headers = ta.target_headers("s3cret", ta.AccessTarget("Production", None))
        self.assertEqual(headers[wp_studio.STUDIO_BACKEND_HEADER], "production")
        self.assertEqual(headers[wp_studio.INTERNAL_TEST_HEADER], "s3cret")
        self.assertNotIn(ta.STUDIO_POOL_HEADER, headers)

    def test_pool_target_sets_backend_and_pool_headers(self):
        headers = ta.target_headers("s3cret", ta.AccessTarget("Honeypot pool 2", 2))
        self.assertEqual(headers[wp_studio.STUDIO_BACKEND_HEADER], "honeypot")
        self.assertEqual(headers[wp_studio.INTERNAL_TEST_HEADER], "s3cret")
        self.assertEqual(headers[ta.STUDIO_POOL_HEADER], "2")

    def test_pool_target_without_secret_omits_auth_and_pool_headers(self):
        headers = ta.target_headers("", ta.AccessTarget("Honeypot pool 2", 2))
        self.assertEqual(headers[wp_studio.STUDIO_BACKEND_HEADER], "honeypot")
        self.assertNotIn(wp_studio.INTERNAL_TEST_HEADER, headers)
        self.assertNotIn(ta.STUDIO_POOL_HEADER, headers)


class TargetLoginTests(unittest.TestCase):
    ENV = {"WP_ADMIN_USER": "admin", "WP_ADMIN_PASSWORD": "real",
           "HONEYPOT_WP_ADMIN_PASSWORD": "decoy"}

    def test_production_target_gets_production_login(self):
        login = ta.target_login(self.ENV, ta.AccessTarget("Production", None))
        self.assertEqual(login, wp_studio.AdminLogin("admin", "real"))

    def test_pool_target_gets_honeypot_login(self):
        login = ta.target_login(self.ENV, ta.AccessTarget("Honeypot pool 1", 1))
        self.assertEqual(login, wp_studio.AdminLogin("admin", "decoy"))
        self.assertNotEqual(login.password, "real")


if __name__ == "__main__":
    unittest.main()
