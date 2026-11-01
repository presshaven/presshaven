"""Tests for core.prod_egress -- the production internet-egress policy that
the WordPress Studio page controls (default-deny, a temporary install bypass,
and a persistent trusted-domain allow-list persisted to the edge .env)."""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from core import prod_egress as pe
from core.env_file import EnvFile


class CleanDomainTests(unittest.TestCase):
    def test_accepts_plain_domain(self):
        self.assertEqual(pe.clean_domain("downloads.wordpress.org"), "downloads.wordpress.org")

    def test_strips_scheme_path_port_and_trailing_dot(self):
        self.assertEqual(pe.clean_domain("https://API.wordpress.org:443/path/"),
                         "api.wordpress.org")

    def test_rejects_bare_word(self):
        self.assertIsNone(pe.clean_domain("localhost"))   # no dot = not a domain

    def test_rejects_junk(self):
        self.assertIsNone(pe.clean_domain("not a domain"))
        self.assertIsNone(pe.clean_domain(""))


class ParseDomainsTests(unittest.TestCase):
    def test_splits_dedupes_and_orders(self):
        acc, rej = pe.parse_domains("a.com, b.com a.com,  b.com")
        self.assertEqual(acc, ["a.com", "b.com"])
        self.assertEqual(rej, [])

    def test_collects_rejects(self):
        acc, rej = pe.parse_domains("good.com, bad_word, also.com")
        self.assertEqual(acc, ["good.com", "also.com"])
        self.assertEqual(rej, ["bad_word"])

    def test_caps_at_max(self):
        text = ",".join(f"d{i}.com" for i in range(pe.MAX_DOMAINS + 5))
        acc, rej = pe.parse_domains(text)
        self.assertEqual(len(acc), pe.MAX_DOMAINS)
        self.assertEqual(len(rej), 5)


class PolicyRoundTripTests(unittest.TestCase):
    def _env(self, body: str) -> Path:
        d = Path(self._tmp.name)
        p = d / ".env"
        p.write_text(body, encoding="utf-8")
        return p

    def setUp(self):
        self._tmp = TemporaryDirectory(prefix="pfwtest_egress_")
        self.addCleanup(self._tmp.cleanup)

    def test_read_defaults_when_absent(self):
        p = self._env("FOO=bar\n")
        policy = pe.read_policy(p)
        self.assertFalse(policy.internet_bypass)
        self.assertEqual(policy.domains, [])

    def test_read_existing(self):
        p = self._env("PRODUCTION_INTERNET_EGRESS=true\n"
                      "PRODUCTION_TRUSTED_EGRESS_DOMAINS=a.com,b.com\n")
        policy = pe.read_policy(p)
        self.assertTrue(policy.internet_bypass)
        self.assertEqual(policy.domains, ["a.com", "b.com"])

    def test_write_then_read(self):
        p = self._env("FOO=bar\n")
        pe.write_policy(pe.EgressPolicy(internet_bypass=True, domains=["x.com", "y.com"]),
                        env_path=p, example_path=None)
        back = pe.read_policy(p)
        self.assertTrue(back.internet_bypass)
        self.assertEqual(back.domains, ["x.com", "y.com"])
        # written in the canonical keys
        env = EnvFile.load(p)
        self.assertEqual(env.get("PRODUCTION_INTERNET_EGRESS"), "true")
        self.assertEqual(env.get("PRODUCTION_TRUSTED_EGRESS_DOMAINS"), "x.com,y.com")

    def test_write_off_and_empty(self):
        p = self._env("PRODUCTION_INTERNET_EGRESS=true\n"
                      "PRODUCTION_TRUSTED_EGRESS_DOMAINS=a.com\n")
        pe.write_policy(pe.EgressPolicy(internet_bypass=False, domains=[]),
                        env_path=p, example_path=None)
        env = EnvFile.load(p)
        self.assertEqual(env.get("PRODUCTION_INTERNET_EGRESS"), "false")
        self.assertEqual(env.get("PRODUCTION_TRUSTED_EGRESS_DOMAINS"), "")


class BuildSettingsTests(unittest.TestCase):
    def test_bypass_toggles_internet_rule(self):
        s_on = pe.build_settings(pe.EgressPolicy(internet_bypass=True))
        rule = {r.key: r.enabled for r in s_on.rules()}
        self.assertTrue(rule[pe.INTERNET_RULE_KEY])
        s_off = pe.build_settings(pe.EgressPolicy(internet_bypass=False))
        rule = {r.key: r.enabled for r in s_off.rules()}
        self.assertFalse(rule[pe.INTERNET_RULE_KEY])

    def test_domains_become_trusted_rules(self):
        s = pe.build_settings(pe.EgressPolicy(domains=["downloads.wordpress.org"]))
        trusted = [r for r in s.rules() if r.id.startswith("trusted-")]
        self.assertEqual(len(trusted), 1)
        self.assertEqual(trusted[0].peer, "downloads.wordpress.org")
        self.assertEqual(trusted[0].direction, "outbound")
        self.assertEqual(trusted[0].ports, "443")
        self.assertTrue(trusted[0].enabled)

    def test_reapply_replaces_old_trusted_rules(self):
        first = pe.build_settings(pe.EgressPolicy(domains=["a.com", "b.com"]))
        # Emulate a persisted settings object carrying the previous trusted rules
        # plus an operator's own custom rule, then rebuild for a new domain set.
        with mock.patch.object(pe.cf.FirewallSettings, "for_profile",
                               return_value=first):
            first.custom_rules.append({"direction": "outbound", "id": "my-own-rule",
                                       "enabled": True, "peer": "10.0.0.5", "proto": "tcp",
                                       "ports": "1234", "label": "operator"})
            rebuilt = pe.build_settings(pe.EgressPolicy(domains=["c.com"]))
        ids = {r.id for r in rebuilt.rules()}
        self.assertIn("trusted-c-com", ids)
        self.assertNotIn("trusted-a-com", ids)
        self.assertNotIn("trusted-b-com", ids)
        self.assertIn("my-own-rule", ids)   # operator's rule survived

    def test_built_document_validates(self):
        s = pe.build_settings(pe.EgressPolicy(internet_bypass=True,
                                              domains=["a.com", "b.com"]))
        doc = pe.cf.build_document(s)
        self.assertEqual(pe.cf.validate_document(doc, "production"), [])


class ApplyPolicyTests(unittest.TestCase):
    def test_apply_persists_even_though_live_apply_mocked(self):
        with TemporaryDirectory(prefix="pfwtest_egress_") as d:
            p = Path(d) / ".env"
            p.write_text("FOO=bar\n", encoding="utf-8")
            with mock.patch.object(pe.cf, "apply_document") as apply_doc, \
                 mock.patch.object(pe.cf.FirewallSettings, "save"):
                pe.apply_policy(None, pe.EgressPolicy(internet_bypass=True, domains=["a.com"]),
                                env_path=p, example_path=None)
            apply_doc.assert_called_once()
            back = pe.read_policy(p)
            self.assertTrue(back.internet_bypass)
            self.assertEqual(back.domains, ["a.com"])


if __name__ == "__main__":
    unittest.main()
