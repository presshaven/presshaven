import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.paths import REPO_ROOT  # noqa: E402
from core.pattern_catalog import PatternCatalog  # noqa: E402


class PatternCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = PatternCatalog.load()

    def test_catalog_has_the_expected_sources(self):
        self.assertGreaterEqual(len(self.catalog.patterns), 120)
        self.assertEqual(self.catalog.summary().get("cves"), 15)
        self.assertEqual(self.catalog.summary().get("suricata_sids"), 70)
        for key in ("lua-layer1", "lua-layer2", "lua-cve", "lua-vuln",
                    "headers", "upload", "suricata", "preset", "owasp-crs"):
            self.assertIn(key, self.catalog.sources)

    def test_owasp_crs_patterns_carry_crs_provenance(self):
        # The generic signatures derived from the OWASP ModSecurity Core Rule
        # Set (pattern_rules.lua's "OWASP CRS-derived" block) must be marked as
        # sourced from OWASP CRS so the pattern DB shows/filters their origin.
        crs = [p for p in self.catalog.patterns
               if any(s["key"] == "owasp-crs" for s in p["sources"])]
        self.assertGreaterEqual(len(crs), 60)
        self.assertEqual(self.catalog.sources["owasp-crs"]["label"], "OWASP CRS")
        for pattern in crs:
            with self.subTest(pattern=pattern["id"]):
                detail = next(s["detail"] for s in pattern["sources"] if s["key"] == "owasp-crs")
                self.assertIn("OWASP", detail)
                self.assertIn("Core Rule Set", detail)

    def test_ids_are_unique_and_every_entry_is_well_formed(self):
        ids = [p["id"] for p in self.catalog.patterns]
        self.assertEqual(len(ids), len(set(ids)), "duplicate catalogue ID")
        for pattern in self.catalog.patterns:
            with self.subTest(pattern=pattern["id"]):
                for field in ("id", "name", "kind", "category", "category_label",
                              "severity", "component", "surface", "description",
                              "sources", "signatures", "detection", "wstg", "tags"):
                    self.assertIn(field, pattern)
                self.assertTrue(pattern["name"].strip())
                self.assertTrue(pattern["description"].strip())
                self.assertTrue(pattern["sources"], "every pattern needs provenance")
                for source in pattern["sources"]:
                    self.assertIn(source["key"], self.catalog.sources)
                self.assertIn(pattern["kind"], self.catalog.kinds)
                self.assertIn(pattern["category"], self.catalog.categories)

    def test_aliases_are_unique_across_patterns(self):
        seen: dict[str, str] = {}
        duplicates = []
        for pattern in self.catalog.patterns:
            for alias in [pattern["id"], *pattern.get("aliases", [])]:
                if alias in seen and seen[alias] != pattern["id"]:
                    duplicates.append((alias, seen[alias], pattern["id"]))
                else:
                    seen[alias] = pattern["id"]
        self.assertEqual(duplicates, [], f"aliases resolve to multiple records: {duplicates}")

    def test_search_finds_cves_sids_and_sources(self):
        self.assertEqual(
            [p["id"] for p in self.catalog.filter(query="CVE-2024-25600")],
            ["cve-2024-25600"])
        sid_matches = self.catalog.filter(query="1000026")
        self.assertTrue(any(any(rule.get("sid") == 1000026 for rule in p.get("suricata", []))
                            for p in sid_matches))
        self.assertTrue(self.catalog.filter(query="upload_rules"))
        self.assertTrue(self.catalog.filter(kind="tool", query="sqlmap"))

    def test_filters_are_conjunctive(self):
        patterns = self.catalog.filter(kind="cve", severity="critical", source="suricata")
        self.assertTrue(patterns)
        for pattern in patterns:
            self.assertEqual(pattern["kind"], "cve")
            self.assertEqual(pattern["severity"], "critical")
            self.assertTrue(any(s["key"] == "suricata" for s in pattern["sources"]))

    def test_export_payload_is_self_describing(self):
        selected = self.catalog.filter(kind="cve")[:3]
        payload = self.catalog.export_payload(selected)
        self.assertEqual(payload["format"], "honeypot-ids-pattern-export")
        self.assertEqual(payload["count"], len(selected))
        self.assertEqual(payload["patterns"], selected)

    def test_generated_file_is_not_stale(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "generate_pattern_catalog.py"), "--check"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
