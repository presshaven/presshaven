"""Unit tests for core.pattern_export: the pure doc-building, bulk-body and
response-parsing used to push the enabled-pattern snapshot into the SIEM. The
orchestrator (push_patterns) runs docker and is exercised via its parts here,
not end-to-end against a live Elasticsearch."""
from __future__ import annotations

import json
import types
import unittest

from core import pattern_export as pe


def _catalog(patterns):
    return types.SimpleNamespace(patterns=patterns)


class PatternDocumentsTests(unittest.TestCase):
    def test_one_doc_per_pattern_tagged_for_the_data_view(self):
        cat = _catalog([
            {"id": "sqli", "name": "SQL Injection", "enabled": True,
             "default_enabled": True, "severity": "high", "category_label": "Injection",
             "kind_label": "Generic Attack", "component": "lua",
             "suricata": [{"sid": 1}, {"sid": 2}]},
        ])
        docs = pe.pattern_documents(cat, snapshot_ts="2026-01-01T00:00:00.000Z")
        self.assertEqual(len(docs), 1)
        d = docs[0]
        self.assertEqual(d["log_type"], "patterns")
        self.assertEqual(d["timestamp"], "2026-01-01T00:00:00.000Z")
        self.assertEqual(d["pattern_id"], "sqli")
        self.assertTrue(d["enabled"])
        self.assertEqual(d["suricata_sid_count"], 2)
        self.assertTrue(d["has_suricata"])

    def test_toggled_flags_a_deviation_from_default(self):
        cat = _catalog([
            {"id": "cve-x", "enabled": True, "default_enabled": False},   # turned ON
            {"id": "gen-y", "enabled": True, "default_enabled": True},    # default
        ])
        docs = {d["pattern_id"]: d for d in pe.pattern_documents(cat)}
        self.assertTrue(docs["cve-x"]["toggled"])
        self.assertFalse(docs["gen-y"]["toggled"])

    def test_custom_pattern_is_marked(self):
        cat = _catalog([{"id": "mine", "component": "custom", "enabled": True}])
        self.assertTrue(pe.pattern_documents(cat)[0]["custom"])

    def test_missing_fields_default_to_empty_not_missing(self):
        # A sparse pattern must still yield every mapped field so the ES mapping
        # stays stable across pushes.
        docs = pe.pattern_documents(_catalog([{"id": "bare"}]))
        for field in ("name", "severity", "category_label", "kind_label"):
            self.assertEqual(docs[0][field], "")


class BulkBodyTests(unittest.TestCase):
    def test_bulk_is_action_then_source_with_trailing_newline(self):
        docs = pe.pattern_documents(_catalog([
            {"id": "a", "enabled": True}, {"id": "b", "enabled": False}]))
        body = pe.build_bulk_ndjson(docs)
        self.assertTrue(body.endswith("\n"))
        lines = body.strip().split("\n")
        self.assertEqual(len(lines), 4)   # 2 patterns x (action + source)
        self.assertEqual(json.loads(lines[0]), {"index": {"_id": "a"}})
        self.assertEqual(json.loads(lines[1])["pattern_id"], "a")
        self.assertEqual(json.loads(lines[2]), {"index": {"_id": "b"}})


class ParseBulkResultTests(unittest.TestCase):
    def test_counts_indexed_and_errored(self):
        resp = json.dumps({"errors": True, "items": [
            {"index": {"status": 201}},
            {"index": {"status": 200}},
            {"index": {"status": 400, "error": {"type": "mapper_parsing"}}},
        ]})
        self.assertEqual(pe.parse_bulk_result(resp), (2, 1))

    def test_non_bulk_response_is_none(self):
        self.assertIsNone(pe.parse_bulk_result("not json"))
        self.assertIsNone(pe.parse_bulk_result(json.dumps({"error": "unauthorized"})))
        self.assertIsNone(pe.parse_bulk_result(""))


if __name__ == "__main__":
    unittest.main()
