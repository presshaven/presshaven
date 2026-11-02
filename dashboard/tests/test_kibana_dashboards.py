"""Tests for the committed Kibana dashboards (siem/kibana): the NDJSON that
kibana_dashboards_setup imports must be exactly what build_dashboards.py
defines, and every panel must point at a visualization that exists.

    cd dashboard && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
KIBANA_DIR = REPO_ROOT / "siem" / "kibana"


def _load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, KIBANA_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_builder():
    return _load_module("build_dashboards")


class KibanaDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bd = _load_builder()

    def test_committed_ndjson_is_up_to_date(self):
        with tempfile.TemporaryDirectory() as tmp:
            fresh = Path(tmp) / "out.ndjson"
            self.bd.write_ndjson(fresh)
            committed = self.bd.NDJSON_PATH.read_text(encoding="utf-8")
            self.assertEqual(
                fresh.read_text(encoding="utf-8"), committed,
                "saved_objects/honeypot-dashboards.ndjson is stale: run "
                "`python3 siem/kibana/build_dashboards.py --ndjson`")

    def test_every_panel_references_a_defined_visualization(self):
        defined = {"visualization": {vid for vid, _ in self.bd.VISUALIZATIONS},
                   "search": {sid for sid, _ in self.bd.SEARCHES}}
        for dash_id, body in self.bd.DASHBOARDS:
            panels = json.loads(body["attributes"]["panelsJSON"])
            for panel, ref in zip(panels, body["references"]):
                with self.subTest(dashboard=dash_id, viz=ref["id"]):
                    self.assertIn(ref["id"], defined[ref["type"]])
                    self.assertEqual(panel["type"], ref["type"])

    def test_no_visualization_is_orphaned(self):
        used = {ref["id"] for _, body in self.bd.DASHBOARDS for ref in body["references"]}
        self.assertEqual(sorted({vid for vid, _ in self.bd.VISUALIZATIONS} - used), [])

    def test_dashboards_do_not_share_panels(self):
        # Each dashboard answers its own question; the old four repeated the
        # same panel shapes. A visualization belongs to exactly one dashboard.
        seen: dict[str, str] = {}
        for dash_id, body in self.bd.DASHBOARDS:
            for ref in body["references"]:
                with self.subTest(viz=ref["id"]):
                    self.assertNotIn(ref["id"], seen, f"also on {seen.get(ref['id'])}")
                seen[ref["id"]] = dash_id

    def test_top_uris_marks_attack_pattern_or_safe(self):
        body = dict(self.bd.VISUALIZATIONS)["viz-web-top-uris"]
        aggs = json.loads(body["attributes"]["visState"])["aggs"]
        fields = [a["params"].get("field") for a in aggs]
        self.assertIn("uri.keyword", fields)
        self.assertIn("uri_class.keyword", fields)

    def test_decision_dashboard_exists_and_is_exported(self):
        self.assertIn("dashboard-threat-decisions", self.bd.DASHBOARD_IDS)
        export = (KIBANA_DIR / "export_dashboards.py").read_text(encoding="utf-8")
        for dash_id in self.bd.DASHBOARD_IDS:
            with self.subTest(dashboard=dash_id):
                self.assertIn(f'"{dash_id}"', export)

    def test_dashboard_app_links_every_dashboard(self):
        page = (REPO_ROOT / "dashboard" / "ui" / "page_kibana.py").read_text(encoding="utf-8")
        notes = (REPO_ROOT / "dashboard" / "core" / "kibana_report.py").read_text(encoding="utf-8")
        for dash_id in self.bd.DASHBOARD_IDS:
            path = f"/app/dashboards#/view/{dash_id}"
            with self.subTest(dashboard=dash_id):
                self.assertIn(path, page)
                self.assertIn(path, notes)


class ThreatIntelTests(unittest.TestCase):
    """The Threat Intelligence dashboard is built on fields only the enrich
    transform's threat-intelligence block in vector.yaml creates."""

    FIELDS = ("client_ip", "sensor", "client_tool", "client_tool_class",
              "risk_verdict", "attack_technique", "attack_tactic", "threat.stage",
              "threat.technique.id", "vulnerability.id")

    @classmethod
    def setUpClass(cls):
        cls.bd = _load_builder()
        cls.vector = (REPO_ROOT / "siem/vector/vector.yaml").read_text(encoding="utf-8")

    def test_dashboard_exists(self):
        self.assertIn("dashboard-threat-intel", self.bd.DASHBOARD_IDS)

    def test_vector_sets_every_field(self):
        for field in self.FIELDS:
            with self.subTest(field=field):
                self.assertIn(f"  .{field} = ", self.vector)

    def test_panels_only_use_fields_vector_sets(self):
        # Every *.keyword / numeric field a TI panel aggregates on must be one
        # vector.yaml writes, or one an existing parse already provides.
        known = set(self.FIELDS) | {"timestamp", "risk_score", "session_id"}
        for vid, body in self.bd.VISUALIZATIONS:
            if not vid.startswith("viz-ti-"):
                continue
            for agg in json.loads(body["attributes"]["visState"])["aggs"]:
                field = agg["params"].get("field")
                if field:
                    with self.subTest(viz=vid, field=field):
                        self.assertIn(field.removesuffix(".keyword"), known)

    def test_ioc_list_is_one_row_per_client(self):
        body = dict(self.bd.VISUALIZATIONS)["viz-ti-indicators"]
        buckets = [a for a in json.loads(body["attributes"]["visState"])["aggs"]
                   if a["schema"] == "bucket"]
        self.assertEqual([a["params"]["field"] for a in buckets], ["client_ip.keyword"])

    def test_vector_unit_tests_cover_the_block(self):
        tests = (REPO_ROOT / "siem/vector/tests/threat_intel.yaml").read_text(encoding="utf-8")
        for field in ("client_tool", "threat.technique.id", "vulnerability.id", "risk_verdict"):
            with self.subTest(field=field):
                self.assertIn(f".{field}", tests)


class InfraLogsTests(unittest.TestCase):
    """The Infrastructure & Ops Logs dashboard surfaces the shipped log types
    that carry no threat score (docker, redis, nginx_error) -- it must stay
    wired like every other dashboard and only aggregate on fields the pipeline
    actually produces for those types."""

    # Fields the edge shipper's tag transforms set explicitly (ids/vector/
    # vector.yaml); container_name/stream come from the docker_logs source
    # itself, and the service label from the enrich transform flattening the
    # dotted label keys.
    EDGE_SET_FIELDS = ("log_type", "log_level")
    PIPELINE_FIELDS = {"log_type", "log_level", "container_name", "stream",
                       "label.com_docker_compose_service", "timestamp"}

    @classmethod
    def setUpClass(cls):
        cls.bd = _load_builder()

    def test_dashboard_exists_and_wired(self):
        self.assertIn("dashboard-infra-logs", self.bd.DASHBOARD_IDS)

    def test_edge_shipper_sets_the_fields(self):
        edge = (REPO_ROOT / "ids/vector/vector.yaml").read_text(encoding="utf-8")
        for field in self.EDGE_SET_FIELDS:
            with self.subTest(field=field):
                self.assertIn(f".{field} = ", edge)

    def test_panels_scope_to_infra_log_types(self):
        # Every infra panel (and its saved search) must name one of the three
        # infra log types in its query, never count across all types.
        for vid, body in self.bd.VISUALIZATIONS + self.bd.SEARCHES:
            if not (vid.startswith("viz-infra-") or vid.startswith("search-infra-")):
                continue
            src = json.loads(body["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            query = src["query"]["query"]
            if vid == "viz-infra-guide":  # a markdown note has no query
                continue
            with self.subTest(viz=vid):
                self.assertTrue(
                    any(t in query for t in ('"docker"', '"redis"', '"nginx_error"')),
                    f"{vid} does not scope to an infra log_type: {query!r}")

    def test_panels_only_use_pipeline_fields(self):
        for vid, body in self.bd.VISUALIZATIONS:
            if not vid.startswith("viz-infra-"):
                continue
            for agg in json.loads(body["attributes"]["visState"])["aggs"]:
                field = agg["params"].get("field")
                if field:
                    with self.subTest(viz=vid, field=field):
                        self.assertIn(field.removesuffix(".keyword"), self.PIPELINE_FIELDS)


class PipelineHealthTests(unittest.TestCase):
    """The Pipeline & Host Health dashboard visualizes Vector's own
    internal_metrics and the edge host_metrics (flattened to log events by
    metric_to_log). It must stay wired like every other dashboard and only
    aggregate on the fields metric_to_log + the edge tag transforms produce."""

    # metric_to_log puts the series name in `name`, the value under
    # `counter.value` (counters) or `gauge.value` (gauges), labels under
    # `tags.*`; the edge tag transforms add log_type + vector_role.
    PIPELINE_FIELDS = {"name", "counter.value", "gauge.value", "vector_role",
                       "log_type", "timestamp"}

    @classmethod
    def setUpClass(cls):
        cls.bd = _load_builder()

    def test_dashboard_exists_and_wired(self):
        self.assertIn("dashboard-pipeline-health", self.bd.DASHBOARD_IDS)

    def test_edge_shipper_tags_the_metric_types(self):
        edge = (REPO_ROOT / "ids/vector/vector.yaml").read_text(encoding="utf-8")
        for field in ('.log_type = "vector_metrics"', '.log_type = "host_metrics"',
                      '.vector_role = '):
            with self.subTest(field=field):
                self.assertIn(field, edge)

    def test_panels_scope_to_a_metric_log_type(self):
        for vid, body in self.bd.VISUALIZATIONS + self.bd.SEARCHES:
            if not (vid.startswith("viz-pipeline-") or vid.startswith("viz-host-")
                    or vid == "search-metrics-feed"):
                continue
            if vid == "viz-pipeline-guide":  # a markdown note has no query
                continue
            src = json.loads(body["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            query = src["query"]["query"]
            with self.subTest(viz=vid):
                self.assertTrue(
                    '"vector_metrics"' in query or '"host_metrics"' in query,
                    f"{vid} does not scope to a metric log_type: {query!r}")

    def test_panels_only_use_metric_fields(self):
        for vid, body in self.bd.VISUALIZATIONS:
            if not (vid.startswith("viz-pipeline-") or vid.startswith("viz-host-")):
                continue
            for agg in json.loads(body["attributes"]["visState"])["aggs"]:
                field = agg["params"].get("field")
                if field:
                    with self.subTest(viz=vid, field=field):
                        self.assertIn(field.removesuffix(".keyword"), self.PIPELINE_FIELDS)


class SuricataEnrichmentTests(unittest.TestCase):
    """The parsed-Suricata panels added to the IDS Alerts dashboard surface the
    rich eve-log sub-fields (SID, action, community_id) Suricata actually emits
    for an alert event (suricata_config/suricata.yaml enables community-id)."""

    @classmethod
    def setUpClass(cls):
        cls.bd = _load_builder()
        cls.vizzes = dict(cls.bd.VISUALIZATIONS)

    def test_new_panels_are_on_the_ids_dashboard(self):
        body = dict(self.bd.DASHBOARDS)["dashboard-ids-alerts"]
        referenced = {r["id"] for r in body["references"]
                      if r["type"] == "visualization"}
        for vid in ("viz-ids-top-sids", "viz-ids-flows"):
            with self.subTest(viz=vid):
                self.assertIn(vid, referenced)

    def test_new_panels_scope_to_suricata_alerts(self):
        for vid in ("viz-ids-top-sids", "viz-ids-flows"):
            body = self.vizzes[vid]
            src = json.loads(body["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            query = src["query"]["query"]
            with self.subTest(viz=vid):
                self.assertIn('log_type:"suricata"', query)
                self.assertIn('event_type:"alert"', query)

    def test_community_id_enabled_in_suricata_config(self):
        cfg = (REPO_ROOT / "ids/suricata_config/suricata.yaml").read_text(encoding="utf-8")
        self.assertIn("community-id: true", cfg)


class PoolCapacityTests(unittest.TestCase):
    """The Pool & Capacity dashboard visualizes the pool_manager's live state
    (honeypot-pool_state-*) and its build/hand-off latency log
    (honeypot-pool_events-*), pushed as JSONL that the edge Vector tails. It
    must stay wired and only aggregate on fields the exporter actually writes."""

    # Fields state_export.py puts on each snapshot / event line and the edge
    # tag transforms add. Kept in sync with manager._export_state + event().
    POOL_FIELDS = {"pools", "ready", "free", "waiting", "building",
                   "host_load1", "host_mem_available_mb", "state",
                   "seconds", "waited", "type", "log_type", "timestamp"}

    @classmethod
    def setUpClass(cls):
        cls.bd = _load_builder()
        cls.vizzes = dict(cls.bd.VISUALIZATIONS)

    def test_dashboard_exists_and_wired(self):
        self.assertIn("dashboard-pool-capacity", self.bd.DASHBOARD_IDS)

    def test_edge_tags_the_pool_log_types(self):
        edge = (REPO_ROOT / "ids/vector/vector.yaml").read_text(encoding="utf-8")
        for field in ('.log_type = "pool_state"', '.log_type = "pool_events"'):
            with self.subTest(field=field):
                self.assertIn(field, edge)

    def test_manager_exports_state_and_events(self):
        mgr = (REPO_ROOT / "ids/images/pool_manager/manager.py").read_text(encoding="utf-8")
        self.assertIn("import state_export", mgr)
        self.assertIn("self.exporter.snapshot", mgr)
        self.assertIn("self.exporter.event", mgr)

    def test_panels_scope_to_a_pool_log_type(self):
        for vid, body in self.bd.VISUALIZATIONS + self.bd.SEARCHES:
            if not (vid.startswith("viz-pool-") or vid == "search-pool-events"):
                continue
            if vid == "viz-pool-guide":  # a markdown note has no query
                continue
            src = json.loads(body["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            query = src["query"]["query"]
            with self.subTest(viz=vid):
                self.assertTrue(
                    '"pool_state"' in query or '"pool_events"' in query,
                    f"{vid} does not scope to a pool log_type: {query!r}")

    def test_panels_only_use_pool_fields(self):
        for vid, body in self.bd.VISUALIZATIONS:
            if not vid.startswith("viz-pool-"):
                continue
            for agg in json.loads(body["attributes"]["visState"])["aggs"]:
                field = agg["params"].get("field")
                if field:
                    with self.subTest(viz=vid, field=field):
                        self.assertIn(field.removesuffix(".keyword"), self.POOL_FIELDS)


class PatternCoverageTests(unittest.TestCase):
    """The Detection Coverage dashboard visualizes the enabled-pattern snapshot
    the dashboard app pushes into honeypot-patterns (core/pattern_export.py). It
    must stay wired and only aggregate on fields pattern_export writes."""

    # Fields core.pattern_export.pattern_documents puts on each pattern doc.
    PATTERN_FIELDS = {"enabled", "default_enabled", "toggled", "suricata_sid_count",
                      "severity", "category_label", "kind_label", "component",
                      "surface", "log_type", "timestamp"}

    @classmethod
    def setUpClass(cls):
        cls.bd = _load_builder()

    def test_dashboard_exists_and_wired(self):
        self.assertIn("dashboard-pattern-coverage", self.bd.DASHBOARD_IDS)

    def test_panels_scope_to_the_patterns_log_type(self):
        for vid, body in self.bd.VISUALIZATIONS + self.bd.SEARCHES:
            if not (vid.startswith("viz-patterns-") or vid == "search-patterns"):
                continue
            if vid == "viz-patterns-guide":  # a markdown note has no query
                continue
            src = json.loads(body["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            query = src["query"]["query"]
            with self.subTest(viz=vid):
                self.assertIn('log_type:"patterns"', query)

    def test_panels_only_use_pattern_fields(self):
        for vid, body in self.bd.VISUALIZATIONS:
            if not vid.startswith("viz-patterns-"):
                continue
            for agg in json.loads(body["attributes"]["visState"])["aggs"]:
                field = agg["params"].get("field")
                if field:
                    with self.subTest(viz=vid, field=field):
                        self.assertIn(field.removesuffix(".keyword"), self.PATTERN_FIELDS)


class DecisionLogFieldTests(unittest.TestCase):
    """nginx's security log format and Vector's parser must agree on the
    routing-decision fields the Threat Decisions dashboard is built on."""

    FIELDS = ("request_score", "decayed_score", "offenses", "decay_state",
              "uri_class", "patterns", "reason")

    def test_both_nginx_layers_log_the_fields(self):
        for conf in (REPO_ROOT / "ids/reverse_proxy_enhanced/nginx.conf",
                     REPO_ROOT / "ids/db_proxy/reverse_proxy_enhanced/nginx.conf"):
            text = conf.read_text(encoding="utf-8")
            for field in self.FIELDS:
                with self.subTest(conf=conf.parent.parent.name, field=field):
                    self.assertIn(f'{field}="$', text)

    def test_vector_parses_the_fields(self):
        text = (REPO_ROOT / "siem/vector/vector.yaml").read_text(encoding="utf-8")
        for field in self.FIELDS:
            with self.subTest(field=field):
                self.assertIn(f'{field}="(?P<', text)


def _fields_in_query(es_query_json: str) -> set[str]:
    """Base field names (``.keyword`` stripped) referenced by an .es-query
    rule's stored esQuery DSL string -- the term/range/exists clauses."""
    dsl = json.loads(es_query_json)
    fields: set[str] = set()
    for clause in dsl["query"]["bool"]["filter"]:
        kind, inner = next(iter(clause.items()))
        if kind in ("term", "range"):
            field = next(iter(inner))
        elif kind == "exists":
            field = inner["field"]
        else:  # pragma: no cover - guards against a new clause type slipping in untested
            raise AssertionError(f"unhandled query clause {kind}")
        fields.add(field.removesuffix(".keyword"))
    return fields


class KibanaAlertRuleTests(unittest.TestCase):
    """The committed alerting-rule JSON (what kibana_alerts_setup posts) must
    be exactly what build_alert_rules.py defines, every rule must be a
    license-free .es-query rule, and every field it queries must be one the
    vector.yaml pipeline actually produces."""

    @classmethod
    def setUpClass(cls):
        cls.ar = _load_module("build_alert_rules")
        cls.vector = (REPO_ROOT / "siem/vector/vector.yaml").read_text(encoding="utf-8")

    def test_committed_rule_files_are_up_to_date(self):
        with tempfile.TemporaryDirectory() as tmp:
            fresh_dir = Path(tmp)
            self.ar.write_json(fresh_dir)
            committed = {p.name: p.read_text(encoding="utf-8")
                         for p in self.ar.RULES_DIR.glob("*.json")}
            fresh = {p.name: p.read_text(encoding="utf-8")
                     for p in fresh_dir.glob("*.json")}
            self.assertEqual(
                fresh, committed,
                "siem/kibana/saved_objects/alert_rules/ is stale: run "
                "`python3 siem/kibana/build_alert_rules.py --json`")

    def test_every_rule_is_a_license_free_es_query(self):
        for rule_id, body in self.ar.RULES:
            with self.subTest(rule=rule_id):
                api = self.ar._api_body(body)
                # .es-query is the only rule type available on the Basic
                # (free) license without a connector -- see the module docstring.
                self.assertEqual(api["rule_type_id"], ".es-query")
                self.assertEqual(api["consumer"], "stackAlerts")
                self.assertEqual(api["params"]["index"], ["honeypot-*"])
                self.assertEqual(api["params"]["timeField"], "timestamp")
                self.assertEqual(api["actions"], [])
                self.assertTrue(api["enabled"])
                self.assertIn("honeypot", api["tags"])

    def test_every_queried_field_exists_in_the_pipeline(self):
        for rule_id, body in self.ar.RULES:
            for field in _fields_in_query(body["params"]["esQuery"]):
                with self.subTest(rule=rule_id, field=field):
                    # Every field vector.yaml sets or parses is referenced
                    # there with a leading dot (.log_type, .route, .alert.severity, ...).
                    self.assertIn(f".{field}", self.vector,
                                  f"{field} is not produced by vector.yaml")

    def test_rule_files_carry_no_local_only_keys(self):
        # The _description helper is for the committed file's readers / these
        # tests; it must never reach the alerting API body.
        for path in self.ar.RULES_DIR.glob("*.json"):
            with self.subTest(file=path.name):
                self.assertNotIn("_description", path.read_text(encoding="utf-8"))

    def test_compose_seeds_and_mounts_the_rules(self):
        compose = (REPO_ROOT / "siem/docker/docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("kibana_alerts_setup:", compose)
        self.assertIn("../kibana/saved_objects/alert_rules:/rules:ro", compose)
        self.assertIn("/api/alerting/rule/", compose)

    def test_dashboard_app_links_the_alerts_rules_page(self):
        path = "/app/management/insightsAndAlerting/triggersActions/rules"
        page = (REPO_ROOT / "dashboard/ui/page_kibana.py").read_text(encoding="utf-8")
        notes = (REPO_ROOT / "dashboard/core/kibana_report.py").read_text(encoding="utf-8")
        self.assertIn(path, page)
        self.assertIn(path, notes)


if __name__ == "__main__":
    unittest.main()
