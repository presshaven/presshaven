"""Push the dashboard's enabled-pattern configuration into the SIEM so Kibana
can show it (honeypot-patterns index, the ``log_type:"patterns"`` data).

The pattern catalogue + the user's enable/disable registry live only in the
dashboard (``patterns/patterns.json`` + ``patterns/registry.json``); they are
control-plane artifacts, not shipped by Vector and not present on the edge. So
rather than the SIEM reaching for them, the dashboard pushes a snapshot of the
*effective* catalogue -- one document per pattern, with its enabled state --
straight into Elasticsearch, the same way the "Clear Elasticsearch" button
runs a curl inside the es01 container (see core/shipper_health.py).

A push is a full replace: delete every existing pattern document, then bulk
index the current set. The index therefore always mirrors exactly what the
dashboard has enabled right now -- no stale rows for a pattern that was since
disabled or removed. The bulk body is streamed over stdin (``--data-binary
@-``), so pattern names/descriptions (which can contain quotes) never touch
the command line. Qt-free; the orchestrator runs docker/ssh, so call it off
the GUI thread."""
from __future__ import annotations

import datetime
import json
import subprocess

from core.kibana_credentials import get_elastic_credentials
from core.shipper_health import aggregator_state

# A fixed index (not date-stamped like the shipped honeypot-<type>-DATE logs):
# the pattern config is current-state, not a time series, so each push replaces
# the index's contents in place. The honeypot-* data view still covers it.
ES_PATTERNS_INDEX = "honeypot-patterns"

# Fields carried per pattern. Kept small and flat (keyword-friendly) so the
# Elasticsearch dynamic mapping stays clean and the Kibana aggs are simple.
_DOC_FIELDS = (
    "name", "kind", "kind_label", "category", "category_label", "severity",
    "component", "surface", "owasp", "mitre", "cve",
)


def _iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def pattern_documents(catalog, *, snapshot_ts: str | None = None,
                      environment: str = "development") -> list[dict]:
    """One flat Elasticsearch document per effective pattern, tagged like every
    other honeypot-* record (log_type/timestamp/environment/tags). ``enabled``
    vs ``default_enabled`` lets Kibana show which patterns the user has toggled
    away from the catalogue default; ``suricata_sid_count`` surfaces network
    detection coverage. Pure -- takes a loaded catalogue, hits nothing."""
    ts = snapshot_ts or _iso_now()
    docs = []
    for p in catalog.patterns:
        enabled = bool(p.get("enabled", True))
        default_enabled = bool(p.get("default_enabled", enabled))
        doc = {
            "timestamp": ts,
            "log_type": "patterns",
            "environment": environment,
            "honeypot_system": "dashboard",
            "tags": ["patterns", "coverage", "honeypot"],
            "pattern_id": p.get("id", ""),
            "enabled": enabled,
            "default_enabled": default_enabled,
            # True when the user flipped this pattern away from its catalogue
            # default -- the "I changed this" signal the dashboard owns.
            "toggled": enabled != default_enabled,
            "suricata_sid_count": len(p.get("suricata", []) or []),
            "has_suricata": bool(p.get("suricata")),
            "has_lua": bool(p.get("signatures")),
            "custom": (p.get("component") == "custom"),
        }
        for field in _DOC_FIELDS:
            doc[field] = p.get(field, "") or ""
        docs.append(doc)
    return docs


def build_bulk_ndjson(docs: list[dict]) -> str:
    """The Elasticsearch ``_bulk`` body for the pattern documents: an index
    action (with a deterministic ``_id`` = pattern id, so a re-push overwrites
    rather than duplicates) followed by the source, newline-delimited with the
    trailing newline ``_bulk`` requires."""
    lines = []
    for doc in docs:
        action = {"index": {"_id": doc.get("pattern_id") or None}}
        lines.append(json.dumps(action, separators=(",", ":")))
        lines.append(json.dumps(doc, separators=(",", ":")))
    return "\n".join(lines) + "\n"


# Delete every existing pattern document, then (in the same shell) the caller
# streams the new bulk body over stdin. ignore_unavailable/allow_no_indices so
# the very first push (index not created yet) is a success, not an error; the
# bulk URL auto-creates the index. Same cert path / auth as shipper_health.
_DELETE_THEN_BULK = (
    "curl -s --max-time 30 -X POST --cacert config/certs/ca/ca.crt -u elastic:{password} "
    '"https://es01:9200/{index}/_delete_by_query'
    '?conflicts=proceed&ignore_unavailable=true&allow_no_indices=true&refresh=true" '
    "-H 'Content-Type: application/json' -d '{{\"query\":{{\"match_all\":{{}}}}}}' >/dev/null 2>&1; "
    "curl -s --max-time 60 -X POST --cacert config/certs/ca/ca.crt -u elastic:{password} "
    '"https://es01:9200/{index}/_bulk?refresh=true" '
    "-H 'Content-Type: application/x-ndjson' --data-binary @-"
)


def parse_bulk_result(text: str) -> tuple[int, int] | None:
    """(indexed, errored) from a ``_bulk`` response. None when the response
    isn't the expected JSON object (auth error, es not ready, error payload)."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict) or "items" not in data:
        return None
    items = data.get("items") or []
    errored = sum(1 for it in items
                  if isinstance(it, dict)
                  and it.get("index", {}).get("status", 200) >= 300)
    return len(items) - errored, errored


def _es_push(argv, cwd, ndjson: str) -> str:
    # The delete + bulk allow ES up to 30 s + 60 s; let the subprocess outlast
    # both so a large push isn't killed mid-flight and reported as a failure.
    try:
        return subprocess.run(argv, cwd=cwd, input=ndjson, capture_output=True,
                              text=True, timeout=100).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def push_patterns(siem_targets, state, catalog=None) -> tuple[dict | None, str | None]:
    """Replace the SIEM's pattern snapshot with the dashboard's current
    effective catalogue. Returns ({"indexed","errored","total","enabled"},
    None) on success, or (None, message) when the SIEM isn't reachable, the
    credentials are missing, or Elasticsearch returned something unexpected.
    Runs docker/ssh, so call it off the GUI thread."""
    if catalog is None:
        from core.pattern_registry import load_catalog
        catalog = load_catalog()
    agg_target = next((t for t in siem_targets if aggregator_state(t.ps()) != "unknown"), None)
    if agg_target is None:
        return None, "The SIEM stack is not reachable from this machine."
    creds = get_elastic_credentials(state)
    if creds is None:
        return None, "No Elasticsearch credentials available (set them on the SIEM page)."

    docs = pattern_documents(catalog, environment=getattr(state, "environment", "development"))
    if not docs:
        return None, "No patterns in the catalogue to push."
    ndjson = build_bulk_ndjson(docs)
    argv, cwd = agg_target.build(
        "exec", "-T", "es01", "sh", "-c",
        _DELETE_THEN_BULK.format(password=creds[1], index=ES_PATTERNS_INDEX))
    out = _es_push(argv, cwd, ndjson)
    parsed = parse_bulk_result(out)
    if parsed is None:
        return None, f"Unexpected response from Elasticsearch: {out[:200].strip() or '(no output)'}"
    indexed, errored = parsed
    return {
        "indexed": indexed,
        "errored": errored,
        "total": len(docs),
        "enabled": sum(1 for d in docs if d["enabled"]),
    }, None
