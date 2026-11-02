#!/usr/bin/env python3
"""Defines the Honeypot Kibana *alerting rules* -- the active, scheduled
Elasticsearch-query rules that fire when the honeypot sees something worth
flagging (a diversion to the decoy, a high-severity Suricata alert, a used
honeytoken, a hijacked session, a CVE attempt, an offensive scanner), and
either writes them to committed JSON or pushes them to a live Kibana.

Why a separate file from build_dashboards.py: dashboards are Kibana *saved
objects* (imported via /api/saved_objects/_import); alerting rules are not
importable saved objects -- they live behind /api/alerting/rule and have to
be create-or-replaced one id at a time. kibana_alerts_setup in
docker-compose.yml does exactly that on every `docker compose up`.

    python3 build_alert_rules.py --json [DIR]
        Writes saved_objects/alert_rules/<rule-id>.json (one file per rule,
        or into DIR) offline -- no Kibana needed. These are the files
        kibana_alerts_setup posts on startup; commit them after changing
        anything here (the dashboard tests fail if they drift).

    python3 build_alert_rules.py
        Create-or-replaces every rule in a live Kibana via the alerting API
        (KIBANA_URL, ELASTIC_USERNAME, ELASTIC_PASSWORD env vars, or
        --kibana-url/--user/--password). Deletes an existing rule of the
        same id first so the committed definition always wins, exactly like
        the dashboards' overwrite=true import.

All rule ids are fixed/stable (not auto-generated) so that re-running this
(or re-deploying) is idempotent, and so page_kibana.py's "Alerts (Rules)"
bookmark lands the operator on the list these seed.

Every rule is of Kibana's built-in Elasticsearch-query rule type
(``.es-query``), which is available on the Basic (free) license and needs
no connector: the query runs on a schedule against ``honeypot-*`` and an
alert is raised whenever it matches in the look-back window. Each rule has
no actions, so firing is visible in Kibana's own Rules/Alerts UI (and
queryable) without any external notifier configured -- the dashboard app's
own OS notifications (ui/main_window.py) cover operator alerting. Add
actions in Kibana later if email/webhook delivery is wanted.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent / "saved_objects" / "alert_rules"

INDEX = "honeypot-*"
TIME_FIELD = "timestamp"


def _rule(rule_id: str, name: str, filters: list[dict], *,
          window_minutes: int, description: str) -> tuple[str, dict]:
    """Builds an Elasticsearch-query (``.es-query``) rule body.

    ``filters`` is a list of raw ES query-DSL clauses AND-ed together; the
    rule itself adds the ``timeField`` range for the look-back window, so a
    clause here only has to say *what* makes an event notable, not *when*.
    threshold ``> 0`` over the window means "raise an alert as soon as one
    matching event appears", which is the right shape for every honeypot
    signal here (a single diversion / honeytoken hit / CVE attempt matters).
    """
    es_query = {"query": {"bool": {"filter": filters}}}
    body = {
        "name": name,
        "rule_type_id": ".es-query",
        # The feature these rules belong to; the value Stack Management's own
        # "Elasticsearch query" rule uses, so they show up under the same
        # Rules list that page_kibana.py's "Alerts (Rules)" bookmark opens.
        "consumer": "stackAlerts",
        "enabled": True,
        "tags": ["honeypot"],
        "schedule": {"interval": "1m"},
        "params": {
            "searchType": "esQuery",
            "index": [INDEX],
            "timeField": TIME_FIELD,
            # A JSON *string* -- the alerting API stores esQuery as text and
            # parses it itself; json.dumps handles the nested escaping.
            "esQuery": json.dumps(es_query),
            "size": 100,
            "threshold": [0],
            "thresholdComparator": ">",
            "timeWindowSize": window_minutes,
            "timeWindowUnit": "m",
            "aggType": "count",
            "groupBy": "all",
            # Don't re-alert on documents an earlier run of the same rule
            # already counted -- each matching event raises the rule once.
            "excludeHitsFromPreviousRun": True,
        },
        # No actions: firing is visible in Kibana's Rules/Alerts UI without a
        # connector. The dashboard app handles operator notification.
        "actions": [],
    }
    # description isn't a rule field; kept alongside for the committed file's
    # own readability / the dashboard test's field checks.
    body["_description"] = description
    return rule_id, body


# -- field/value shorthands for the query DSL --------------------------------
# String fields are matched on their dynamically-mapped ``.keyword`` subfield
# (exact, un-analyzed) so a term query is unambiguous regardless of how the
# analyzer would tokenize the text field.
def _term(field: str, value: str) -> dict:
    return {"term": {f"{field}.keyword": value}}


def _range(field: str, **bounds) -> dict:
    return {"range": {field: bounds}}


def _exists(field: str) -> dict:
    return {"exists": {"field": field}}


RULES = [
    _rule(
        "honeypot-rule-honeypot-diversion",
        "Honeypot: session diverted to the decoy",
        [_term("log_type", "nginx_security"), _term("route", "honeypot")],
        window_minutes=5,
        description="A request's session crossed the honeypot threshold and was "
                    "routed to the decoy shop (nginx_security route=honeypot).",
    ),
    _rule(
        "honeypot-rule-suricata-high-severity",
        "Honeypot: high-severity Suricata IDS alert",
        [_term("log_type", "suricata"), _term("event_type", "alert"),
         _range("alert.severity", lte=2)],
        window_minutes=5,
        description="Suricata raised a network IDS alert of severity 1-2 "
                    "(1 is the most severe).",
    ),
    _rule(
        "honeypot-rule-honeytoken-used",
        "Honeypot: planted honeytoken was used",
        [_term("security_event_type", "honeytoken_used")],
        window_minutes=10,
        description="A honeytoken the proxy planted (fake credential/key/path) "
                    "was later used -- a strong compromise indicator.",
    ),
    _rule(
        "honeypot-rule-session-compromised",
        "Honeypot: session compromise detected",
        [_term("security_event_type", "session_compromised")],
        window_minutes=10,
        description="The proxy flagged a session as compromised (e.g. a stolen "
                    "session cookie replayed from a new context).",
    ),
    _rule(
        "honeypot-rule-cve-exploit",
        "Honeypot: CVE exploitation attempt",
        [_exists("vulnerability.id")],
        window_minutes=10,
        description="A request matched a known CVE signature (vector tagged it "
                    "with a vulnerability.id).",
    ),
    _rule(
        "honeypot-rule-offensive-scanner",
        "Honeypot: offensive scanning tool detected",
        [_term("client_tool_class", "offensive_scanner")],
        window_minutes=15,
        description="An offensive scanner (sqlmap, nikto, wpscan, nuclei, a "
                    "directory brute-forcer, ...) was fingerprinted from the "
                    "User-Agent.",
    ),
]

RULE_IDS = [rid for rid, _ in RULES]


def _api_body(body: dict) -> dict:
    """The rule body as the alerting API accepts it -- i.e. without the
    local-only ``_description`` helper key."""
    return {k: v for k, v in body.items() if not k.startswith("_")}


def write_json(out_dir: Path) -> None:
    """Writes one ``<rule-id>.json`` per rule (the exact POST body
    kibana_alerts_setup sends) into ``out_dir``, which is created and, if it
    already holds stale ``honeypot-rule-*.json`` files, swept of them first so
    a removed rule doesn't linger."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("honeypot-rule-*.json"):
        if stale.stem not in set(RULE_IDS):
            stale.unlink()
    for rule_id, body in RULES:
        path = out_dir / f"{rule_id}.json"
        path.write_text(json.dumps(_api_body(body), indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(f"Wrote {len(RULES)} rule(s) to {out_dir}")


def put(session, base: str, rule_id: str, body: dict) -> None:
    """Delete-then-create so the committed definition always wins (the
    alerting API has no overwrite flag). A 404 on delete just means the rule
    didn't exist yet."""
    session.delete(f"{base}/api/alerting/rule/{rule_id}", verify=False, timeout=30)
    resp = session.post(f"{base}/api/alerting/rule/{rule_id}",
                        json=_api_body(body), verify=False, timeout=30,
                        headers={"Content-Type": "application/json"})
    if resp.status_code >= 300:
        print(f"FAILED rule/{rule_id}: {resp.status_code} {resp.text}", file=sys.stderr)
        resp.raise_for_status()
    print(f"OK rule/{rule_id}")


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "--json":
        write_json(Path(sys.argv[2]) if len(sys.argv) > 2 else RULES_DIR)
        return

    # Imported here so --json (and the tests that import this module) work
    # without `requests` installed.
    from _kibana_client import make_session, parse_connection_args

    args = parse_connection_args()
    session = make_session(args.user, args.password)
    for rule_id, body in RULES:
        put(session, args.kibana_url, rule_id, body)
    print("\nAll alerting rules created/updated.")


if __name__ == "__main__":
    main()
