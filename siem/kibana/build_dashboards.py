#!/usr/bin/env python3
"""Defines the six Honeypot Kibana dashboards (IDS Alerts, Web Traffic,
Threat Decisions & Decay, Session Analysis, Attack Patterns, Threat
Intelligence), their visualizations, saved searches and the honeypot-* data
view, and either pushes them to a live Kibana or writes the committed NDJSON.

    python3 build_dashboards.py --ndjson [PATH]
        Writes saved_objects/honeypot-dashboards.ndjson (or PATH) offline --
        no Kibana needed. This is the file kibana_dashboards_setup in
        docker-compose.yml imports on every `docker compose up`; commit it
        after changing anything here.

    python3 build_dashboards.py
        Creates/overwrites the same objects in a live Kibana via the Saved
        Objects API (KIBANA_URL, ELASTIC_USERNAME, ELASTIC_PASSWORD env vars,
        or --kibana-url/--user/--password). export_dashboards.py can then
        re-export them if panels were hand-edited in Kibana afterwards.

All object IDs are fixed/stable (not auto-generated) so that:
  - re-running this script is idempotent (overwrite=true),
  - dashboard/ui/page_kibana.py's bookmark buttons, which hardcode the
    dashboard-* ids, keep working.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

DATA_VIEW_ID = "honeypot-data-view"
NDJSON_PATH = Path(__file__).resolve().parent / "saved_objects" / "honeypot-dashboards.ndjson"


def _viz(vis_id: str, title: str, vis_type: str, aggs: list[dict], *,
         query: str = "", filters: list[dict] | None = None,
         params_extra: dict | None = None, description: str = "") -> tuple[str, dict]:
    """Builds a classic-type visualization saved object body.

    Classic (not Lens) visualizations were chosen deliberately, same as the
    original build -- see ARCHITECTURE.md's Dashboards section: their
    visState/aggs JSON schema has stayed stable across Kibana versions,
    where Lens's internal state has not.
    """
    params = {"addTooltip": True, "addLegend": True, "legendPosition": "right"}
    if params_extra:
        params.update(params_extra)
    vis_state = {
        "title": title,
        "type": vis_type,
        "params": params,
        "aggs": aggs,
    }
    body = {
        "attributes": {
            "title": title,
            "description": description,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": query, "language": "kuery"},
                    "filter": filters or [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                })
            },
        },
        "references": [
            {"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}
        ],
    }
    return vis_id, body


def _markdown(vis_id: str, title: str, text: str) -> tuple[str, dict]:
    """A text panel (no data) -- each dashboard opens with one saying what it
    answers and how to read it, since the audience is students."""
    vis_state = {
        "title": title, "type": "markdown", "aggs": [],
        "params": {"markdown": text, "fontSize": 12, "openLinksInNewTab": False},
    }
    body = {
        "attributes": {
            "title": title,
            "description": "",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
        "references": [],
    }
    return vis_id, body


def _search(search_id: str, title: str, columns: list[str], query: str,
            description: str = "") -> tuple[str, dict]:
    """A Discover saved search: a filtered, column-picked event list. Opens in
    Discover (where Share > CSV export turns it into a file) and can also sit
    on a dashboard as a table panel."""
    body = {
        "attributes": {
            "title": title,
            "description": description,
            "columns": columns,
            "sort": [["timestamp", "desc"]],
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": query, "language": "kuery"},
                    "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                })
            },
        },
        "references": [
            {"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}
        ],
    }
    return search_id, body


def _xy_params(chart: str, series: list[tuple[str, str]], *, mode: str = "normal",
               y_title: str = "", threshold: float | None = None,
               horizontal: bool = False) -> dict:
    """Full vislib xy params (line/area/histogram/horizontal_bar).

    ``series`` is [(metric agg id, label)], one line/bar series each.
    ``threshold`` draws a dashed reference line (the honeypot threshold)."""
    cat_pos, val_pos = ("left", "bottom") if horizontal else ("bottom", "left")
    params = {
        "type": chart,
        "grid": {"categoryLines": False, "valueAxis": "ValueAxis-1"},
        "categoryAxes": [{
            "id": "CategoryAxis-1", "type": "category", "position": cat_pos, "show": True,
            "style": {}, "scale": {"type": "linear"},
            "labels": ({"show": True, "rotate": 0, "filter": False, "truncate": 200} if horizontal
                       else {"show": True, "filter": True, "truncate": 100}),
            "title": {},
        }],
        "valueAxes": [{
            "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": val_pos,
            "show": True, "style": {}, "scale": {"type": "linear", "mode": mode},
            "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
            "title": {"text": y_title},
        }],
        "seriesParams": [{
            "show": True,
            "type": "histogram" if chart in ("histogram", "horizontal_bar") else chart,
            "mode": "stacked" if mode == "stacked" or chart in ("histogram", "horizontal_bar") else "normal",
            "data": {"label": label, "id": agg_id},
            "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
            "lineWidth": 2, "interpolate": "linear", "showCircles": True,
        } for agg_id, label in series],
        "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "times": [], "addTimeMarker": False, "labels": {"show": False},
        "detailedTooltip": True,
        "thresholdLine": {"show": threshold is not None, "value": threshold or 0,
                          "width": 1, "style": "dashed", "color": "#E7664C"},
    }
    return params


def _count_metric_agg(label: str = "") -> dict:
    params = {"customLabel": label} if label else {}
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": params}


def _date_histogram_agg(agg_id: str = "2") -> dict:
    return {
        "id": agg_id, "enabled": True, "type": "date_histogram", "schema": "segment",
        "params": {"field": "timestamp", "timeRange": {"from": "now-24h", "to": "now"},
                    "useNormalizedEsInterval": True, "interval": "auto", "drop_partials": False,
                    "min_doc_count": 1, "extended_bounds": {}},
    }


def _terms_agg(field: str, agg_id: str = "2", size: int = 10, schema: str = "segment",
                order_by: str = "1", label: str = "", order: str = "desc") -> dict:
    """``order_by`` is a metric agg id, or "_key" to sort buckets by value."""
    params = {"field": field, "orderBy": order_by, "order": order, "size": size,
              "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False}
    if label:
        params["customLabel"] = label
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema, "params": params}


def _metric_agg(agg_type: str, field: str, agg_id: str, label: str = "") -> dict:
    """A non-count metric (cardinality/max/min/avg), schema=metric -- same
    shape as _count_metric_agg() but for a real field."""
    params = {"field": field}
    if label:
        params["customLabel"] = label
    return {"id": agg_id, "enabled": True, "type": agg_type, "schema": "metric", "params": params}


def _histogram_agg(field: str, interval: int, agg_id: str = "2") -> dict:
    return {
        "id": agg_id, "enabled": True, "type": "histogram", "schema": "segment",
        "params": {"field": field, "interval": interval, "min_doc_count": True, "extended_bounds": {}},
    }


_TABLE = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
          "showTotal": False, "totalFunc": "sum", "percentageCol": ""}
_TAGCLOUD = {"scale": "linear", "orientation": "single", "minFontSize": 14,
             "maxFontSize": 48, "showLabel": False}
_PIE = {"isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}


# The honeypot-* data view spans EVERY shipped log type (docker, suricata,
# nginx_access, nginx_security, nginx_error, redis all land in their own
# honeypot-<log_type>-YYYY.MM.DD index, but one data view covers all of
# them by wildcard) -- confirmed live that an unfiltered query counts
# 21,207 docs across all types where only 166 were actually nginx_security
# requests, and that `event_type:alert` alone (no log_type filter) picks
# up 44 cross-type matches vs. 41 real Suricata alerts (a docker-sourced
# log line's message text apparently free-text-matched "alert" too, since
# `event_type` is a text field, not just a keyword one). Every panel below
# explicitly scopes to its own log_type accordingly, rather than relying
# on which fields happen to only exist on the intended type.
_IDS_Q = 'log_type:"suricata" and event_type:"alert"'
_WEB_Q = 'log_type:"nginx_security"'
# nginx_security lines that carry the routing-decision fields
# (request_score/decayed_score/offenses/decay_state/uri_class/patterns/
# route_reason -- nginx.conf's log_format security, router_rules.lua's
# decision_trace(), parsed in siem/vector/vector.yaml). Lines from a proxy
# that predates them simply don't match.
_DECISION_Q = f'{_WEB_Q} and decay_state:*'
# Requests that went through nginx's proxy_cache -- the static-asset locations
# (CSS/JS/fonts/images) served via `proxy_cache static_cache`. cache_status is
# "none" when no cache was involved at all; anything else (HIT/MISS/EXPIRED/
# STALE/REVALIDATED/UPDATING/BYPASS) means the request was cache-bound. The
# URIs were always logged; this field (siem/vector/vector.yaml's cache_status
# parse, from nginx.conf's $upstream_cache_status) is what finally makes the
# cache-bound ones visible and filterable in Kibana.
_CACHE_Q = f'{_WEB_Q} and cache_status:* and not cache_status:"none"'

# session_id-bearing nginx_security requests -- the per-request risk-scored
# traffic each user session is made of (§3.5/§6). client_sophistication_
# classified events (nginx_error, parsed by the enrich transform's
# log_security_event() JSON parsing -- see vector.yaml) carry the same
# session_id, hoisted to the top level specifically so these two dashboards
# can correlate on one field name.
_SESSION_Q = 'log_type:"nginx_security" and session_id:*'
_SOPHISTICATION_Q = 'log_type:"nginx_error" and security_event_type:"client_sophistication_classified"'

# All log_security_event()-sourced events (honeytoken hits, session
# compromise, CVE pattern matches, high-risk requests, honeypot routing
# decisions, sophistication classification) -- see init.lua's
# _G.utils.log_security_event() and the enrich transform's nginx_error
# parsing block in vector.yaml.
_ATTACK_Q = 'log_type:"nginx_error" and security_event_type:*'

# reverse_proxy's honeypot_threshold (init.lua, hard-coded): an effective
# score at or above it diverts the session to the honeypot. Drawn as a
# reference line on the score charts.
HONEYPOT_THRESHOLD = 80

# Threat-intelligence fields, added by the enrich transform's THREAT
# INTELLIGENCE block in siem/vector/vector.yaml to every proxy-scored
# request, proxy security event and Suricata alert: client_ip, sensor,
# client_tool(_class), risk_verdict, threat.technique.*/threat.tactic.*
# (MITRE ATT&CK, ECS names), attack_technique/attack_tactic (id+name and
# stage+tactic in one value each), threat.stage, vulnerability.id (CVEs).
_TI_Q = 'client_ip:*'
_TI_MAL_Q = 'risk_verdict:"flagged"'
_TI_TECH_Q = 'attack_technique:*'

# Infrastructure / ops log types: the shipped logs that carry no threat score
# but say whether the stack itself is healthy -- Docker container stdout/stderr
# (honeypot-docker-*: .container_name, .stream, .label.com_docker_compose_service
# once the enrich transform flattens the dotted label keys), the Redis session
# store (honeypot-redis-*) and nginx's own error/info log (honeypot-nginx_error-*,
# carrying .log_level info/warn/error/crit from the edge shipper's nginx_error_tag).
# reverse_proxy's own container stdout is shipped as files (nginx_access/security/
# error) and filtered OUT of docker_logs (docker_dedupe), so it is deliberately
# absent from the container panels.
_INFRA_Q = 'log_type:("docker" or "redis" or "nginx_error")'
_DOCKER_Q = 'log_type:"docker"'
_REDIS_Q = 'log_type:"redis"'
_NGINX_ERR_Q = 'log_type:"nginx_error"'

# Each dashboard answers a different question and uses different panel
# types, so they no longer read as copies of each other (the old four were
# all "count metric + count-over-time + pies + top-N tables"):
#   IDS Alerts        -- what the network IDS saw (severity bars, protocols,
#                        ports), independent of the proxy's own scoring
#   Web Traffic       -- what was requested and how it was answered, with
#                        every top URI marked attack_pattern or safe
#   Threat Decisions  -- why each request went where it went: own score vs.
#     & Decay            carried-over score vs. threshold, decay states,
#                        offenses, routing reasons
#   Session Analysis  -- who: per-session volume, duration, peak threat,
#                        offenses and sophistication class
#   Attack Patterns   -- what the attacks were: matched patterns, CVEs,
#                        honeytokens, security events over time
#   Threat            -- the same events turned into intelligence: one
#     Intelligence       indicator list per user IP across both sensors,
#                        MITRE ATT&CK techniques and kill-chain stage reached,
#                        tools fingerprinted, CVEs targeted, and an exportable
#                        flagged-event feed
VISUALIZATIONS = [
    # -- IDS Alerts (Suricata) --------------------------------------------
    _markdown("viz-ids-guide", "About: IDS Alerts",
              "**Network-level view.** Suricata inspects raw traffic before the reverse proxy "
              "scores it, so these alerts are an independent second opinion. Severity 1 is the "
              "most serious. Alerts also raise the source IP's reputation, which the proxy "
              "folds into its risk score."),
    _viz("viz-ids-total-alerts", "Total Alerts", "metric",
         [_count_metric_agg("Suricata alerts")], query=_IDS_Q),
    _viz("viz-ids-alerts-over-time", "Alerts Over Time by Severity", "histogram",
         [_count_metric_agg(), _date_histogram_agg(),
          _terms_agg("alert.severity", agg_id="3", size=4, schema="group", label="Severity")],
         query=_IDS_Q,
         params_extra=_xy_params("histogram", [("1", "Alerts")], mode="stacked", y_title="Alerts")),
    _viz("viz-ids-alerts-by-category", "Alerts by Category", "horizontal_bar",
         [_count_metric_agg(), _terms_agg("alert.category.keyword", size=10, label="Category")],
         query=_IDS_Q,
         params_extra=_xy_params("horizontal_bar", [("1", "Alerts")], horizontal=True)),
    _viz("viz-ids-alerts-by-protocol", "Alerts by Application Protocol", "pie",
         [_count_metric_agg(), _terms_agg("app_proto.keyword", size=8, label="Protocol")],
         query=_IDS_Q, params_extra=_PIE),
    _viz("viz-ids-top-signatures", "Top Signatures", "table",
         [_count_metric_agg("Alerts"), _metric_agg("min", "alert.severity", "3", "Worst severity"),
          _terms_agg("alert.signature.keyword", agg_id="2", size=10, schema="bucket", label="Signature")],
         query=_IDS_Q, params_extra=_TABLE),
    _viz("viz-ids-top-source-ips", "Top Source IPs", "table",
         [_count_metric_agg("Alerts"), _metric_agg("cardinality", "alert.signature.keyword", "3", "Distinct signatures"),
          _terms_agg("src_ip.keyword", agg_id="2", size=10, schema="bucket", label="Source IP")],
         query=_IDS_Q, params_extra=_TABLE),
    _viz("viz-ids-dest-ports", "Targeted Destination Ports", "tagcloud",
         [_count_metric_agg(), _terms_agg("dest_port", size=15)],
         query=_IDS_Q, params_extra=_TAGCLOUD),
    # proto is Suricata's transport layer (TCP/UDP/ICMP), distinct from the
    # app_proto pie above -- it was in every eve alert but never surfaced.
    _viz("viz-ids-transport-proto", "Alerts by Transport Protocol", "pie",
         [_count_metric_agg(), _terms_agg("proto.keyword", size=6, label="Transport")],
         query=_IDS_Q, params_extra=_PIE),
    # HTTP-layer alerts carry the host, URL and method Suricata saw on the
    # wire (eve http.*), an independent record of what was targeted next to
    # the proxy's own nginx_security URIs.
    _viz("viz-ids-http-targets", "Targeted URLs (HTTP alerts)", "table",
         [_count_metric_agg("Alerts"),
          _terms_agg("http.hostname.keyword", agg_id="3", size=5, schema="bucket", label="Host"),
          _terms_agg("http.url.keyword", agg_id="2", size=15, schema="bucket", label="URL"),
          _terms_agg("http.http_method.keyword", agg_id="4", size=6, schema="bucket", label="Method")],
         query=f'{_IDS_Q} and http.url:*', params_extra=_TABLE),

    # -- Web Traffic ---------------------------------------------------------
    _markdown("viz-web-guide", "About: Web Traffic",
              "**What was requested and how it was answered.** Every request passes the reverse "
              "proxy, which scores it and sends it to production or the honeypot. "
              "**User Requests** counts real page views (navigation); **Background Requests** counts "
              "the sub-resources a browser then fetches on its own — CSS, JS, images, fonts — plus "
              "XHR/REST calls, so one page load doesn't read as dozens of hits. "
              "**Top URIs** marks each URI as `attack_pattern` (it matched an attack pattern or "
              "CVE signature) or `safe`. **Cache Status** and **Cache-Bound URIs** show which "
              "static assets nginx answered from its `proxy_cache` (HIT) versus fetched upstream "
              "(MISS) — every URI is listed either way. See *Threat Decisions & Decay* for why a "
              "request was routed where it was."),
    _viz("viz-web-total-requests", "User Requests (page views)", "metric",
         [_count_metric_agg("Page views")], query=f'{_WEB_Q} and request_kind:"navigation"'),
    _viz("viz-web-background-requests", "Background Requests (assets / XHR)", "metric",
         [_count_metric_agg("Background")], query=f'{_WEB_Q} and request_kind:"asset"'),
    _viz("viz-web-request-kind-pie", "User Navigation vs Background", "pie",
         [_count_metric_agg(), _terms_agg("request_kind.keyword", size=2, label="Request kind")],
         query=_WEB_Q, params_extra=_PIE),
    _viz("viz-web-requests-over-time", "Requests Over Time by Route", "area",
         [_count_metric_agg(), _date_histogram_agg(),
          _terms_agg("route.keyword", agg_id="3", size=5, schema="group", label="Route")],
         query=_WEB_Q,
         params_extra=_xy_params("area", [("1", "Requests")], mode="stacked", y_title="Requests")),
    _viz("viz-web-routing-pie", "Production vs Honeypot Routing", "pie",
         [_count_metric_agg(), _terms_agg("route.keyword", size=5, label="Route")],
         query=_WEB_Q, params_extra=_PIE),
    _viz("viz-web-uri-class-pie", "Attack-Pattern vs Safe Requests", "pie",
         [_count_metric_agg(), _terms_agg("uri_class.keyword", size=2, label="URI class")],
         query=_DECISION_Q, params_extra=_PIE),
    _viz("viz-web-status-codes", "HTTP Status Codes", "histogram",
         [_count_metric_agg(), _terms_agg("status", size=10, label="Status"),
          _terms_agg("route.keyword", agg_id="3", size=2, schema="group", label="Route")],
         query=_WEB_Q,
         params_extra=_xy_params("histogram", [("1", "Requests")], mode="stacked", y_title="Requests")),
    _viz("viz-web-top-uris", "Top URIs (attack pattern or safe)", "table",
         [_count_metric_agg("Requests"), _metric_agg("max", "risk_score", "4", "Peak risk score"),
          _terms_agg("uri.keyword", agg_id="2", size=15, schema="bucket", label="URI"),
          _terms_agg("uri_class.keyword", agg_id="3", size=2, schema="bucket", label="Attack pattern or safe")],
         query=_DECISION_Q, params_extra=_TABLE),
    _viz("viz-web-top-user-agents", "Top User-Agents", "table",
         [_count_metric_agg("Requests"),
          _terms_agg("user_agent.keyword", agg_id="2", size=10, schema="bucket", label="User-Agent")],
         query=_WEB_Q, params_extra=_TABLE),
    _viz("viz-web-methods", "HTTP Methods", "tagcloud",
         [_count_metric_agg(), _terms_agg("method.keyword", size=10)],
         query=_WEB_Q, params_extra=_TAGCLOUD),
    # Cache visibility: every URI is logged, but whether it was answered from
    # nginx's proxy_cache was not until cache_status was added. HIT/EXPIRED/
    # STALE/REVALIDATED = served from cache; MISS/UPDATING = cache consulted,
    # fetched upstream; BYPASS = cache skipped; none = not a cached location.
    _viz("viz-web-cache-pie", "Cache Status (static assets)", "pie",
         [_count_metric_agg(), _terms_agg("cache_status.keyword", size=8, label="Cache status")],
         query=_WEB_Q, params_extra=_PIE),
    _viz("viz-web-cached-uris", "Cache-Bound URIs (served through proxy_cache)", "table",
         [_count_metric_agg("Requests"),
          _terms_agg("uri.keyword", agg_id="2", size=25, schema="bucket", label="URI"),
          _terms_agg("cache_status.keyword", agg_id="3", size=8, schema="bucket", label="Cache status")],
         query=_CACHE_Q, params_extra=_TABLE),
    # body_bytes_sent (the response size nginx logged, parsed to an int in
    # vector.yaml) summed over time = how much data each route actually served
    # -- the honeypot decoy's bandwidth cost vs. production's, previously logged
    # but never charted.
    _viz("viz-web-bytes-over-time", "Bandwidth Served Over Time by Route", "area",
         [_metric_agg("sum", "body_bytes_sent", "1", "Bytes sent"), _date_histogram_agg(),
          _terms_agg("route.keyword", agg_id="3", size=5, schema="group", label="Route")],
         query=_WEB_Q,
         params_extra=_xy_params("area", [("1", "Bytes sent")], mode="stacked", y_title="Bytes sent")),
    # http_version (from the request line) tells a modern browser on HTTP/2.0
    # from a scripted client or scanner that usually speaks HTTP/1.1 or 1.0.
    _viz("viz-web-http-versions", "HTTP Protocol Versions", "pie",
         [_count_metric_agg(), _terms_agg("http_version.keyword", size=5, label="HTTP version")],
         query=_WEB_Q, params_extra=_PIE),
    # referer: where a request said it came from -- "-" (none) is typical of a
    # direct hit / tool / scanner; a real site or an internal page points at a
    # browser following a link. Excluded "-" so the panel lists only real ones.
    _viz("viz-web-top-referers", "Top Referers", "table",
         [_count_metric_agg("Requests"),
          _terms_agg("referer.keyword", agg_id="2", size=15, schema="bucket", label="Referer")],
         query=f'{_WEB_Q} and referer:* and not referer:"-"', params_extra=_TABLE),

    # -- Threat Decisions & Decay ---------------------------------------------
    _markdown("viz-decision-guide", "About: Threat Decisions & Decay",
              f"**Why each request went where it went.** The proxy adds this request's own score "
              f"(*request score*) to what is left of the session's earlier score after decay "
              f"(*carried score*). If the result (*effective score*) reaches **{HONEYPOT_THRESHOLD}** "
              f"(dashed line) the session is diverted to the honeypot. Scores halve every half-life; "
              f"each offense slows that, and a *permaflagged* session never decays."),
    _viz("viz-decision-honeypot-count", "Requests Diverted to Honeypot", "metric",
         [_count_metric_agg("Diverted requests")], query=f'{_WEB_Q} and route:"honeypot"'),
    _viz("viz-decision-score-composition", "Effective Score = Own + Carried (avg)", "line",
         [_metric_agg("avg", "risk_score", "1", "Effective score"),
          _metric_agg("avg", "request_score", "3", "This request's own score"),
          _metric_agg("avg", "carried_score", "4", "Carried over from history"),
          _date_histogram_agg()],
         query=_DECISION_Q,
         params_extra=_xy_params("line", [("1", "Effective score"), ("3", "This request's own score"),
                                          ("4", "Carried over from history")],
                                 y_title="Risk score", threshold=HONEYPOT_THRESHOLD)),
    _viz("viz-decision-peak-score", "Peak Effective Score vs Threshold", "line",
         [_metric_agg("max", "risk_score", "1", "Peak effective score"),
          _metric_agg("max", "decayed_score", "3", "Peak decayed carry-over"),
          _date_histogram_agg()],
         query=_DECISION_Q,
         params_extra=_xy_params("line", [("1", "Peak effective score"), ("3", "Peak decayed carry-over")],
                                 y_title="Risk score", threshold=HONEYPOT_THRESHOLD)),
    _viz("viz-decision-decay-states", "Decay State of Requests", "pie",
         [_count_metric_agg(), _terms_agg("decay_state.keyword", size=4, label="Decay state")],
         query=_DECISION_Q, params_extra=_PIE),
    _viz("viz-decision-routing-reasons", "Honeypot Routing Reasons", "horizontal_bar",
         [_count_metric_agg(), _terms_agg("route_reason.keyword", size=10, label="Reason")],
         query=f'{_DECISION_Q} and route:"honeypot"',
         params_extra=_xy_params("horizontal_bar", [("1", "Requests")], horizontal=True)),
    _viz("viz-decision-offenses", "Offenses per Request's Session", "histogram",
         [_count_metric_agg(), _histogram_agg("offenses", 1),
          _terms_agg("route.keyword", agg_id="3", size=2, schema="group", label="Route")],
         query=_DECISION_Q,
         params_extra=_xy_params("histogram", [("1", "Requests")], mode="stacked", y_title="Requests")),
    _viz("viz-decision-by-route", "Score Breakdown by Route", "table",
         [_count_metric_agg("Requests"),
          _metric_agg("avg", "request_score", "3", "Avg own score"),
          _metric_agg("avg", "carried_score", "4", "Avg carried score"),
          _metric_agg("avg", "risk_score", "5", "Avg effective score"),
          _metric_agg("max", "offenses", "6", "Max offenses"),
          _terms_agg("route.keyword", agg_id="2", size=2, schema="bucket", label="Route"),
          _terms_agg("decay_state.keyword", agg_id="7", size=4, schema="bucket", label="Decay state")],
         query=_DECISION_Q, params_extra=_TABLE),

    # -- Session Analysis ---------------------------------------------------
    _markdown("viz-session-guide", "About: Session Analysis",
              "**Who is behind the traffic.** A session is one visitor (cookie, or IP when the "
              "cookie is dropped). Its score accumulates across requests and decays over time, so "
              "a session can be diverted even if no single request crossed the threshold. "
              "*Offenses* counts the attack signals a session has fired."),
    _viz("viz-session-total-sessions", "Total Distinct Sessions", "metric",
         [_metric_agg("cardinality", "session_id.keyword", "1", "Sessions")], query=_SESSION_Q),
    _viz("viz-session-over-time", "Distinct Sessions Active Over Time by Route", "histogram",
         [_metric_agg("cardinality", "session_id.keyword", "1"), _date_histogram_agg(),
          _terms_agg("route.keyword", agg_id="3", size=2, schema="group", order_by="1", label="Route")],
         query=_SESSION_Q,
         params_extra=_xy_params("histogram", [("1", "Sessions")], mode="stacked", y_title="Sessions")),
    _viz("viz-session-requests-table", "Requests & Duration per Session", "table",
         [_count_metric_agg("Requests"), _metric_agg("min", "timestamp", "2", "First seen"),
          _metric_agg("max", "timestamp", "3", "Last seen"),
          _metric_agg("cardinality", "uri.keyword", "5", "Distinct URIs"),
          _terms_agg("session_id.keyword", agg_id="4", size=15, schema="bucket", order_by="1", label="Session")],
         query=_SESSION_Q, params_extra=_TABLE),
    _viz("viz-session-top-threat", "Most Hostile Sessions", "table",
         [_metric_agg("max", "risk_score", "1", "Peak effective score"),
          _metric_agg("max", "offenses", "3", "Offenses"),
          _metric_agg("cardinality", "patterns.keyword", "4", "Distinct attack patterns"),
          _terms_agg("session_id.keyword", agg_id="2", size=15, schema="bucket", order_by="1", label="Session")],
         query=_SESSION_Q, params_extra=_TABLE),
    _viz("viz-session-sophistication-pie", "Sophistication Classifications", "pie",
         [_count_metric_agg(), _terms_agg("security_event.classification.keyword", size=10, label="Class")],
         query=_SOPHISTICATION_Q, params_extra=_PIE),
    _viz("viz-session-sophistication-confidence", "Sophistication Confidence Over Time", "line",
         [_metric_agg("avg", "security_event.confidence", "1", "Avg confidence"), _date_histogram_agg()],
         query=_SOPHISTICATION_Q,
         params_extra=_xy_params("line", [("1", "Avg confidence")], y_title="Confidence")),

    # -- Attack Patterns ------------------------------------------------------
    _markdown("viz-attack-guide", "About: Attack Patterns",
              "**What the attacks were.** The cloud shows which attack patterns and CVE signatures "
              "requests matched; the table lists the URIs that matched them. The lower panels come "
              "from security events the proxy logs explicitly (CVE matches, honeytoken reuse, "
              "high-risk requests)."),
    _viz("viz-attack-total-events", "Total Security Events", "metric",
         [_count_metric_agg("Security events")], query=_ATTACK_Q),
    _viz("viz-attack-pattern-cloud", "Matched Attack Patterns", "tagcloud",
         [_count_metric_agg(), _terms_agg("patterns.keyword", size=30)],
         query=f'{_DECISION_Q} and uri_class:"attack_pattern"', params_extra=_TAGCLOUD),
    _viz("viz-attack-pattern-uris", "URIs Matching Attack Patterns", "table",
         [_count_metric_agg("Requests"), _metric_agg("max", "request_score", "4", "Own score"),
          _terms_agg("uri.keyword", agg_id="2", size=15, schema="bucket", label="URI"),
          _terms_agg("patterns.keyword", agg_id="3", size=3, schema="bucket", label="Pattern")],
         query=f'{_DECISION_Q} and uri_class:"attack_pattern"', params_extra=_TABLE),
    _viz("viz-attack-events-over-time", "Security Events Over Time by Type", "area",
         [_count_metric_agg(), _date_histogram_agg(),
          _terms_agg("security_event_type.keyword", agg_id="3", size=8, schema="group", label="Event type")],
         query=_ATTACK_Q,
         params_extra=_xy_params("area", [("1", "Events")], mode="stacked", y_title="Events")),
    _viz("viz-attack-top-cves", "Top CVEs Detected", "table",
         [_count_metric_agg("Detections"),
          _metric_agg("cardinality", "remote_addr.keyword", "3", "Distinct IPs"),
          _terms_agg("security_event.cve.keyword", agg_id="2", size=10, schema="bucket", label="CVE")],
         query=f'{_ATTACK_Q} and security_event_type:"cve_pattern_detected"', params_extra=_TABLE),
    _viz("viz-attack-top-ips", "Top Attacking IPs", "table",
         [_count_metric_agg("Events"),
          _metric_agg("cardinality", "security_event_type.keyword", "3", "Event types"),
          _terms_agg("remote_addr.keyword", agg_id="2", size=10, schema="bucket", label="IP")],
         query=_ATTACK_Q, params_extra=_TABLE),
    _viz("viz-attack-honeytoken-types", "Honeytoken Hits by Type", "pie",
         [_count_metric_agg(), _terms_agg("security_event.token_type.keyword", size=10, label="Token type")],
         query=f'{_ATTACK_Q} and security_event_type:"honeytoken_used"', params_extra=_PIE),
    # security_event.signals: the named reasons the proxy scored a request as
    # high-risk (e.g. a matched pattern, a bad user-agent, request frequency)
    # -- an array parsed by the enrich transform but not shown anywhere until
    # now. Says WHY a request was flagged, next to WHAT pattern it matched.
    _viz("viz-attack-risk-signals", "Top Risk Signals (why requests were flagged)", "table",
         [_count_metric_agg("Events"),
          _metric_agg("cardinality", "remote_addr.keyword", "3", "Distinct IPs"),
          _terms_agg("security_event.signals.keyword", agg_id="2", size=20, schema="bucket", label="Risk signal")],
         query=f'{_ATTACK_Q} and security_event.signals:*', params_extra=_TABLE),

    # -- Threat Intelligence --------------------------------------------------
    _markdown("viz-ti-guide", "About: Threat Intelligence",
              "**Who attacked, with what, and how far they got.** Every proxy request, proxy "
              "security event and Suricata alert is tagged with the user's IP, the tool its "
              "User-Agent gives away, and the **MITRE ATT&CK** techniques its patterns or "
              "signature stand for. **User Indicators** is the IOC list: one row per IP, "
              "first/last seen, how many *sensors* (proxy, Suricata) saw it, and the furthest "
              "ATT&CK stage it reached (1 Reconnaissance, 3 Initial Access, 4 Execution, "
              "5 Persistence, 7 Defense Evasion, 8 Credential Access, 11 Collection). "
              "**Flagged Event Feed** opens in Discover, where *Share > CSV* exports it."),
    _viz("viz-ti-headline", "Threat Intelligence Summary", "metric",
         [_metric_agg("cardinality", "client_ip.keyword", "1", "Flagged IPs"),
          _metric_agg("cardinality", "attack_technique.keyword", "2", "ATT&CK techniques"),
          _metric_agg("cardinality", "vulnerability.id.keyword", "3", "CVEs targeted"),
          _metric_agg("cardinality", "client_tool.keyword", "4", "Tool fingerprints")],
         query=_TI_MAL_Q),
    _viz("viz-ti-indicators", "User Indicators (IOC list)", "table",
         [_count_metric_agg("Flagged events"),
          _metric_agg("min", "timestamp", "3", "First seen"),
          _metric_agg("max", "timestamp", "4", "Last seen"),
          _metric_agg("cardinality", "sensor.keyword", "5", "Sensors"),
          _metric_agg("max", "threat.stage", "6", "Furthest ATT&CK stage"),
          _metric_agg("cardinality", "attack_technique.keyword", "7", "Techniques"),
          _metric_agg("max", "risk_score", "8", "Peak risk score"),
          _metric_agg("cardinality", "session_id.keyword", "9", "Sessions"),
          _terms_agg("client_ip.keyword", agg_id="2", size=25, schema="bucket", label="Client IP")],
         query=_TI_MAL_Q, params_extra=_TABLE),
    _viz("viz-ti-kill-chain", "Kill Chain: Users per ATT&CK Tactic", "horizontal_bar",
         [_metric_agg("cardinality", "client_ip.keyword", "1", "Users"),
          _terms_agg("attack_tactic.keyword", size=14, order_by="_key", order="asc", label="Tactic"),
          _terms_agg("sensor.keyword", agg_id="3", size=2, schema="group", label="Sensor")],
         query=_TI_TECH_Q,
         params_extra=_xy_params("horizontal_bar", [("1", "Users")], horizontal=True)),
    _viz("viz-ti-client-progression", "How Far Each User Got (events per tactic)", "horizontal_bar",
         [_count_metric_agg(),
          _terms_agg("client_ip.keyword", size=10, label="Client IP"),
          _terms_agg("attack_tactic.keyword", agg_id="3", size=14, schema="group",
                     order_by="_key", order="asc", label="Tactic")],
         query=_TI_TECH_Q,
         params_extra=_xy_params("horizontal_bar", [("1", "Events")], horizontal=True)),
    _viz("viz-ti-techniques", "MITRE ATT&CK Techniques Observed", "table",
         [_count_metric_agg("Events"),
          _metric_agg("cardinality", "client_ip.keyword", "3", "Users"),
          _metric_agg("cardinality", "sensor.keyword", "4", "Sensors"),
          _metric_agg("min", "timestamp", "5", "First seen"),
          _metric_agg("max", "timestamp", "6", "Last seen"),
          _terms_agg("attack_technique.keyword", agg_id="2", size=20, schema="bucket", label="Technique")],
         query=_TI_TECH_Q, params_extra=_TABLE),
    _viz("viz-ti-tactics-over-time", "ATT&CK Tactics Over Time", "area",
         [_count_metric_agg(), _date_histogram_agg(),
          _terms_agg("attack_tactic.keyword", agg_id="3", size=14, schema="group",
                     order_by="_key", order="asc", label="Tactic")],
         query=_TI_TECH_Q,
         params_extra=_xy_params("area", [("1", "Events")], mode="stacked", y_title="Events")),
    _viz("viz-ti-tools", "Attack Tools Fingerprinted (User-Agent)", "pie",
         [_count_metric_agg(),
          _terms_agg("client_tool_class.keyword", size=5, label="Tool class"),
          _terms_agg("client_tool.keyword", agg_id="3", size=10, label="Tool")],
         # "unknown" = the event didn't record a User-Agent (most Suricata
         # alerts, the proxy's own security events), not a tool.
         query=f'{_TI_Q} and not risk_verdict:"benign" and not client_tool:"unknown"',
         params_extra=_PIE),
    _viz("viz-ti-cves", "CVEs Targeted (all sensors)", "table",
         [_count_metric_agg("Events"),
          _metric_agg("cardinality", "client_ip.keyword", "3", "Users"),
          _metric_agg("cardinality", "sensor.keyword", "4", "Sensors"),
          _metric_agg("max", "timestamp", "5", "Last seen"),
          _terms_agg("vulnerability.id.keyword", agg_id="2", size=15, schema="bucket", label="CVE")],
         query=f'{_TI_Q} and vulnerability.id:*', params_extra=_TABLE),
    _viz("viz-ti-verdicts", "Verdict per Sensor", "histogram",
         [_count_metric_agg(), _terms_agg("sensor.keyword", size=2, label="Sensor"),
          _terms_agg("risk_verdict.keyword", agg_id="3", size=3, schema="group", label="Verdict")],
         query=_TI_Q,
         params_extra=_xy_params("histogram", [("1", "Events")], mode="stacked", y_title="Events")),

    # -- Infrastructure & Ops Logs --------------------------------------------
    _markdown("viz-infra-guide", "About: Infrastructure & Ops Logs",
              "**Is the stack itself healthy?** These are the shipped log types that carry no "
              "threat score: Docker container output, the Redis session store, and nginx's own "
              "error/info log. **Proxy Log Levels** separates routine `info` request traces from "
              "real `warn`/`error`/`crit` lines; **Container Logs by Service** and **stdout vs "
              "stderr** show which container is noisy and whether it is writing to its error "
              "stream. The reverse proxy's own access/security/error logs are shipped as files "
              "(the other dashboards), not through Docker, so it does not appear among the "
              "containers here."),
    _viz("viz-infra-redis", "Redis Session-Store Log Lines", "metric",
         [_count_metric_agg("Redis log lines")], query=_REDIS_Q),
    _viz("viz-infra-nginx-level-pie", "Proxy Log Levels", "pie",
         [_count_metric_agg(), _terms_agg("log_level.keyword", size=6, label="Level")],
         query=_NGINX_ERR_Q, params_extra=_PIE),
    _viz("viz-infra-log-volume", "Operational Log Volume Over Time by Type", "area",
         [_count_metric_agg(), _date_histogram_agg(),
          _terms_agg("log_type.keyword", agg_id="3", size=4, schema="group", label="Log type")],
         query=_INFRA_Q,
         params_extra=_xy_params("area", [("1", "Log lines")], mode="stacked", y_title="Log lines")),
    _viz("viz-infra-nginx-levels", "Proxy Log Levels Over Time (nginx)", "histogram",
         [_count_metric_agg(), _date_histogram_agg(),
          _terms_agg("log_level.keyword", agg_id="3", size=6, schema="group", label="Level")],
         query=_NGINX_ERR_Q,
         params_extra=_xy_params("histogram", [("1", "Lines")], mode="stacked", y_title="Lines")),
    _viz("viz-infra-containers", "Container Logs by Service", "horizontal_bar",
         [_count_metric_agg(),
          _terms_agg("label.com_docker_compose_service.keyword", size=12, label="Service")],
         query=_DOCKER_Q,
         params_extra=_xy_params("horizontal_bar", [("1", "Log lines")], horizontal=True)),
    _viz("viz-infra-container-table", "Top Containers by Log Volume", "table",
         [_count_metric_agg("Log lines"),
          _metric_agg("cardinality", "stream.keyword", "3", "Streams used"),
          _terms_agg("container_name.keyword", agg_id="2", size=15, schema="bucket", label="Container")],
         query=_DOCKER_Q, params_extra=_TABLE),
    _viz("viz-infra-streams", "Container Output: stdout vs stderr", "pie",
         [_count_metric_agg(), _terms_agg("stream.keyword", size=2, label="Stream")],
         query=_DOCKER_Q, params_extra=_PIE),
]

# Discover saved searches: event lists with the indicator columns already
# picked, for drilling into one user or exporting a feed as CSV.
SEARCHES = [
    _search("search-ti-flagged-feed", "Threat Intel: Flagged Event Feed",
            ["client_ip", "sensor", "client_tool", "attack_technique", "vulnerability.id",
             "uri", "alert.signature", "route", "risk_score"],
            _TI_MAL_Q,
            "Every event judged flagged by either sensor, newest first, with its indicators. "
            "Share > CSV in Discover exports it as an IOC feed."),
    _search("search-ti-credential-abuse", "Threat Intel: Credential & Session Abuse",
            ["client_ip", "security_event_type", "security_event.token_type",
             "security_event.session_id", "request_line", "attack_technique"],
            'security_event_type:("honeytoken_used" or "session_compromised")',
            "Planted honeytokens being reused and hijacked sessions: proof a user took "
            "something from the honeypot and tried to use it."),
    _search("search-infra-feed", "Infrastructure: Recent Log Lines",
            ["log_type", "container_name", "label.com_docker_compose_service", "stream",
             "log_level", "message"],
            _INFRA_Q,
            "Docker, Redis and nginx-error log lines newest first -- the raw operational "
            "feed behind the Infrastructure panels, for spotting a crash loop or an error "
            "burst. Share > CSV in Discover exports it."),
]


def _panel(panel_index: str, x: int, y: int, w: int, h: int, ref_name: str,
           obj_type: str = "visualization") -> dict:
    return {
        "version": "8.17.3", "type": obj_type,
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_index},
        "panelIndex": panel_index, "embeddableConfig": {}, "panelRefName": ref_name,
    }


def _dashboard(dash_id: str, title: str, description: str, layout: list[tuple[str, int, int, int, int]]) -> tuple[str, dict]:
    """layout: list of (viz_id, x, y, w, h) in panel order. An id starting
    with "search-" embeds that saved search instead of a visualization."""
    panels = []
    references = []
    for idx, (viz_id, x, y, w, h) in enumerate(layout, start=1):
        panel_index = str(idx)
        ref_name = f"panel_{panel_index}"
        obj_type = "search" if viz_id.startswith("search-") else "visualization"
        panels.append(_panel(panel_index, x, y, w, h, ref_name, obj_type))
        references.append({"id": viz_id, "name": ref_name, "type": obj_type})

    body = {
        "attributes": {
            "title": title,
            "description": description,
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False,
                                         "syncCursor": True, "syncTooltips": False,
                                         "hidePanelTitles": False}),
            "timeRestore": True,
            "timeFrom": "now-24h",
            "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 30000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
        "references": references,
    }
    return dash_id, body


DASHBOARDS = [
    _dashboard(
        "dashboard-ids-alerts", "Honeypot: IDS Alerts (Suricata)",
        "Network IDS view: alert severity over time, categories, protocols, targeted ports, top signatures and source IPs.",
        [
            ("viz-ids-guide", 0, 0, 16, 8),
            ("viz-ids-total-alerts", 16, 0, 8, 8),
            ("viz-ids-alerts-over-time", 24, 0, 24, 8),
            ("viz-ids-alerts-by-category", 0, 8, 24, 15),
            ("viz-ids-alerts-by-protocol", 24, 8, 12, 15),
            ("viz-ids-dest-ports", 36, 8, 12, 15),
            ("viz-ids-top-signatures", 0, 23, 28, 15),
            ("viz-ids-top-source-ips", 28, 23, 20, 15),
            ("viz-ids-transport-proto", 0, 38, 16, 13),
            ("viz-ids-http-targets", 16, 38, 32, 13),
        ],
    ),
    _dashboard(
        "dashboard-web-threat-overview", "Honeypot: Web Traffic & Threat Overview",
        "What was requested and how it was answered: volume by route, status codes, methods, top URIs marked attack_pattern or safe, and which static assets were served from cache.",
        [
            ("viz-web-guide", 0, 0, 16, 8),
            ("viz-web-total-requests", 16, 0, 8, 4),
            ("viz-web-background-requests", 16, 4, 8, 4),
            ("viz-web-requests-over-time", 24, 0, 24, 8),
            ("viz-web-top-uris", 0, 8, 28, 18),
            ("viz-web-routing-pie", 28, 8, 10, 9),
            ("viz-web-uri-class-pie", 38, 8, 10, 9),
            ("viz-web-methods", 28, 17, 20, 9),
            ("viz-web-status-codes", 0, 26, 24, 13),
            ("viz-web-top-user-agents", 24, 26, 24, 13),
            ("viz-web-request-kind-pie", 0, 39, 16, 10),
            ("viz-web-cache-pie", 16, 39, 16, 10),
            ("viz-web-http-versions", 32, 39, 16, 10),
            ("viz-web-cached-uris", 0, 49, 48, 16),
            ("viz-web-bytes-over-time", 0, 65, 32, 13),
            ("viz-web-top-referers", 32, 65, 16, 13),
        ],
    ),
    _dashboard(
        "dashboard-threat-decisions", "Honeypot: Threat Decisions & Decay",
        "Why each request was routed where it was: own vs. carried-over score against the honeypot threshold, decay states, offenses and routing reasons.",
        [
            ("viz-decision-guide", 0, 0, 36, 8),
            ("viz-decision-honeypot-count", 36, 0, 12, 8),
            ("viz-decision-score-composition", 0, 8, 48, 14),
            ("viz-decision-peak-score", 0, 22, 24, 13),
            ("viz-decision-decay-states", 24, 22, 12, 13),
            ("viz-decision-offenses", 36, 22, 12, 13),
            ("viz-decision-routing-reasons", 0, 35, 20, 14),
            ("viz-decision-by-route", 20, 35, 28, 14),
        ],
    ),
    _dashboard(
        "dashboard-session-analysis", "Honeypot: Session Analysis",
        "Per-session request volume and duration, peak threat, offenses and user-sophistication classification.",
        [
            ("viz-session-guide", 0, 0, 16, 8),
            ("viz-session-total-sessions", 16, 0, 8, 8),
            ("viz-session-over-time", 24, 0, 24, 8),
            ("viz-session-requests-table", 0, 8, 26, 16),
            ("viz-session-top-threat", 26, 8, 22, 16),
            ("viz-session-sophistication-pie", 0, 24, 16, 14),
            ("viz-session-sophistication-confidence", 16, 24, 32, 14),
        ],
    ),
    _dashboard(
        "dashboard-attack-patterns", "Honeypot: Attack Patterns",
        "Which attack patterns and CVEs requests matched, the URIs behind them, honeytoken hits and top attacking IPs.",
        [
            ("viz-attack-guide", 0, 0, 16, 8),
            ("viz-attack-total-events", 16, 0, 8, 8),
            ("viz-attack-events-over-time", 24, 0, 24, 8),
            ("viz-attack-pattern-cloud", 0, 8, 20, 16),
            ("viz-attack-pattern-uris", 20, 8, 28, 16),
            ("viz-attack-top-cves", 0, 24, 18, 14),
            ("viz-attack-top-ips", 18, 24, 18, 14),
            ("viz-attack-honeytoken-types", 36, 24, 12, 14),
            ("viz-attack-risk-signals", 0, 38, 48, 15),
        ],
    ),
    _dashboard(
        "dashboard-threat-intel", "Honeypot: Threat Intelligence",
        "User indicators across the proxy and Suricata: IOC list per IP, MITRE ATT&CK techniques and kill-chain stage reached, attack tools, CVEs targeted, and an exportable flagged-event feed.",
        [
            ("viz-ti-guide", 0, 0, 24, 9),
            ("viz-ti-headline", 24, 0, 24, 9),
            ("viz-ti-indicators", 0, 9, 48, 16),
            ("viz-ti-kill-chain", 0, 25, 20, 15),
            ("viz-ti-client-progression", 20, 25, 28, 15),
            ("viz-ti-techniques", 0, 40, 30, 16),
            ("viz-ti-tools", 30, 40, 18, 16),
            ("viz-ti-tactics-over-time", 0, 56, 30, 13),
            ("viz-ti-verdicts", 30, 56, 18, 13),
            ("viz-ti-cves", 0, 69, 20, 14),
            ("search-ti-flagged-feed", 20, 69, 28, 14),
        ],
    ),
    _dashboard(
        "dashboard-infra-logs", "Honeypot: Infrastructure & Ops Logs",
        "Operational health of the stack itself: container log volume by service and stream, nginx error/info levels over time, Redis session-store activity, and a raw infrastructure log feed.",
        [
            ("viz-infra-guide", 0, 0, 24, 9),
            ("viz-infra-redis", 24, 0, 8, 9),
            ("viz-infra-nginx-level-pie", 32, 0, 16, 9),
            ("viz-infra-log-volume", 0, 9, 24, 13),
            ("viz-infra-nginx-levels", 24, 9, 24, 13),
            ("viz-infra-containers", 0, 22, 24, 15),
            ("viz-infra-container-table", 24, 22, 24, 15),
            ("viz-infra-streams", 0, 37, 16, 13),
            ("search-infra-feed", 16, 37, 32, 13),
        ],
    ),
]

DASHBOARD_IDS = [dash_id for dash_id, _ in DASHBOARDS]


def saved_objects() -> list[tuple[str, str, dict]]:
    """Every object to create, in dependency order: (type, id, body)."""
    objs = [("index-pattern", DATA_VIEW_ID,
             {"attributes": {"title": "honeypot-*", "timeFieldName": "timestamp"}, "references": []})]
    objs += [("visualization", vid, body) for vid, body in VISUALIZATIONS]
    objs += [("search", sid, body) for sid, body in SEARCHES]
    objs += [("dashboard", did, body) for did, body in DASHBOARDS]
    return objs


def write_ndjson(path: Path) -> None:
    """Writes the saved objects as an import-ready NDJSON file without a live
    Kibana (same format `_export` produces, minus server-side timestamps)."""
    lines = []
    for obj_type, obj_id, body in saved_objects():
        lines.append(json.dumps({
            "attributes": body["attributes"],
            "coreMigrationVersion": "8.8.0",
            "id": obj_id,
            "managed": False,
            "references": body.get("references", []),
            "type": obj_type,
        }, sort_keys=True))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {path} ({len(lines)} objects)")


def put(session, base: str, obj_type: str, obj_id: str, body: dict) -> None:
    resp = session.post(f"{base}/api/saved_objects/{obj_type}/{obj_id}?overwrite=true",
                         json=body, verify=False, timeout=30)
    if resp.status_code >= 300:
        print(f"FAILED {obj_type}/{obj_id}: {resp.status_code} {resp.text}", file=sys.stderr)
        resp.raise_for_status()
    print(f"OK {obj_type}/{obj_id}")


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "--ndjson":
        write_ndjson(Path(sys.argv[2]) if len(sys.argv) > 2 else NDJSON_PATH)
        return

    # Imported here so --ndjson (and the dashboard tests that import this
    # module) work without `requests` installed.
    from _kibana_client import make_session, parse_connection_args

    args = parse_connection_args()
    session = make_session(args.user, args.password)

    for obj_type, obj_id, body in saved_objects():
        put(session, args.kibana_url, obj_type, obj_id, body)

    print("\nAll saved objects created/updated.")


if __name__ == "__main__":
    main()
