"""Is the edge's Vector shipper actually delivering logs to the SIEM
aggregator? (Qt-free.) The container being "up" says nothing about the mTLS
channel between vector_outbound and vector_inbound -- ARCHITECTURE.md
documents two bugs that left it up but silently broken. This reads the
shipper's own log tail and reduces it to a verdict.

Vector does not log every successful batch, so the evidence is indirect and
the wording says so: the last healthcheck pass, and whether any delivery
error (retry, TLS, DNS, connection refused) has been logged since it."""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field

from core.container_status import classify, DOWN, EXITED_BAD, EXITED_OK, CREATED
from core.container_status import STOPPED as C_STOPPED
from core.kibana_credentials import get_elastic_credentials

SHIPPER_SERVICE = "vector_outbound"
AGGREGATOR_SERVICE = "vector_inbound"

# Verdicts, worst-first for the page's colouring.
DELIVERING, UNCONFIRMED, FAILING, STOPPED, DISABLED = (
    "delivering", "unconfirmed", "failing", "not running", "shipping off")

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_TS = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)")
_ERROR_TEXT = re.compile(r"error=([^\n]*?)(?:\s+(?:internal_log_rate_limit|request_id|component_\w+)=|$)")
_OK_RE = re.compile(r"healthcheck passed|healthcheck: passed", re.I)
_FAIL_RE = re.compile(
    r"retrying after error|healthcheck failed|healthcheck: failed|\bERROR\b|certificate|"
    r"handshake|connection refused|dns error|failed to (?:connect|send)|unable to connect", re.I)


@dataclass
class Evidence:
    ok: bool
    timestamp: str
    text: str


@dataclass
class ShipperHealth:
    verdict: str = UNCONFIRMED
    detail: str = ""
    last_ok: str = ""                 # timestamp of the last healthcheck pass ("" if none seen)
    last_error: str = ""
    error_count: int = 0
    last_error_text: str = ""
    evidence: list[Evidence] = field(default_factory=list)   # newest last


def _clean(line: str) -> str:
    line = _ANSI.sub("", line)
    return re.sub(r"^\S+\s*\|\s*", "", line).strip()      # drop "<service>-1  | "


def analyse_logs(text: str) -> ShipperHealth:
    """Verdict from the shipper's log tail. The LAST classified line decides:
    a healthcheck pass after the final error means the channel recovered."""
    h = ShipperHealth()
    last_kind = None
    for raw in text.splitlines():
        line = _clean(raw)
        if not line:
            continue
        # A "pass" line that also mentions an error word is still a pass.
        ok = bool(_OK_RE.search(line))
        fail = not ok and bool(_FAIL_RE.search(line))
        if not (ok or fail):
            continue
        m = _TS.search(line)
        ts = m.group(1) if m else ""
        last_kind = "ok" if ok else "fail"
        if ok:
            h.last_ok = ts or h.last_ok
        else:
            h.error_count += 1
            h.last_error = ts or h.last_error
            e = _ERROR_TEXT.search(line)
            h.last_error_text = (e.group(1) if e else line)[:240].strip()
        h.evidence.append(Evidence(ok, ts, line[:300]))
    h.evidence = h.evidence[-12:]

    if last_kind == "fail":
        h.verdict = FAILING
        h.detail = (f"{h.error_count} delivery error(s) in the log tail and no healthcheck pass after the "
                    f"last one. Latest: {h.last_error_text}")
    elif last_kind == "ok":
        h.verdict = DELIVERING
        h.detail = ("Healthcheck passed" + (f" at {h.last_ok}" if h.last_ok else "") +
                    (f"; {h.error_count} earlier error(s) have cleared." if h.error_count else
                     " and no delivery error has been logged since."))
    else:
        h.verdict = UNCONFIRMED
        h.detail = "No healthcheck or delivery message in the log tail yet (the shipper may have just started)."
    return h


def combine(shipping_enabled: bool, why_not: str, shipper: dict | None, logs: str) -> ShipperHealth:
    """Full verdict: shipping configured? shipper container running? then the
    log analysis. `shipper` is the vector_outbound `docker compose ps` record
    (None when absent)."""
    if not shipping_enabled:
        return ShipperHealth(DISABLED, f"Log shipping is switched off: {why_not}.")
    status = classify(shipper)
    # vector_outbound is long-running, so a clean exit now classifies as
    # C_STOPPED rather than EXITED_OK -- both mean nothing is being shipped.
    if status in (DOWN, EXITED_BAD, EXITED_OK, C_STOPPED, CREATED):
        return ShipperHealth(STOPPED, f"vector_outbound is {status.replace('_', ' ')}; nothing is being shipped.")
    return analyse_logs(logs)


# Inside the es01 container: list the shipped honeypot-* indices with doc
# counts. The cert path and es01:9200 match the SIEM compose healthcheck.
ES_INDEX_CURL = (
    "curl -s --max-time 10 --cacert config/certs/ca/ca.crt -u elastic:{password} "
    '"https://es01:9200/_cat/indices/honeypot-*?h=index,docs.count,store.size&format=json&s=index"')


def parse_index_stats(text: str) -> dict | None:
    """Total shipped documents and per-index counts from the _cat/indices
    JSON. None when the response isn't the expected JSON array (e.g. an
    auth error or es not ready)."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    total = 0
    indices = []
    for row in data:
        if not isinstance(row, dict):
            continue
        try:
            docs = int(row.get("docs.count") or 0)
        except (TypeError, ValueError):
            docs = 0
        total += docs
        indices.append((str(row.get("index", "")), docs, str(row.get("store.size", ""))))
    return {"total_docs": total, "index_count": len(indices), "indices": sorted(indices)}


# Clear every shipped document: a match_all _delete_by_query over honeypot-*.
# Deliberately NOT a `DELETE /honeypot-*` of the indices -- Elasticsearch's
# action.destructive_requires_name guard (on by default) refuses a wildcard
# index delete, whereas _delete_by_query is allowed and leaves the (now empty)
# indices and their mappings in place for Vector to keep writing to.
# conflicts=proceed so a concurrent indexing batch doesn't abort the wipe;
# ignore_unavailable/allow_no_indices so "nothing shipped yet" is a success,
# not an error. Same cert path / auth as ES_INDEX_CURL above.
ES_DELETE_ALL_CURL = (
    "curl -s --max-time 120 -X POST --cacert config/certs/ca/ca.crt -u elastic:{password} "
    "-H 'Content-Type: application/json' "
    '"https://es01:9200/honeypot-*/_delete_by_query'
    '?conflicts=proceed&refresh=true&ignore_unavailable=true&allow_no_indices=true" '
    "-d '{{\"query\":{{\"match_all\":{{}}}}}}'")


def parse_delete_result(text: str) -> int | None:
    """Documents deleted, from a _delete_by_query response (its "deleted"
    field). None when the response isn't that JSON object -- an auth error,
    es not ready, or an error payload without a "deleted" count."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict) or "deleted" not in data:
        return None
    try:
        return int(data["deleted"])
    except (TypeError, ValueError):
        return None


def _es_exec(argv, cwd) -> str:
    # The delete-by-query below allows ES itself up to 120 s (--max-time 120),
    # so the subprocess must outlast that -- a 30 s cap here would kill a wipe
    # of a large index mid-flight and report a spurious failure.
    try:
        return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=130).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def clear_all_documents(siem_targets, state):
    """Delete every honeypot-* document in the SIEM (a match_all
    _delete_by_query, see ES_DELETE_ALL_CURL -- indices and mappings stay, so
    Vector keeps shipping into them). Returns (deleted, None) on success, or
    (None, message) when the SIEM isn't reachable, the credentials are missing,
    or Elasticsearch returned something unexpected. Runs docker/ssh, so call it
    off the GUI thread."""
    agg_target = next((t for t in siem_targets if aggregator_state(t.ps()) != "unknown"), None)
    if agg_target is None:
        return None, "The SIEM stack is not reachable from this machine."
    creds = get_elastic_credentials(state)
    if creds is None:
        return None, "No Elasticsearch credentials available (set them on the SIEM page)."
    argv, cwd = agg_target.build("exec", "-T", "es01", "sh", "-c",
                                 ES_DELETE_ALL_CURL.format(password=creds[1]))
    out = _es_exec(argv, cwd)
    deleted = parse_delete_result(out)
    if deleted is None:
        return None, f"Unexpected response from Elasticsearch: {out[:200].strip() or '(no output)'}"
    return deleted, None


def aggregator_state(containers: list[dict]) -> str:
    """One word for the SIEM-side vector_inbound container from the SIEM
    target's ps records ("unknown" when the SIEM stack is not visible)."""
    for c in containers:
        if c.get("Service") == AGGREGATOR_SERVICE:
            return classify(c)
    return "unknown"
