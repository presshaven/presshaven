"""Qt-free helpers for the Live Events page (ui/page_live_events.py):
severity levels derived from the parser's colours, the view filters,
grouping of a request's related events into a single row (with a per-request
latency derived from the log timestamps), and plain-text/CSV export."""
from __future__ import annotations

import calendar
import csv
import io
import re
import time
from dataclasses import dataclass, field

from core.pattern_log_parser import (
    COLOR_HIGH, COLOR_INFO, COLOR_LOW, COLOR_MED, LineBuffer, PatternEvent, parse_line,
)

SEVERITY_ORDER = ["info", "low", "medium", "high"]
_COLOR_TO_SEVERITY = {COLOR_INFO: "info", COLOR_LOW: "low", COLOR_MED: "medium", COLOR_HIGH: "high"}

# View filters offered on the page: id -> label.
FILTERS = {
    "all": "All events",
    "medium": "Medium and above",
    "high": "High severity only",
    "diversions": "Honeypot diversions",
    "outcomes": "Per-request outcomes",
}


def severity(color: str) -> str:
    return _COLOR_TO_SEVERITY.get(color, "info")


def is_honeypot_diversion(kind: str, label: str) -> bool:
    """True when this event is the moment a session is routed to the
    honeypot -- i.e. "the honeypot received a visitor". Its routing outcome
    carries HONEYPOT in the label. Single source of truth for the diversion
    test, shared by the alert policy and the desktop-notification path."""
    return kind == "outcome" and "HONEYPOT" in (label or "").upper()


def severity_rank(color: str) -> int:
    return SEVERITY_ORDER.index(severity(color))


def matches(filter_id: str, kind: str, label: str, color: str, text: str = "") -> bool:
    """Whether an event passes the view filter `filter_id` and the free-text
    `text` (case-insensitive substring of label+detail, passed pre-joined
    by the caller as `label` plus detail in `text`)."""
    if filter_id == "medium" and severity_rank(color) < SEVERITY_ORDER.index("medium"):
        return False
    if filter_id == "high" and severity(color) != "high":
        return False
    if filter_id == "diversions" and "HONEYPOT" not in label.upper():
        return False
    if filter_id == "outcomes" and kind != "outcome":
        return False
    return True


def text_matches(needle: str, *fields: str) -> bool:
    needle = needle.strip().lower()
    return not needle or any(needle in f.lower() for f in fields)


def format_time(ts: int) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "--:--:--"


_RFC3339_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})")
# Same, but captures the fractional-second part so sub-second latency math
# (summarize_group) keeps the nanosecond precision docker's --timestamps emits.
_RFC3339_FRAC_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?")


def rfc3339_to_epoch(ts: str | None) -> int:
    """Epoch seconds from a `docker compose logs --timestamps` RFC3339
    string (always UTC/Z here), 0 when it's missing or unparseable."""
    if not ts:
        return 0
    m = _RFC3339_RE.match(ts)
    if not m:
        return 0
    return calendar.timegm(tuple(int(g) for g in m.groups()) + (0, 0, 0))


def rfc3339_to_epoch_float(ts: str | None) -> float:
    """Like rfc3339_to_epoch but keeps the fractional second, so the gap
    between two log lines can be measured in milliseconds. 0.0 when the
    string is missing or unparseable."""
    if not ts:
        return 0.0
    m = _RFC3339_FRAC_RE.match(ts)
    if not m:
        return 0.0
    base = calendar.timegm(tuple(int(g) for g in m.groups()[:6]) + (0, 0, 0))
    frac = float(m.group(7)) if m.group(7) else 0.0
    return base + frac


def parse_backfill(text: str) -> list[tuple[int, object]]:
    """Parse a `docker compose logs --timestamps reverse_proxy` tail into
    (epoch, PatternEvent) rows, oldest first, so a freshly-opened feed is
    not blank. Lines the parser doesn't recognise are skipped; each event's
    own log timestamp is used (0 when absent)."""
    buffer = LineBuffer()
    rows: list[tuple[int, object]] = []
    for line in buffer.feed(text + "\n"):
        event = parse_line(line)
        if event is not None:
            rows.append((rfc3339_to_epoch(event.timestamp), event))
    return rows


@dataclass
class EventGroup:
    """One request's worth of related pattern-analyzer events collapsed into a
    single row. A request logs a burst of lines -- scoring signals, routing
    steps, a final score -- terminated by exactly one "outcome" line
    ([LOCATION / HEADER], one per request). group_events() splits the stream
    on that terminator, and this holds the burst plus the fields the table
    shows for it."""
    events: list = field(default_factory=list)   # (epoch_or_wallclock_int, PatternEvent), arrival order
    ts: int = 0                 # display time: the outcome's, else the last event's
    color: str = COLOR_INFO     # worst severity seen in the burst
    title: str = ""             # the outcome's label, else the worst-severity event's
    score: int | None = None    # the request's final risk score, when one was logged
    signals: str = ""           # the scoring signals that fired, joined for one glance
    detail: str = ""            # every line's label+detail, for the row tooltip / CSV
    latency_ms: int | None = None   # span first->outcome from the log timestamps (None if unknown)
    has_outcome: bool = False   # False while a request is still mid-flight (no outcome line yet)
    search_text: str = ""       # all labels+details joined, for the free-text filter


def summarize_group(group: list[tuple[int, PatternEvent]]) -> EventGroup:
    """Collapse one burst of (ts, PatternEvent) into an EventGroup. `group`
    must be non-empty and in arrival order."""
    events = list(group)
    color = max((e.color for _ts, e in events), key=severity_rank)
    outcome = next((e for _ts, e in reversed(events) if e.kind == "outcome"), None)
    scored = next((e for _ts, e in reversed(events)
                   if e.kind in ("outcome", "final_score") and e.score is not None), None)
    # The row's headline: the request's outcome if it has landed, otherwise
    # the worst thing seen so far while it is still in flight.
    rep = outcome or max(events, key=lambda te: severity_rank(te[1].color))[1]
    ts = next((t for t, e in reversed(events) if e.kind == "outcome"), events[-1][0])
    signals = " · ".join(e.label for _t, e in events if e.kind == "signal")
    detail = "  |  ".join(
        (e.label + (f" — {e.detail}" if e.detail else "")) for _t, e in events)
    # Latency = span between the earliest and latest log timestamps in the
    # burst (first signal -> routing outcome), i.e. how long the analyzer took
    # on this request. Needs real log timestamps (docker --timestamps); None
    # when fewer than two lines carried one.
    epochs = [rfc3339_to_epoch_float(e.timestamp) for _t, e in events if e.timestamp]
    latency_ms = round((max(epochs) - min(epochs)) * 1000) if len(epochs) >= 2 else None
    search_text = " ".join(f"{e.label} {e.detail}" for _t, e in events)
    return EventGroup(events, ts, color, rep.label,
                      outcome.score if outcome and outcome.score is not None else (scored.score if scored else None),
                      signals, detail, latency_ms, outcome is not None, search_text)


def group_events(events: list[tuple[int, PatternEvent]]) -> list[EventGroup]:
    """Split a flat, time-ordered event stream into per-request EventGroups,
    cutting a group after each "outcome" line. A trailing burst with no
    outcome yet becomes a final, still-open group (has_outcome False)."""
    groups: list[EventGroup] = []
    current: list[tuple[int, PatternEvent]] = []
    for ts, e in events:
        current.append((ts, e))
        if e.kind == "outcome":
            groups.append(summarize_group(current))
            current = []
    if current:
        groups.append(summarize_group(current))
    return groups


def group_matches(filter_id: str, group: EventGroup) -> bool:
    """Whether a collapsed request row passes the view filter `filter_id`
    (the group-level analogue of matches())."""
    if filter_id == "medium" and severity_rank(group.color) < SEVERITY_ORDER.index("medium"):
        return False
    if filter_id == "high" and severity(group.color) != "high":
        return False
    if filter_id == "diversions" and "HONEYPOT" not in group.search_text.upper():
        return False
    if filter_id == "outcomes" and not group.has_outcome:
        return False
    return True


def groups_to_csv(groups: list[EventGroup]) -> str:
    """One row per collapsed request: time, severity, outcome, score, latency,
    the signals that fired, and the full detail."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["time", "severity", "request", "score", "latency_ms", "signals", "detail"])
    for g in groups:
        iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(g.ts)) if g.ts else ""
        writer.writerow([iso, severity(g.color), g.title,
                         "" if g.score is None else g.score,
                         "" if g.latency_ms is None else g.latency_ms,
                         g.signals, g.detail])
    return out.getvalue()


def to_csv(rows: list[tuple[int, str, str, str, str]]) -> str:
    """rows: (timestamp, severity, kind, label, detail)."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["time", "severity", "kind", "label", "detail"])
    for ts, sev, kind, label, detail in rows:
        iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)) if ts else ""
        writer.writerow([iso, sev, kind, label, detail])
    return out.getvalue()
