"""Security-alert policy (Qt-free): which parsed proxy events should raise a
notification, how often, and where it goes (desktop balloon and/or a
webhook). The policy is a plain dict in AppState.alert_policy so it
persists and survives older state files; AlertPolicy.from_dict fills any
missing key with its default.

should_alert() is the pure decision (severity threshold, honeypot
diversions, risk-score threshold, per-event cooldown); webhook_payload()
builds the JSON body; send_webhook() POSTs it (call from a thread)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, fields

from core import live_events

MIN_SEVERITIES = ["medium", "high"]


@dataclass
class AlertPolicy:
    enabled: bool = True
    min_severity: str = "high"          # "medium" | "high"
    on_diversion: bool = True            # always alert when a session is routed to the honeypot
    score_threshold: int = 0             # alert at/above this risk score (0 = off)
    cooldown_seconds: int = 60           # don't repeat the same alert within this window
    desktop: bool = True                 # tray balloon
    webhook_url: str = ""                # POST JSON here when set (Slack-compatible "text" field included)

    @classmethod
    def from_dict(cls, data) -> "AlertPolicy":
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in (data or {}).items() if k in known} if isinstance(data, dict) else {}
        policy = cls(**clean)
        if policy.min_severity not in MIN_SEVERITIES:
            policy.min_severity = "high"
        policy.score_threshold = max(0, min(100, int(policy.score_threshold or 0)))
        policy.cooldown_seconds = max(0, int(policy.cooldown_seconds or 0))
        return policy

    def to_dict(self) -> dict:
        return asdict(self)


def should_alert(policy: AlertPolicy, kind: str, label: str, color: str, score: int | None,
                 last_sent: dict[str, float], now: float) -> bool:
    """Whether this event raises an alert under `policy`. Records the send
    time in `last_sent` (keyed by label) when it does, so identical events
    inside the cooldown are dropped."""
    if not policy.enabled:
        return False
    rank = live_events.severity_rank(color)
    wanted = rank >= live_events.SEVERITY_ORDER.index(policy.min_severity)
    if policy.on_diversion and live_events.is_honeypot_diversion(kind, label):
        wanted = True
    if policy.score_threshold and score is not None and score >= policy.score_threshold:
        wanted = True
    if not wanted:
        return False
    previous = last_sent.get(label)
    if previous is not None and now - previous < policy.cooldown_seconds:
        return False
    last_sent[label] = now
    return True


def message(label: str, detail: str) -> str:
    return f"{label} — {detail}" if detail else label


def webhook_payload(label: str, detail: str, severity: str, score: int | None, timestamp: int) -> dict:
    text = f"[PressHaven.io] {severity.upper()}: {message(label, detail)}"
    return {"text": text, "label": label, "detail": detail, "severity": severity,
            "score": score, "timestamp": timestamp}


def send_webhook(url: str, payload: dict, timeout: float = 5.0) -> str:
    """POSTs payload as JSON; returns "" on success or an error message.
    Only http(s) URLs are accepted."""
    if not url.lower().startswith(("http://", "https://")):
        return "Webhook URL must start with http:// or https://"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout):   # noqa: S310 -- scheme checked above
            return ""
    except (urllib.error.URLError, OSError, ValueError) as e:
        return str(e)
