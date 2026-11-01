"""Suricata (the edge stack's network IDS) from the dashboard: recent alerts
from eve.json, the local.rules rule set with per-rule enable/disable, and
the docker-compose plumbing to read/write them in the suricata_ids
container (locally or over SSH, via Target.build). Parsing is pure and
unit-tested (tests/test_suricata_ctl.py); the fetch/save helpers are thin
wrappers around `docker compose exec`."""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass

from core.docker_ctl import Target
from core.proc import run_checked
from core.state import RemoteConfig

SERVICE = "suricata_ids"
EVE_PATH = "/var/log/suricata/eve.json"
RULES_PATH = "/var/lib/suricata/rules/local.rules"

SEVERITY_LABELS = {1: "critical", 2: "high", 3: "medium"}


class SuricataError(Exception):
    pass


@dataclass(frozen=True)
class SuricataAlert:
    timestamp: str
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    signature: str
    sid: int
    category: str
    severity: int
    action: str
    url: str
    user_agent: str
    proto: str = ""
    app_proto: str = ""
    hostname: str = ""
    http_method: str = ""

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, f"sev {self.severity}")

    def detail_lines(self) -> list[tuple[str, str]]:
        """(label, value) pairs for a detail pane, blanks omitted."""
        rows = [
            ("Signature", f"{self.signature}  (sid {self.sid}, sev {self.severity})"),
            ("Category", self.category), ("Action", self.action),
            ("Source", f"{self.src_ip}:{self.src_port}"),
            ("Target", f"{self.dest_ip}:{self.dest_port}"),
            ("Protocol", " / ".join(p for p in (self.proto, self.app_proto) if p)),
            ("Host", self.hostname),
            ("Request", f"{self.http_method} {self.url}".strip()),
            ("User agent", self.user_agent), ("Time", self.timestamp),
        ]
        return [(k, v) for k, v in rows if v]


def parse_alerts(text: str) -> list[SuricataAlert]:
    """Alert records from eve.json lines (anything not an alert event, or not
    JSON, is skipped), oldest first as in the file."""
    out: list[SuricataAlert] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict) or e.get("event_type") != "alert" or not isinstance(e.get("alert"), dict):
            continue
        a, http = e["alert"], e.get("http") if isinstance(e.get("http"), dict) else {}
        out.append(SuricataAlert(
            timestamp=str(e.get("timestamp", "")), src_ip=str(e.get("src_ip", "")),
            src_port=int(e.get("src_port") or 0), dest_ip=str(e.get("dest_ip", "")),
            dest_port=int(e.get("dest_port") or 0), signature=str(a.get("signature", "")),
            sid=int(a.get("signature_id") or 0), category=str(a.get("category", "")),
            severity=int(a.get("severity") or 3), action=str(a.get("action", "")),
            url=str(http.get("url", "")), user_agent=str(http.get("http_user_agent", "")),
            proto=str(e.get("proto", "")), app_proto=str(e.get("app_proto", "")),
            hostname=str(http.get("hostname", "")), http_method=str(http.get("http_method", ""))))
    return out


def summarize(alerts: list[SuricataAlert], top: int = 5) -> dict:
    """Headline counts: total, per severity label, and the top signatures /
    source IPs."""
    return {
        "total": len(alerts),
        "by_severity": dict(Counter(a.severity_label for a in alerts)),
        "top_signatures": Counter(a.signature for a in alerts).most_common(top),
        "top_sources": Counter(a.src_ip for a in alerts).most_common(top),
    }


# ---- rules ----

_RULE_RE = re.compile(r"^(?P<hash>#\s*)?(?P<action>alert|drop|reject|pass)\s+\S+.*\((?P<opts>.*)\)\s*$")
_SID_RE = re.compile(r"\bsid:\s*(\d+)")
_MSG_RE = re.compile(r'msg:\s*"((?:[^"\\]|\\.)*)"')
_CLASS_RE = re.compile(r"\bclasstype:\s*([\w-]+)")
_REV_RE = re.compile(r"\brev:\s*(\d+)")


@dataclass(frozen=True)
class Rule:
    line_no: int           # 0-based index in the file
    sid: int
    msg: str
    action: str
    classtype: str
    rev: int
    enabled: bool


def parse_rules(text: str) -> list[Rule]:
    """Every rule line in a rules file, enabled or commented out (`# alert
    ...`). Comments that aren't rules are ignored."""
    rules: list[Rule] = []
    for i, line in enumerate(text.splitlines()):
        m = _RULE_RE.match(line.strip())
        if not m:
            continue
        sid = _SID_RE.search(m.group("opts"))
        if not sid:
            continue
        msg, cls, rev = (_MSG_RE.search(m.group("opts")), _CLASS_RE.search(m.group("opts")),
                         _REV_RE.search(m.group("opts")))
        rules.append(Rule(i, int(sid.group(1)), msg.group(1) if msg else "", m.group("action"),
                          cls.group(1) if cls else "", int(rev.group(1)) if rev else 1,
                          enabled=m.group("hash") is None))
    return rules


def set_rule_enabled(text: str, sid: int, enabled: bool) -> str:
    """The rules text with rule `sid` commented out or restored. Raises
    SuricataError when the sid isn't in the file."""
    lines = text.split("\n")
    for rule in parse_rules(text):
        if rule.sid != sid:
            continue
        line = lines[rule.line_no]
        body = re.sub(r"^\s*#\s*", "", line) if not rule.enabled else line
        lines[rule.line_no] = body if enabled else f"# {body.lstrip()}"
        return "\n".join(lines)
    raise SuricataError(f"Rule sid {sid} not found.")


# ---- container access ----

def _exec(remote: RemoteConfig | None, *cmd: str, input: str | None = None, timeout: float = 30.0) -> str:
    argv, cwd = Target(project="edge", remote=remote).build("exec", "-T", SERVICE, *cmd)
    return run_checked(argv, error=SuricataError, cwd=cwd, timeout=timeout, input=input,
                       what="docker compose exec").stdout


def fetch_alerts(remote: RemoteConfig | None, limit: int = 500) -> list[SuricataAlert]:
    # Piped through tail so "no alerts yet" is an empty result, not grep's exit 1.
    out = _exec(remote, "sh", "-c",
                f"grep '\"event_type\":\"alert\"' {EVE_PATH} 2>/dev/null | tail -n {int(limit)}")
    return parse_alerts(out)


def clear_alerts(remote: RemoteConfig | None) -> None:
    """Empty the eve.json alert log so the Alerts tab starts fresh.

    Truncates the file in place (`: > eve.json`) rather than deleting it:
    Suricata holds eve.json open in append mode, so truncation makes its next
    write land at offset 0 of the same file, whereas `rm` would unlink the
    inode Suricata keeps writing to -- the log would look empty in the UI while
    Suricata silently logged to a now-nameless file until its next restart."""
    _exec(remote, "sh", "-c", f": > {EVE_PATH}")


def container_ip_map(remote: RemoteConfig | None, timeout: float = 15.0) -> dict[str, str]:
    """Best-effort map of container IP -> container name for every running
    container on the target host, so the Alerts tab can name the container an
    alert's source/target IP belongs to.

    Suricata runs with network_mode:host and logs the raw Docker bridge IPs it
    sees (e.g. 172.20.0.7), which are meaningless on their own; `docker inspect`
    turns them back into container names. This spans ALL running containers, not
    just the edge compose project, so production, the honeypot pools and the
    reverse proxy all resolve. Runs `docker` directly (not compose) via
    build_shell so it works locally and over SSH. Returns {} on any failure --
    the IPs still show unannotated, so enrichment never breaks the Alerts view."""
    argv, cwd = Target(project="edge", remote=remote).build_shell(
        "docker ps -q | xargs -r docker inspect "
        "--format '{{$n := .Name}}{{range .NetworkSettings.Networks}}"
        "{{.IPAddress}} {{$n}}{{println}}{{end}}'")
    try:
        out = run_checked(argv, error=SuricataError, cwd=cwd, timeout=timeout,
                          what="docker inspect").stdout
    except SuricataError:
        return {}
    mapping: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        ip, name = parts[0], parts[1].lstrip("/")
        if ip and name:
            mapping[ip] = name
    return mapping


def fetch_rules_text(remote: RemoteConfig | None) -> str:
    return _exec(remote, "cat", RULES_PATH)


def save_rules_text(remote: RemoteConfig | None, text: str) -> None:
    _exec(remote, "sh", "-c", f"cat > {RULES_PATH}", input=text)


def restart(remote: RemoteConfig | None) -> None:
    """Restart suricata_ids so it loads the edited rule file."""
    argv, cwd = Target(project="edge", remote=remote).build("restart", SERVICE)
    run_checked(argv, error=SuricataError, cwd=cwd, timeout=180.0, what="docker compose restart")
