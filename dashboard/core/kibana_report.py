"""Kibana PDF export: one section per SIEM Analytics page button on the SIEM Analytics page
(ui/page_kibana._BOOKMARKS), each with a short explanation of what the page
shows and a full-page screenshot of it.

The screenshots themselves are captured by ui/kibana_export.KibanaCapture
(it needs a live, logged-in QWebEngineView); this module only turns the
captured images into the PDF, so it stays usable headlessly.

A full-page capture of a dashboard is usually far taller than one A4 page,
and QTextDocument never splits an image across pages -- so each capture is
sliced into page-sized strips here and laid out one after another.
"""
from __future__ import annotations

import html as _html
from dataclasses import dataclass
from datetime import datetime

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QFont, QImage, QTextDocument

from core.pattern_report_pdf import _FONT_CSS_STACK, _report_font_family
from core.thesis_export import _finish_pdf

# What each SIEM Analytics page button shows, keyed by its path relative to the
# Kibana root (same keys as ui/page_kibana._BOOKMARKS). Panel names match
# siem/kibana/build_dashboards.py.
PAGE_NOTES: dict[str, str] = {
    "/app/home": (
        "Kibana's landing page for the SIEM stack. It is the entry point to the saved "
        "dashboards and to Discover below, and confirms the SIEM (Vector &rarr; "
        "Elasticsearch &rarr; Kibana) is up and the dashboard is logged in."
    ),
    "/app/dashboards#/view/dashboard-web-threat-overview": (
        "What was requested through the reverse proxy and how it was answered. "
        "<b>Requests Over Time by Route</b> and <b>Production vs Honeypot Routing</b> show "
        "volume and the share diverted to the decoy shop; <b>Top URIs</b> lists the most "
        "requested URIs, each marked <i>attack_pattern</i> (it matched an attack pattern or "
        "CVE signature) or <i>safe</i>, with its peak risk score; <b>Attack-Pattern vs Safe "
        "Requests</b>, <b>HTTP Status Codes</b>, <b>HTTP Methods</b> and <b>Top User-Agents</b> "
        "round out the picture of the traffic."
    ),
    "/app/dashboards#/view/dashboard-ids-alerts": (
        "Network-level alerts from the Suricata IDS, independent of the reverse proxy's "
        "own scoring. <b>Alerts Over Time by Severity</b> gives volume (severity 1 is the "
        "worst); <b>Alerts by Category</b>, <b>Alerts by Application Protocol</b> and "
        "<b>Targeted Destination Ports</b> show what kind of traffic was flagged; <b>Top "
        "Signatures</b> names the rules that fired most and <b>Top Source IPs</b> the hosts "
        "that triggered them. These alerts also feed the IP-reputation signal of the "
        "scoring pipeline."
    ),
    "/app/dashboards#/view/dashboard-threat-decisions": (
        "Why each request was routed where it was. The proxy adds a request's own score to "
        "what is left of its session's earlier score after decay; at the honeypot threshold "
        "(dashed line) the session is diverted. <b>Effective Score = Own + Carried</b> plots "
        "the three over time, <b>Peak Effective Score vs Threshold</b> the worst moment; "
        "<b>Decay State of Requests</b> shows how many sessions were still decaying or "
        "permaflagged (never decay), <b>Offenses per Request's Session</b> how many attack "
        "signals they had fired, <b>Honeypot Routing Reasons</b> what triggered each "
        "diversion, and <b>Score Breakdown by Route</b> the average scores behind each "
        "outcome."
    ),
    "/app/dashboards#/view/dashboard-session-analysis": (
        "Behaviour per tracked session rather than per request. <b>Total Distinct "
        "Sessions</b> and <b>Distinct Sessions Active Over Time by Route</b> give the "
        "population; <b>Requests &amp; Duration per Session</b> and <b>Most Hostile "
        "Sessions</b> single out the busiest and most hostile sessions (peak score after "
        "accumulation and decay, offenses, distinct attack patterns); the sophistication "
        "panels show how users were classified and with what confidence over time."
    ),
    "/app/dashboards#/view/dashboard-attack-patterns": (
        "What the attacks were. <b>Matched Attack Patterns</b> is a cloud of the attack "
        "patterns and CVE signatures requests matched, and <b>URIs Matching Attack "
        "Patterns</b> lists the URIs behind them with their own score. The lower panels come "
        "from security events the proxy logged explicitly: <b>Security Events Over Time by "
        "Type</b>, <b>Top CVEs Detected</b>, <b>Top Attacking IPs</b> and <b>Honeytoken Hits "
        "by Type</b> (which planted honeytokens were reused)."
    ),
    "/app/dashboards#/view/dashboard-threat-intel": (
        "The same events turned into threat intelligence. Every proxy request, proxy "
        "security event and Suricata alert carries the user's IP, the tool its "
        "User-Agent gives away and the MITRE ATT&amp;CK techniques it stands for. "
        "<b>User Indicators</b> is the IOC list: one row per IP with first and last "
        "seen, how many sensors saw it and the furthest ATT&amp;CK stage it reached; "
        "<b>Kill Chain</b> and <b>How Far Each User Got</b> place that activity on the "
        "ATT&amp;CK tactics in order; <b>MITRE ATT&amp;CK Techniques Observed</b>, <b>Attack "
        "Tools Fingerprinted</b> and <b>CVEs Targeted</b> say what was used against the shop; "
        "<b>Verdict per Sensor</b> compares the proxy's and Suricata's judgement, and the "
        "<b>Flagged Event Feed</b> lists the events behind it all, exportable from Discover "
        "as CSV."
    ),
    "/app/dashboards#/view/dashboard-infra-logs": (
        "Operational health of the stack itself, from the shipped log types that carry no "
        "threat score. <b>Proxy Log Levels</b> and <b>Proxy Log Levels Over Time</b> separate "
        "nginx's routine <i>info</i> request traces from real <i>warn</i>/<i>error</i>/"
        "<i>crit</i> lines; <b>Container Logs by Service</b>, <b>Top Containers by Log "
        "Volume</b> and <b>stdout vs stderr</b> show which container is noisy and whether it "
        "is writing to its error stream; <b>Redis Session-Store Log Lines</b> counts the "
        "session store's activity and <b>Operational Log Volume Over Time</b> the three "
        "together. The <b>Recent Log Lines</b> feed is the raw text behind them, for spotting "
        "a crash loop or an error burst. The reverse proxy's own logs ship as files, not "
        "through Docker, so it is not among the containers here."
    ),
    "/app/management/insightsAndAlerting/triggersActions/rules": (
        "The active Kibana alerting rules seeded for the honeypot "
        "(Elasticsearch-query rules over <code>honeypot-*</code>): a session "
        "diverted to the decoy, a high-severity Suricata alert, a used "
        "honeytoken, a compromised session, a CVE exploitation attempt and an "
        "offensive scanner. Each runs on a schedule and raises an alert, shown "
        "here as its status (<i>Active</i> when currently firing) with a count "
        "of alerts; open a rule to see what matched. These fire inside Kibana "
        "independently of the dashboard app's own OS notifications."
    ),
    "/app/discover": (
        "Raw log search over the <code>honeypot-*</code> data view: every event Vector "
        "shipped into Elasticsearch, newest first, with a histogram of event volume over "
        "the selected time range. Used to drill into the individual documents behind any "
        "panel on the dashboards above."
    ),
}


@dataclass
class KibanaShot:
    label: str          # the SIEM Analytics page button's label
    path: str           # path relative to the Kibana root
    url: str            # full URL that was captured
    image: QImage | None
    error: str = ""     # why there is no image, if there isn't one


def _esc(text: str) -> str:
    return _html.escape(text or "")


def _slices(img: QImage, max_aspect: float) -> list[QImage]:
    """Cut ``img`` into horizontal strips at most ``width * max_aspect`` tall."""
    strip_h = max(1, int(img.width() * max_aspect))
    if img.height() <= strip_h:
        return [img]
    return [img.copy(0, y, img.width(), min(strip_h, img.height() - y))
            for y in range(0, img.height(), strip_h)]


def render_kibana_pdf(shots: list[KibanaShot], out_path: str, kibana_url: str) -> int:
    """Write the Kibana export PDF. Returns the number of pages captured."""
    family = _report_font_family()
    doc = QTextDocument()
    doc.setDefaultFont(QFont(family, 11))
    width = 620
    # Strips about as tall as an A4 page's text area allows at this width,
    # leaving room for the heading/explanation on the first strip's page.
    max_aspect = 1.5

    parts: list[str] = [f'<div style="font-family: {_FONT_CSS_STACK};">']
    parts.append('<h1 style="color:#222;">Kibana (SIEM) pages</h1>')
    parts.append('<p style="color:#555;">Generated '
                 f'{_esc(datetime.now().strftime("%Y-%m-%d %H:%M"))} from '
                 f'<code>{_esc(kibana_url)}</code>. One section per page button on the '
                 "dashboard's SIEM Analytics page: what the page shows, then a full-page screenshot "
                 'of it as it looked at export time (dashboards use their saved time range, '
                 'the last 24 hours). Tall pages continue over several strips.</p><hr/>')

    captured = 0
    for i, shot in enumerate(shots, start=1):
        parts.append(f'<h2 style="color:#222;">{i}. {_esc(shot.label)}</h2>')
        note = PAGE_NOTES.get(shot.path, "")
        if note:
            parts.append(f'<p style="color:#444;">{note}</p>')
        parts.append(f'<p style="color:#888; font-size:9pt;">{_esc(shot.url)}</p>')
        if shot.image is None or shot.image.isNull():
            parts.append('<p style="color:#c62828;"><b>Not captured:</b> '
                         f'{_esc(shot.error or "the page did not load")}</p>')
            continue
        captured += 1
        for j, strip in enumerate(_slices(shot.image, max_aspect)):
            key = f"kibana-{i}-{j}"
            doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(f"shot://{key}"), strip)
            h = int(width * strip.height() / max(1, strip.width()))
            parts.append(f'<p><img src="shot://{key}" width="{width}" height="{h}"/></p>')

    parts.append('</div>')
    doc.setHtml("<body>" + "".join(parts) + "</body>")
    _finish_pdf(doc, out_path)
    return captured
