"""Renders a core.account_persistence.AccountPersistenceReport to a PDF: the
step-by-step proof that a diverted logged-in adversary keeps their own account
on the honeypot pool ("account persistence", request 26).

GUI-thread only, same print machinery and Baskerville styling as
core/breach_audit_pdf.py.
"""
from __future__ import annotations

from PyQt6.QtCore import QMarginsF, QSizeF
from PyQt6.QtGui import QColor, QFont, QPageLayout, QPageSize, QPen, QTextDocument
from PyQt6.QtPrintSupport import QPrinter

from core import diagrams, report_pagination, vector_figures
from core.diagrams import _arrow, _box, _label, _new
from core.pattern_report_pdf import (_FONT_CSS_STACK, _GREEN, _GREY, _ORANGE, _RED,
                                     _badge, _esc, _report_font_family)
from core.account_persistence import (ERROR, FAIL, INFO, PASS, SKIP, WARN,
                                      AccountPersistenceReport, StepOutcome)

_BLUE = "#1f6feb"
_STATUS_COLOR = {PASS: _GREEN, FAIL: _RED, WARN: _ORANGE, INFO: _BLUE, SKIP: _GREY, ERROR: _GREY}
_STATUS_LABEL = {PASS: "PASS", FAIL: "FAIL", WARN: "WARN", INFO: "INFO", SKIP: "SKIP", ERROR: "ERROR"}


def _status_badge(status: str) -> str:
    return _badge(_STATUS_LABEL.get(status, status.upper()),
                  _STATUS_COLOR.get(status, _GREY))


def flow_figure(report: AccountPersistenceReport, family: str = "Serif"):
    """The account-persistence pipeline, left to right: a logged-in visitor on
    production, the edge that diverts them and keys the copy off production's
    verified identity, and the pool they land on -- still logged in. Each stage
    is tinted by the matching step's verdict so the reader sees where (if
    anywhere) the chain breaks."""
    by_num = {s.number: s for s in report.steps}

    def tint(num: int) -> str:
        s = by_num.get(num)
        if s is None:
            return "#9aa0a6"
        return {PASS: "#2e7d32", FAIL: "#c62828", WARN: "#e08a00",
                INFO: _BLUE, SKIP: "#9aa0a6", ERROR: "#9aa0a6"}.get(s.status, "#9aa0a6")

    img, p = _new(840, 250)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor("#1a1a1a"))
    p.drawText(20, 24, "How a diverted logged-in adversary keeps their account")

    prod = _box(p, 30, 70, 210, 64, "Production shop", "logged-in visitor",
                fill=tint(3), text="#ffffff")
    edge = _box(p, 320, 70, 200, 64, "Edge (reverse proxy)", "diverts + keys copy",
                fill=tint(4), text="#ffffff")
    pool = _box(p, 600, 70, 210, 64, "Honeypot pool", "same account, logged in",
                fill=tint(6), text="#ffffff")

    # _box returns the box centre; route arrows centre-to-centre, clearing the
    # box half-widths (105 for the 210-wide boxes, 100 for the 200-wide edge).
    _arrow(p, prod[0] + 105, prod[1], edge[0] - 100, edge[1], color="#555555")
    _label(p, (prod[0] + edge[0]) / 2, prod[1] - 16, "X-Auth-User", color="#555555")
    _arrow(p, edge[0] + 100, edge[1], pool[0] - 105, pool[1], color="#555555")
    _label(p, (edge[0] + pool[0]) / 2, edge[1] - 16, "copy + autologin", color="#555555")

    p.setFont(QFont(family, 9))
    p.setPen(QColor("#555555"))
    p.drawText(30, 170, "The username also rides the gdpr_token as metadata, but the edge keys the")
    p.drawText(30, 185, "account copy off production's verified X-Auth-User -- never the spoofable token")
    p.drawText(30, 200, "value -- so a client cannot name someone else's account to have it copied.")
    p.setFont(QFont(family, 8))
    p.setPen(QColor("#999999"))
    p.drawText(30, 228, "Box colour = the matching step's verdict (green pass, orange warning, red fail, grey skipped).")
    p.end()
    return img


def _steps_table(steps: list[StepOutcome]) -> str:
    rows = [
        '<table width="100%" cellpadding="5" cellspacing="0" border="1" '
        'style="border-collapse:collapse; border-color:#ddd; font-size:9.5pt;">',
        '<tr style="background-color:#f0f0f0;">'
        '<th align="left" width="8%">#</th>'
        '<th align="left" width="14%">Result</th>'
        '<th align="left" width="78%">Step</th></tr>',
    ]
    for s in steps:
        details = ""
        if s.details:
            details = ('<br/><span style="color:#666; font-size:9pt;">'
                       + "<br/>".join(_esc(d) for d in s.details) + "</span>")
        evidence = ""
        if s.evidence:
            evidence = (f'<br/><span style="color:#444; font-size:9pt;"><i>'
                        f'{_esc(s.evidence)}</i></span>')
        rows.append(
            "<tr>"
            f'<td align="center"><b>{s.number}</b></td>'
            f'<td>{_status_badge(s.status)}</td>'
            f'<td><b>{_esc(s.name)}</b><br/>'
            f'<span style="color:#555;">{_esc(s.summary)}</span>{evidence}{details}</td>'
            "</tr>")
    rows.append("</table>")
    return "".join(rows)


def render_pdf(report: AccountPersistenceReport, out_path: str) -> None:
    family = _report_font_family()
    status, summary = report.headline()
    status_color = _RED if status.startswith("NOT") else (
        _ORANGE if "warning" in status.lower() else (
            _GREY if status.startswith("INCONCLUSIVE") else _GREEN))
    counts = report.counts()

    doc = QTextDocument()
    doc.setDefaultFont(QFont(family, 11))

    parts = [
        f'<div style="font-family: {_FONT_CSS_STACK};">',
        '<h1 style="color:#222;">Account Persistence report</h1>',
        '<table width="100%" style="color:#555;"><tr><td>'
        f'Generated: {_esc(report.generated_at)}<br/>'
        f'Target: {_esc(report.target_label)} &nbsp; ({_esc(report.base_url)})<br/>'
        f'Live proof screen size: {_esc(report.screen)}<br/>'
        f'Live proof username (synthetic): {_esc(report.username)}'
        '</td></tr></table><hr/>',
        '<h2 style="color:#222;">Result</h2>',
        f'<p>{_badge(status, status_color)} &nbsp;<b>{_esc(summary)}</b></p>',
        '<p style="color:#555;">'
        f'{counts[PASS]} verified &middot; {counts[FAIL]} broken &middot; '
        f'{counts[WARN]} warnings &middot; {counts[SKIP]} skipped &middot; '
        f'{counts[ERROR]} errored.</p>',
    ]

    if report.failures:
        parts.append('<h2 style="color:#c62828;">Steps that did not hold</h2><ul>')
        for s in report.failures:
            parts.append(f'<li><b>Step {s.number}: {_esc(s.name)}</b> &mdash; {_esc(s.evidence)}</li>')
        parts.append('</ul>')

    parts.append('<h2 style="color:#222;">What this verifies</h2>')
    parts.append(
        '<p style="color:#555;">When a logged-in visitor\'s gdpr_signature turns '
        'suspicious and the edge diverts them to a honeypot pool, their own '
        'production account &ndash; role, profile, password hash and all &ndash; is '
        'copied into that pool and they are silently logged in there, so nothing '
        'about the move hints they have been dropped into a honeypot. This report '
        'walks that chain one step at a time: a live proof that the username rides '
        'the gdpr_token as metadata and never changes the signature, then read-only '
        'inspection that production publishes the authenticated identity, the edge '
        'keys the copy off that verified identity (never the spoofable token value) '
        'and strips the identity/autologin headers from client traffic, the '
        'replication worker is running, and the pool autologin plugin is '
        'secret-gated. Every check is read-only; no account is actually copied.</p>')

    parts.append(diagrams.figure_html(
        doc, flow_figure(report, family), "persistence-flow", 1,
        "The account-persistence pipeline. Production emits the authenticated identity, the "
        "edge diverts and keys the copy off it, and the adversary lands on the pool still "
        "logged in as themselves. Each box is tinted by the matching step's verdict.",
        width=660))

    parts.append('<h2 style="color:#222;">Step-by-step</h2>')
    parts.append(_steps_table(report.steps))

    parts.append('</div>')
    doc.setHtml("<body>" + "".join(parts) + "</body>")
    vector_figures.embed_figures(doc)

    printer = QPrinter(QPrinter.PrinterMode.ScreenResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(out_path)
    printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    printer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
    doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.DevicePixel).size()))
    report_pagination.keep_together(doc)
    doc.print(printer)
