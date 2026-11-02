#!/usr/bin/env python3
"""Build the shared pattern catalogue used by the docs site and the dashboard.

The catalogue is a checked-in JSON file, not something either front end reads
straight out of Lua at runtime.  That keeps the documentation site buildable
without a Lua interpreter, keeps the PyQt dashboard startup fast, and gives
both views exactly the same stable IDs and metadata.

Sources merged here
-------------------
* ``ids/reverse_proxy_enhanced/lua/pattern_rules.lua``
  - Layer 1 ``SUSPICIOUS_PATTERNS`` (literal / extension / parameter / segment
    / Lua-pattern entries, +15 each)
  - Layer 2 ``specific_checks`` (per-signature scores and WSTG mapping)
  - header, method and automation heuristics
* ``ids/reverse_proxy_enhanced/lua/init.lua`` (``cve_patterns``)
* ``ids/reverse_proxy_enhanced/lua/vulnerability_rules.lua`` (narrower
  plugin-path CVE detector + generic WordPress checks)
* ``ids/reverse_proxy_enhanced/lua/upload_rules.lua`` (upload-specific rules)
* ``ids/suricata_rules/local.rules`` (SIDs, messages, classes, WSTG comments)
* ``dashboard/core/patterns.py`` (the Attack Simulation presets: payloads,
  category axes, DB-isolation notes)
* ``dashboard/core/learning.py`` (per-pattern lesson content)

Run ``python3 tools/generate_pattern_catalog.py`` after changing any of those
files.  ``--check`` exits non-zero when the checked-in JSON is stale; that is
the hook for CI / a pre-commit check.

The output schema is intentionally small and front-end neutral:

    id, name, kind, category, category_label, severity,
    component, plugin, surface, description, trigger, trigger_type,
    score, score_note, wstg, owasp, mitre, cve, attack_vector,
    detection, sources, signatures, suricata, preset, lesson,
    reportable, enabled, tags, notes

Both front ends may ignore fields they do not need, but they must not invent
IDs: the catalogue ID is the future plugin key for enable/disable/edit/export.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LUA_DIR = REPO / "ids" / "reverse_proxy_enhanced" / "lua"
SURICATA_RULES = REPO / "ids" / "suricata_rules" / "local.rules"
OUTPUT = REPO / "patterns" / "patterns.json"
DASHBOARD_DIR = REPO / "dashboard"

sys.path.insert(0, str(DASHBOARD_DIR))
from core.learning import lesson_for  # noqa: E402
from core.patterns import (  # noqa: E402
    GDPR_RESTORE_CVE,
    GDPR_RESTORE_PRESET,
    PATTERN_PRESETS,
    default_enabled,
)

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

KIND_LABELS = {
    "cve": "CVE pattern",
    "generic": "Generic attack",
    "tool": "Scanner tool",
    "behaviour": "Behavioural signal",
    "session": "Session signal",
}

CATEGORY_LABELS = {
    "cve": "CVE",
    "sqli": "SQL injection",
    "xss": "Cross-site scripting",
    "traversal": "Path traversal",
    "file-inclusion": "File inclusion",
    "command-injection": "Command injection",
    "sensitive-file": "Sensitive file",
    "recon": "Reconnaissance",
    "enumeration": "Enumeration",
    "access-control": "Access control",
    "authentication": "Authentication",
    "upload": "File upload",
    "injection": "Injection",
    "http": "HTTP abuse",
    "wordpress": "WordPress core",
    "plugin": "Plugin / theme",
    "tool": "Scanner / automation",
    "behaviour": "Behavioural",
    "network": "Network IDS",
    "session": "Session",
    "cloud": "Cloud / storage",
    "deserialization": "Deserialization",
    "template": "Template injection",
    "webshell": "Web shell",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

CATEGORY_DESCRIPTIONS = {
    "sqli": "Database query manipulation: tautologies, UNION SELECT, time delays or destructive statements.",
    "xss": "Browser-side script injection through tags, event handlers or javascript: URIs.",
    "traversal": "Escaping the web root with ../ sequences, including encoded variants.",
    "file-inclusion": "PHP/file/data stream wrappers used to include or read local or remote files.",
    "command-injection": "Shell metacharacters and command names used to execute operating-system commands.",
    "sensitive-file": "Requests for configuration, backup and installer files that should not be public.",
    "recon": "Discovery probes for admin panels, backups, version strings and installed components.",
    "enumeration": "Walking user, plugin, theme or object identifiers to learn what exists.",
    "access-control": "Missing authorization checks, IDOR object walks and privilege escalation.",
    "authentication": "Login, registration, password-reset and brute-force behaviour.",
    "upload": "Dangerous extensions, MIME-type mismatches, traversal in upload paths and executable destinations.",
    "injection": "Code, template, header and parameter injection outside the SQL/XSS families.",
    "http": "HTTP-level abuse such as CRLF splitting, unusual methods and parameter pollution.",
    "wordpress": "WordPress core endpoints and configuration surfaces.",
    "plugin": "Plugin or theme specific endpoints and vulnerable components.",
    "tool": "Known scanners and generic automation clients identified by User-Agent or behaviour.",
    "behaviour": "Signals that need request history rather than one payload: rates, bursts and session changes.",
    "network": "Signatures evaluated by Suricata on the network path.",
    "session": "Session continuity, identity and restoration behaviour.",
    "cloud": "Cloud-storage backup probing.",
    "deserialization": "Serialized object payloads that can trigger gadget chains.",
    "template": "Server-side template expression syntax.",
    "webshell": "PHP web-shell uploads and encoded payloads.",
}

SOURCES = {
    "lua-layer1": {
        "label": "Lua Layer 1",
        "module": "pattern_rules.lua",
        "detail": "SUSPICIOUS_PATTERNS generic entries (+15 each)",
    },
    "lua-layer2": {
        "label": "Lua Layer 2",
        "module": "pattern_rules.lua",
        "detail": "specific_checks with per-signature scores",
    },
    "lua-cve": {
        "label": "Lua CVE pattern",
        "module": "init.lua",
        "detail": "vulnerability.cve_patterns (URI, query string and headers; +40)",
    },
    "lua-vuln": {
        "label": "Vulnerability rules",
        "module": "vulnerability_rules.lua",
        "detail": "detect_vulnerability_pattern() narrow plugin-path detector",
    },
    "owasp-crs": {
        "label": "OWASP CRS",
        "module": "pattern_rules.lua",
        "detail": "Generic signature derived from the OWASP ModSecurity Core "
                  "Rule Set (LFI/RFI, RCE, PHP/Java injection, SSTI, SSRF, XXE, "
                  "NoSQL, deeper SQLi/XSS, CRLF)",
    },
    "headers": {
        "label": "Header analysis",
        "module": "pattern_rules.lua",
        "detail": "analyze_headers()",
    },
    "automation": {
        "label": "Automation scoring",
        "module": "pattern_rules.lua",
        "detail": "score_automation_user_agent()",
    },
    "method": {
        "label": "Request method",
        "module": "pattern_rules.lua",
        "detail": "analyze_request_method()",
    },
    "upload": {
        "label": "Upload analysis",
        "module": "upload_rules.lua",
        "detail": "analyze_upload_parameters / endpoint / user agent / content type",
    },
    "suricata": {
        "label": "Suricata rule",
        "module": "ids/suricata_rules/local.rules",
        "detail": "eve.json alert, severity-graded into IP reputation",
    },
    "preset": {
        "label": "Simulation preset",
        "module": "dashboard/core/patterns.py",
        "detail": "Attack Simulation request with a real payload",
    },
    "session": {
        "label": "Session policy",
        "module": "session_rules.lua / GDPR",
        "detail": "identity continuity and restoration behaviour",
    },
    "edge": {
        "label": "Edge block",
        "module": "nginx.conf access_by_lua_block",
        "detail": "outright 403 at the edge, before scoring or routing",
    },
}


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _clean_lua_string(value: str) -> str:
    """Unescape the small subset of Lua escapes used by the rules."""
    out = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _humanise(name: str) -> str:
    text = name.replace("_", " ").replace("-", " ").strip()
    return text[:1].upper() + text[1:]


def _severity_for_score(score: int | None) -> str:
    if not score:
        return "info"
    if score >= 70:
        return "critical"
    if score >= 25:
        return "high"
    if score >= 15:
        return "medium"
    return "low"


def _category_from_wstg(wstg: str) -> str:
    if wstg.startswith("WSTG-INPV-01"):
        return "traversal"
    if wstg.startswith("WSTG-INPV-02"):
        return "xss"
    if wstg.startswith("WSTG-INPV-04"):
        return "http"
    if wstg.startswith("WSTG-INPV-05"):
        return "sqli"
    if wstg.startswith("WSTG-INPV-10"):
        return "upload"
    if wstg.startswith("WSTG-INPV-11"):
        return "file-inclusion"
    if wstg.startswith("WSTG-INPV-12"):
        return "command-injection"
    if wstg.startswith("WSTG-INPV-15"):
        return "http"
    if wstg.startswith("WSTG-INPV-18"):
        return "template"
    if wstg.startswith("WSTG-CONF"):
        return "sensitive-file"
    if wstg.startswith("WSTG-INFO"):
        return "recon"
    if wstg.startswith("WSTG-IDNT"):
        return "enumeration"
    if wstg.startswith("WSTG-AUTHZ"):
        return "access-control"
    if wstg.startswith("WSTG-ATHN"):
        return "authentication"
    if wstg.startswith("WSTG-SESS"):
        return "session"
    return "injection"


def _owasp_from_wstg(wstg: str) -> str:
    """OWASP Top 10 (2021) category for a WSTG code.

    Used to tag the generic CRS-style signatures with an OWASP bucket when no
    lesson supplies one -- the ModSecurity Core Rule Set maps its rule families
    (930 LFI, 931 RFI, 932 RCE, 933 PHP, 941 XSS, 942 SQLi, 944 Java, ...) onto
    these same Top 10 categories.
    """
    if wstg.startswith(("WSTG-INPV-02", "WSTG-INPV-04", "WSTG-INPV-05",
                        "WSTG-INPV-06", "WSTG-INPV-10", "WSTG-INPV-11",
                        "WSTG-INPV-12", "WSTG-INPV-15", "WSTG-INPV-18")):
        return "A03 Injection"
    if wstg.startswith("WSTG-INPV-19"):
        return "A10 Server-Side Request Forgery (SSRF)"
    if wstg.startswith("WSTG-INPV-07"):   # XXE
        return "A05 Security Misconfiguration"
    if wstg.startswith(("WSTG-INPV-01", "WSTG-AUTHZ")):
        return "A01 Broken Access Control"
    if wstg.startswith(("WSTG-CONF", "WSTG-INFO")):
        return "A05 Security Misconfiguration"
    if wstg.startswith(("WSTG-IDNT", "WSTG-ATHN", "WSTG-SESS")):
        return "A07 Identification and Authentication Failures"
    return ""


def parse_init_cve_patterns() -> dict[str, dict]:
    text = _read(LUA_DIR / "init.lua")
    start = text.index("cve_patterns = {")
    block = text[start:text.index("\n        }", start) + len("\n        }")]
    patterns: dict[str, dict] = {}
    comments: list[str] = []
    for raw in block.splitlines():
        line = raw.strip()
        if line.startswith("--"):
            comment = line[2:].strip()
            if comment and not comment.startswith("----"):
                comments.append(comment)
            continue
        match = re.search(r'\["([^"]+)"\]\s*=\s*"((?:\\.|[^"\\])*)"', line)
        if not match:
            continue
        cve, pattern = match.group(1), _clean_lua_string(match.group(2))
        description = ""
        for comment in comments:
            if cve in comment:
                description = comment.split(":", 1)[1].strip() if ":" in comment else comment
                break
        if not description and comments:
            description = comments[0]
        patterns[cve] = {"pattern": pattern, "description": description, "comments": list(comments)}
        comments = []
    return patterns


def parse_plugin_map() -> dict[str, str]:
    text = _read(LUA_DIR / "init.lua")
    mapping: dict[str, str] = {}
    for match in re.finditer(r'"([^"]+)"\s*,?\s*--\s*((?:CVE-[\d-]+,?\s*)+)', text):
        plugin = match.group(1)
        for cve in re.findall(r"CVE-\d{4}-\d+", match.group(2)):
            mapping.setdefault(cve, plugin)
    return mapping


def parse_vulnerability_rules() -> dict[str, dict]:
    text = _read(LUA_DIR / "vulnerability_rules.lua")
    found: dict[str, dict] = {}
    for block in re.findall(r"return\s*\{(.*?)\n\s*\}", text, re.S):
        cve = re.search(r'cve\s*=\s*"([^"]+)"', block)
        if not cve:
            continue
        meta = {"condition": VULN_CONDITIONS.get(cve.group(1), "")}
        for key in ("severity", "description", "plugin", "attack_vector"):
            match = re.search(key + r'\s*=\s*"([^"]*)"', block)
            if match:
                meta[key] = match.group(1)
        found.setdefault(cve.group(1), meta)
    # CVE-2024-8425 shares the Gift Voucher return branch with CVE-2025-47577.
    if "CVE-2025-47577" in found:
        found.setdefault("CVE-2024-8425", {
            **found["CVE-2025-47577"],
            "description": "Gift Voucher file upload RCE (same mwb_wgm_preview_mail action as CVE-2025-47577)",
        })
    return found


VULN_CONDITIONS = {
    "CVE-2023-28121": "URI contains wp-json/wp/v2/users AND the X-WCPAY-PLATFORM-CHECKOUT-USER header is present",
    "CVE-2023-2986": "URI or query string contains wcal_action=checkout_link AND validate=",
    "CVE-2025-4403": "URI or query string contains dnd_codedropz_upload AND supported_type",
    "CVE-2025-2266": "URI or query string contains cwmpupdateoptions",
    "CVE-2025-47577": "URI or query string contains mwb_wgm_preview_mail",
    "CVE-2024-2387": "URI contains advanced-form-integration-log AND integration_id with a quote/union/select",
    "CVE-2025-10142": "URI or query string contains pc_added_uploaded_image AND file[path]",
    "CVE-2024-50508": "URI or query string contains file[path] AND (../ or /etc/)",
    "GENERIC-WP-001": "URI contains wp-config.php",
    "GENERIC-WP-002": "URI contains wp-admin/install.php or wp-admin/setup-config.php",
    "GENERIC-WP-003": "URI contains wp-json/wp/v2/users, or rest_route=.../wp/v2/users, or author=<digits>",
    "GENERIC-WP-004": "URI contains xmlrpc.php",
}


def parse_layer2() -> list[dict]:
    text = _read(LUA_DIR / "pattern_rules.lua")
    start = text.index("local specific_checks = {")
    block = text[start:text.index("\n    }", start)]
    checks: list[dict] = []
    wstg = ""
    for raw in block.splitlines():
        line = raw.strip()
        match = re.search(r"WSTG-[A-Z]+(?:-[A-Z0-9]+)?", line)
        if match and line.startswith("--"):
            wstg = match.group(0)
        rule = re.search(
            r'\{pattern\s*=\s*"((?:\\.|[^"\\])*)",\s*score\s*=\s*(\d+),\s*name\s*=\s*"([^"]+)"\}',
            line,
        )
        if rule:
            checks.append({
                "pattern": _clean_lua_string(rule.group(1)),
                "score": int(rule.group(2)),
                "name": rule.group(3),
                "wstg": wstg,
            })
    return checks


def parse_layer1() -> list[dict]:
    text = _read(LUA_DIR / "pattern_rules.lua")
    start = text.index("_M.SUSPICIOUS_PATTERNS = {")
    block = text[start:text.index("\n}", start)]
    entries: list[dict] = []
    wstg = ""
    # Everything from the "OWASP CRS-derived generic signatures" banner to the
    # end of the SUSPICIOUS_PATTERNS block is sourced from the OWASP ModSecurity
    # Core Rule Set; tag those entries so build_layer1() can mark their
    # provenance as OWASP CRS in the catalogue.
    in_crs = False
    for raw in block.splitlines():
        line = raw.strip()
        if "OWASP CRS-derived" in line:
            in_crs = True
        match = re.search(r"WSTG-[A-Z]+(?:-[A-Z0-9]+)?", line)
        if match and line.startswith("--"):
            wstg = match.group(0)
        cves = re.findall(r"CVE-\d{4}-\d+", line)
        calls: list[tuple[str, str, str]] = []
        for helper in ("plain", "ext", "param", "segment", "pat"):
            pattern = rf"{helper}\(\s*\"((?:\\.|[^\"\\])*)\"\s*(?:,\s*\"((?:\\.|[^\"\\])*)\"\s*)?\)"
            for call in re.finditer(pattern, line):
                first = _clean_lua_string(call.group(1))
                second = _clean_lua_string(call.group(2)) if call.group(2) else first
                calls.append((helper, first, second))
        for helper, match_text, display in calls:
            entries.append({
                "helper": helper,
                "match": match_text,
                "name": display,
                "wstg": wstg,
                "cves": cves,
                "crs": in_crs,
            })
    return entries


def parse_suricata() -> list[dict]:
    """Parse local.rules into one record per alert.

    The file interleaves a comment block, then a blank line, then one or more
    alert lines; splitting on the ``#----`` separators therefore yields
    comment-only chunks followed by alert-only chunks.  Keep the most recent
    metadata block and attach it to the alert chunk that follows, instead of
    looking for comments inside the alert chunk itself.
    """
    text = _read(SURICATA_RULES)
    chunks = re.split(r"^#-{5,}\s*$", text, flags=re.M)
    rules: list[dict] = []
    meta = {"cves": [], "wstg": [], "plugin": "", "attack": ""}
    for chunk in chunks:
        comments = [line.lstrip("#").strip() for line in chunk.splitlines() if line.strip().startswith("#")]
        has_alerts = any(line.startswith("alert ") for line in chunk.splitlines())
        if comments and not has_alerts:
            comment_text = " ".join(comments)
            meta = {
                "cves": re.findall(r"CVE-\d{4}-\d+", comment_text),
                "wstg": re.findall(r"WSTG-[A-Z]+(?:-[A-Z0-9]+)?", comment_text),
                "plugin": next((c.split(":", 1)[1].strip() for c in comments
                                if c.lower().startswith("plugin:")), ""),
                "attack": next((c.split(":", 1)[1].strip() for c in comments
                                if c.lower().startswith("attack:")), ""),
            }
        for line in chunk.splitlines():
            if not line.startswith("alert "):
                continue
            msg = re.search(r'msg:"([^"]*)"', line)
            sid = re.search(r"\bsid:(\d+)", line)
            rev = re.search(r"\brev:(\d+)", line)
            classtype = re.search(r"\bclasstype:([^;]+)", line)
            if not (msg and sid):
                continue
            message = msg.group(1)
            # A comment block can cover several CVEs (e.g. the PagSeguro /
            # WP File Upload shared path-traversal group). The message names
            # the CVE each rule belongs to, so prefer it over the block list.
            message_cves = re.findall(r"CVE-\d{4}-\d+", message)
            rules.append({
                "sid": int(sid.group(1)),
                "rev": int(rev.group(1)) if rev else 1,
                "message": message,
                "classtype": classtype.group(1) if classtype else "",
                "cves": message_cves or list(meta["cves"]),
                "wstg": list(meta["wstg"]),
                "plugin": meta["plugin"],
                "attack": meta["attack"],
                "raw": line.strip(),
            })
    return rules


# ---------------------------------------------------------------------------
# Concept metadata
# ---------------------------------------------------------------------------

# Layer 2 names -> (display name, category, surface, description, extra tags)
LAYER2_META: dict[str, tuple[str, str, str, str, tuple[str, ...]]] = {
    "directory_traversal": ("Directory traversal (../)", "traversal", "backend", "Literal ../ or ..\\ sequence in the URI, used to climb out of the web root.", ()),
    "encoded_directory_traversal": ("Encoded directory traversal", "traversal", "backend", "Percent-encoded traversal (..%2f / %2e%2e/), used to evade plain-text filters.", ()),
    "sql_union": ("SQL UNION SELECT", "sqli", "backend", "A UNION ... SELECT sequence, used to append adversary-controlled rows to a query.", ()),
    "sql_or_condition": ("SQL OR tautology", "sqli", "backend", "A quoted OR x=x tautology, the classic boolean SQL-injection probe.", ()),
    "sql_quote_or": ("SQL quote + OR", "sqli", "backend", "A quote followed by OR, indicating a broken string context inside a query.", ()),
    "sql_select": ("SQL SELECT ... FROM", "sqli", "backend", "A SELECT ... FROM sequence in the URI, a broad SQL-injection indicator.", ()),
    "sql_drop": ("SQL DROP TABLE", "sqli", "backend", "A DROP TABLE sequence, a destructive SQL-injection attempt.", ()),
    "sql_insert": ("SQL INSERT INTO", "sqli", "backend", "An INSERT ... INTO sequence, used to write adversary-controlled rows.", ()),
    "xss_script": ("XSS script tag", "xss", "frontend", "A <script> tag in the request, the simplest reflected-XSS payload.", ()),
    "xss_javascript": ("XSS javascript: URI", "xss", "frontend", "The javascript: URI scheme, used in links and attributes to execute script.", ()),
    "xss_onerror": ("XSS onerror handler", "xss", "frontend", "An onerror= event handler, a common XSS vector that avoids <script>.", ()),
    "xss_onload": ("XSS onload handler", "xss", "frontend", "An onload= event handler that executes when an element loads.", ()),
    "xss_alert": ("XSS alert() probe", "xss", "frontend", "An alert( call, a typical proof-of-concept JavaScript payload.", ()),
    "cmd_cat": ("Command injection: cat", "command-injection", "backend", "A shell separator followed by cat, used to read files through command injection.", ()),
    "cmd_ls": ("Command injection: ls", "command-injection", "backend", "A shell separator followed by ls, used to list directories.", ()),
    "cmd_netcat": ("Command injection: netcat", "command-injection", "backend", "A pipe into nc, a common reverse-shell or data-exfiltration pattern.", ()),
    "cmd_curl": ("Command injection: curl", "command-injection", "backend", "An && curl sequence, used to fetch a second-stage payload.", ()),
    "cmd_backticks": ("Command injection: backticks", "command-injection", "backend", "Backtick command substitution, used to execute shell commands.", ()),
    "php_wrapper": ("PHP stream wrapper", "file-inclusion", "backend", "The php:// stream wrapper, used for local file inclusion or code execution.", ()),
    "file_wrapper": ("file:// stream wrapper", "file-inclusion", "backend", "The file:// stream wrapper, used to read local files.", ()),
    "data_wrapper": ("data:// stream wrapper", "file-inclusion", "backend", "The data:// stream wrapper, used to inject inline payloads.", ()),
    "wp_config_access": ("wp-config.php disclosure", "sensitive-file", "backend", "A direct request for wp-config.php, which holds database credentials and secret keys.", ("wordpress",)),
    "wp_install_access": ("WordPress installer access", "sensitive-file", "backend", "A request for wp-admin/install.php during an active installation.", ("wordpress",)),
    "wp_user_creation": ("WordPress user creation", "access-control", "backend", "A request for user-new.php, indicating an attempt to create an admin user.", ("wordpress",)),
    "wp_xmlrpc": ("XML-RPC endpoint probe", "sensitive-file", "backend", "xmlrpc.php access, used for brute force and pingback abuse.", ("wordpress",)),
    "wp_config_bak": ("wp-config.php.bak disclosure", "sensitive-file", "backend", "A request for wp-config.php.bak, a backup copy that may be served as plain text.", ("wordpress",)),
    "wp_config_variant": ("wp-config variant", "sensitive-file", "backend", "A request for a wp-config-* variant, often a backup or editor file.", ("wordpress",)),
    "bak_file": ("Backup extension .bak", "sensitive-file", "backend", "A request ending in .bak, exposing an old version of a file.", ()),
    "old_file": ("Backup extension .old", "sensitive-file", "backend", "A request ending in .old, exposing a previous version of a file.", ()),
    "backup_zip": ("backup.zip archive", "sensitive-file", "backend", "A request for backup.zip, a common archive left in the web root.", ()),
    "wp_backup": ("WordPress backup path", "sensitive-file", "backend", "A request for a WordPress backup path.", ("wordpress",)),
    "phpinfo_file": ("phpinfo.php disclosure", "sensitive-file", "backend", "A request for phpinfo.php, which leaks configuration and environment details.", ()),
    "htaccess_file": (".htaccess disclosure", "sensitive-file", "backend", "A request for .htaccess, which may expose rewrite and auth rules.", ()),
    "install_php": ("Installer file access", "sensitive-file", "backend", "A request for install.php, an installer that should be removed after setup.", ()),
    "etc_passwd": ("Local file read: /etc/passwd", "traversal", "backend", "A request for /etc/passwd, a path-traversal / local file inclusion target.", ()),
    "enc_script": ("Encoded <script tag", "xss", "frontend", "A percent-encoded <script, used to evade XSS filters.", ()),
    "xmlrpc_methods": ("XML-RPC listMethods probe", "recon", "backend", "An XML-RPC system.listMethods probe used to enumerate available methods.", ("wordpress",)),
    "xmlrpc_multicall": ("XML-RPC multicall", "authentication", "backend", "XML-RPC multicall, used to amplify password brute-force attempts.", ("wordpress",)),
    "admin_post": ("admin-post.php access", "wordpress", "backend", "A request for admin-post.php, a WordPress admin AJAX endpoint.", ("wordpress",)),
    "author_enum": ("User enumeration via ?author=", "enumeration", "backend", "A numeric ?author= value, used to enumerate WordPress users.", ("wordpress",)),
    "admin_scan": ("Admin panel discovery", "recon", "backend", "A request for /admin, a standard admin-panel discovery probe.", ()),
    "administrator_scan": ("Administrator panel discovery", "recon", "backend", "A request for /administrator, a standard admin-panel discovery probe.", ()),
    "phpmyadmin_scan": ("phpMyAdmin discovery", "recon", "backend", "A request for /phpmyadmin, a database-admin panel probe.", ()),
    "backup_scan": ("Backup path discovery", "recon", "backend", "A request for /backup, looking for exposed archives.", ()),
    "env_file_scan": (".env disclosure", "sensitive-file", "backend", "A request for /.env, which can leak application secrets.", ()),
    "wp_user_enumeration": ("WordPress REST user enumeration", "enumeration", "backend", "The REST API users endpoint, used to enumerate WordPress accounts.", ("wordpress",)),
    "wp_user_enumeration_rest": ("WordPress user enumeration via rest_route", "enumeration", "backend", "A rest_route query targeting /wp/v2/users, an alternate user-enumeration path.", ("wordpress",)),
    "url_encoding_detected": ("URL-encoding evasion", "http", "backend", "Percent-encoded bytes in the URI, often used to evade pattern matching.", ()),
    "excessive_parameters": ("Excessive query parameters", "http", "backend", "More than 20 query parameters, a parameter-pollution / fuzzing signal.", ()),
}

# Layer-1-only concepts that do not correspond to a Layer 2 check.
NEW_CONCEPTS: dict[str, tuple[str, str, str, str, int, str]] = {
    # id: (name, category, surface, description, score, wstg)
    "sql-time-blind": ("Time-based blind SQL injection", "sqli", "backend", "SLEEP() or BENCHMARK() in the request, used to prove blind SQL injection by timing.", 15, "WSTG-INPV-05"),
    "sensitive-archive": ("Sensitive archive or backup extension", "sensitive-file", "backend", "A request for archive/backup extensions (.sql, .tar, .gz, .zip, .backup) in the web root.", 15, "WSTG-CONF"),
    "htpasswd-file": (".htpasswd disclosure", "sensitive-file", "backend", "A request for .htpasswd, which can expose password hashes.", 15, "WSTG-CONF"),
    "readme-file": ("readme.html fingerprinting", "recon", "backend", "A request for readme.html, often used to fingerprint WordPress or a plugin.", 15, "WSTG-INFO"),
    "setup-config-file": ("setup-config.php access", "sensitive-file", "backend", "A request for setup-config.php, an installer helper that should not be public.", 15, "WSTG-CONF"),
    "crossdomain-xml": ("crossdomain.xml probe", "recon", "backend", "A request for crossdomain.xml, used to enumerate a Flash-era cross-domain policy.", 15, "WSTG-INFO"),
    "suspicious-parameter": ("Sensitive parameter names", "injection", "backend", "Common injection parameter names (cmd, template, page, file, redirect) that deserve scrutiny.", 15, "WSTG-INPV"),
    "http-splitting": ("HTTP response splitting", "http", "backend", "An encoded CRLF (%0d%0a) in the URI, used for HTTP response splitting.", 15, "WSTG-INPV-15"),
    "idor-parameter": ("IDOR object identifier parameters", "access-control", "backend", "Sequential object identifiers (user_id, customer_id, order_id, post_id) used in IDOR probes.", 15, "WSTG-AUTHZ"),
    "context-edit": ("context=edit probe", "access-control", "backend", "A context=edit parameter, often used to request editable content from an API.", 15, "WSTG-AUTHZ"),
    "auth-action": ("Registration / password-reset probe", "authentication", "backend", "lostpassword or register actions, used to probe account-recovery and registration flows.", 15, "WSTG-ATHN"),
    "cloud-storage": ("Cloud storage backup probe", "cloud", "backend", "An s3-backup string, indicating a probe for cloud storage backups.", 15, "WSTG-CONF"),
}

# Edge blocks: controls enforced as an outright 403 in nginx.conf's access
# phase, BEFORE scoring or routing -- they are not threat scores and never feed
# honeypot diversion, so they have no Lua pattern for parse_layer*() to see and
# need their own catalogue record. id: (name, category, surface, description,
# severity, wstg).
EDGE_BLOCKS: dict[str, tuple[str, str, str, str, str, str]] = {
    "sig-untrusted-external-callback": ("Untrusted external callback / open redirect", "injection", "backend", "An absolute http(s)/ftp URL in the request URI pointing at a host outside the trusted payment/OAuth callback allowlist (the shop's own WP_SITE_URL host plus known bank/gateway providers, see TRUSTED_CALLBACK_DOMAINS) -- the shape of an RFI, open-redirect or SSRF payload. Blocked outright with a 403 at the edge; deliberately NOT scored or routed, because such a URL can be planted in a link and sent to an innocent visitor to get them diverted and mislabelled. Legitimate WooCommerce gateway and OAuth callbacks point at a trusted host and pass.", "critical", "WSTG-INPV-19"),
}

# Layer 1 helper/name -> canonical record id.
LAYER1_TO_CONCEPT: dict[tuple[str, str], str] = {
    ("plain", "../"): "sig-directory-traversal",
    ("plain", "..\\"): "sig-directory-traversal",
    ("pat", "union.*select"): "sig-sql-union",
    ("pat", "or.*1.*=.*1"): "sig-sql-or-condition",
    ("pat", "select.*from"): "sig-sql-select",
    ("pat", "drop.*table"): "sig-sql-drop",
    ("pat", "insert.*into"): "sig-sql-insert",
    ("pat", "sleep"): "sql-time-blind",
    ("pat", "benchmark"): "sql-time-blind",
    ("plain", "<script"): "sig-xss-script",
    ("plain", "javascript:"): "sig-xss-javascript",
    ("plain", "onerror="): "sig-xss-onerror",
    ("plain", "onload="): "sig-xss-onload",
    ("pat", "alert"): "sig-xss-alert",
    ("pat", ";cat"): "sig-cmd-cat",
    ("pat", ";ls"): "sig-cmd-ls",
    ("pat", "|nc"): "sig-cmd-netcat",
    ("pat", "&&curl"): "sig-cmd-curl",
    ("plain", "php://"): "sig-php-wrapper",
    ("plain", "file://"): "sig-file-wrapper",
    ("plain", "data://"): "sig-data-wrapper",
    ("plain", "wp-config.php"): "sig-wp-config-access",
    ("plain", "wp-config-"): "sig-wp-config-variant",
    ("ext", ".env"): "sig-env-file-scan",
    ("ext", ".bak"): "sig-bak-file",
    ("ext", ".old"): "sig-old-file",
    ("ext", ".backup"): "sensitive-archive",
    ("ext", ".sql"): "sensitive-archive",
    ("ext", ".tar"): "sensitive-archive",
    ("ext", ".gz"): "sensitive-archive",
    ("ext", ".zip"): "sensitive-archive",
    ("ext", ".htaccess"): "sig-htaccess-file",
    ("ext", ".htpasswd"): "htpasswd-file",
    ("segment", "/backup"): "sig-backup-scan",
    ("plain", "readme.html"): "readme-file",
    ("plain", "install.php"): "sig-install-php",
    ("plain", "setup-config.php"): "setup-config-file",
    ("plain", "phpinfo"): "sig-phpinfo-file",
    ("plain", "crossdomain.xml"): "crossdomain-xml",
    ("segment", "/admin"): "sig-admin-scan",
    ("segment", "/administrator"): "sig-administrator-scan",
    ("segment", "/phpmyadmin"): "sig-phpmyadmin-scan",
    ("plain", "xmlrpc.php"): "sig-wp-xmlrpc",
    ("param", "author"): "sig-author-enum",
    ("plain", "/wp-json/wp/v2/users"): "sig-wp-user-enumeration",
    ("param", "rest_route"): "sig-wp-user-enumeration-rest",
    ("plain", "wcal_action=checkout_link"): "cve-2023-2986",
    ("param", "integration_id"): "cve-2024-2387",
    ("plain", "cwmpupdateoptions"): "cve-2025-2266",
    ("plain", "mwb_wgm_preview_mail"): "cve-2025-47577",
    ("plain", "dnd-wc-upload-file"): "cve-2025-4403",
    ("plain", "pc_added_uploaded_image"): "cve-2025-10142",
    ("plain", "file[path]"): "cve-2024-50508",
    ("param", "cmd"): "suspicious-parameter",
    ("param", "template"): "suspicious-parameter",
    ("param", "page"): "suspicious-parameter",
    ("param", "file"): "suspicious-parameter",
    ("param", "redirect"): "suspicious-parameter",
    ("plain", "%0d%0a"): "http-splitting",
    ("param", "user_id"): "idor-parameter",
    ("param", "customer_id"): "idor-parameter",
    ("param", "order_id"): "idor-parameter",
    ("param", "post_id"): "idor-parameter",
    ("plain", "context=edit"): "context-edit",
    ("plain", "action=lostpassword"): "auth-action",
    ("plain", "action=register"): "auth-action",
    ("plain", "s3-backup"): "cloud-storage",
}

# Attack Simulation preset aliases that map onto a canonical concept.
PRESET_TO_CONCEPT = {
    "GENERIC-WP-001": "sig-wp-config-access",
    "GENERIC-WP-002": "sig-install-php",
    "GENERIC-WP-003": "sig-author-enum",
    "GENERIC-WP-004": "sig-wp-xmlrpc",
    "GENERIC-XSS-001": "sig-xss-script",
    "GENERIC-XSS-002": "sig-xss-onerror",
    "GENERIC-SQLI-001": "sig-sql-or-condition",
    "GENERIC-SQLI-002": "sql-time-blind",
    "GENERIC-TOOL-001": "tool-sqlmap",
    "GENERIC-TOOL-002": "tool-nikto",
    "GENERIC-TOOL-003": "tool-metasploit",
    "GENERIC-TOOL-004": "tool-gobuster",
    "GENERIC-TOOL-005": "tool-wpscan",
}

# Suricata SIDs -> canonical concept. SIDs without an entry become their own
# network rule record.
SURICATA_TO_CONCEPT = {
    1000017: "brute-force",
    1000018: "sig-wp-user-enumeration",
    1000019: "sig-wp-config-access",
    1000020: "sensitive-archive",
    1000026: "sig-sql-union",
    1000027: "sql-information-schema",
    1000028: "sql-functions",
    1000029: "sql-time-blind",
    1000030: "sig-xss-script",
    1000031: "sig-xss-onerror",
    1000032: "sig-xss-javascript",
    1000033: "cmd-system",
    1000034: "cmd-pipe",
    1000035: "sig-cmd-backticks",
    1000036: "sig-directory-traversal",
    1000037: "sig-encoded-directory-traversal",
    1000038: "double-encoded-traversal",
    1000039: "sig-php-wrapper",
    1000040: "sig-data-wrapper",
    1000041: "sig-file-wrapper",
    1000042: "tool-sqlmap",
    1000043: "tool-nikto",
    1000044: "tool-nmap",
    1000045: "tool-wpscan",
    1000046: "tool-gobuster",
    1000047: "tool-dirb",
    1000048: "tool-burpsuite",
    1000049: "wp-version-recon",
    1000050: "wp-theme-recon",
    1000051: "wp-plugin-recon",
    1000052: "sig-admin-scan",
    1000053: "upload-php",
    1000054: "upload-executable",
    1000055: "upload-script",
    1000056: "high-request-rate",
    1000057: "brute-force",
    1000058: "honeypot-multi-attempt",
    1000059: "honeypot-automation",
    1000060: "honeypot-rapid-scan",
    1000061: "session-ip-change",
    1000062: "session-ua-change",
    1000063: "session-cookie-manipulation",
    1000064: "generic-code-injection",
    1000065: "deserialization",
    1000066: "template-injection",
    1000067: "rest-api-abuse",
    1000068: "xmlrpc-amplification",
    1000069: "php-webshell",
    1000070: "encoded-php-payload",
}

# A few comment blocks cover several SIDs with different WSTG categories.
SURICATA_SID_WSTG = {
    1000017: ["WSTG-ATHN-04"],
    1000018: ["WSTG-IDNT-04"],
    1000019: ["WSTG-CONF-05"],
    1000020: ["WSTG-CONF-05"],
}

# CVE records without a Suricata comment can still be mapped by attack vector
# or by the attack class in their learning lesson.
CVE_WSTG = {
    "CVE-2022-0739": "WSTG-INPV-05",
    "CVE-2024-1071": "WSTG-INPV-05",
    "CVE-2024-27956": "WSTG-INPV-05",
    "CVE-2024-2879": "WSTG-INPV-05",
    "CVE-2024-25600": "WSTG-INPV-11",
    "CVE-2024-8425": "WSTG-INPV-10",
    "CVE-2025-47577": "WSTG-INPV-10",
    "CVE-2025-4403": "WSTG-INPV-10",
    "CVE-2025-10142": "WSTG-INPV-01",
    "CVE-2024-50508": "WSTG-INPV-01",
    "CVE-2023-28121": "WSTG-AUTHZ",
    "CVE-2023-2986": "WSTG-ATHN",
    "CVE-2025-2266": "WSTG-AUTHZ",
    "CVE-2024-2387": "WSTG-INPV-05",
    "CVE-2017-1001000": "WSTG-AUTHZ",
    "GENERIC-WP-001": "WSTG-CONF-05",
    "GENERIC-WP-002": "WSTG-CONF",
    "GENERIC-WP-003": "WSTG-IDNT-04",
    "GENERIC-WP-004": "WSTG-CONF",
}

ATTACK_VECTOR_WSTG = {
    "sql_injection": "WSTG-INPV-05",
    "file_upload_bypass": "WSTG-INPV-10",
    "file_upload_rce": "WSTG-INPV-10",
    "path_traversal": "WSTG-INPV-01",
    "directory_traversal": "WSTG-INPV-01",
    "header_manipulation": "WSTG-AUTHZ",
    "privilege_escalation": "WSTG-AUTHZ",
    "encryption_bypass": "WSTG-ATHN",
    "sensitive_file_access": "WSTG-CONF-05",
    "installation_abuse": "WSTG-CONF",
    "information_disclosure": "WSTG-IDNT-04",
    "xmlrpc_abuse": "WSTG-CONF",
}

ATTACK_CLASS_WSTG = {
    "Remote code execution (code injection)": "WSTG-INPV-11",
    "SQL injection": "WSTG-INPV-05",
    "Path traversal": "WSTG-INPV-01",
    "Unrestricted file upload": "WSTG-INPV-10",
    "Unrestricted file upload leading to RCE": "WSTG-INPV-10",
    "Cross-site scripting (script tag)": "WSTG-INPV-02",
    "Cross-site scripting (event handler)": "WSTG-INPV-02",
}

SURICATA_PLUGIN_CVE = {
    1000021: "CVE-2023-28121",
    1000022: "CVE-2023-2986",
    1000023: "CVE-2025-4403",
    1000024: "CVE-2025-2266",
    1000025: "CVE-2025-47577",
}

# Suricata-only concepts: id -> (name, category, description, severity)
SURICATA_CONCEPTS = {
    "sql-information-schema": ("SQL information_schema probe", "sqli", "information_schema in the URI, used to enumerate database structure.", "high"),
    "sql-functions": ("SQL function probe", "sqli", "Database functions (concat, substring, database, version, user) in the request.", "high"),
    "cmd-system": ("Command injection: system commands", "command-injection", "System command names (wget, curl, bash, sh) in the URI.", "critical"),
    "cmd-pipe": ("Command injection: pipe", "command-injection", "A pipe or command separator followed by a command.", "high"),
    "cmd-backticks": ("Command injection: backticks", "command-injection", "Backtick command substitution in the request.", "high"),
    "double-encoded-traversal": ("Double-encoded directory traversal", "traversal", "A double URL-encoded ../ sequence, used to bypass decoding filters.", "high"),
    "wp-version-recon": ("WordPress version detection", "recon", "A WordPress version string detected in the request or response.", "low"),
    "wp-theme-recon": ("WordPress theme detection", "recon", "Theme stylesheet access, used to identify the active theme.", "medium"),
    "wp-plugin-recon": ("WordPress plugin enumeration", "recon", "Plugin directory access, used to enumerate installed plugins.", "medium"),
    "high-request-rate": ("High request rate", "behaviour", "A high request rate from one source, a DoS or brute-force signal.", "medium"),
    "brute-force": ("Login brute force", "authentication", "Repeated login attempts against wp-login.php.", "high"),
    "honeypot-multi-attempt": ("Multiple vulnerability attempts", "behaviour", "Multiple vulnerability attempts from one source.", "high"),
    "honeypot-automation": ("Automation detected by Suricata", "tool", "An automation/tool fingerprint observed by Suricata.", "medium"),
    "honeypot-rapid-scan": ("Rapid vulnerability scanning", "recon", "A rapid vulnerability-scanning pattern.", "high"),
    "session-ip-change": ("Session IP change", "session", "A session used from a different IP address.", "medium"),
    "session-ua-change": ("Session User-Agent change", "session", "A session used with a different User-Agent.", "medium"),
    "session-cookie-manipulation": ("Suspicious session-cookie manipulation", "session", "Suspicious session-cookie manipulation.", "high"),
    "generic-code-injection": ("Generic code injection", "injection", "Generic code-injection syntax in the request.", "high"),
    "deserialization": ("Deserialization attack", "deserialization", "Serialized-object payloads, a deserialization attack indicator.", "high"),
    "template-injection": ("Server-side template injection", "template", "Template-expression syntax, a server-side template injection indicator.", "high"),
    "rest-api-abuse": ("WordPress REST API abuse", "wordpress", "Unusual WordPress REST API access.", "medium"),
    "xmlrpc-amplification": ("XML-RPC amplification", "authentication", "XML-RPC multicall amplification.", "high"),
    "php-webshell": ("PHP web shell", "webshell", "PHP web-shell signatures in a request or upload.", "critical"),
    "encoded-php-payload": ("Encoded PHP payload", "webshell", "A base64/encoded PHP payload.", "critical"),
}

# Attack Simulation presets that stay standalone (they describe a sequence or a
# behaviour rather than one URI signature).
PRESET_ONLY = {
    "GENERIC-SQLI-003": {
        "id": "sql-body-injection",
        "name": "SQL injection in a POST body",
        "category": "sqli",
        "surface": "backend",
        "description": "A SQL-injection payload in a POST form field. The proxy inspects the URI, query string and headers, not the body, so this preset demonstrates a detection gap.",
        "notes": "No engine signature: the request body is not inspected by the URI/header rules.",
    },
    "GENERIC-ENUM-001": {
        "id": "wordlist-scan",
        "name": "Wordlist scan: sensitive paths",
        "category": "recon",
        "surface": "backend",
        "description": "A directory-brute-force style walk through admin, backup and configuration paths. The signal is the sequence of requests, not one payload.",
    },
    "GENERIC-ENUM-002": {
        "id": "plugin-theme-discovery",
        "name": "Wordlist scan: plugin and theme discovery",
        "category": "recon",
        "surface": "backend",
        "description": "Requests for plugin readme and theme stylesheet files, as WPScan-style tools do to identify installed components.",
    },
    "GENERIC-IDOR-001": {
        "id": "idor-users",
        "name": "IDOR: user IDs",
        "category": "access-control",
        "surface": "backend",
        "description": "Walks REST API user IDs to read accounts that should not be listed.",
    },
    "GENERIC-IDOR-002": {
        "id": "idor-orders",
        "name": "IDOR: WooCommerce order IDs",
        "category": "access-control",
        "surface": "backend",
        "description": "Walks WooCommerce order IDs to read other customers' orders.",
    },
}

TOOL_NAMES = {
    "sqlmap": ("sqlmap", ""),
    "nikto": ("Nikto", ""),
    "metasploit": ("Metasploit", ""),
    "gobuster": ("Gobuster", ""),
    "wpscan": ("WPScan", ""),
    "nmap": ("Nmap", ""),
    "masscan": ("masscan", ""),
    "zap": ("OWASP ZAP", ""),
    "acunetix": ("Acunetix", ""),
    "dirb": ("Dirb", ""),
    "whatweb": ("WhatWeb", ""),
    "nuclei": ("Nuclei", ""),
    "burpsuite": ("Burp Suite", ""),
    "havij": ("Havij", ""),
    "pangolin": ("Pangolin", ""),
}

UPLOAD_CONCEPTS = {
    "upload-php": ("PHP upload", "Dangerous PHP-family extensions in upload parameters or destinations.", 45),
    "upload-executable": ("Executable upload", "An executable extension (.exe) in an upload parameter.", 45),
    "upload-script": ("Script upload", "A script/executable extension (asp, jsp, bat, sh, py, pl, rb) in an upload parameter.", 35),
    "upload-double-extension": ("Double-extension upload bypass", "A double extension such as shell.php.jpg, used to bypass extension allow-lists.", 35),
    "upload-null-byte": ("Null-byte upload bypass", "A %00 null byte after an executable extension, a classic upload-filter bypass.", 40),
    "upload-space-bypass": ("Space upload bypass", "A trailing %20 after .php, used to defeat naive extension checks.", 30),
    "upload-directory": ("Upload into an executable directory", "A destination path under wp-admin, themes, wp-includes or cgi-bin.", 35),
    "upload-editor-access": ("Theme/plugin editor or file manager", "Access to theme-editor.php, plugin-editor.php or a file manager, a direct code-edit path.", 40),
    "upload-content-type": ("Upload content-type mismatch", "A declared MIME type that disguises a PHP/script payload as an image or text file.", 40),
}


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

class CatalogBuilder:
    def __init__(self):
        self.patterns: dict[str, dict] = {}
        self.init_cves = parse_init_cve_patterns()
        self.vuln = parse_vulnerability_rules()
        self.plugin_map = parse_plugin_map()
        self.presets = {p.cve: p for p in PATTERN_PRESETS}
        self.presets[GDPR_RESTORE_CVE] = GDPR_RESTORE_PRESET
        self.layer1 = parse_layer1()
        self.layer2 = parse_layer2()
        self.suricata = parse_suricata()
        self.suricata_by_sid = {r["sid"]: r for r in self.suricata}

    # -- record primitives -------------------------------------------------
    def get(self, record_id: str, **defaults) -> dict:
        if record_id not in self.patterns:
            self.patterns[record_id] = {
                "id": record_id,
                "aliases": [],
                "name": defaults.get("name", _humanise(record_id)),
                "kind": defaults.get("kind", "generic"),
                "category": defaults.get("category", "generic"),
                "category_label": CATEGORY_LABELS.get(defaults.get("category", "generic"), "Generic"),
                "severity": defaults.get("severity", "info"),
                "component": defaults.get("component", "core"),
                "plugin": defaults.get("plugin", ""),
                "surface": defaults.get("surface", "backend"),
                "description": defaults.get("description", CATEGORY_DESCRIPTIONS.get(defaults.get("category", "generic"), "")),
                "trigger": defaults.get("trigger", ""),
                "trigger_type": defaults.get("trigger_type", ""),
                "score": defaults.get("score"),
                "score_note": defaults.get("score_note", ""),
                "wstg": list(defaults.get("wstg", [])),
                "owasp": defaults.get("owasp", ""),
                "mitre": defaults.get("mitre", ""),
                "cve": defaults.get("cve", ""),
                "attack_vector": defaults.get("attack_vector", ""),
                "detection": [],
                "sources": [],
                "signatures": [],
                "suricata": [],
                "preset": None,
                "lesson": None,
                "reportable": defaults.get("reportable", True),
                "enabled": True,
                "tags": sorted(set(defaults.get("tags", []))),
                "notes": defaults.get("notes", ""),
            }
        return self.patterns[record_id]

    def source(self, record: dict, key: str, detail: str = "") -> None:
        src = dict(SOURCES[key])
        src["key"] = key
        if detail:
            src["detail"] = detail
        if not any(s["key"] == key and s.get("detail") == src["detail"] for s in record["sources"]):
            record["sources"].append(src)

    def detection(self, record: dict, text: str) -> None:
        if text and text not in record["detection"]:
            record["detection"].append(text)

    def signature(self, record: dict, **sig) -> None:
        if sig not in record["signatures"]:
            record["signatures"].append(sig)

    def tag(self, record: dict, *tags: str) -> None:
        record["tags"] = sorted(set(record["tags"]) | {t for t in tags if t})

    def wstg(self, record: dict, *values: str) -> None:
        for value in values:
            if value and value not in record["wstg"]:
                record["wstg"].append(value)

    def add_preset(self, record: dict, preset) -> None:
        if preset is None:
            return
        record["preset"] = {
            "name": preset.name,
            "cve": preset.cve,
            "severity": preset.severity,
            "description": preset.description,
            "method": preset.method,
            "path": preset.path,
            "headers": dict(preset.headers),
            "body": preset.body,
            "kind": preset.kind,
            "component": preset.component,
            "plugin": preset.plugin,
            "surface": preset.surface,
            "db_isolated": preset.db_isolated,
            "coverage_note": preset.coverage_note,
            "sequence": list(preset.sequence),
        }
        self.source(record, "preset", f"{preset.cve} · {preset.method} {preset.path}")
        self.detection(record, f"Simulation preset {preset.cve}: {preset.method} {preset.path}")
        if preset.cve not in record["aliases"]:
            record["aliases"].append(preset.cve)
        lesson = lesson_for(preset.cve)
        if lesson is not None and record["lesson"] is None:
            record["lesson"] = {
                "attack_class": lesson.attack_class,
                "owasp": lesson.owasp,
                "attack": lesson.attack,
                "how_it_works": lesson.how_it_works,
                "defence": lesson.defence,
            }
            if not record["owasp"]:
                record["owasp"] = lesson.owasp
            if not record["mitre"]:
                record["mitre"] = lesson.attack

    # -- passes ------------------------------------------------------------
    def build_cves(self) -> None:
        cve_ids = set(self.init_cves) | set(self.vuln) | {
            cve for cve in self.presets if cve.startswith("CVE-")
        }
        for cve in sorted(cve_ids):
            preset = self.presets.get(cve)
            init = self.init_cves.get(cve, {})
            vuln = self.vuln.get(cve, {})
            generic_wp = cve.startswith("GENERIC-WP-")
            plugin = (preset.plugin if preset else "") or vuln.get("plugin", "") or self.plugin_map.get(cve, "")
            if plugin == "wordpress-core":
                plugin = ""
            component = (preset.component if preset else "") or ("plugin" if plugin else "core")
            description = (
                (preset.description if preset else "")
                or vuln.get("description", "")
                or init.get("description", "")
                or f"Published vulnerability {cve}."
            )
            severity = (preset.severity if preset else "") or vuln.get("severity", "HIGH")
            surface = (preset.surface if preset else "") or "backend"
            if preset:
                name = preset.name
            elif vuln.get("description"):
                name = vuln["description"].split(" (", 1)[0]
            else:
                name = f"{cve} vulnerability"
            if generic_wp:
                record_id = PRESET_TO_CONCEPT.get(cve, cve.lower())
                category = {
                    "GENERIC-WP-001": "sensitive-file",
                    "GENERIC-WP-002": "sensitive-file",
                    "GENERIC-WP-003": "enumeration",
                    "GENERIC-WP-004": "sensitive-file",
                }.get(cve, "wordpress")
                kind = "generic"
            else:
                record_id = cve.lower()
                category = "cve"
                kind = "cve"
            record = self.get(
                record_id,
                name=name,
                kind=kind,
                category=category,
                severity=severity.lower(),
                component=component,
                plugin=plugin,
                surface=surface,
                description=description,
                cve=cve,
                attack_vector=vuln.get("attack_vector", ""),
                score=40 if init else None,
                score_note=("+40 when the URI, query string or a header matches the Lua CVE pattern"
                            if init else ("Detected by the narrow vulnerability_rules path; score comes from the "
                                          "underlying URI/header rules" if generic_wp
                                          else "No direct Lua signature; simulation preset only")),
                tags=[cve, *(["wordpress"] if generic_wp else [])],
            )
            if cve not in record["aliases"]:
                record["aliases"].append(cve)
            # Every CVE gets its lesson here, not only CVEs that happen to have
            # an Attack Simulation preset (add_preset used to be the only path).
            lesson = lesson_for(cve)
            if lesson is not None and record["lesson"] is None:
                record["lesson"] = {
                    "attack_class": lesson.attack_class,
                    "owasp": lesson.owasp,
                    "attack": lesson.attack,
                    "how_it_works": lesson.how_it_works,
                    "defence": lesson.defence,
                }
                if not record["owasp"]:
                    record["owasp"] = lesson.owasp
                if not record["mitre"]:
                    record["mitre"] = lesson.attack
            fallback_wstg = (CVE_WSTG.get(cve) or ATTACK_VECTOR_WSTG.get(vuln.get("attack_vector", ""))
                             or ATTACK_CLASS_WSTG.get((lesson_for(cve).attack_class if lesson_for(cve) else ""), ""))
            if fallback_wstg:
                self.wstg(record, fallback_wstg)
                self.tag(record, fallback_wstg)
            if init:
                record["trigger"] = init.get("pattern", "")
                record["trigger_type"] = "lua_pattern"
                self.source(record, "lua-cve", f"{cve} → {init.get('pattern', '')}")
                self.signature(record, layer="cve", match=init.get("pattern", ""), kind="lua_pattern")
                self.detection(record, f"Lua CVE pattern (init.lua) · +40 · `{init.get('pattern', '')}`")
            if vuln:
                self.source(record, "lua-vuln", f"{cve} · {vuln.get('attack_vector', '')}")
                if vuln.get("condition"):
                    if not record["trigger"]:
                        record["trigger"] = vuln["condition"]
                        record["trigger_type"] = "condition"
                    self.detection(record, f"vulnerability_rules.lua · {vuln['condition']}")
            if preset:
                self.add_preset(record, preset)
                if not record["trigger"]:
                    record["trigger"] = preset.path
                    record["trigger_type"] = "path"
            self.tag(record, *( [vuln.get("attack_vector", "")] if vuln else [] ))

    def build_layer2(self) -> None:
        for check in self.layer2:
            name = check["name"]
            meta = LAYER2_META.get(name)
            if meta:
                display, category, surface, description, tags = meta
            else:
                display, category, surface = _humanise(name), _category_from_wstg(check["wstg"]), "backend"
                description = CATEGORY_DESCRIPTIONS.get(category, "")
                tags = ()
            record = self.get(
                "sig-" + name.replace("_", "-"),
                name=display,
                category=category,
                surface=surface,
                description=description,
                severity=_severity_for_score(check["score"]),
                score=check["score"],
                score_note=f"+{check['score']} when the URI matches `{check['pattern']}`",
                wstg=[check["wstg"]] if check["wstg"] else [],
                tags=list(tags),
            )
            if record["score"] is None:
                record["score"] = check["score"]
                record["score_note"] = f"+{check['score']} when the URI matches `{check['pattern']}`"
            self.source(record, "lua-layer2", f"{name} · {check['pattern']} · +{check['score']}")
            self.signature(record, layer="layer2", match=check["pattern"], kind="lua_pattern",
                           score=check["score"], name=name)
            self.detection(record, f"Lua Layer 2 · +{check['score']} · `{check['pattern']}`")
            if check["wstg"]:
                self.tag(record, check["wstg"])

    def build_layer1(self) -> None:
        for entry in self.layer1:
            concept = LAYER1_TO_CONCEPT.get((entry["helper"], entry["name"]))
            if concept is None and entry["cves"]:
                concept = entry["cves"][0].lower()
                if concept not in self.patterns:
                    concept = None
            if concept is None:
                # Unmapped entries are still reported, under a stable generated
                # ID, so a future rule addition cannot silently disappear.
                slug = re.sub(r"[^a-z0-9]+", "-", entry["name"].lower()).strip("-") or "unnamed"
                concept = f"lua-layer1-{entry['helper']}-{slug}"
                category = _category_from_wstg(entry["wstg"])
                record = self.get(
                    concept,
                    name=f"{_humanise(entry['name'])} ({entry['helper']})",
                    category=category,
                    description=CATEGORY_DESCRIPTIONS.get(category, ""),
                    severity="medium",
                    score=15,
                    score_note="+15 base score when this generic entry matches",
                    wstg=[entry["wstg"]] if entry["wstg"] else [],
                )
            else:
                record = self.get(concept)
            if not record["sources"] and not record["name"]:
                record["name"] = _humanise(entry["name"])
            if record["score"] is None:
                record["score"] = 15
                record["score_note"] = "+15 base score when this generic entry matches"
            self.source(record, "lua-layer1", f"{entry['helper']} · {entry['match']} · +15")
            if entry.get("crs"):
                # Note the OWASP CRS provenance (shown in the pattern DB's
                # Sources column/panel and filterable there).
                self.source(record, "owasp-crs")
            self.signature(record, layer="layer1", match=entry["match"], kind=entry["helper"],
                           name=entry["name"], score=15)
            self.detection(record, f"Lua Layer 1 generic entry · +15 · `{entry['match']}`")
            if entry["wstg"]:
                self.wstg(record, entry["wstg"])
                self.tag(record, entry["wstg"])
            for cve in entry["cves"]:
                if cve.lower() in self.patterns:
                    self.source(self.patterns[cve.lower()], "lua-layer1",
                                f"{entry['helper']} · {entry['match']} · +15")
                    self.signature(self.patterns[cve.lower()], layer="layer1",
                                   match=entry["match"], kind=entry["helper"], name=entry["name"], score=15)
                    self.detection(self.patterns[cve.lower()],
                                   f"Lua Layer 1 generic entry · +15 · `{entry['match']}`")

    def build_new_concepts(self) -> None:
        for concept_id, (name, category, surface, description, score, wstg) in NEW_CONCEPTS.items():
            record = self.get(
                concept_id,
                name=name,
                category=category,
                surface=surface,
                description=description,
                severity=_severity_for_score(score),
                score=score,
                score_note=f"+{score} from the matching Layer 1 generic entry",
                wstg=[wstg] if wstg else [],
                tags=[category, wstg] if wstg else [category],
            )
            self.source(record, "lua-layer1", "specific entry")

    def build_edge_blocks(self) -> None:
        for concept_id, (name, category, surface, description, severity, wstg) in EDGE_BLOCKS.items():
            record = self.get(
                concept_id,
                name=name,
                category=category,
                surface=surface,
                description=description,
                severity=severity,
                score=None,
                score_note="blocked outright with a 403 at the edge; not scored or routed",
                wstg=[wstg] if wstg else [],
                tags=[category, wstg, "edge-block"] if wstg else [category, "edge-block"],
            )
            self.source(record, "edge", f"{name} · outright 403")
            self.detection(record, "Edge · outright 403 · not scored or routed")
            if wstg:
                self.tag(record, wstg)

    def build_presets(self) -> None:
        for preset in [*PATTERN_PRESETS, GDPR_RESTORE_PRESET]:
            if preset.cve.startswith("CVE-"):
                continue
            if preset.cve in PRESET_TO_CONCEPT:
                record = self.get(PRESET_TO_CONCEPT[preset.cve])
                self.add_preset(record, preset)
                # A preset's human description is richer than a generated one.
                if preset.description and (not record["description"] or len(preset.description) > len(record["description"])):
                    record["description"] = preset.description
                if preset.component:
                    record["component"] = preset.component
                if preset.plugin:
                    record["plugin"] = preset.plugin
                if preset.surface:
                    record["surface"] = preset.surface
                if preset.severity and record["severity"] == "info":
                    record["severity"] = preset.severity.lower()
                continue
            if preset.cve in PRESET_ONLY:
                meta = PRESET_ONLY[preset.cve]
                record = self.get(
                    meta["id"],
                    name=meta["name"],
                    category=meta["category"],
                    surface=meta["surface"],
                    description=meta["description"],
                    severity=preset.severity.lower(),
                    component=preset.component,
                    plugin=preset.plugin,
                    notes=meta.get("notes", ""),
                    score=None,
                    score_note="Simulation-only: no single engine signature",
                    tags=[meta["category"], "simulation"],
                )
                self.add_preset(record, preset)
                continue
            if preset.cve == GDPR_RESTORE_CVE:
                record = self.get(
                    "session-gdpr-restore",
                    name=preset.name,
                    kind="session",
                    category="session",
                    surface="frontend",
                    description=preset.description,
                    severity="info",
                    score=None,
                    score_note="No attack signature; demonstrates session restoration",
                    reportable=False,
                    tags=["gdpr", "session"],
                )
                self.add_preset(record, preset)
                self.source(record, "session", "GDPR signature restoration")
                continue
            # Any future preset with an unknown ID still lands in the catalogue.
            record = self.get(
                preset.cve.lower(),
                name=preset.name,
                category="generic",
                surface=preset.surface,
                description=preset.description,
                severity=preset.severity.lower(),
                component=preset.component,
                plugin=preset.plugin,
                tags=["simulation"],
            )
            self.add_preset(record, preset)

    def build_suricata(self) -> None:
        for rule in self.suricata:
            sid = rule["sid"]
            target: dict | None = None
            if sid in SURICATA_PLUGIN_CVE:
                target = self.patterns.get(SURICATA_PLUGIN_CVE[sid].lower())
            elif rule["cves"]:
                target = self.patterns.get(rule["cves"][0].lower())
            elif sid in SURICATA_TO_CONCEPT:
                target = self.patterns.get(SURICATA_TO_CONCEPT[sid])
            if target is not None:
                if not any(s["sid"] == sid for s in target["suricata"]):
                    target["suricata"].append({
                        "sid": sid,
                        "rev": rule["rev"],
                        "message": rule["message"],
                        "classtype": rule["classtype"],
                    })
                self.source(target, "suricata", f"SID {sid} · {rule['message']}")
                self.detection(target, f"Suricata SID {sid} · {rule['message']}")
                rule_wstg = SURICATA_SID_WSTG.get(sid, rule["wstg"])
                self.wstg(target, *rule_wstg)
                self.tag(target, *rule_wstg, "suricata")
                continue

            concept = SURICATA_TO_CONCEPT.get(sid)
            if concept and concept in SURICATA_CONCEPTS:
                name, category, description, severity = SURICATA_CONCEPTS[concept]
            else:
                # SID not yet mapped: keep it visible as a network rule.
                concept = f"sid-{sid}"
                name = rule["message"]
                category = _category_from_wstg(rule["wstg"][0]) if rule["wstg"] else "network"
                description = rule["attack"] or f"Suricata signature: {rule['message']}"
                severity = "high" if rule["wstg"] and "INPV" in rule["wstg"][0] else "medium"
            record = self.get(
                concept,
                name=name,
                kind="generic",
                category=category,
                surface="network",
                component="network",
                description=description,
                severity=severity,
                score=None,
                score_note="Severity-graded Suricata alert: severity 1 → +50, 2 → +25, other → +10",
                wstg=SURICATA_SID_WSTG.get(sid, rule["wstg"]),
                tags=[category, *SURICATA_SID_WSTG.get(sid, rule["wstg"]), "network"],
                reportable=True,
                trigger=rule["message"],
                trigger_type="suricata_signature",
            )
            record["suricata"].append({
                "sid": sid,
                "rev": rule["rev"],
                "message": rule["message"],
                "classtype": rule["classtype"],
            })
            self.source(record, "suricata", f"SID {sid} · {rule['message']}")
            self.detection(record, f"Suricata SID {sid} · {rule['message']}")
            self.signature(record, layer="suricata", match=rule["raw"], kind="suricata", sid=sid)

    def build_headers_tools(self) -> None:
        # Flagged User-Agents: one record per named tool where a preset exists,
        # plus one shared record for the rest.
        flagged = ["sqlmap", "nmap", "masscan", "zap", "acunetix", "nikto", "dirb",
                   "gobuster", "wpscan", "whatweb", "nuclei", "burpsuite", "havij", "pangolin"]
        preset_tools = {"sqlmap": "GENERIC-TOOL-001", "nikto": "GENERIC-TOOL-002",
                        "metasploit": "GENERIC-TOOL-003", "gobuster": "GENERIC-TOOL-004",
                        "wpscan": "GENERIC-TOOL-005"}
        for tool in [*preset_tools, *flagged, "masscan", "zap", "acunetix", "whatweb", "nuclei", "havij", "pangolin"]:
            record_id = f"tool-{tool}"
            if record_id in self.patterns:
                record = self.patterns[record_id]
            else:
                display, _ = TOOL_NAMES.get(tool, (tool, ""))
                record = self.get(
                    record_id,
                    name=f"Scanner tool: {display}",
                    kind="tool",
                    category="tool",
                    surface="backend",
                    description=f"A request whose User-Agent names {display}.",
                    severity="medium",
                    score=50,
                    score_note="+50 when a flagged scanner User-Agent is present",
                    tags=["tool", "user-agent"],
                )
                self.source(record, "headers", f"flagged User-Agent: {tool}")
                self.source(record, "automation", f"User-Agent match: {tool}")
                self.detection(record, f"Header analysis · +50 · User-Agent contains `{tool}`")
                self.signature(record, layer="header", match=tool, kind="user_agent", score=50)
            if tool in preset_tools:
                self.add_preset(record, self.presets.get(preset_tools[tool]))
            if tool in ("sqlmap", "nikto", "nmap", "wpscan", "gobuster", "dirb", "burpsuite"):
                sid_map = {"sqlmap": 1000042, "nikto": 1000043, "nmap": 1000044,
                           "wpscan": 1000045, "gobuster": 1000046, "dirb": 1000047, "burpsuite": 1000048}
                rule = self.suricata_by_sid.get(sid_map[tool])
                if rule and not any(s["sid"] == rule["sid"] for s in record["suricata"]):
                    record["suricata"].append({"sid": rule["sid"], "rev": rule["rev"],
                                               "message": rule["message"], "classtype": rule["classtype"]})
                    self.source(record, "suricata", f"SID {rule['sid']} · {rule['message']}")
                    self.detection(record, f"Suricata SID {rule['sid']} · {rule['message']}")
        # Metasploit has no Suricata UA rule, but it does have a preset.
        if "tool-metasploit" not in self.patterns:
            record = self.get(
                "tool-metasploit",
                name="Scanner tool: Metasploit",
                kind="tool", category="tool", surface="backend",
                description="A request whose User-Agent names Metasploit.",
                severity="medium", score=50,
                score_note="+50 when a flagged scanner User-Agent is present",
                tags=["tool", "user-agent"],
            )
            self.source(record, "headers", "flagged User-Agent: metasploit")
            self.add_preset(record, self.presets.get("GENERIC-TOOL-003"))

        automation = self.get(
            "tool-automation-clients",
            name="Generic automation clients",
            kind="tool",
            category="tool",
            surface="backend",
            description="Generic HTTP clients (curl, wget, python-requests, Go, Apache HttpClient, OkHttp) and bot/crawler/scanner strings that commonly indicate automation.",
            severity="low",
            score=20,
            score_note="+5 to +20 depending on the client; 'scanner' adds +20",
            tags=["tool", "user-agent", "automation"],
        )
        for match, score in (("curl", 5), ("wget", 5), ("python-requests", 10),
                             ("go-http-client", 10), ("apache-httpclient", 10),
                             ("okhttp", 10), ("bot", 15), ("crawler", 10),
                             ("scanner", 20)):
            self.source(automation, "automation", f"{match} · +{score}")
            self.signature(automation, layer="automation", match=match, kind="user_agent", score=score)
            self.detection(automation, f"Automation scoring · +{score} · User-Agent contains `{match}`")

        missing_ua = self.get(
            "behaviour-missing-user-agent",
            name="Missing User-Agent",
            kind="behaviour", category="behaviour", surface="backend",
            description="Legitimate browsers always send a User-Agent; a missing one is a weak automation signal.",
            severity="low", score=10, score_note="+10 when the User-Agent is empty",
            tags=["behaviour", "header"],
        )
        self.source(missing_ua, "headers", "missing_user_agent")
        self.detection(missing_ua, "Header analysis · +10 · missing User-Agent")

        missing_referer = self.get(
            "behaviour-missing-referer",
            name="Missing Referer on POST",
            kind="behaviour", category="behaviour", surface="backend",
            description="A POST without a Referer is unusual for a real browser and is a small automation signal.",
            severity="low", score=5, score_note="+5 on a POST without a Referer",
            tags=["behaviour", "header"],
        )
        self.source(missing_referer, "headers", "missing_referer_on_post")
        self.detection(missing_referer, "Header analysis · +5 · POST without Referer")

        basic_auth = self.get(
            "behaviour-basic-auth",
            name="HTTP Basic authentication probe",
            kind="behaviour", category="authentication", surface="backend",
            description="An Authorization: Basic header, a low-weight probe for protected resources.",
            severity="low", score=5, score_note="+5 when an Authorization: Basic header is present",
            tags=["behaviour", "header", "authentication"],
        )
        self.source(basic_auth, "headers", "basic_auth_attempt")
        self.detection(basic_auth, "Header analysis · +5 · Authorization: Basic")

        method = self.get(
            "behaviour-method-anomaly",
            name="Unusual HTTP method",
            kind="behaviour", category="http", surface="backend",
            description="OPTIONS, TRACE or CONNECT requests, which are unusual on a WordPress storefront.",
            severity="low", score=10, score_note="+10 for OPTIONS/TRACE/CONNECT",
            tags=["behaviour", "http"],
        )
        self.source(method, "method", "OPTIONS / TRACE / CONNECT · +10")
        self.detection(method, "Request method · +10 · OPTIONS, TRACE or CONNECT")

        override = self.get(
            "behaviour-method-override",
            name="Method override header",
            kind="behaviour", category="http", surface="backend",
            description="An X-HTTP-Method-Override header, often used to bypass method-based access controls.",
            severity="medium", score=15, score_note="+15 when X-HTTP-Method-Override is present",
            tags=["behaviour", "http", "header"],
        )
        self.source(override, "method", "X-HTTP-Method-Override · +15")
        self.detection(override, "Request method · +15 · method override header")

    def build_uploads(self) -> None:
        # Upload extension / bypass / destination rules, grouped into
        # analyst-sized concepts rather than one row per regex.
        upload_rules = {
            "upload-php": [("php_extension", 40), ("phtml_variant", 35), ("php3_variant", 35),
                           ("php4_variant", 35), ("php5_variant", 35)],
            "upload-executable": [("executable_extension", 45)],
            "upload-script": [("asp_extension", 35), ("jsp_extension", 35), ("batch_file", 40),
                              ("shell_script", 40), ("python_script", 25), ("perl_script", 25),
                              ("ruby_script", 25), ("script_content_type", 30)],
            "upload-double-extension": [("double_extension_bypass", 35), ("double_extension", 35)],
            "upload-null-byte": [("null_byte_injection", 40)],
            "upload-space-bypass": [("space_bypass", 30)],
            "upload-directory": [("admin_directory_upload", 20), ("theme_directory_upload", 25),
                                 ("includes_directory_upload", 30), ("cgi_directory_upload", 35)],
            "upload-editor-access": [("theme_editor_access", 40), ("plugin_editor_access", 40),
                                     ("file_manager_access", 30), ("file_manager_variant", 30)],
            "upload-content-type": [("php_disguised_as_image", 40), ("executable_disguised_as_text", 35),
                                    ("script_content_type", 30), ("script_disguised_as_image", 35)],
        }
        for upload_id, (name, description, _score) in UPLOAD_CONCEPTS.items():
            record = self.get(
                upload_id,
                name=name,
                kind="generic",
                category="upload",
                surface="backend",
                component="core",
                description=description,
                severity="high",
                score=max(score for _, score in upload_rules.get(upload_id, [("", _score)])),
                score_note="Upload analysis adds the matching factor scores",
                wstg=["WSTG-INPV-10"],
                tags=["upload", "WSTG-INPV-10"],
            )
            for factor, score in upload_rules.get(upload_id, []):
                self.source(record, "upload", f"{factor} · +{score}")
                self.signature(record, layer="upload", match=factor, kind="factor", score=score)
                self.detection(record, f"Upload analysis · +{score} · {factor}")
            if upload_id == "upload-editor-access":
                # A theme/plugin editor is not strictly an upload; keep the
                # same record but make the category explicit.
                record["category_label"] = CATEGORY_LABELS["upload"]

        # Attach upload-specific CVE endpoint factors to their CVE records.
        endpoint_map = {
            "CVE-2025-4403": ("dnd_codedropz_upload", 50),
            "CVE-2025-47577": ("mwb_wgm_preview_mail", 50),
            "CVE-2025-10142": ("pc_added_uploaded_image", 45),
        }
        for cve, (factor, score) in endpoint_map.items():
            record = self.patterns.get(cve.lower())
            if record:
                self.source(record, "upload", f"{factor} · +{score} upload endpoint")
                self.signature(record, layer="upload", match=factor, kind="factor", score=score)
                self.detection(record, f"Upload analysis · +{score} · {factor}")

    def build_tool_presets_without_suricata(self) -> None:
        # Metasploit is in the preset list but not in Suricata's UA rules.
        record = self.patterns.get("tool-metasploit")
        if record:
            self.add_preset(record, self.presets.get("GENERIC-TOOL-003"))

    def finalise(self) -> None:
        # Canonical label for unset categories, dedupe detection strings, and
        # normalise tags.
        for record in self.patterns.values():
            record["category_label"] = CATEGORY_LABELS.get(record["category"], _humanise(record["category"]))
            record["kind_label"] = KIND_LABELS.get(record["kind"], _humanise(record["kind"]))
            record["severity"] = record["severity"].lower()
            record["wstg"] = sorted(set(record["wstg"]))
            record["tags"] = sorted(set(record["tags"]))
            record["sources"].sort(key=lambda s: (list(SOURCES).index(s["key"]) if s["key"] in SOURCES else 99,
                                                  s.get("detail", "")))
            record["detection"] = list(dict.fromkeys(record["detection"]))
            if not record["score"] and not record["score_note"]:
                record["score_note"] = "No score of its own; contributes through related signatures."
            if not record["trigger"] and record["signatures"]:
                first = record["signatures"][0]
                if first.get("layer") != "suricata":
                    record["trigger"] = first.get("match", "")
                    record["trigger_type"] = first.get("layer", "") + "_" + first.get("kind", "")

    # -- orchestration -----------------------------------------------------
    def build(self) -> dict:
        self.build_cves()
        self.build_layer2()
        self.build_new_concepts()
        self.build_edge_blocks()
        self.build_layer1()
        self.build_uploads()
        self.build_headers_tools()
        self.build_presets()
        self.build_suricata()
        self.build_tool_presets_without_suricata()
        self.finalise()

        # Fill the OWASP Top 10 tag from the WSTG mapping wherever a lesson did
        # not already supply one, so every WSTG-classified signature (the new
        # generic CRS-style ones included) carries an OWASP category.
        for p in self.patterns.values():
            if not p["owasp"] and p["wstg"]:
                p["owasp"] = _owasp_from_wstg(p["wstg"][0])

        patterns = list(self.patterns.values())
        for p in patterns:
            p["enabled"] = default_enabled(p["kind"])
        patterns.sort(key=lambda p: (
            SEVERITY_ORDER.get(p["severity"], 9),
            p["kind"],
            p["category_label"].lower(),
            p["name"].lower(),
        ))
        counts = {
            "total": len(patterns),
            "by_kind": dict(sorted(Counter(p["kind"] for p in patterns).items())),
            "by_category": dict(sorted(Counter(p["category"] for p in patterns).items())),
            "by_severity": dict(sorted(Counter(p["severity"] for p in patterns).items())),
            "by_source": dict(sorted(Counter(s["key"] for p in patterns for s in p["sources"]).items())),
            "cves": sum(1 for p in patterns if p["kind"] == "cve"),
            "suricata_sids": len({s["sid"] for p in patterns for s in p["suricata"]}),
        }
        return {
            "version": 1,
            "generated": date.today().isoformat(),
            "source_files": [
                "ids/reverse_proxy_enhanced/lua/pattern_rules.lua",
                "ids/reverse_proxy_enhanced/lua/init.lua",
                "ids/reverse_proxy_enhanced/lua/vulnerability_rules.lua",
                "ids/reverse_proxy_enhanced/lua/upload_rules.lua",
                "ids/suricata_rules/local.rules",
                "dashboard/core/patterns.py",
                "dashboard/core/learning.py",
            ],
            "sources": SOURCES,
            "kinds": KIND_LABELS,
            "categories": CATEGORY_LABELS,
            "counts": counts,
            "patterns": patterns,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero if patterns/patterns.json is stale")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    catalog = CatalogBuilder().build()
    text = json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    if args.check:
        if not OUTPUT.exists():
            print(f"missing {OUTPUT.relative_to(REPO)}", file=sys.stderr)
            return 1
        current = json.loads(OUTPUT.read_text(encoding="utf-8"))
        expected = dict(catalog)
        current.pop("generated", None)
        expected.pop("generated", None)
        if current != expected:
            print(f"{OUTPUT.relative_to(REPO)} is stale; run tools/generate_pattern_catalog.py",
                  file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"{OUTPUT.relative_to(REPO)} is up to date")
        return 0

    OUTPUT.write_text(text, encoding="utf-8")
    if not args.quiet:
        c = catalog["counts"]
        print(f"wrote {OUTPUT.relative_to(REPO)}: {c['total']} patterns "
              f"({c['cves']} CVE, {c['suricata_sids']} Suricata SIDs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
