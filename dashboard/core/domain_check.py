"""Detect domain/host settings in an .env that are still at their localhost
(or example-placeholder) defaults, so the dashboard can remind the operator to
set a real domain before/after the file goes to a remote host.

Pure text in, variable NAMES out -- values are never returned or logged."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from core.env_file import EnvFile

# Variables that carry a public domain / reachable address, per project.
_KNOWN: dict[str, tuple[str, ...]] = {
    "edge": ("WP_SITE_URL", "TRUSTED_CALLBACK_DOMAINS",
             "VECTOR_HOST", "ELASTICSEARCH_HOST", "KIBANA_HOST"),
    "siem": (),
}
# The siem .env ships no domain variables today; scan for any added later.
_GENERIC_KEY = re.compile(r"(^|_)(HOST|HOSTNAME|DOMAIN|DOMAINS|FQDN|URL)(_|$)", re.I)
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "your-siem-vm.example.com"}


def _host_of(item: str) -> str:
    item = item.strip().strip("'\"")
    if not item:
        return ""
    parsed = urlparse(item if "://" in item else "//" + item)
    return (parsed.hostname or "").lower()


def _is_local(value: str) -> bool:
    """True when every comma-separated entry is localhost-ish (or the value is
    empty-but-set is NOT counted: an unset var is a different problem)."""
    hosts = [_host_of(p) for p in value.split(",") if p.strip()]
    return bool(hosts) and all(h in _LOCAL_HOSTS for h in hosts)


def localhost_domain_vars(text: str, project: str) -> list[str]:
    """Names of domain variables in `text` still pointing at localhost."""
    env = EnvFile.from_text(text, Path(".env"))
    names = list(_KNOWN.get(project, ()))
    for key in env.keys():
        if key not in names and _GENERIC_KEY.search(key):
            names.append(key)
    out = []
    for name in names:
        value = env.get(name).strip().strip("'\"")
        if value and _is_local(value):
            out.append(name)
    return out
