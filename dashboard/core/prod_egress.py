"""Production internet-egress policy -- the WordPress Studio page's control
over what production_eshop may reach on the public internet.

Production egress is default-deny (ids/images/container_firewall/production.json
ships internet-https off), which is what keeps a compromised production plugin
from phoning home, pulling a payload or exfiltrating -- and therefore from ever
becoming a path around the honeypots. Two knobs loosen it deliberately:

  * a TEMPORARY all-internet HTTPS bypass (PRODUCTION_INTERNET_EGRESS) an
    operator turns on only while installing or updating a plugin/theme, and
  * a persistent allow-list of specific outbound-443 domains
    (PRODUCTION_TRUSTED_EGRESS_DOMAINS), e.g. downloads.wordpress.org.

Both live in the edge .env (so they survive restarts and a `down -v`, where
the firewall re-seeds its ruleset from these via container-firewall.php's
production_egress_overlay). Applying them also pushes a matching live ruleset
to the running production firewall through the existing container_firewall
machinery, so the change takes effect on the fly without a redeploy.

This module is Qt-free and unit-tested; ui/page_wp_studio.py is the thin
adapter around it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from core import container_firewall as cf
from core.env_file import EnvFile
from core.paths import EDGE_ENV_EXAMPLE, EDGE_ENV_FILE
from core.state import RemoteConfig

ENV_BYPASS = "PRODUCTION_INTERNET_EGRESS"
ENV_DOMAINS = "PRODUCTION_TRUSTED_EGRESS_DOMAINS"

# The internet-HTTPS built-in rule of the production profile; the bypass toggle
# is simply this rule's enabled flag (see production.json).
INTERNET_RULE_KEY = "outbound/internet-https"

_TRUE = {"1", "true", "yes", "on"}
# A domain, not a bare word or an address: lowercase, dotted, same shape the
# firewall's container-firewall.php trusted_egress_domains() accepts.
_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
MAX_DOMAINS = 20


def _truthy(value: str) -> bool:
    return value.strip().strip("\"'").lower() in _TRUE


def clean_domain(raw: str) -> str | None:
    """A single entry normalised (lowercased, no scheme, no trailing dot/port/
    path), or None if it is not a usable domain."""
    d = (raw or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)        # tolerate a pasted scheme
    d = d.split("/", 1)[0].split(":", 1)[0]  # drop any path / :port
    d = d.rstrip(".")
    if d and "." in d and _DOMAIN_RE.match(d):
        return d
    return None


def parse_domains(text: str) -> tuple[list[str], list[str]]:
    """(accepted, rejected) from a comma/space-separated list. Deduplicates,
    preserves first-seen order and caps at MAX_DOMAINS; anything past the cap
    or not a valid domain lands in `rejected`."""
    accepted: list[str] = []
    rejected: list[str] = []
    for part in re.split(r"[\s,]+", (text or "").strip()):
        if not part:
            continue
        d = clean_domain(part)
        if d is None:
            rejected.append(part)
        elif d in accepted:
            continue
        elif len(accepted) >= MAX_DOMAINS:
            rejected.append(part)
        else:
            accepted.append(d)
    return accepted, rejected


def _domain_id(domain: str) -> str:
    return ("trusted-" + re.sub(r"[^a-z0-9-]", "-", domain))[:48]


@dataclass
class EgressPolicy:
    internet_bypass: bool = False
    domains: list[str] = field(default_factory=list)

    def domains_text(self) -> str:
        return ", ".join(self.domains)


def read_policy(env_path=EDGE_ENV_FILE) -> EgressPolicy:
    """The current policy as recorded in the edge .env (missing keys = the
    shipped default: deny, no trusted domains)."""
    env = EnvFile.load(env_path)
    domains, _ = parse_domains(env.get(ENV_DOMAINS, ""))
    return EgressPolicy(internet_bypass=_truthy(env.get(ENV_BYPASS, "false")), domains=domains)


def write_policy(policy: EgressPolicy, env_path=EDGE_ENV_FILE,
                 example_path=EDGE_ENV_EXAMPLE) -> None:
    """Persist the policy to the edge .env (creating the keys from
    .env.example's position if they are missing), so it survives a restart
    and re-seeds the firewall on a fresh deploy."""
    env = EnvFile.load(env_path)
    if example_path is not None and example_path.exists():
        env.merge_missing_from(EnvFile.load(example_path))
    env.set(ENV_BYPASS, "true" if policy.internet_bypass else "false")
    env.set(ENV_DOMAINS, ",".join(policy.domains))
    env.save()


def build_settings(policy: EgressPolicy) -> cf.FirewallSettings:
    """The production firewall settings with this policy overlaid: the
    internet-HTTPS rule follows the bypass toggle, and the trusted domains
    become `trusted-<domain>` outbound-443 rules. Operator-added custom rules
    that are not ours (anything whose id does not start with "trusted-") are
    left untouched, so the Container Firewall page and this page coexist."""
    settings = cf.FirewallSettings.for_profile(cf.PRODUCTION)
    settings.set_enabled(INTERNET_RULE_KEY, policy.internet_bypass)
    settings.custom_rules = [c for c in settings.custom_rules
                             if not c["id"].startswith("trusted-")]
    taken = {c["id"] for c in settings.custom_rules}
    for d in policy.domains:
        rid = _domain_id(d)
        if rid in taken:
            continue
        taken.add(rid)
        settings.custom_rules.append({
            "direction": "outbound", "id": rid, "enabled": True, "peer": d,
            "proto": "tcp", "ports": "443",
            "label": f"Trusted egress domain (WordPress Studio): {d}"})
    return settings


def apply_policy(remote: RemoteConfig | None, policy: EgressPolicy,
                 env_path=EDGE_ENV_FILE, example_path=EDGE_ENV_EXAMPLE) -> None:
    """Persist the policy, record it in the dashboard's production firewall
    settings, and push the matching ruleset to the running firewall so it
    takes effect immediately. Raises cf.FirewallError if the live apply fails
    (the .env + settings are still written -- a redeploy would then pick them
    up)."""
    write_policy(policy, env_path, example_path)
    settings = build_settings(policy)
    settings.save()
    cf.apply_document(remote, cf.build_document(settings), cf.PRODUCTION)
