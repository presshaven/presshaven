"""Qt-free logic for the Targeted Access page.

Lets an operator jump an embedded wp-admin browser straight to production OR
to one specific honeypot pool, on demand -- e.g. to confirm a WordPress
Studio propagation actually landed on a given pool, rather than trusting
that it did, or to look around inside a pool while investigating a session.

Reuses WordPress Studio's secret-gated edge passthrough
(X-Studio-Backend / X-Internal-Test-Auth, see core.wp_studio), extended on
the Lua side (router_rules.studio_honeypot_target in
ids/reverse_proxy_enhanced/lua/router_rules.lua) to also accept a pool
number via X-Studio-Pool and force-route straight to that pool's
`upstream honeypot_backend_N` block -- scoring/session routing never runs,
so the check itself can never get diverted or land on the wrong pool.

Only the pools declared statically in docker-compose.yml
(1..wp_studio.STATIC_POOLS) have a matching nginx upstream block, so those
are the only ones a single forced request can be routed to -- a pool
pool_manager creates later at runtime has no such target (see
router_rules.lua's studio_honeypot_target).
"""
from __future__ import annotations

from dataclasses import dataclass

from core import wp_studio

# Header carrying the pool number, read alongside X-Studio-Backend: honeypot.
# See router_rules.studio_honeypot_target.
STUDIO_POOL_HEADER = "X-Studio-Pool"


@dataclass(frozen=True)
class AccessTarget:
    """One place the embedded browser can be pinned to: production
    (pool is None) or one honeypot pool (pool is its number, 1-based)."""
    label: str
    pool: int | None  # None = production


def available_pools() -> list[int]:
    """The pools this page can target: the statically-declared ones. These
    are the only ones with a matching nginx upstream block, so a pool that
    exists at runtime (pool_manager scaled past STATIC_POOLS) but isn't one
    of them cannot be force-routed to by a single request."""
    return list(range(1, wp_studio.STATIC_POOLS + 1))


def targets(pools=None) -> list[AccessTarget]:
    """Production first, then one entry per pool in `pools` (ascending,
    deduplicated). Defaults to available_pools()."""
    pools = available_pools() if pools is None else pools
    result = [AccessTarget("Production", None)]
    for p in sorted({int(p) for p in pools}):
        result.append(AccessTarget(f"Honeypot pool {p}", p))
    return result


def target_headers(secret: str | None, target: AccessTarget) -> dict[str, str]:
    """Headers the embedded browser injects to pin itself to `target`. The
    backend header is always sent; the auth/pool headers only when a secret
    is configured. Without the secret nginx fails closed and the request is
    routed normally (and may be diverted/scored), same contract as
    wp_studio.studio_headers -- the caller is expected to warn about this,
    not this function."""
    if target.pool is None:
        return wp_studio.studio_headers(secret)
    headers = {wp_studio.STUDIO_BACKEND_HEADER: "honeypot"}
    secret = (secret or "").strip()
    if secret:
        headers[wp_studio.INTERNAL_TEST_HEADER] = secret
        headers[STUDIO_POOL_HEADER] = str(int(target.pool))
    return headers


def target_login(env, target: AccessTarget) -> wp_studio.AdminLogin | None:
    """The admin account automatic sign-in should use for `target`:
    production's account for production, the honeypot account (same
    username, HONEYPOT_WP_ADMIN_PASSWORD) for a pool. Never returns
    production's password for a honeypot target."""
    if target.pool is None:
        return wp_studio.admin_login(env)
    return wp_studio.honeypot_admin_login(env)
