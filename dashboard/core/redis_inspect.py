"""Redis introspection for the "session_store" service (ids /
edge project) -- backs ui/page_redis.py's table+graph viewer.

Goes through `docker compose exec session_store redis-cli ...` (locally or
over SSH for a remote edge target, via Target.build() -- same plumbing
every other docker-facing feature in this app already uses) rather than a
direct redis-py TCP connection: session_store has no published host port
by design (only reachable on the internal docker network, see
docker-compose.yml), so a direct client connection isn't even possible
without punching a hole in that isolation just for this dashboard.
`docker compose exec` also sidesteps having to know/guess the actual
compose-generated container name (e.g. "honeypot-ids-system-v1-
session_store-1") -- it resolves the service name within the right
project context the same way Target.build() already does for every other
compose command.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from core.docker_ctl import Target
from core.env_upload import EnvUploadError, load_project_env
from core.proc import run_checked
from core.state import RemoteConfig

REDIS_SERVICE = "session_store"

# Single round-trip: SCAN is the "right" way to list keys without blocking
# the single-threaded server, but for the per-key TYPE/TTL/size table this
# app needs, doing N docker-exec round-trips (real subprocess/SSH latency
# each) for N keys would make the page feel broken on anything but a
# trivial keyspace. This dev/test keyspace is small enough that a plain
# KEYS-based server-side Lua script (one round-trip total, computed
# entirely inside redis) is both simpler and correct enough -- it's the
# same tradeoff admin tooling makes routinely at this scale.
_LIST_KEYS_SCRIPT = (
    'local keys = redis.call("KEYS", ARGV[1]) '
    "local result = {} "
    "for i, k in ipairs(keys) do "
    '  local t = redis.call("TYPE", k)["ok"] '
    '  local ttl = redis.call("TTL", k) '
    "  local size = 0 "
    '  if t == "string" then size = redis.call("STRLEN", k) '
    '  elseif t == "list" then size = redis.call("LLEN", k) '
    '  elseif t == "set" then size = redis.call("SCARD", k) '
    '  elseif t == "hash" then size = redis.call("HLEN", k) '
    '  elseif t == "zset" then size = redis.call("ZCARD", k) '
    "  end "
    "  table.insert(result, k) "
    "  table.insert(result, t) "
    "  table.insert(result, tostring(ttl)) "
    "  table.insert(result, tostring(size)) "
    "end "
    "return result"
)


# Clears threat_ips entries, and the sessions (with their per-session pool
# assignments and fingerprint pointers), of any IP that can only be internal-to-this-docker-host traffic (RFC1918 private
# ranges + loopback) -- the dashboard's own pattern-runner curls, manual
# browser testing done directly on this machine, container-to-container
# health checks, and Suricata's own host-network visibility all show up as
# one of these (confirmed live throughout this project's development: the
# shared client IP for anything hitting a published port from the host
# itself is the docker bridge gateway address, e.g. 172.21.0.1). A genuine
# external user reaching a real two-host deployment's published port
# keeps their real public source IP -- Docker's DNAT preserves it on that
# leg -- so this can never touch real user data, only this dev
# environment's own self-generated noise.
#
# All three stores done server-side in one round-trip (not N docker-exec
# calls) via Lua: KEYS+DEL for the private-IP-matching session:* records and
# their honeypot_pool_session:* / fp_session:* keys, and a filter-then-SET (or DEL if now empty)
# for threat_ips, which is a single JSON blob keyed by IP rather than one
# redis key per IP.
_UNPOISON_SCRIPT = r"""
local function is_local_ip(ip)
    local a, b = ip:match("^(%d+)%.(%d+)%.%d+%.%d+$")
    if not a then return false end
    a, b = tonumber(a), tonumber(b)
    if a == 10 or a == 127 then return true end
    if a == 172 and b >= 16 and b <= 31 then return true end
    if a == 192 and b == 168 then return true end
    return false
end

local removed_sessions = 0
local removed_ids = {}
local session_keys = redis.call("KEYS", "session:*")
for _, key in ipairs(session_keys) do
    local val = redis.call("GET", key)
    if val then
        local ok, data = pcall(cjson.decode, val)
        if ok and type(data) == "table" and data.ip_address and is_local_ip(data.ip_address) then
            redis.call("DEL", key)
            removed_sessions = removed_sessions + 1
            removed_ids[key:sub(#"session:" + 1)] = true
        end
    end
end

-- Pools are assigned per session (honeypot_pool_session:<session id>): drop
-- the assignments of the sessions removed above, and the passive-fingerprint
-- pointers (fp_session:<fingerprint>) that would recover them.
local removed_pools = {}
for _, key in ipairs(redis.call("KEYS", "honeypot_pool_session:*")) do
    local sid = key:sub(#"honeypot_pool_session:" + 1)
    if removed_ids[sid] then
        redis.call("DEL", key)
        table.insert(removed_pools, sid)
    end
end
for _, key in ipairs(redis.call("KEYS", "fp_session:*")) do
    if removed_ids[redis.call("GET", key) or ""] then
        redis.call("DEL", key)
    end
end

local removed_threat_ips = {}
local threat_raw = redis.call("GET", "threat_ips")
if threat_raw then
    local ok, data = pcall(cjson.decode, threat_raw)
    if ok and type(data) == "table" then
        local kept = {}
        local any_removed = false
        for ip, v in pairs(data) do
            if is_local_ip(ip) then
                table.insert(removed_threat_ips, ip)
                any_removed = true
            else
                kept[ip] = v
            end
        end
        if any_removed then
            local is_empty = true
            for _ in pairs(kept) do
                is_empty = false
            end
            if is_empty then
                redis.call("DEL", "threat_ips")
            else
                redis.call("SET", "threat_ips", cjson.encode(kept))
            end
        end
    end
end

return cjson.encode({
    sessions_removed = removed_sessions,
    pool_assignments_removed = removed_pools,
    threat_ips_removed = removed_threat_ips,
})
"""


class RedisInspectError(Exception):
    pass


@dataclass(frozen=True)
class RedisKeyInfo:
    name: str
    type: str
    ttl: int  # -1 = no expiry
    size: int  # strlen/llen/scard/hlen/zcard depending on type


def _get_redis_password(remote: RemoteConfig | None, timeout: float = 10.0) -> str:
    try:
        env = load_project_env("edge", remote, timeout=timeout)
    except EnvUploadError as e:
        raise RedisInspectError(f"Could not read remote .env: {e}")
    password = env.get("REDIS_PASSWORD")
    if not password:
        if remote is None and not env.path.exists():
            raise RedisInspectError(f"{env.path} not found -- run the setup wizard first.")
        raise RedisInspectError("REDIS_PASSWORD not set in .env")
    return password


def _run_redis_cli(
    remote: RemoteConfig | None, *args: str, raw: bool = True, timeout: float = 15.0,
) -> str:
    password = _get_redis_password(remote, timeout=timeout)
    target = Target(project="edge", remote=remote)
    raw_flag = ["--raw"] if raw else ["--no-raw"]
    argv, cwd = target.build(
        "exec", "-T", REDIS_SERVICE, "redis-cli", "-a", password, *raw_flag, *args,
    )
    try:
        result = run_checked(argv, error=RedisInspectError, cwd=cwd, timeout=timeout, what="redis-cli")
    except RedisInspectError as e:
        # The "-a" password warning goes to stderr -- strip it out of a
        # failure message so the actual error is what the user sees.
        message = re.sub(r"^Warning: Using a password.*\n?", "", str(e), flags=re.MULTILINE).strip()
        raise RedisInspectError(message or str(e))
    # stdout is already clean (the warning only ever goes to stderr).
    return result.stdout


def list_keys(remote: RemoteConfig | None, pattern: str = "*", timeout: float = 15.0) -> list[RedisKeyInfo]:
    out = _run_redis_cli(remote, "EVAL", _LIST_KEYS_SCRIPT, "0", pattern, timeout=timeout)
    lines = out.splitlines()

    infos = []
    for i in range(0, len(lines) - 3, 4):
        name, key_type, ttl_str, size_str = lines[i:i + 4]
        try:
            ttl = int(ttl_str)
        except ValueError:
            ttl = -1
        try:
            size = int(size_str)
        except ValueError:
            size = 0
        infos.append(RedisKeyInfo(name=name, type=key_type, ttl=ttl, size=size))
    return sorted(infos, key=lambda k: k.name)


def get_value(remote: RemoteConfig | None, key: str, key_type: str, timeout: float = 15.0) -> str:
    """Raw value text for a key, JSON-pretty-printed when it parses as
    JSON (most of this project's redis values are cjson-encoded -- see
    threat_ips/session:* throughout reverse_proxy_enhanced/lua)."""
    if key_type == "string":
        text = _run_redis_cli(remote, "GET", key, timeout=timeout)
    elif key_type == "list":
        text = _run_redis_cli(remote, "LRANGE", key, "0", "-1", timeout=timeout)
    elif key_type == "set":
        text = _run_redis_cli(remote, "SMEMBERS", key, timeout=timeout)
    elif key_type == "hash":
        text = _run_redis_cli(remote, "HGETALL", key, timeout=timeout)
    elif key_type == "zset":
        text = _run_redis_cli(remote, "ZRANGE", key, "0", "-1", "WITHSCORES", timeout=timeout)
    else:
        text = _run_redis_cli(remote, "GET", key, timeout=timeout)

    text = text.strip()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text
    return json.dumps(parsed, indent=2, sort_keys=True)


# --- Site-wide scheduled-maintenance flag ---------------------------------
#
# The WordPress Update page takes the whole site offline while a core/
# WooCommerce upgrade runs by SET-ing this key with a TTL; the edge mirrors it
# into a shared dict and serves a 503 maintenance page (see
# reverse_proxy_enhanced/lua/maintenance.lua + init_worker.lua's mirror timer).
# The TTL is the fail-safe: if the dashboard dies mid-update the key expires on
# its own and the site comes back without manual intervention.
MAINTENANCE_KEY = "honeypot_maintenance"


def set_maintenance(remote: RemoteConfig | None, ttl_seconds: int, timeout: float = 15.0) -> None:
    """Turn the site-wide maintenance page ON for at most `ttl_seconds`.

    Written with an expiry on purpose -- see MAINTENANCE_KEY. The edge's mirror
    timer picks the change up within a few seconds (it is not instantaneous),
    so callers should allow a short grace period before assuming traffic is
    being held."""
    ttl = int(ttl_seconds)
    if ttl < 1:
        raise RedisInspectError("maintenance TTL must be at least 1 second")
    _run_redis_cli(remote, "SET", MAINTENANCE_KEY, "1", "EX", str(ttl), timeout=timeout)


def clear_maintenance(remote: RemoteConfig | None, timeout: float = 15.0) -> None:
    """Turn the maintenance page OFF immediately (idempotent -- DEL of a missing
    key is a no-op)."""
    _run_redis_cli(remote, "DEL", MAINTENANCE_KEY, timeout=timeout)


def maintenance_ttl(remote: RemoteConfig | None, timeout: float = 15.0) -> int:
    """Remaining seconds the maintenance flag stays on: >=0 when set, -2 when
    absent (maintenance off), -1 if set with no expiry (should not happen here).
    Mirrors redis TTL semantics."""
    out = _run_redis_cli(remote, "TTL", MAINTENANCE_KEY, timeout=timeout).strip()
    try:
        return int(out)
    except ValueError:
        return -2


# --- Edge URL policy (whitelist + honeypot targets) ------------------------
# One JSON document (core/edge_policy.py build_payload), no TTL: the policy is
# configuration, not threat state. init_worker.lua mirrors it into the
# threat_intel shared dict every 5 s; a missing key means the edge's built-in
# defaults (the pre-policy behaviour).
EDGE_POLICY_KEY = "honeypot_edge_policy"


def set_edge_policy(remote: RemoteConfig | None, document: str, timeout: float = 15.0) -> None:
    _run_redis_cli(remote, "SET", EDGE_POLICY_KEY, document, timeout=timeout)


def get_edge_policy(remote: RemoteConfig | None, timeout: float = 15.0) -> str | None:
    """The document the edge is running with, or None when none was applied."""
    out = _run_redis_cli(remote, "GET", EDGE_POLICY_KEY, timeout=timeout).strip()
    return out or None


def clear_edge_policy(remote: RemoteConfig | None, timeout: float = 15.0) -> None:
    _run_redis_cli(remote, "DEL", EDGE_POLICY_KEY, timeout=timeout)


def get_risk_scores(remote: RemoteConfig | None, timeout: float = 15.0) -> dict[str, int]:
    """{ip: raw_score} from the "threat_ips" key (see router.lua/
    init_worker.lua), for page_redis.py's bar chart. This is the raw,
    ever-only-increasing stored value (capped at 100) -- NOT the same
    number pattern_analyzer.lua actually applies to a request's score,
    which is a time-decayed view of this (suricata_rules.decayed_score()),
    smaller once any time has passed since `updated`. Seeing a bigger
    number here than in reverse_proxy's own logs for the same IP is
    expected, not a bug. Empty dict if the key doesn't exist yet or
    doesn't parse -- both are normal states (a freshly-started stack has
    no threat data yet), not errors."""
    try:
        text = _run_redis_cli(remote, "GET", "threat_ips", timeout=timeout).strip()
    except RedisInspectError:
        return {}
    if not text:
        return {}
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    scores = {}
    for ip, entry in data.items():
        if isinstance(entry, dict) and "raw_score" in entry:
            scores[ip] = int(entry["raw_score"])
    return scores


def _is_private_ip(ip: str) -> bool:
    """Private/loopback IPv4 -- the admin host's address as the edge sees the
    WordPress Studio browser. Mirrors is_local_ip() in _UNPOISON_SCRIPT so the
    live score and the un-poison button agree on which IPs are "ours"."""
    m = re.match(r"^(\d+)\.(\d+)\.\d+\.\d+$", ip)
    if not m:
        return False
    a, b = int(m.group(1)), int(m.group(2))
    return a in (10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def local_threat_score(remote: RemoteConfig | None, timeout: float = 15.0) -> int:
    """The worst raw threat score currently recorded against a private/local
    IP -- i.e. the admin host the Studio browser connects from -- or 0 if there
    is none. This is the stored, un-decayed value (see get_risk_scores), so it
    is an upper bound on what pattern_analyzer.lua actually applies right now;
    at or above the honeypot threshold (80) the admin is at risk of being
    diverted into a honeypot instead of reaching production."""
    scores = get_risk_scores(remote, timeout=timeout)
    local = [s for ip, s in scores.items() if _is_private_ip(ip)]
    return max(local) if local else 0


def clear_local_threat_state(remote: RemoteConfig | None, timeout: float = 15.0) -> dict:
    """Un-poisons threat_ips/session/pool-assignment state for the shared
    host IP (see _UNPOISON_SCRIPT) so pattern testing always starts from a
    clean, production-routed session -- run this before/after running
    patterns from the Attack Simulation page. Returns a summary dict:
    {"sessions_removed": int, "pool_assignments_removed": [session id, ...],
    "threat_ips_removed": [ip, ...]}."""
    out = _run_redis_cli(remote, "EVAL", _UNPOISON_SCRIPT, "0", timeout=timeout).strip()
    try:
        return json.loads(out)
    except (json.JSONDecodeError, ValueError):
        raise RedisInspectError(f"Unexpected response from unpoison script: {out!r}")


def dbsize(remote: RemoteConfig | None, timeout: float = 10.0) -> int:
    try:
        return int(_run_redis_cli(remote, "DBSIZE", timeout=timeout).strip())
    except (RedisInspectError, ValueError):
        return 0


def flush_all(remote: RemoteConfig | None, timeout: float = 15.0) -> None:
    """Wipes EVERY key in session_store's Redis -- equivalent to `redis-cli
    FLUSHALL` (same command this project's own README documents as the
    "flush all Redis state" one-liner). Used by page_redis.py's "Reset
    Redis KV store" button: this is where router.lua's session-level
    scoring lives (session:*), pattern_analyzer.lua's IP-reputation
    classification (threat_ips, fed by Suricata/admin/vulnerability/
    AbuseIPDB detections), pool_router.lua's sticky pool assignments
    (honeypot_pool_session:*), and rate limiting -- unlike
    clear_local_threat_state()'s targeted un-poisoning of just this
    host's own local/test IP, this clears every IP's state, real or
    test. No coming back from this short of the state rebuilding itself
    from live traffic."""
    _run_redis_cli(remote, "FLUSHALL", timeout=timeout)


# Deletes every key except the honeypot pool registry (honeypot_pool:ready /
# :free / :owner:* / :pw:* ...), which pool_manager owns, and the edge URL
# policy (configuration, see EDGE_POLICY_KEY). "honeypot_pool_session:*"
# (a different prefix) IS deleted: that is the per-IP assignment, i.e. threat
# state.
_FLUSH_THREAT_SCRIPT = """
local n = 0
for _, k in ipairs(redis.call('KEYS', '*')) do
  if string.sub(k, 1, 14) ~= 'honeypot_pool:' and k ~= 'honeypot_edge_policy' then
    redis.call('DEL', k)
    n = n + 1
  end
end
return n
"""


def flush_threat_state(remote: RemoteConfig | None, timeout: float = 15.0) -> int:
    """Like flush_all(), but keeps the honeypot pool registry that pool_manager
    maintains. flush_all() would make every pool look unregistered until the
    manager re-adopts them (and lose runtime pools' database passwords).
    Returns the number of keys deleted."""
    out = _run_redis_cli(remote, "EVAL", _FLUSH_THREAT_SCRIPT, "0", timeout=timeout).strip()
    try:
        return int(out)
    except ValueError:
        raise RedisInspectError(f"Unexpected response from flush script: {out!r}")


def session_decision_raw(remote: RemoteConfig | None, session_id: str,
                         timeout: float = 15.0) -> tuple[str, str, str]:
    """(session:<id> JSON, honeypot_pool_session:<id> value, the session's score
    in honeypot_pool:waiting -- set while it borrows a pool until its own is
    built) in one redis-cli call; an empty string where there is none."""
    script = ("return {redis.call('GET', KEYS[1]) or '', redis.call('GET', KEYS[2]) or '', "
              "redis.call('ZSCORE', KEYS[3], ARGV[1]) or ''}")
    out = _run_redis_cli(remote, "EVAL", script, "3", f"session:{session_id}",
                         f"honeypot_pool_session:{session_id}", "honeypot_pool:waiting",
                         session_id, timeout=timeout)
    lines = out.split("\n")
    lines += [""] * (3 - len(lines))
    return lines[0].strip(), lines[1].strip(), lines[2].strip()


def pool_state(remote: RemoteConfig | None, timeout: float = 15.0) -> dict:
    """Snapshot of the honeypot pool registry: ready pools, free (unowned)
    pools, per-pool owner counts, sessions waiting for a pool that is being
    built for them, and why pool_manager is not growing the pool (the `capped`
    reason), if it is not."""
    def ints(text: str) -> list[int]:
        return sorted(int(x) for x in text.split() if x.strip().isdigit())
    ready = ints(_run_redis_cli(remote, "SMEMBERS", "honeypot_pool:ready", timeout=timeout))
    free = ints(_run_redis_cli(remote, "ZRANGE", "honeypot_pool:free", "0", "-1", timeout=timeout))
    owners = {}
    for n in ready:
        owners[n] = int(_run_redis_cli(remote, "SCARD", f"honeypot_pool:owner:{n}",
                                       timeout=timeout).strip() or 0)
    capped = _run_redis_cli(remote, "GET", "honeypot_pool:capped", timeout=timeout).strip()
    reused = _run_redis_cli(remote, "GET", "honeypot_pool:counter", timeout=timeout).strip()
    waiting = _run_redis_cli(remote, "ZCARD", "honeypot_pool:waiting", timeout=timeout).strip()
    try:
        status = json.loads(_run_redis_cli(remote, "GET", "honeypot_pool:status",
                                           timeout=timeout).strip() or "{}")
    except ValueError:
        status = {}
    return {"ready": ready, "free": free, "owners": owners, "capped": capped,
            "waiting": int(waiting) if waiting.isdigit() else 0,
            "reused_assignments": int(reused) if reused.isdigit() else 0,
            # pool_manager's own view: budget, room for more pools, builds in
            # progress ({pool: start epoch}); {} when the manager is not running.
            "status": status if isinstance(status, dict) else {},
            # A forced scale-down (request_scaledown) pool_manager has not finished.
            "scaledown_pending": _run_redis_cli(
                remote, "EXISTS", "honeypot_pool:scaledown_now", timeout=timeout).strip() == "1"}


def server_time(remote: RemoteConfig | None, timeout: float = 10.0) -> float:
    """Redis' clock (epoch seconds) -- the edge host's, which pool_manager's
    event timestamps use too."""
    parts = _run_redis_cli(remote, "TIME", timeout=timeout).split()
    return int(parts[0]) + int(parts[1]) / 1e6


def pool_events(remote: RemoteConfig | None, timeout: float = 15.0) -> list[dict]:
    """pool_manager's event log (builds with phase timings, hand-offs with wait
    times, resource-limit transitions), oldest first."""
    out = []
    for line in _run_redis_cli(remote, "LRANGE", "honeypot_pool:events", "0", "-1",
                               timeout=timeout).splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and "at" in e:
            out.append(e)
    return out


# The proxy's log of rejected (edited / forged / unsigned) session cookies,
# newest first (session_identity_rules.lua: REJECTIONS_KEY).
COOKIE_REJECTIONS_KEY = "session_cookie_rejections"


def cookie_rejections(remote: RemoteConfig | None, count: int = 500,
                      timeout: float = 15.0) -> list[dict]:
    """The newest ``count`` rejected session cookies the proxy logged: each
    {"at", "status", "cookie_sha1", "claimed_id", "scored", "score", "ip", ...}.
    The cookie value itself is never stored, only its SHA-1."""
    out = []
    for line in _run_redis_cli(remote, "LRANGE", COOKIE_REJECTIONS_KEY, "0", str(count - 1),
                               timeout=timeout).splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and e.get("cookie_sha1"):
            out.append(e)
    return out


def set_pool_reserve(remote: RemoteConfig | None, pools: int, ttl: int = 1800,
                     timeout: float = 10.0) -> None:
    """Ask pool_manager to keep `pools` unowned pools ready (on top of
    POOL_SPARES, within the resource limit); 0 withdraws the request. The TTL
    makes a forgotten request expire on its own."""
    if pools > 0:
        _run_redis_cli(remote, "SET", "honeypot_pool:reserve", str(pools), "EX", str(ttl),
                       timeout=timeout)
    else:
        _run_redis_cli(remote, "DEL", "honeypot_pool:reserve", timeout=timeout)


def set_query_log(remote: RemoteConfig | None, on: bool, ttl: int = 7200,
                  timeout: float = 10.0) -> None:
    """Database layer: ask pool_manager to build every database with MySQL's
    general query log on while `on` (honeypot_pool:query_log); False withdraws
    it. The TTL makes a request a crashed run left behind expire."""
    if on:
        _run_redis_cli(remote, "SET", "honeypot_pool:query_log", "1", "EX", str(ttl),
                       timeout=timeout)
    else:
        _run_redis_cli(remote, "DEL", "honeypot_pool:query_log", timeout=timeout)


def request_scaledown(remote: RemoteConfig | None, session_ids: list[str], ttl: int = 600,
                      timeout: float = 10.0) -> None:
    """Ask pool_manager to scale down now instead of after
    POOL_IDLE_TIMEOUT_SECONDS: drop these sessions' pool assignments, then
    remove unowned runtime pools down to the spare count. Other sessions'
    pools are left alone. pool_manager deletes the request when done."""
    # One EVAL, so pool_manager never sees the sessions to release without the
    # scale-down flag: it would release them in an ordinary pass and remove
    # nothing, and the forced pass after it would then have nothing to report.
    script = ("for i = 2, #ARGV do redis.call('SADD', KEYS[1], ARGV[i]) end "
              "redis.call('SET', KEYS[2], '1', 'EX', ARGV[1]) return 1")
    _run_redis_cli(remote, "EVAL", script, "2", "honeypot_pool:release",
                   "honeypot_pool:scaledown_now", str(ttl), *session_ids, timeout=timeout)


def ready_pool_count(remote: RemoteConfig | None, timeout: float = 10.0) -> int | None:
    """How many honeypot pools are registered ready with the router."""
    out = _run_redis_cli(remote, "SCARD", "honeypot_pool:ready", timeout=timeout).strip()
    return int(out) if out.isdigit() else None


# One round-trip snapshot of every proxy session with its pool assignment,
# plus the threat_ips blob, for ui/page_sessions.py (interpreted by
# core/session_view.parse_snapshot()).
_LIST_SESSIONS_SCRIPT = """
local rows = {}
for _, k in ipairs(redis.call('KEYS', 'session:*')) do
  local id = string.sub(k, 9)
  local v = redis.call('GET', k)
  if v then
    table.insert(rows, {id = id, session = v,
                        pool = redis.call('GET', 'honeypot_pool_session:' .. id) or ''})
  end
end
return cjson.encode({sessions = rows, threat_ips = redis.call('GET', 'threat_ips') or '{}'})
"""


def list_sessions(remote: RemoteConfig | None, timeout: float = 20.0) -> str:
    """Raw JSON snapshot of all sessions (see _LIST_SESSIONS_SCRIPT); parse
    with core.session_view.parse_snapshot()."""
    return _run_redis_cli(remote, "EVAL", _LIST_SESSIONS_SCRIPT, "0", timeout=timeout).strip()


# One-round-trip snapshot of the honeypot pool registry for the standing
# Pool Scaling page (interpreted by core/pool_view.parse_snapshot()).
_POOL_SNAPSHOT_SCRIPT = """
local owners = {}
for _, n in ipairs(redis.call('SMEMBERS', 'honeypot_pool:ready')) do
  owners[n] = redis.call('SCARD', 'honeypot_pool:owner:' .. n)
end
return cjson.encode({
  ready = redis.call('SMEMBERS', 'honeypot_pool:ready'),
  free = redis.call('ZRANGE', 'honeypot_pool:free', 0, -1),
  owners = owners,
  capped = redis.call('GET', 'honeypot_pool:capped') or '',
  waiting = redis.call('ZCARD', 'honeypot_pool:waiting'),
  status = redis.call('GET', 'honeypot_pool:status') or '',
  last_seen = redis.call('HGETALL', 'honeypot_pool:last_seen'),
  health = redis.call('HGETALL', 'honeypot_pool:health'),
  events = redis.call('LRANGE', 'honeypot_pool:events', -60, -1),
  scaledown = redis.call('EXISTS', 'honeypot_pool:scaledown_now'),
  now = tonumber(redis.call('TIME')[1])
})
"""


def pool_snapshot(remote: RemoteConfig | None, timeout: float = 20.0) -> str:
    """Raw JSON snapshot of the pool registry; parse with
    core.pool_view.parse_snapshot()."""
    return _run_redis_cli(remote, "EVAL", _POOL_SNAPSHOT_SCRIPT, "0", timeout=timeout).strip()


# Removes one session and everything that would recover or re-bind it: the
# session record, its honeypot pool assignment, its passive-fingerprint
# pointer(s), the active_sessions index entry and any waiting-queue entry.
# For the Adversary Sessions page's "Reset session" -- unlike
# clear_local_threat_state() this is a single, explicitly chosen session,
# so it is not limited to local/test IPs.
_DELETE_SESSION_SCRIPT = """
local id = ARGV[1]
redis.call('DEL', 'session:' .. id)
redis.call('DEL', 'honeypot_pool_session:' .. id)
redis.call('SREM', 'active_sessions', id)
redis.call('ZREM', 'honeypot_pool:waiting', id)
for _, k in ipairs(redis.call('KEYS', 'fp_session:*')) do
  if redis.call('GET', k) == id then redis.call('DEL', k) end
end
return 1
"""


def delete_session(remote: RemoteConfig | None, session_id: str, timeout: float = 15.0) -> None:
    """Drop one session's state so its next request is scored fresh (see
    _DELETE_SESSION_SCRIPT). The session id must be a bare id, no prefix."""
    if not session_id:
        raise RedisInspectError("No session id given.")
    _run_redis_cli(remote, "EVAL", _DELETE_SESSION_SCRIPT, "0", session_id, timeout=timeout)
