"""pool_manager: scales the honeypot pools with the number of user sessions.

A pool is a honeypot_eshop_N (WordPress) + honeypot_database_N (MySQL) pair,
each database seeded from production. pool_router.lua gives each new user
session a free ready pool exclusively. When none is free, the session borrows a
ready pool round-robin and joins honeypot_pool:waiting; this service then
builds one pool per waiting session (POOL_PARALLEL_BUILDS at a time), plus
POOL_SPARES unowned ones, and moves each waiting session to its own pool as
soon as that pool is healthy. Growth stops at the resource budget
(POOL_MAX_MEMORY_MB / POOL_MAX_CPUS, reserved by the pools' container limits),
at POOL_MAX pools, or when the host itself runs short; the service then sets
honeypot_pool:capped and the router assigns every further session to the ready
pools round-robin. See pool_router_rules.lua for the Redis key schema both
sides share.

Two honeypot layers, chosen with POOL_MODE:
  wordpress (default)  pool = honeypot_eshop_N + honeypot_database_N. Pools 1-3
                       come from docker-compose.yml. New pools copy a pre-seeded
                       template (files + database, POOL_TEMPLATE) and rotate the
                       DB password, skipping the ~50 s wp-cli install each time.
  database             pool = honeypot_database_N only (docker-compose.db-proxy.yml:
                       one shared WordPress picks the database per request, see
                       wp-content/db.php). Pool 1 is the compose `honeypot_database`.
                       New pools copy a pre-seeded template data directory
                       (POOL_TEMPLATE) rather than dumping production each time,
                       so a scale-up is ready in roughly MySQL's start time.
Compose-declared pools are only adopted here (registered in Redis once healthy).
Pools above them are created and destroyed through the Docker API. Their containers deliberately carry no
com.docker.compose.* labels, so `docker compose up --remove-orphans` leaves
them alone; they are found again by the `honeypot.pool` label.

SECURITY: this container mounts the Docker socket (root-equivalent on the
host). It publishes no ports, joins only session_network (Redis), and runs no
user-reachable code. Do not put it on honeynet-facing networks.
"""
from __future__ import annotations

import os
import secrets
import shutil
import socket
import sys
import threading
import time

import hashlib
import hmac
import json

import docker
import redis

import pool_logic as pl
import state_export

READY_KEY = "honeypot_pool:ready"
FREE_KEY = "honeypot_pool:free"
OWNER_PREFIX = "honeypot_pool:owner:"
PROVISION_KEY = "honeypot_pool:provision"
CAPPED_KEY = "honeypot_pool:capped"
WAITING_KEY = "honeypot_pool:waiting"
# session id -> epoch of its last request while waiting (pool_router stamps it).
WAITING_SEEN_KEY = "honeypot_pool:waiting_seen"
# Extra unowned pools a client asks to have ready (an int, with a TTL) on top of
# POOL_SPARES, e.g. the dashboard's pool test before its delayed windows attack.
RESERVE_KEY = "honeypot_pool:reserve"
# JSON snapshot of the manager's view (budget, room, builds in progress).
STATUS_KEY = "honeypot_pool:status"
# JSON event log (builds with per-phase timings, hand-offs with wait times,
# resource-limit transitions), newest last, capped to EVENTS_MAX.
EVENTS_KEY = "honeypot_pool:events"
EVENTS_MAX = 500
# Scale-down. pool_router stamps LAST_SEEN_KEY (pool -> epoch) whenever it routes
# a request to a pool. DIRTY_KEY holds pools a user has used. A client may
# ask for an immediate scale-down: RELEASE_KEY lists session ids whose pools to
# give up now, SCALEDOWN_KEY (flag, TTL) removes unowned runtime pools down to
# the spare count without waiting for the idle timeout. The manager deletes
# both once done and logs "scaledown_done".
LAST_SEEN_KEY = "honeypot_pool:last_seen"
DIRTY_KEY = "honeypot_pool:dirty"
RELEASE_KEY = "honeypot_pool:release"
SCALEDOWN_KEY = "honeypot_pool:scaledown_now"
PW_PREFIX = "honeypot_pool:pw:"
# Database layer: pool -> JSON {"healthy", "state", "at"} for every ready pool,
# from its MySQL container's state (publish_health). The proxy mirrors it into
# the health cache pool_router.lua consults, so a session whose database is
# down is served from another pool until it is back.
HEALTH_KEY = "honeypot_pool:health"
# Database layer: while this flag exists (a client sets it with a TTL, e.g. the
# dashboard's segmentation validation), every database built is registered
# with MySQL's general query log on (log_output=TABLE), so the client can tell
# from mysql.general_log which of its sessions each database served -- from
# the first request on, a newly built database being handed to a waiting
# session at once. The client turns the log on in the existing databases and
# off again in all of them when it is done.
QUERY_LOG_KEY = "honeypot_pool:query_log"
SESSION_KEY_PREFIX = "honeypot_pool_session:"

PROJECT = os.environ.get("COMPOSE_PROJECT", "honeypot-ids-system-v1")
MODE = os.environ.get("POOL_MODE", "wordpress")
if MODE not in ("wordpress", "database"):
    sys.exit(f"pool_manager: POOL_MODE must be 'wordpress' or 'database', not {MODE!r}")
# Pools declared in the compose file (never created/destroyed here).
STATIC_COUNT = int(os.environ.get("POOL_STATIC_COUNT", "3" if MODE == "wordpress" else "1"))
POLL_SECONDS = float(os.environ.get("POOL_POLL_SECONDS", "5"))
SPARES = int(os.environ.get("POOL_SPARES", "1"))
MAX_POOLS = int(os.environ.get("POOL_MAX", "10"))
READY_TIMEOUT_S = int(os.environ.get("POOL_READY_TIMEOUT_SECONDS", "900"))
RETRY_BACKOFF_S = int(os.environ.get("POOL_RETRY_BACKOFF_SECONDS", "60"))
# Resource budget for all pools together (compose-declared ones included), as
# reserved by their containers' memory/CPU limits; 0 = no budget, POOL_MAX only.
MAX_MEMORY_MB = float(os.environ.get("POOL_MAX_MEMORY_MB", "0") or 0)
MAX_CPUS = float(os.environ.get("POOL_MAX_CPUS", "0") or 0)
POOL_MEM_MB, POOL_CPUS = pl.pool_cost(MODE)
# What the budget charges per pool. Defaults to the containers' limits (the
# most a pool can ever take); real use is far lower (a WordPress pool measured
# ~430 MB / near-idle CPU in the pool test), so a limits-based budget stops
# scaling at a fraction of what the host could carry. Set these closer to
# measured use to fit more pools; POOL_MIN_FREE_MEM_MB and the load / disk
# checks still stop growth if the host really runs short.
POOL_MEM_MB = float(os.environ.get("POOL_RESERVE_MEM_MB", "") or POOL_MEM_MB)
POOL_CPUS = float(os.environ.get("POOL_RESERVE_CPUS", "") or POOL_CPUS)
# A waiting session counts as active (gets the next pool, counts as demand for
# builds) only while its client sent a request this recently. A client that
# cleared its cookies leaves its old session in the queue; without this the
# next pool went to that abandoned session while a live user kept waiting.
WAITING_ACTIVE_S = float(os.environ.get("POOL_WAITING_ACTIVE_SECONDS", "60") or 60)
# Runtime pools clone the already-configured production database, so their
# WordPress storefront config (permalinks, shipping, enabled gateways) is
# already present. With fast clone on, the per-pool WordPress-seed step skips
# re-applying it (~50s of wp-cli per pool), relying on the clone + content
# sync. Off by default: enable only after verifying a pool still serves
# correctly on your stack. Never affects the compose-declared pools 1-3.
FAST_CLONE = os.environ.get("POOL_FAST_CLONE", "0") == "1"
# Build each pool by copying a pre-seeded template instead of redoing the slow
# per-pool seeding, which cuts a pool build to roughly the container start time.
# Database layer: the template is a MySQL data directory cloned + scrubbed from
# production once (the same CLONE_SCRIPT a pool would run); a pool copies it and
# starts MySQL -- no per-pool dump from production (~44 s saved). WordPress layer:
# the template is a files + database volume pair seeded once, migrations and the
# wp-cli WordPress install included; a pool copies both, rotates the DB password
# to its own and syncs the current catalog -- skipping the ~50 s wp-cli install
# per pool. The manager pre-builds the template at start-up so even the first
# scale-up is fast, and rebuilds it when older than POOL_TEMPLATE_TTL_SECONDS
# (0 = keep for the manager's lifetime) so fresh pools track production's catalog.
# A pool built while the template is (re)building is built from scratch, as is
# every pool when POOL_TEMPLATE=0.
USE_TEMPLATE = os.environ.get("POOL_TEMPLATE", "1") != "0"
TEMPLATE_TTL_S = float(os.environ.get("POOL_TEMPLATE_TTL_SECONDS", "0") or 0)
# Pools built at the same time while sessions wait for one.
PARALLEL_BUILDS = max(1, int(os.environ.get("POOL_PARALLEL_BUILDS", "2")))
# Scale down pools no request has reached for this long (seconds; 0 = never).
# At least 600: nginx caches a session's pool for 300 s, so a shorter timeout
# could remove a pool a cached session is about to use.
MIN_IDLE_TIMEOUT_S = 600
IDLE_TIMEOUT_S = float(os.environ.get("POOL_IDLE_TIMEOUT_SECONDS", "1800") or 0)
if 0 < IDLE_TIMEOUT_S < MIN_IDLE_TIMEOUT_S:
    print(f"pool_manager: POOL_IDLE_TIMEOUT_SECONDS={IDLE_TIMEOUT_S:g} raised to "
          f"{MIN_IDLE_TIMEOUT_S}", flush=True)
    IDLE_TIMEOUT_S = MIN_IDLE_TIMEOUT_S
# Host limits for starting another pool. A WordPress pool reserves ~1.5 GB (eshop
# 1 GB + database 512 MB limits), a database-only pool 512 MB.
MIN_FREE_MEM_MB = float(os.environ.get(
    "POOL_MIN_FREE_MEM_MB", "2560" if MODE == "wordpress" else "1024"))
MAX_LOAD_PER_CPU = float(os.environ.get("POOL_MAX_LOAD_PER_CPU", "1.5"))
MIN_FREE_DISK_GB = float(os.environ.get("POOL_MIN_FREE_DISK_GB", "5"))
# Rebuild a clean pool when a user's assignment expires (if the host has
# room); 0 = always hand the used pool to the next user as it is.
RECYCLE_IDLE = os.environ.get("POOL_RECYCLE_IDLE", "1") != "0"

# Same server flags as docker-compose.yml's databases (see the comment on
# production_database there): the MariaDB-based wp-cli client has no
# caching_sha2_password plugin.
MYSQL_IMAGE = "mysql:8.4.13"
MYSQLD_ARGS = "--mysql-native-password=ON --authentication-policy=mysql_native_password"
# Built by docker-compose.yml (images/wordpress_hardened): the same WordPress
# and PHP as the compose pools, with the PHP2Shell mitigations, so a runtime
# pool is never softer than pools 1-3.
WORDPRESS_IMAGE = os.environ.get("POOL_WORDPRESS_IMAGE", "presshaven/wordpress:7.1.3-php8.4-hardened")
# Built by docker-compose.yml (images/container_firewall): every runtime pool's
# WordPress lives in the network namespace of one of these, which holds the
# honeypot firewall profile (see x-container-firewall in docker-compose.yml).
FIREWALL_IMAGE = os.environ.get("POOL_FIREWALL_IMAGE", "presshaven/container-firewall:1")
WPCLI_IMAGE = "wordpress:cli-2.12.0-php8.4"
DB_NAME = "production_database"
DB_USER = "production_user"

LOG_CONFIG = {"type": "json-file", "config": {"max-size": "10m", "max-file": "3"}}
NS = 1_000_000_000


def _keep_healthcheck_start_interval() -> None:
    """docker-py (7.1) rebuilds every healthcheck dict through Healthcheck(),
    which knows no start_interval and drops it. Keep it (Docker API 1.44+):
    the pools probe every 1-2 s until their first success, so a build is not
    slowed down by the 30 s steady-state interval. A no-op where docker is
    stubbed (the unit tests)."""
    try:
        import docker.types.containers as container_types
        from docker.types.healthcheck import Healthcheck
    except ImportError:
        return

    class HealthcheckWithStartInterval(Healthcheck):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            start_interval = kwargs.get("start_interval", kwargs.get("StartInterval"))
            if start_interval is not None:
                self["StartInterval"] = start_interval

    container_types.Healthcheck = HealthcheckWithStartInterval


_keep_healthcheck_start_interval()


def log(msg: str) -> None:
    print(f"[pool_manager {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def env_required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        sys.exit(f"pool_manager: required environment variable {name} is not set")
    return value


class Manager:
    # A disabled no-op exporter by default, so instances built with __init__
    # bypassed (the unit tests) still have one; __init__ replaces it with the
    # real, possibly-enabled exporter.
    exporter = state_export.StateExporter(None)

    def __init__(self) -> None:
        self.docker = docker.from_env()
        self.redis = redis.Redis(
            host=os.environ.get("REDIS_HOST", "session_store"),
            password=env_required("REDIS_PASSWORD"),
            decode_responses=True)
        # Production's database password: only ever sent to production (the
        # clone / content-sync helpers read from it). Every honeypot database
        # gets its own user and root password instead (_create_database_container).
        self.mysql_password = env_required("MYSQL_PASSWORD")
        # Database layer: production_eshop's db.php connects to whichever
        # honeypot database with this one password (HONEYPOT_DB_PASSWORD), so
        # it is every database-layer pool's, and never production's.
        self.honeypot_db_password = (env_required("HONEYPOT_DB_PASSWORD")
                                     if MODE == "database" else None)
        self.host_paths = self._own_mount_sources()
        self.image = self.docker.containers.get(socket.gethostname()).image
        self.in_flight: set[int] = set()   # pools being built (one thread each)
        self.backoff_until = 0.0
        self.build_started: dict[int, float] = {}
        self.build_reasons: dict[int, str] = {}
        self.capped_reason = ""
        self.forced_removed: list[int] = []   # removed so far by an unfinished forced scale-down
        self.health: dict[int, bool] = {}     # last published health per ready pool
        self._local = threading.local()    # per build thread: phase timings
        self._template_lock = threading.Lock()   # one template (re)build at a time
        # Push the live pool view + latency events to the edge log pipeline as
        # JSONL for the SIEM (honeypot-pool_state-* / honeypot-pool_events-*).
        # A no-op unless POOL_STATE_EXPORT_DIR is set; never raises into the
        # reconcile loop. See state_export.py and vector/vector.yaml.
        self.exporter = state_export.StateExporter(
            os.environ.get("POOL_STATE_EXPORT_DIR"),
            float(os.environ.get("POOL_STATE_SNAPSHOT_SECONDS", "30") or 30),
            log=log)

    # ---- discovery -------------------------------------------------------

    def _own_mount_sources(self) -> dict[str, str]:
        """Container path -> host path for this container's bind mounts. Helper
        containers mount the same host directories (the Docker daemon resolves
        paths on the host, not inside this container)."""
        me = self.docker.containers.get(socket.gethostname())
        return {m["Destination"]: m["Source"] for m in me.attrs.get("Mounts", [])}

    def _net(self, short: str) -> str:
        return f"{PROJECT}_{short}"

    def runtime_pools(self) -> set[int]:
        """Numbers of pools this service created (by label), running or not."""
        out = set()
        # sparse: labels straight from the list call. A full list inspects each
        # container in turn and fails (aborting the whole reconcile pass) when
        # a short-lived build helper is removed in between.
        for c in self.docker.containers.list(all=True, sparse=True,
                                             filters={"label": "honeypot.pool"}):
            try:
                out.add(int((c.attrs.get("Labels") or {})["honeypot.pool"]))
            except (KeyError, ValueError):
                pass
        return out

    def static_pool_up(self, n: int) -> bool:
        """A compose-declared pool counts once its serving container (the eshop,
        or the database in database mode) is healthy."""
        service = f"honeypot_eshop_{n}" if MODE == "wordpress" else (
            "honeypot_database" if n == 1 else f"honeypot_database_{n}")
        for c in self.docker.containers.list(filters={
                "label": [f"com.docker.compose.project={PROJECT}",
                          f"com.docker.compose.service={service}"]}):
            if c.attrs["State"].get("Health", {}).get("Status") == "healthy":
                return True
        return False

    def static_pool_pending(self, n: int) -> bool:
        """A compose-declared pool that is still on its way: its serving
        container exists but is only created, restarting or in its health
        grace period. compose creates every container at the start of `up`
        and starts the eshops only once their databases are seeded, so for
        the first minute or so of a stack start none of pools 1-3 is ready
        yet. Without this the manager built a runtime "spare" right then,
        one the compose pools made redundant a minute later. A pool whose
        container is missing, exited or unhealthy is not pending."""
        service = f"honeypot_eshop_{n}" if MODE == "wordpress" else (
            "honeypot_database" if n == 1 else f"honeypot_database_{n}")
        for c in self.docker.containers.list(all=True, filters={
                "label": [f"com.docker.compose.project={PROJECT}",
                          f"com.docker.compose.service={service}"]}):
            state = c.attrs.get("State", {})
            if state.get("Status") in ("created", "restarting"):
                return True
            if state.get("Status") == "running" and \
                    state.get("Health", {}).get("Status") == "starting":
                return True
        return False

    def pool_container_healthy(self, n: int) -> bool:
        try:
            prefix = "honeypot_eshop_" if MODE == "wordpress" else "honeypot_database_"
            c = self.docker.containers.get(f"{prefix}{n}")
        except docker.errors.NotFound:
            return False
        c.reload()
        return c.attrs["State"].get("Health", {}).get("Status") == "healthy"

    # ---- Redis registry --------------------------------------------------

    def register_ready(self, n: int, owned: bool = False) -> None:
        self.redis.sadd(READY_KEY, n)
        # Idle time counts from registration until a request reaches the pool.
        self.redis.hset(LAST_SEEN_KEY, str(n), f"{time.time():.3f}")
        if owned:
            log(f"pool {n} is ready (owned)")
            return
        sid = self.hand_off_or_free(n)
        log(f"pool {n} is ready ("
            + (f"handed to waiting session {sid[:8]}..." if sid else "free") + ")")

    def hand_off_or_free(self, n: int) -> str | None:
        """Give unowned pool n to the session that has waited longest for a pool
        of its own (moving it off the pool it borrowed), or put n in the free
        set when nobody waits. Returns the session id it went to."""
        res = self.redis.eval(HANDOFF_SCRIPT, 4, WAITING_KEY, FREE_KEY, READY_KEY, WAITING_SEEN_KEY,
                              str(n), SESSION_KEY_PREFIX, OWNER_PREFIX,
                              f"{time.time():.3f}", str(WAITING_ACTIVE_S))
        if not res:
            return None
        sid, since, old = res
        now = time.time()
        self.event("handoff", pool=n, session=sid,
                   borrowed=int(old) if str(old).isdigit() else None,
                   waited=round(max(0.0, now - float(since)), 3) if since else None)
        return sid

    # ---- event log -------------------------------------------------------

    def event(self, kind: str, **fields) -> None:
        """Append one event to the log clients (the dashboard's pool test
        report) read back for latency figures. Never fails the caller."""
        payload = {"type": kind, "at": round(time.time(), 3), **fields}
        try:
            self.redis.rpush(EVENTS_KEY, json.dumps(payload))
            self.redis.ltrim(EVENTS_KEY, -EVENTS_MAX, -1)
        except Exception as e:  # noqa: BLE001
            log(f"event log write failed: {e}")
        # Mirror the same event to the SIEM feed (honeypot-pool_events-*), so a
        # build's duration / a hand-off's wait time is queryable as latency.
        self.exporter.event(payload)

    def _phase(self, name: str, started: float) -> None:
        phases = getattr(self._local, "phases", None)
        if phases is not None:
            phases.append([name, round(time.time() - started, 3)])

    def unregister(self, n: int) -> None:
        self.redis.srem(READY_KEY, n)
        self.redis.zrem(FREE_KEY, str(n))
        self.redis.delete(OWNER_PREFIX + str(n))

    def adopt_static_pools(self) -> None:
        for n in range(1, STATIC_COUNT + 1):
            if self.redis.sismember(READY_KEY, n):
                continue
            if self.static_pool_up(n):
                self.register_ready(n, owned=bool(self.redis.scard(OWNER_PREFIX + str(n))))

    def restore_passwords(self) -> None:
        """Put each runtime pool's database password back in Redis if it was
        lost (a FLUSHALL from the dashboard wipes it). The WordPress container
        still has it in its environment. Content replication reads it from
        Redis. Not needed in the database layer, where every database uses
        production's credentials."""
        if MODE != "wordpress":
            return
        for n in self.runtime_pools():
            if n in self.in_flight or self.redis.exists(PW_PREFIX + str(n)):
                continue
            try:
                env = self.docker.containers.get(f"honeypot_eshop_{n}").attrs["Config"]["Env"]
            except docker.errors.NotFound:
                continue
            for item in env:
                if item.startswith("WORDPRESS_DB_PASSWORD="):
                    self.redis.set(PW_PREFIX + str(n), item.split("=", 1)[1])
                    log(f"pool {n}: restored database password in Redis")

    def remove_partial_pools(self) -> None:
        """At start-up: remove runtime pools a previous run left half-built (the
        manager was restarted mid-build, e.g. by `docker compose up`). Nothing
        is building in this process yet, so a runtime pool that is not healthy
        will never be registered -- it would only hold memory and count
        against the resource budget for good."""
        for n in sorted(self.runtime_pools()):
            if n > STATIC_COUNT and not self.pool_container_healthy(n) \
                    and not self.pool_still_starting(n):
                log(f"pool {n}: left half-built by an earlier run, removing")
                self.destroy(n)

    def remove_dead_pools(self) -> None:
        """Every pass: remove runtime pools that are neither registered nor being
        built and whose serving container is no longer healthy or starting
        (e.g. one kept at start-up because it was still starting, that then
        never became healthy). Such a pool can never be registered, yet it
        counts against the resource budget, so with a low POOL_MAX_MEMORY_MB /
        POOL_MAX_CPUS / POOL_MAX it would cap growth for good."""
        building = set(self.in_flight)   # before READY: a build registers, then leaves in_flight
        ready = {int(x) for x in self.redis.smembers(READY_KEY)}
        for n in sorted(self.runtime_pools()):
            if n <= STATIC_COUNT or n in building or n in ready:
                continue
            if not self.pool_container_healthy(n) and not self.pool_still_starting(n):
                log(f"pool {n}: not healthy and not registered, removing")
                self.destroy(n)

    def pool_still_starting(self, n: int) -> bool:
        """A finished WordPress pool whose eshop is running but not healthy
        yet: after a host reboot Docker restarts it together with this
        service, and it needs well over a minute to report healthy. The
        eshop container is only created once every seeding step is done, so
        it existing and running means the pool is complete; adopt_runtime_pools
        registers it once healthy. (In the database layer the serving
        container exists before the clone, so there is no such signal.)"""
        if MODE != "wordpress":
            return False
        try:
            c = self.docker.containers.get(f"honeypot_eshop_{n}")
        except docker.errors.NotFound:
            return False
        state = c.attrs["State"]
        return state.get("Status") == "running" and \
            state.get("Health", {}).get("Status") == "starting"

    def adopt_runtime_pools(self) -> None:
        """After a manager restart: re-register pools created earlier that are
        still healthy (Redis may have been wiped, which loses ready/free)."""
        for n in sorted(self.runtime_pools()):
            if n in self.in_flight or self.redis.sismember(READY_KEY, n):
                continue
            if self.pool_container_healthy(n):
                self.register_ready(n, owned=bool(self.redis.scard(OWNER_PREFIX + str(n))))

    # ---- database health (database layer) ---------------------------------

    def database_states(self) -> dict[int, str] | None:
        """Pool number -> state of its MySQL container (see pl.container_state),
        or None when the listing failed (a container removed while it was
        being listed, e.g. during a scale-down: next pass)."""
        try:
            listed = self.docker.containers.list(all=True, filters={"name": "honeypot_database"})
        except docker.errors.NotFound:
            return None
        out: dict[int, str] = {}
        for c in listed:
            if c.name.endswith("_net"):   # the database's firewall, not MySQL
                continue
            n = pl.database_pool_number(c.attrs.get("Config", {}).get("Labels") or {}, PROJECT)
            if n is not None:
                out[n] = pl.container_state(c.attrs.get("State", {}))
        return out

    def publish_health(self) -> None:
        """Database layer: publish every ready pool's database health
        (HEALTH_KEY). In this layer the proxy has no HTTP backend per pool to
        probe -- one production_eshop serves every pool -- so without this a
        database that crashed or hung kept getting its sessions, which then
        saw WordPress's "Error establishing a database connection". A stopped
        or restarting container counts at once; a hung mysqld once Docker's
        healthcheck (mysqladmin ping) has failed its retries."""
        if MODE != "database":
            return
        states = self.database_states()
        if states is None:
            return
        ready = {int(x) for x in self.redis.smembers(READY_KEY)}
        now = time.time()
        for n in sorted(ready):
            state = states.get(n, "missing")
            healthy = state == "healthy"
            self.redis.hset(HEALTH_KEY, str(n), json.dumps(
                {"healthy": healthy, "state": state, "at": round(now, 3)}))
            if self.health.get(n, True) != healthy:
                log(f"pool {n}: database {'healthy again' if healthy else 'UNHEALTHY'} ({state})")
                self.event("pool_health", pool=n, healthy=healthy, state=state)
            self.health[n] = healthy
        gone = [f for f in self.redis.hkeys(HEALTH_KEY) if not f.isdigit() or int(f) not in ready]
        if gone:
            self.redis.hdel(HEALTH_KEY, *gone)
        for n in [n for n in self.health if n not in ready]:
            del self.health[n]

    # ---- capacity --------------------------------------------------------

    @staticmethod
    def host_stats() -> tuple[float, float, int, float]:
        """(MemAvailable MB, 1-minute load, CPU count, free disk GB). Read from
        /proc, which shows the host's (or the WSL VM's) figures, not this
        container's cgroup."""
        mem_kb = 0
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    mem_kb = int(line.split()[1])
                    break
        load1 = os.getloadavg()[0]
        disk = shutil.disk_usage("/")
        return mem_kb / 1024.0, load1, os.cpu_count() or 1, disk.free / 1024 ** 3

    def can_grow(self) -> tuple[bool, str]:
        """Whether the host can take another pool. When it can't, the router
        reuses existing pools round-robin instead (see CAPPED_KEY)."""
        mem, load1, cpus, disk = self.host_stats()
        reason = pl.host_pressure(mem, load1, cpus, disk, MIN_FREE_MEM_MB,
                                  MAX_LOAD_PER_CPU, MIN_FREE_DISK_GB)
        return (not reason), reason

    # ---- idle pools ------------------------------------------------------

    def release_idle_pools(self) -> None:
        """Drop owners whose assignment expired. A pool left with no owner is
        either recycled (destroyed; a clean spare is rebuilt) when the host has
        room, or put back in the free set to be reused as it is."""
        for n in sorted(int(x) for x in self.redis.smembers(READY_KEY)):
            key = OWNER_PREFIX + str(n)
            owners = self.redis.smembers(key)
            if not owners:
                continue
            current = {}
            for owner in owners:   # session ids (pool_router assigns per session)
                v = self.redis.get(SESSION_KEY_PREFIX + owner)
                current[owner] = int(v) if v is not None and v.isdigit() else None
            stale = pl.stale_owners(owners, current, n)
            if not stale:
                continue
            self.redis.srem(key, *stale)
            if self.redis.scard(key):
                continue
            ready = self.redis.scard(READY_KEY)
            action = pl.idle_action(
                n > STATIC_COUNT and RECYCLE_IDLE, self.can_grow()[0], ready >= MAX_POOLS)
            if action == "recycle":
                log(f"pool {n}: all users gone, recycling")
                self.destroy(n)   # the spare logic rebuilds a clean one
            else:
                sid = self.hand_off_or_free(n)
                log(f"pool {n}: all users gone, reusing as it is"
                    + (f" (handed to waiting session {sid[:8]}...)" if sid else ""))

    # ---- provisioning ----------------------------------------------------

    def provision(self, n: int) -> None:
        """Build pool n end to end. Raises on failure (caller cleans up)."""
        if MODE == "database":
            self.provision_database(n)
        else:
            self.provision_wordpress(n)

    def provision_database(self, n: int) -> None:
        """Database layer: one more honeypot database. With POOL_TEMPLATE on
        (default) its data directory is copied from the pre-seeded template
        (see _build_template_database) and MySQL started on the ready-made directory --
        no per-pool dump from production, so a pool is ready in roughly MySQL's
        start time instead of ~44 s. With POOL_TEMPLATE=0, or while the template
        is still (re)building, it is cloned + scrubbed from production directly,
        the same way honeypot_db_init prepares the first one. All honeypot
        databases share HONEYPOT_DB_PASSWORD (production_eshop's db.php has one
        honeypot credential), never production's; each gets its own random root
        password (_create_database_container)."""
        db_name = f"honeypot_database_{n}"
        db_vol = f"{PROJECT}_{db_name}_data"
        labels = {"honeypot.pool": str(n), "honeypot.pool.managed-by": "pool_manager"}
        from_template = False
        if USE_TEMPLATE:
            try:
                self.ensure_template()
                from_template = self._template_is_fresh()
            except Exception as e:  # noqa: BLE001 -- fall back to a direct clone
                log(f"pool {n}: template unavailable ({e}); cloning from production")
        log(f"pool {n}: provisioning database {db_name} (volume {db_vol})"
            + (" from template" if from_template else ""))
        self.docker.volumes.create(name=db_vol, labels=labels)
        db = None
        if from_template:
            # Copy the template's MySQL data directory into this pool's volume
            # (local I/O; tar as root restores ownership, as the WordPress-layer
            # seed step already does for a raw DB dir), then start MySQL on it.
            self._run_helper(
                self.image, ["sh", "-c", "tar -C /src -cf - . | tar -C /dest -xf -"],
                binds={self._template_volume_name(): ("/src", "ro"), db_vol: ("/dest", "rw")},
                labels=labels, what="copy template")
            db = self._create_database_container(db_name, db_vol, self.honeypot_db_password, labels)
            db.start()
            self._wait_healthy(db, "database")
        else:
            db = self._create_database_container(db_name, db_vol, self.honeypot_db_password, labels)
            db.start()
            self._wait_healthy(db, "database")
            self._run_helper(
                MYSQL_IMAGE, ["bash", "-c", CLONE_SCRIPT],
                binds={self.host_paths["/migrations"]: ("/migrations", "ro"),
                       self.host_paths["/migrations_override/01_clean-honeypot-data.sql"]:
                           ("/migrations/01_clean-honeypot-data.sql", "ro")},
                labels=labels, what="clone + scrub", network=self._net("honeypot_network"),
                extra_networks=[self._net("production_network")],
                environment={"HP": db_name, "PROD": "production_database",
                             "MYSQL_USER": DB_USER, "MYSQL_PASSWORD": self.mysql_password,
                             "HP_PASSWORD": self.honeypot_db_password,
                             "MYSQL_DATABASE": DB_NAME})
        if self.redis.exists(QUERY_LOG_KEY):
            self._enable_query_log(db)
        self.register_ready(n)

    # ---- pool template (both layers) -------------------------------------

    def _template_volume_name(self) -> str:
        # Database layer: the single MySQL data-directory template volume.
        return f"{PROJECT}_honeypot_pool_template_data"

    def _template_db_volume_name(self) -> str:
        # WordPress layer: the database half of the template.
        return f"{PROJECT}_honeypot_pool_template_db"

    def _template_files_volume_name(self) -> str:
        # WordPress layer: the WordPress files half of the template.
        return f"{PROJECT}_honeypot_pool_template_files"

    def _template_marker_name(self) -> str:
        # A tiny companion volume created only once the data volume is fully
        # built, so a half-built template reads as absent (Docker volume labels
        # are immutable, so the data volume cannot carry a "done" flag set last).
        return f"{PROJECT}_honeypot_pool_template_ready"

    def _template_built_at(self) -> float | None:
        """Epoch the template finished building (from the marker volume's
        label), or None when there is no complete template."""
        name = self._template_marker_name()
        for v in self.docker.volumes.list(filters={"name": name}):
            if v.name == name:
                try:
                    return float((v.attrs.get("Labels") or {}).get("honeypot.template.built", 0))
                except (TypeError, ValueError):
                    return 0.0
        return None

    def _template_marker_labels(self) -> dict:
        name = self._template_marker_name()
        for v in self.docker.volumes.list(filters={"name": name}):
            if v.name == name:
                return v.attrs.get("Labels") or {}
        return {}

    @staticmethod
    def _decoy_admin_fingerprint() -> str:
        """Identifies the decoy admin settings the WordPress template was seeded
        with. Pools copied from the template skip wp-cli, so a changed
        HONEYPOT_WP_ADMIN_PASSWORD (or user/e-mail) must rebuild it. Keyed HMAC,
        not a plain hash, because volume labels are readable by anyone who can
        list volumes."""
        material = "\0".join((os.environ.get("WP_ADMIN_USER", "admin"),
                               os.environ.get("HONEYPOT_WP_ADMIN_PASSWORD",
                                              "change_this_honeypot_wp_admin_password"),
                               os.environ.get("WP_ADMIN_EMAIL", "admin@example.com")))
        return hmac.new(env_required("MYSQL_PASSWORD").encode(), material.encode(),
                        hashlib.sha256).hexdigest()[:16]

    def _template_is_fresh(self) -> bool:
        """A usable template volume exists and is within POOL_TEMPLATE_TTL_SECONDS
        (and, for the WordPress template, was seeded with the current decoy admin)."""
        built = self._template_built_at()
        if built is None:
            return False
        if MODE == "wordpress" and (self._template_marker_labels().get("honeypot.template.admin")
                                    != self._decoy_admin_fingerprint()):
            return False
        return TEMPLATE_TTL_S <= 0 or time.time() - built < TEMPLATE_TTL_S

    def ensure_template(self) -> None:
        """Build the template volume if it is missing or past its TTL. Only one
        build runs at a time; concurrent builds wait, then copy from it."""
        if not USE_TEMPLATE:
            return
        with self._template_lock:
            if self._template_is_fresh():
                return
            if MODE == "wordpress":
                self._build_template_wordpress()
            else:
                self._build_template_database()

    def _build_template_database(self) -> None:
        """Clone + scrub a honeypot database from production once (exactly as a
        pool would), then shut MySQL down cleanly so its data directory copies
        consistently (no crash recovery on the copies). Keeps only the volume;
        the container is removed. The "ready" marker is created last, so a build
        that fails part-way leaves no usable template. Runs under
        _template_lock."""
        vol, marker, name = (self._template_volume_name(), self._template_marker_name(),
                             "honeypot_pool_template")
        labels = {"honeypot.template": "1"}
        log(f"building pool template {vol} (one-time clone + scrub from production)")
        started = time.time()
        for leftover in (name, f"{name}_net"):   # the database before its firewall
            try:
                self.docker.containers.get(leftover).remove(force=True)
            except docker.errors.NotFound:
                pass
        # Drop the marker first (so a crash now leaves the template "absent"),
        # then any previous, possibly half-built, data volume.
        for vname in (marker, vol):
            for v in self.docker.volumes.list(filters={"name": vname}):
                if v.name == vname:
                    v.remove(force=True)
        self.docker.volumes.create(name=vol, labels=labels)
        db = self._create_database_container(name, vol, self.honeypot_db_password, labels)
        db.start()
        try:
            self._wait_healthy(db, "template database")
            self._run_helper(
                MYSQL_IMAGE, ["bash", "-c", CLONE_SCRIPT],
                binds={self.host_paths["/migrations"]: ("/migrations", "ro"),
                       self.host_paths["/migrations_override/01_clean-honeypot-data.sql"]:
                           ("/migrations/01_clean-honeypot-data.sql", "ro")},
                labels=labels, what="template clone + scrub", network=self._net("honeypot_network"),
                extra_networks=[self._net("production_network")],
                environment={"HP": name, "PROD": "production_database",
                             "MYSQL_USER": DB_USER, "MYSQL_PASSWORD": self.mysql_password,
                             "HP_PASSWORD": self.honeypot_db_password,
                             "MYSQL_DATABASE": DB_NAME})
            db.stop(timeout=90)   # clean InnoDB shutdown -> copies need no recovery
        finally:
            self._remove_database(db)
        self.docker.volumes.create(name=marker, labels={
            "honeypot.template": "1", "honeypot.template.built": f"{time.time():.0f}"})
        log(f"pool template ready in {time.time() - started:.0f}s")

    def _build_template_wordpress(self) -> None:
        """Seed a WordPress files + database volume pair once -- production files,
        a database clone, migrations and the wp-cli install -- under a throwaway
        DB password, then shut MySQL down cleanly so the data directory copies
        without crash recovery. Keeps both volumes; the container and the
        wp-cli helper are removed. Each pool copied from this template starts
        MySQL with its own DB password (mysql_credentials_entrypoint.sh). The "ready" marker is created last, so
        a build that fails part-way leaves no usable template. Runs under
        _template_lock."""
        db_vol, files_vol = self._template_db_volume_name(), self._template_files_volume_name()
        marker, db_name = self._template_marker_name(), "honeypot_pool_template_db"
        labels = {"honeypot.template": "1"}
        log(f"building WordPress pool template ({files_vol} + {db_vol}); one-time wp-cli install")
        started = time.time()
        for leftover in (db_name, f"{db_name}_net"):   # the database before its firewall
            try:
                self.docker.containers.get(leftover).remove(force=True)
            except docker.errors.NotFound:
                pass
        # Drop the marker first (so a crash now leaves the template "absent"),
        # then any previous, possibly half-built, data volumes.
        for vname in (marker, files_vol, db_vol):
            for v in self.docker.volumes.list(filters={"name": vname}):
                if v.name == vname:
                    v.remove(force=True)
        for vol in (files_vol, db_vol):
            self.docker.volumes.create(name=vol, labels=labels)
        self._seed_wordpress_volumes(files_vol, db_vol, labels)
        password = secrets.token_hex(12)   # the template's own; no pool keeps it
        db = self._create_database_container(db_name, db_vol, password, labels)
        db.start()
        try:
            self._wait_healthy(db, "template database")
            self._migrate_pool_db(db_name, labels, password, "template migrations")
            self._wordpress_cli_seed(db_name, files_vol, labels, password,
                                     "template WordPress seed")
            db.stop(timeout=90)   # clean InnoDB shutdown -> copies need no recovery
        finally:
            self._remove_database(db)
        self.docker.volumes.create(name=marker, labels={
            "honeypot.template": "1", "honeypot.template.built": f"{time.time():.0f}",
            "honeypot.template.admin": self._decoy_admin_fingerprint()})
        log(f"WordPress pool template ready in {time.time() - started:.0f}s")

    def _enable_query_log(self, db) -> None:
        """Turn the general query log on (see QUERY_LOG_KEY). Not fatal: the
        pool still serves, the client's evidence for it is only incomplete."""
        started = time.time()
        res = db.exec_run(["sh", "-c", "mysql -uroot -p\"$MYSQL_ROOT_PASSWORD\" -e "
                           "\"SET GLOBAL log_output='TABLE'; SET GLOBAL general_log='ON'\""])
        if res.exit_code != 0:
            log(f"{db.name}: could not turn the query log on: "
                + (res.output or b"").decode(errors="replace")[-200:])
            return
        self._phase("query log", started)

    def _create_database_container(self, name, volume, password, labels):
        """A pool (or template) MySQL container, inside the network namespace
        of its own firewall (_start_database_firewall), as docker-compose.yml's
        honeypot_database_1: attackers who get into a pool's WordPress own its
        database too, and from there honeypot_network would lead everywhere
        else -- the firewall lets connections in on 3306 and none out.

        Credentials, as the compose databases: the data directory is a copy
        (of production's, or of the template), so mysql_credentials_entrypoint.sh
        resets its accounts on start -- the user to `password`, root@localhost
        to a random password of this container's own (used only from inside
        it, by docker exec), root@'%' dropped."""
        fw = self._start_database_firewall(name, labels)
        return self.docker.containers.create(
            MYSQL_IMAGE, name=name, labels=labels, detach=True,
            command=["bash", "/mysql_credentials_entrypoint.sh", "mysqld", *MYSQLD_ARGS.split()],
            environment={"MYSQL_DATABASE": DB_NAME, "MYSQL_USER": DB_USER,
                         "MYSQL_PASSWORD": password,
                         "MYSQL_ROOT_PASSWORD": secrets.token_hex(16),
                         "MYSQL_ROOT_HOST": "localhost"},
            volumes={volume: {"bind": "/var/lib/mysql", "mode": "rw"},
                     self.host_paths["/scripts"] + "/mysql_credentials_entrypoint.sh":
                         {"bind": "/mysql_credentials_entrypoint.sh", "mode": "ro"}},
            network_mode=f"container:{fw.id}",
            security_opt=["no-new-privileges:true"], cap_drop=["ALL"],
            cap_add=["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "SYS_NICE"],
            mem_limit="512m", nano_cpus=500_000_000, pids_limit=200,
            log_config=LOG_CONFIG, restart_policy={"Name": "unless-stopped"},
            # Every 30 s once healthy (each probe is a docker exec; ten pools
            # at 10 s kept dockerd/containerd busy), every 1 s until then.
            # 127.0.0.1 (TCP), NOT localhost (socket): the socket ping also
            # answers the image's temporary --skip-networking bootstrap server
            # and would go green before the networked server accepts TCP,
            # releasing service_healthy dependents too early. No credentials:
            # "alive" (exit 0) even on access denied, no password in inspect.
            healthcheck={"test": ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1"],
                         "interval": 30 * NS, "timeout": 5 * NS, "retries": 5,
                         "start_period": 60 * NS, "start_interval": 1 * NS})

    def provision_wordpress(self, n: int) -> None:
        """WordPress layer: a full honeypot_eshop_N + honeypot_database_N pair.
        With POOL_TEMPLATE on (default) the files and database volumes are copied
        from a pre-seeded template (see _build_template_wordpress), skipping the
        one-time WordPress install (wp-cli, ~50 s) per pool; MySQL starts with
        this pool's own DB password and the current catalog is synced. While the
        template is still (re)building, or with POOL_TEMPLATE=0, the pool is built
        from scratch the same way init_setup prepares pools 1-3."""
        project, db_name, wp_name = PROJECT, f"honeypot_database_{n}", f"honeypot_eshop_{n}"
        db_vol, files_vol = f"{project}_{db_name}_data", f"{project}_{wp_name}_files"
        labels = {"honeypot.pool": str(n), "honeypot.pool.managed-by": "pool_manager"}
        password = secrets.token_hex(12)
        from_template = False
        if USE_TEMPLATE:
            try:
                self.ensure_template()
                from_template = self._template_is_fresh()
            except Exception as e:  # noqa: BLE001 -- fall back to a full build
                log(f"pool {n}: template unavailable ({e}); building from scratch")
        self.redis.set(PW_PREFIX + str(n), password)
        log(f"pool {n}: provisioning (volumes {db_vol}, {files_vol})"
            + (" from template" if from_template else ""))

        if from_template:
            self._provision_wordpress_from_template(n, db_name, db_vol, files_vol, labels, password)
        else:
            self._provision_wordpress_full(n, db_name, db_vol, files_vol, labels, password)
        # Both paths serve the install-time catalog until this mirrors production's
        # current one (the same sync honeypot_content_sync runs every few minutes).
        self._sync_pool_content(n, password, labels, "content sync")
        self._start_wordpress_container(n, db_name, wp_name, files_vol, labels, password)

    def _provision_wordpress_full(self, n, db_name, db_vol, files_vol, labels, password):
        """Build the pool's database and files from scratch: seed both volumes
        from production, start MySQL with this pool's password, migrate, then
        run the WordPress install (wp-cli)."""
        for vol in (db_vol, files_vol):
            self.docker.volumes.create(name=vol, labels=labels)
        self._seed_wordpress_volumes(files_vol, db_vol, labels)       # 1
        db = self._create_database_container(db_name, db_vol, password, labels)
        db.start()                                                    # 2
        self._wait_healthy(db, "database")
        self._migrate_pool_db(db_name, labels, password, "migrations")  # 3
        self._wordpress_cli_seed(db_name, files_vol, labels, password, "WordPress seed")    # 4

    def _provision_wordpress_from_template(self, n, db_name, db_vol, files_vol, labels, password):
        """Copy the template's files + database volumes into this pool's, start
        MySQL on the ready-made data dir with this pool's own DB password, then
        apply the migrations. No wp-cli install: the template already ran it.

        The files volume (~770 MB) dwarfs the DB data dir (~200 MB) but is not
        needed until the catalog sync and the WordPress container, both of which
        run only after MySQL is up and migrated. So the files copy runs on a
        worker thread concurrently with the small DB copy, MySQL startup and the
        migrations, and is joined just before the caller needs it; on a warm host
        the whole files copy hides behind MySQL's start, shaving it off the build."""
        for vol in (db_vol, files_vol):
            self.docker.volumes.create(name=vol, labels=labels)
        # Local tar copy (tar as root restores ownership, as the raw DB seed does).
        join_files = self._copy_template_files_async(files_vol, labels)
        try:
            self._run_helper(
                self.image, ["sh", "-c", "tar -C /src_db -cf - . | tar -C /dest_db -xf -"],
                binds={self._template_db_volume_name(): ("/src_db", "ro"),
                       db_vol: ("/dest_db", "rw")},
                labels=labels, what="copy template db")
            db = self._create_database_container(db_name, db_vol, password, labels)
            db.start()
            self._wait_healthy(db, "database")
            self._migrate_pool_db(db_name, labels, password, "migrations")
        finally:
            # Always reap the worker (even on failure) so no orphan helper or
            # thread outlives the build; join_files re-raises its own error.
            join_files()

    def _copy_template_files_async(self, files_vol, labels):
        """Start the (large) template files copy on a worker thread so it runs
        concurrently with the caller's DB copy + MySQL startup. Returns a
        callable that blocks until the copy finishes, records its phase timing
        on the caller's thread, and re-raises any error from the worker."""
        started = time.time()
        error: list[BaseException] = []

        def _work():
            try:
                self._run_helper(
                    self.image, ["sh", "-c", "tar -C /src_files -cf - . | tar -C /dest_files -xf -"],
                    binds={self._template_files_volume_name(): ("/src_files", "ro"),
                           files_vol: ("/dest_files", "rw")},
                    labels=labels, what="copy template files")
            except BaseException as e:  # noqa: BLE001 -- surfaced to the caller on join
                error.append(e)

        t = threading.Thread(target=_work, daemon=True)
        t.start()

        def _join():
            t.join()
            self._phase("copy template files", started)
            if error:
                raise error[0]

        return _join

    def _seed_wordpress_volumes(self, files_vol, db_vol, labels):
        """WordPress files from production (minus the production-only hardening
        plugin) and a raw copy of the database directory, as init_setup does for
        pools 1-3."""
        self._run_helper(
            self.image, ["sh", "-c", (
                "rsync -a /source_files/ /dest_files/ && "
                "rm -f /dest_files/wp-content/mu-plugins/production-hardening.php "
                "/dest_files/wp-content/sql-routing.log /dest_files/wp-content/db.php.backup && "
                "tar -C /source_db -cf - . | tar -C /dest_db -xf -")],
            binds={self.host_paths["/source_files"]: ("/source_files", "ro"),
                   self.host_paths["/source_db"]: ("/source_db", "ro"),
                   files_vol: ("/dest_files", "rw"), db_vol: ("/dest_db", "rw")},
            labels=labels, what="seed volumes")

    def _migrate_pool_db(self, db_name, labels, password, what):
        """Apply the migrations to a pool database (idempotent, --force). Its
        user already has the pool's password: MySQL started with it."""
        self._run_helper(
            MYSQL_IMAGE, ["bash", "-c", MIGRATE_SCRIPT],
            binds={self.host_paths["/migrations"]: ("/migrations", "ro")},
            labels=labels, what=what, entrypoint=[],
            environment={"DB_HOST": db_name, "DB_USER": DB_USER, "DB_NAME": DB_NAME,
                         "DB_PASSWORD": password},
            network=self._net("honeypot_network"))

    def _wordpress_cli_seed(self, db_name, files_vol, labels, password, what):
        """Install WordPress into the database + files (same script as db_seed_N).
        The slow step (~50 s of wp-cli); the template runs it once so pools copied
        from it skip it."""
        self._run_helper(
            WPCLI_IMAGE, ["sh", "/seed_wordpress_db.sh"],
            binds={files_vol: ("/var/www/html", "rw"),
                   self.host_paths["/scripts"] + "/seed_wordpress_db.sh": ("/seed_wordpress_db.sh", "ro")},
            labels=labels, what=what, user="root",
            environment={
                "WORDPRESS_DB_HOST": f"{db_name}:3306", "WORDPRESS_DB_NAME": DB_NAME,
                "WORDPRESS_DB_USER": DB_USER, "WORDPRESS_DB_PASSWORD": password,
                "WP_ADMIN_USER": os.environ.get("WP_ADMIN_USER", "admin"),
                # A decoy's admin password, never production's (see .env).
                "WP_ADMIN_PASSWORD": os.environ.get("HONEYPOT_WP_ADMIN_PASSWORD",
                                                    "change_this_honeypot_wp_admin_password"),
                "WP_ADMIN_EMAIL": os.environ.get("WP_ADMIN_EMAIL", "admin@example.com"),
                "WP_SITE_URL": os.environ.get("WP_SITE_URL", "http://localhost"),
                "WP_SITE_TITLE": os.environ.get("WP_SITE_TITLE", "Fernhill Coffee Roasters"),
                "FORCE_RESEED": "0", "IMPORT_SAMPLE_CONTENT": "0",
                "SKIP_STOREFRONT_CONFIG": "1" if FAST_CLONE else "0",
                "STRIPE_TEST_PUBLISHABLE_KEY": os.environ.get("STRIPE_TEST_PUBLISHABLE_KEY", ""),
                "STRIPE_TEST_SECRET_KEY": os.environ.get("STRIPE_TEST_SECRET_KEY", "")},
            network=self._net("honeypot_network"),
            caps=["DAC_OVERRIDE", "CHOWN", "FOWNER", "SETGID", "SETUID"])

    def _sync_pool_content(self, n, password, labels, what):
        """Mirror production's current catalog (pages, posts, products) into pool
        n once, so a diverted visitor's cart (rebuilt from product IDs) is not
        empty and the catalog is not the install-time snapshot's."""
        self._run_helper(
            MYSQL_IMAGE, ["bash", "/scripts/replicate_content_to_honeypot.sh", "--once", str(n)],
            binds={self.host_paths["/scripts"]: ("/scripts", "ro")},
            labels=labels, what=what, entrypoint=[],
            environment={"MYSQL_PASSWORD": self.mysql_password, "POOL_DB_PASSWORD": password},
            network=self._net("honeypot_network"),
            extra_networks=[self._net("production_network")])

    def _start_wordpress_container(self, n, db_name, wp_name, files_vol, labels, password):
        """The WordPress container itself, inside the network namespace of its
        firewall (_start_firewall_container). It generates wp-config from the
        per-pool DB password it is handed (production_eshop_files/wp-config.php
        reads WORDPRESS_DB_PASSWORD from the environment), so a template-cloned
        files volume needs no editing."""
        fw = self._start_firewall_container(n, db_name, wp_name, labels)
        wp = self.docker.containers.create(
            WORDPRESS_IMAGE, name=wp_name, labels=labels, detach=True,
            command=["sh", "-c", WP_START_SCRIPT],
            environment={
                "WORDPRESS_DB_HOST": f"{db_name}:3306", "WORDPRESS_DB_NAME": DB_NAME,
                "WORDPRESS_DB_USER": DB_USER, "WORDPRESS_DB_PASSWORD": password,
                "WORDPRESS_DEBUG": "1", "WORDPRESS_DEBUG_LOG": "1",
                "HONEYPOT_POOL_ID": str(n)},
            volumes={files_vol: {"bind": "/var/www/html", "mode": "rw"}},
            network_mode=f"container:{fw.id}",
            security_opt=["no-new-privileges:true"], cap_drop=["ALL"],
            cap_add=["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID",
                     "NET_BIND_SERVICE", "KILL"],
            mem_limit="1024m", nano_cpus=1_000_000_000, pids_limit=300,
            log_config=LOG_CONFIG, restart_policy={"Name": "unless-stopped"},
            healthcheck={"test": ["CMD", "curl", "-f", "http://localhost/"],
                         "interval": 30 * NS, "timeout": 10 * NS, "retries": 3,
                         "start_period": 60 * NS, "start_interval": 2 * NS})
        wp.start()
        self._wait_healthy(wp, "WordPress")
        self.register_ready(n)

    def _start_database_firewall(self, db_name, labels):
        """<db_name>_net, as docker-compose.yml's honeypot_database_1_net: owns
        the database's network namespace on honeypot_network, answers to its
        DNS name and enforces the locked honeypot_database profile (MySQL in
        from honeypot_network, no connection out) before MySQL starts in it.
        Replaces a leftover of the same name (a template build cut short).
        Not charged to the pool budget (pool_logic.pool_cost): ~10 MB, idle."""
        name = f"{db_name}_net"
        try:
            self.docker.containers.get(name).remove(force=True)
        except docker.errors.NotFound:
            pass
        return self._start_firewall(name, db_name, labels, {
            "FIREWALL_PROFILE": "honeypot_database",
            "FIREWALL_LAYER": "db-proxy" if MODE == "database" else "default"})

    def _remove_database(self, db) -> None:
        """Remove a database container, then its firewall (MySQL lives in the
        firewall's network namespace)."""
        name = db.name
        db.remove(force=True)
        try:
            self.docker.containers.get(f"{name}_net").remove(force=True)
        except docker.errors.NotFound:
            pass

    def _start_firewall_container(self, n, db_name, wp_name, labels):
        """honeypot_eshop_N_net, as docker-compose.yml's honeypot_eshop_1_net:
        owns the pool's network namespace on honeypot_network only (see
        honeypot_eshop_1 there: on production_network a compromised pool could
        log into production_database) and answers to the pool's DNS name, with
        the honeypot firewall profile enforced before WordPress starts in it.
        Not charged to the pool budget (pool_logic.pool_cost): ~10 MB, idle."""
        return self._start_firewall(f"{wp_name}_net", wp_name, labels, {
            "FIREWALL_PROFILE": "honeypot", "FIREWALL_LAYER": "default",
            "FIREWALL_DB_HOST": f"{db_name}:3306"})

    def _start_firewall(self, name, alias, labels, environment):
        """A container-firewall sidecar on honeypot_network only, answering to
        `alias`, started and healthy (its ruleset enforced) on return."""
        net = self._net("honeypot_network")
        fw = self.docker.containers.create(
            FIREWALL_IMAGE, name=name, labels=labels, detach=True,
            environment=environment,
            volumes={f"{PROJECT}_container_firewall_rules":
                     {"bind": "/var/lib/container-firewall", "mode": "rw"}},
            network=net,
            networking_config={net: self.docker.api.create_endpoint_config(aliases=[alias])},
            init=True, read_only=True, tmpfs={"/run": ""},
            security_opt=["no-new-privileges:true"], cap_drop=["ALL"], cap_add=["NET_ADMIN"],
            mem_limit="64m", nano_cpus=250_000_000, pids_limit=50,
            log_config=LOG_CONFIG, restart_policy={"Name": "unless-stopped"},
            healthcheck={"test": ["CMD", "container-firewall", "health"],
                         "interval": 30 * NS, "timeout": 5 * NS, "retries": 3,
                         "start_period": 30 * NS, "start_interval": 1 * NS})
        fw.start()
        self._wait_healthy(fw, "firewall")
        return fw

    def _run_helper(self, image, command, binds, labels, what, user=None,
                    environment=None, network=None, caps=None, entrypoint=None,
                    extra_networks=()):
        """Run a short-lived container to completion; raise unless it exits 0."""
        volumes = {src: {"bind": dst, "mode": mode} for src, (dst, mode) in binds.items()}
        started = time.time()
        c = self.docker.containers.create(
            image, command=command, labels=labels, volumes=volumes, user=user,
            environment=environment, network=network, entrypoint=entrypoint,
            cap_drop=["ALL"] if caps else None, cap_add=caps, log_config=LOG_CONFIG,
            # One on two networks never routes between them (as reverse_proxy).
            sysctls={"net.ipv4.ip_forward": "0"} if extra_networks else None)
        try:
            for extra in extra_networks:
                self.docker.networks.get(extra).connect(c)
            c.start()
            result = c.wait(timeout=READY_TIMEOUT_S)
            if result.get("StatusCode") != 0:
                tail = c.logs(tail=30).decode(errors="replace")
                raise RuntimeError(f"helper '{what}' exited {result.get('StatusCode')}:\n{tail}")
        finally:
            c.remove(force=True)
        self._phase(what, started)

    def _wait_healthy(self, container, what: str) -> None:
        started = time.time()
        deadline = started + READY_TIMEOUT_S
        while time.time() < deadline:
            container.reload()
            state = container.attrs["State"]
            if state.get("Health", {}).get("Status") == "healthy":
                self._phase(f"{what} start", started)
                return
            if state.get("Status") in ("exited", "dead"):
                raise RuntimeError(f"{what} container {container.name} stopped: "
                                   + container.logs(tail=20).decode(errors="replace"))
            time.sleep(3)
        raise TimeoutError(f"{what} container {container.name} not healthy after {READY_TIMEOUT_S}s")

    def destroy(self, n: int) -> None:
        """Remove pool n's containers and volumes (runtime pools only)."""
        if n <= STATIC_COUNT:
            raise ValueError("static pools are owned by docker compose")
        self.unregister(n)
        self.redis.hdel(LAST_SEEN_KEY, str(n))
        self.redis.hdel(HEALTH_KEY, str(n))
        self.redis.srem(DIRTY_KEY, n)
        # The firewall last: WordPress lives in its network namespace.
        for c in sorted(self.docker.containers.list(all=True, filters={"label": f"honeypot.pool={n}"}),
                        key=lambda c: c.name.endswith("_net")):
            c.remove(force=True, v=True)
        for v in self.docker.volumes.list(filters={"label": f"honeypot.pool={n}"}):
            v.remove(force=True)
        self.redis.delete(PW_PREFIX + str(n))
        log(f"pool {n}: destroyed")

    def _provision_thread(self, n: int) -> None:
        self._local.phases = []
        started = self.build_started.get(n, time.time())
        try:
            self.provision(n)
            took = time.time() - started
            log(f"pool {n}: built in {took:.0f}s")
            self.event("build", pool=n, start=round(started, 3), seconds=round(took, 3),
                       ok=True, phases=self._local.phases)
        except Exception as e:  # noqa: BLE001 -- keep the manager alive
            log(f"pool {n}: provisioning FAILED: {e}")
            self.event("build", pool=n, start=round(started, 3),
                       seconds=round(time.time() - started, 3), ok=False,
                       phases=self._local.phases, error=str(e)[:300])
            try:
                self.destroy(n)
            except Exception as e2:  # noqa: BLE001
                log(f"pool {n}: cleanup after failure also failed: {e2}")
            self.backoff_until = time.time() + RETRY_BACKOFF_S
        finally:
            self.in_flight.discard(n)
            self.build_started.pop(n, None)
            self.build_reasons.pop(n, None)

    def start_build(self, n: int, reason: str = "spare") -> None:
        self.in_flight.add(n)
        self.build_reasons[n] = reason
        self.build_started[n] = time.time()
        self.event("build_start", pool=n, reason=reason)
        threading.Thread(target=self._provision_thread, args=(n,), daemon=True).start()

    # ---- main loop -------------------------------------------------------

    def drain_wakeups(self) -> int:
        n = 0
        while self.redis.lpop(PROVISION_KEY) is not None:
            n += 1
        return n

    def prune_waiting(self) -> int:
        """Drop waiting sessions whose assignment has expired; returns how many
        still wait for a pool of their own AND are active (see
        WAITING_ACTIVE_S) -- only those are demand for a new build."""
        now = time.time()
        queued = self.redis.zrange(WAITING_KEY, 0, -1)
        seen = self.redis.hgetall(WAITING_SEEN_KEY)
        active = 0
        for sid in queued:
            if not self.redis.exists(SESSION_KEY_PREFIX + sid):
                self.redis.zrem(WAITING_KEY, sid)
                self.redis.hdel(WAITING_SEEN_KEY, sid)
            elif sid not in seen or now - float(seen[sid]) <= WAITING_ACTIVE_S:
                active += 1
        stray = [sid for sid in seen if sid not in set(queued)]
        if stray:
            self.redis.hdel(WAITING_SEEN_KEY, *stray)
        return active

    def all_pools(self, ready: set[int]) -> set[int]:
        """Every pool that exists or is being built, compose-declared included."""
        return ready | self.runtime_pools() | self.in_flight | set(range(1, STATIC_COUNT + 1))

    # ---- scale-down ------------------------------------------------------

    def release_sessions(self, sids, reason: str, pool: int | None = None) -> dict[int, list[str]]:
        """Drop these sessions' pool assignments (and their place in the wait
        queue). Returns pool -> released session ids."""
        out: dict[int, list[str]] = {}
        for sid in sids:
            key = SESSION_KEY_PREFIX + sid
            v = self.redis.get(key)
            n = int(v) if v is not None and v.isdigit() else pool
            if pool is None or n == pool:
                self.redis.delete(key)
            self.redis.zrem(WAITING_KEY, sid)
            if n is not None:
                self.redis.srem(OWNER_PREFIX + str(n), sid)
                out.setdefault(n, []).append(sid)
        for n, released in out.items():
            self.event("released", pool=n, sessions=released, reason=reason)
            log(f"pool {n}: released {len(released)} session(s) ({reason})")
        return out

    def scale_down(self, spares: int) -> None:
        """Release pools idle past the timeout, remove the runtime pools that are
        no longer needed, and serve a client's forced scale-down request."""
        forced_sids = list(self.redis.smembers(RELEASE_KEY))
        forced = bool(self.redis.exists(SCALEDOWN_KEY))
        # Pools being built as this pass starts. A build thread registers its
        # pool as ready a moment before it leaves in_flight, so this one
        # snapshot decides both what is skipped now and whether a forced
        # scale-down has to wait for another pass.
        building = set(self.in_flight)
        released: dict[int, list[str]] = {}
        if forced_sids:
            released = self.release_sessions(forced_sids, "released on request")
            self.redis.srem(RELEASE_KEY, *forced_sids)
        now = time.time()
        seen = self.redis.hgetall(LAST_SEEN_KEY)
        dirty = {int(x) for x in self.redis.smembers(DIRTY_KEY) if x.isdigit()}
        pools = {}
        for n in sorted(int(x) for x in self.redis.smembers(READY_KEY)):
            if n in building:
                continue
            owned = bool(self.redis.scard(OWNER_PREFIX + str(n)))
            if owned and n not in dirty:
                self.redis.sadd(DIRTY_KEY, n)
                dirty.add(n)
            if str(n) not in seen:   # adopted after a restart: idle from now on
                self.redis.hset(LAST_SEEN_KEY, str(n), f"{now:.3f}")
                seen[str(n)] = str(now)
            pools[n] = {"owned": owned, "last_seen": float(seen[str(n)]), "dirty": n in dirty}
        release, destroy = pl.scaledown_plan(pools, STATIC_COUNT, spares, now, IDLE_TIMEOUT_S,
                                             forced=forced)
        for n in release:
            self.release_sessions(self.redis.smembers(OWNER_PREFIX + str(n)),
                                  f"idle for {now - pools[n]['last_seen']:.0f} s", pool=n)
            if n not in destroy:
                self.hand_off_or_free(n)
        for n in destroy:
            started = time.time()
            idle = round(now - pools[n]["last_seen"], 3)
            self.destroy(n)
            self.event("scaledown", pool=n, idle=idle,
                       forced=not (IDLE_TIMEOUT_S > 0 and idle >= IDLE_TIMEOUT_S),
                       seconds=round(time.time() - started, 3), mem_mb=POOL_MEM_MB, cpus=POOL_CPUS)
        # Pools given up on request that stay: back to the free set (or to a
        # session waiting for a pool).
        for n in released:
            if n in pools and n not in destroy and not self.redis.scard(OWNER_PREFIX + str(n)):
                self.hand_off_or_free(n)
        if not forced:
            self.forced_removed = []
            return
        removed = getattr(self, "forced_removed", []) + destroy
        if building:
            # A pool still being built (a spare started before the request)
            # would land after "done" and stay until the idle timeout: keep
            # the request open, no new spares meanwhile (see reconcile), and
            # remove it on the pass after it is registered.
            self.forced_removed = removed
            log(f"forced scale-down: waiting for pool(s) {sorted(building)} "
                "still being built")
            return
        self.forced_removed = []
        ready = self.redis.scard(READY_KEY)
        self.redis.delete(SCALEDOWN_KEY)
        self.event("scaledown_done", removed=removed, pools=ready,
                   reserved_mb=ready * POOL_MEM_MB, reserved_cpus=ready * POOL_CPUS)
        log(f"forced scale-down done: removed {removed or 'nothing'}, {ready} pool(s) left")

    def reserve(self) -> int:
        """Extra unowned pools a client asked for (RESERVE_KEY), 0 if none."""
        v = self.redis.get(RESERVE_KEY)
        return max(0, min(MAX_POOLS, int(v))) if v and v.isdigit() else 0

    def set_capped(self, reason: str) -> None:
        """Publish (or clear) the cap and log each transition."""
        if reason:
            self.redis.set(CAPPED_KEY, reason, ex=int(POLL_SECONDS * 6))
        else:
            self.redis.delete(CAPPED_KEY)
        if reason and not self.capped_reason:
            self.event("capped", reason=reason)
            log(f"growth capped: {reason}")
        elif self.capped_reason and not reason:
            self.event("uncapped")
        self.capped_reason = reason

    def reconcile(self) -> None:
        self.adopt_static_pools()
        self.adopt_runtime_pools()
        self.remove_dead_pools()
        self.restore_passwords()
        self.publish_health()
        self.release_idle_pools()
        self.drain_wakeups()

        spares = max(SPARES, self.reserve())
        self.scale_down(spares)
        if self.redis.exists(SCALEDOWN_KEY):
            # A forced scale-down is still finishing: build only for sessions
            # waiting for a pool, no spares it would then have to remove.
            spares = 0

        ready = {int(x) for x in self.redis.smembers(READY_KEY)}
        free = self.redis.zcard(FREE_KEY)
        waiting = self.prune_waiting()
        in_flight = len(self.in_flight)
        # Compose pools still starting count as on their way, like a build.
        coming = sum(1 for n in range(1, STATIC_COUNT + 1)
                     if n not in ready and self.static_pool_pending(n))
        pools = self.all_pools(ready)
        room, reason = pl.budget_room(len(pools), POOL_MEM_MB, POOL_CPUS,
                                      MAX_MEMORY_MB, MAX_CPUS, MAX_POOLS)
        start = pl.pools_to_start(free, in_flight + coming, waiting, spares, room,
                                  PARALLEL_BUILDS + coming)
        if not reason and start > 0:
            ok, reason = self.can_grow()
        self.redis.set(STATUS_KEY, json.dumps({
            "at": round(time.time(), 3), "pools": len(pools), "ready": len(ready),
            "free": free, "waiting": waiting, "room": room, "spares": spares,
            # A copy: build threads remove their entry when they finish.
            "building": {str(n): round(t, 3) for n, t in dict(self.build_started).items()},
            "max_pools": MAX_POOLS, "max_memory_mb": MAX_MEMORY_MB, "max_cpus": MAX_CPUS,
            "mem_per_pool": POOL_MEM_MB, "cpus_per_pool": POOL_CPUS,
            "parallel": PARALLEL_BUILDS, "idle_timeout": IDLE_TIMEOUT_S,
            "capped": reason}), ex=int(POLL_SECONDS * 6))
        self.set_capped(reason)
        self._export_state(pools, ready, free, waiting, room, reason)
        if reason:
            # The resource limit is reached: the router now assigns every new
            # session round-robin for good. Sessions already waiting keep their
            # borrowed pool, except as many as pools are still being built.
            dropped = self.redis.zrange(WAITING_KEY, in_flight, -1)
            if dropped:
                self.redis.zrem(WAITING_KEY, *dropped)
                self.redis.hdel(WAITING_SEEN_KEY, *dropped)
                self.event("dropped_waiting", sessions=dropped, reason=reason)
            return
        if start <= 0 or time.time() < self.backoff_until:
            return
        if waiting:
            log(f"{waiting} session(s) waiting for a pool of their own; "
                f"building {start} more ({in_flight} already building, room for {room})")
        # Builds started now are credited to waiting sessions unless a free pool
        # or a build ALREADY started for a waiter covers them; an in-flight
        # spare doesn't (it was meant for the next user, and crediting it
        # to the waiter labelled a build for a waiting session as a "spare").
        waiter_builds = sum(1 for r in self.build_reasons.values() if r == "waiting session")
        for_waiting = max(0, waiting - free - waiter_builds)
        taken = set(pools)
        for i in range(start):
            n = pl.next_pool_number(taken, STATIC_COUNT)
            taken.add(n)
            self.start_build(n, "waiting session" if i < for_waiting
                             else ("reserve" if spares > SPARES else "spare"))

    def _export_state(self, pools, ready, free, waiting, room, reason) -> None:
        """Push one pool-state snapshot to the SIEM feed (throttled inside the
        exporter). A no-op unless POOL_STATE_EXPORT_DIR is set, and it never
        raises -- shipping state must not break the reconcile loop."""
        if not self.exporter.enabled:
            return
        try:
            building = len(self.build_started)
            capped = bool(reason)
            state = ("capped" if capped else "scaling up" if building
                     else "sessions waiting" if waiting else "steady")
            try:
                mem, load1, cpus, disk = self.host_stats()
            except Exception:  # noqa: BLE001 -- ship the pool view without host figures
                mem = load1 = disk = cpus = None
            self.exporter.snapshot({
                "manager_alive": True,
                "pools": len(pools), "ready": len(ready), "free": free,
                "waiting": waiting, "building": building, "room": room,
                "spares": max(SPARES, self.reserve()),
                "max_pools": MAX_POOLS, "capped": capped, "capped_reason": reason or "",
                "state": state,
                "host_mem_available_mb": round(mem, 1) if mem is not None else None,
                "host_load1": round(load1, 2) if load1 is not None else None,
                "host_cpus": cpus,
                "host_free_disk_gb": round(disk, 1) if disk is not None else None,
                "mem_per_pool_mb": POOL_MEM_MB, "cpus_per_pool": POOL_CPUS,
                "max_memory_mb": MAX_MEMORY_MB, "max_cpus": MAX_CPUS,
                "parallel": PARALLEL_BUILDS, "idle_timeout": IDLE_TIMEOUT_S})
        except Exception as e:  # noqa: BLE001
            log(f"pool state export failed: {e}")

    def run(self) -> None:
        log(f"started (project {PROJECT}, mode {MODE}, spares {SPARES}, max pools {MAX_POOLS}, "
            f"budget {MAX_MEMORY_MB:g} MB / {MAX_CPUS:g} CPUs (0 = none), "
            f"{POOL_MEM_MB} MB / {POOL_CPUS:g} CPUs per pool, {PARALLEL_BUILDS} parallel builds, "
            f"idle timeout {IDLE_TIMEOUT_S:g} s (0 = never)"
            + (", fast clone ON" if FAST_CLONE else "")
            + (", pool template ON" if USE_TEMPLATE else "") + ")")
        try:
            self.remove_partial_pools()
        except Exception as e:  # noqa: BLE001
            log(f"removing half-built pools failed: {e}")
        if USE_TEMPLATE:
            # Pre-build the template now (in the background, so adopting the
            # compose pools is not held up) -- then even the first scale-up
            # copies it instead of waiting out a dump from production.
            threading.Thread(target=self._prebuild_template, daemon=True).start()
        while True:
            try:
                self.reconcile()
            except Exception as e:  # noqa: BLE001
                log(f"reconcile error: {e}")
            time.sleep(POLL_SECONDS)

    def _prebuild_template(self) -> None:
        """Startup helper: build the template once, non-fatally. If it fails
        (e.g. production not up yet), pools clone from production until a later
        build succeeds."""
        try:
            self.ensure_template()
        except Exception as e:  # noqa: BLE001
            log(f"pool template pre-build failed ({e}); pools will clone from production")


# Hands a newly ready (or newly idle) pool to the session that has waited
# longest for one of its own: the session's assignment moves from the pool it
# borrowed to this one (TTL kept), and the borrowed pool goes back to the free
# set if nobody else owns it. Sessions whose assignment expired are dropped;
# sessions whose client sent nothing for POOL_WAITING_ACTIVE_SECONDS are
# skipped (they keep their place in the queue, and get a pool once active).
# Returns {session id, waiting since (epoch s), borrowed pool}, or nil.
# With nobody waiting the pool becomes free. Atomic, so pool_router's
# ASSIGN_SCRIPT never sees a half-moved session.
#   KEYS: waiting ZSET, free ZSET, ready SET
#   ARGV: pool number, session key prefix, owner key prefix
HANDOFF_SCRIPT = r"""
local n = ARGV[1]
local now, active = tonumber(ARGV[4]), tonumber(ARGV[5])
for _, sid in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
  local skey = ARGV[2] .. sid
  local old = redis.call('GET', skey)
  local seen = tonumber(redis.call('HGET', KEYS[4], sid))
  if not old then
    redis.call('ZREM', KEYS[1], sid)          -- assignment expired: forget it
    redis.call('HDEL', KEYS[4], sid)
  elseif seen == nil or now - seen <= active then
    local since = redis.call('ZSCORE', KEYS[1], sid)
    redis.call('ZREM', KEYS[1], sid)
    redis.call('HDEL', KEYS[4], sid)
    if old ~= n then
      local ttl = redis.call('TTL', skey)
      redis.call('SET', skey, n)
      if ttl > 0 then redis.call('EXPIRE', skey, ttl) end
      redis.call('SREM', ARGV[3] .. old, sid)
      if redis.call('SCARD', ARGV[3] .. old) == 0 and redis.call('SISMEMBER', KEYS[3], old) == 1 then
        redis.call('ZADD', KEYS[2], 'NX', tonumber(old), old)
      end
    end
    redis.call('SADD', ARGV[3] .. n, sid)
    redis.call('ZREM', KEYS[2], n)
    return {sid, since, old}
  end
  -- else: its client has gone quiet; it keeps its place but not this pool
end
redis.call('ZADD', KEYS[2], 'NX', tonumber(n), n)
return false
"""

# Same steps as honeypot_db_init in docker-compose.db-proxy.yml, for one database.
# MYSQL_PASSWORD is production's (read side only), HP_PASSWORD the honeypot's.
CLONE_SCRIPT = r"""
set -e
wait_for() {
  TRIES=0
  until mysqladmin ping -h"$1" -u"$MYSQL_USER" -p"$2" 2>/dev/null | grep -q 'mysqld is alive'; do
    TRIES=$((TRIES+1)); [ "$TRIES" -ge 90 ] && { echo "$1 never became reachable"; exit 1; }
    sleep 2
  done
}
wait_for "$PROD" "$MYSQL_PASSWORD"; wait_for "$HP" "$HP_PASSWORD"
HAS_SCHEMA=$(mysql --local-infile=0 -h"$HP" -u"$MYSQL_USER" -p"$HP_PASSWORD" -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$MYSQL_DATABASE' AND table_name='wp_options'" 2>/dev/null || echo 0)
# --default-character-set=binary on both ends of the pipe transfers stored
# bytes verbatim. Without it the dump/restore round-trips through the client's
# connection charset and re-encodes multibyte bytes in PHP-serialized postmeta
# (WooCommerce _product_attributes: · = C2 B7 -> C3 82 C2 B7), breaking the
# byte-length prefix (s:16:) so unserialize() fails -- no variation dropdowns,
# "Add to cart" blocked. Mirrors replicate_content_to_honeypot.sh.
if [ "$HAS_SCHEMA" = 0 ]; then
  mysqldump -h"$PROD" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" --default-character-set=binary --single-transaction --no-tablespaces --skip-add-locks "$MYSQL_DATABASE" \
    | mysql --local-infile=0 -h"$HP" -u"$MYSQL_USER" -p"$HP_PASSWORD" --default-character-set=binary "$MYSQL_DATABASE"
fi
for m in $(ls /migrations/*.sql 2>/dev/null | sort); do
  mysql --local-infile=0 -h"$HP" -u"$MYSQL_USER" -p"$HP_PASSWORD" --force "$MYSQL_DATABASE" < "$m" || echo "  (non-zero from $m, continuing)"
done
# Production's own site name (see honeypot_db_init): a renamed honeypot gave
# itself away to every diverted user.
mysqldump -h"$PROD" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" --default-character-set=binary --no-create-info --replace --skip-add-locks \
  --no-tablespaces --skip-triggers --where="option_name='blogname'" "$MYSQL_DATABASE" wp_options \
  | mysql --local-infile=0 -h"$HP" -u"$MYSQL_USER" -p"$HP_PASSWORD" --default-character-set=binary "$MYSQL_DATABASE" || true
"""

MIGRATE_SCRIPT = r"""
set -u
for i in $(seq 1 60); do
  mysqladmin ping -h"$DB_HOST" -u"$DB_USER" -p"$DB_PASSWORD" 2>&1 | grep -q 'mysqld is alive' && break
  sleep 2
done
failed=0
for f in $(ls /migrations/*.sql | sort); do
  if [ "$(basename "$f")" = 01_clean-honeypot-data.sql ]; then
    mysql --local-infile=0 -h"$DB_HOST" -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" --force < "$f" 2>/dev/null
  else
    mysql --local-infile=0 -h"$DB_HOST" -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" --force < "$f" || failed=1
  fi
done
exit $failed
"""

# Same start-up as honeypot_eshop_N in docker-compose.yml: remap www-data to the
# volume's owner, then run apache.
WP_START_SCRIPT = """
HOST_UID=$(stat -c '%u' /var/www/html)
HOST_GID=$(stat -c '%g' /var/www/html)
usermod -u "$HOST_UID" www-data
groupmod -g "$HOST_GID" www-data
chown -R www-data:www-data /var/www/html/wp-content
exec apache2-foreground
"""

if __name__ == "__main__":
    Manager().run()
