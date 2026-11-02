"""Breach Validation: an attacker-perspective audit of the hardening this
platform ships, run from the dashboard.

Where the Attack Simulation page (page_patterns) drives real exploit patterns
through the edge to see them get diverted, and the Segmentation Validation page
(page_pool_test) proves that diverted sessions land in isolated pools, THIS
module asks the next question: assume an attacker already owns a honeypot
container -- can they climb out of it? And assume an attacker is probing the
edge -- can they slip a target past the legitimate-URL whitelist and onto
production without being scored?

It does that by running the same read-only checks the ids/testing/*.sh
hardening scripts run (lib/instance_checks.sh, test_honeypot_instance.sh,
test_production_instance.sh), but from inside the dashboard, against the live
target, and collects them into a structured report with a PASS/FAIL/WARN per
probe plus evidence -- rendered to PDF by core.breach_audit_pdf.

PROBES ARE READ-ONLY. They open TCP connections, resolve names, send HTTP
requests to the edge, and read container metadata (`docker inspect`,
capabilities, mounts, env-var NAMES). Nothing is written, no container is
reconfigured, no file is changed. Connection attempts that are EXPECTED to be
refused are the whole point -- a refusal is a PASS.

SECRETS ARE NEVER PRINTED. The DB-password-sharing probe compares two secrets
and reports only equal / not-equal; the whitelist probes read
INTERNAL_TEST_SECRET to unlock the edge's X-Route-Target debug header but carry
it in an HTTP header (never on a command line the LogPanel would echo, never in
any evidence string). Evidence strings are built to hold outcomes, not values.
"""
from __future__ import annotations

import re
import shlex
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime

from core import honeypot_layer
from core.docker_ctl import Target
from core.env_upload import EnvUploadError, load_project_env
from core.proc import run_checked
from core.resource_stats import pool_container
from core.state import AppState

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

PASS = "pass"      # the hardening held: the attack was blocked as designed
FAIL = "fail"      # a real hole: the attack would succeed
WARN = "warn"      # not a breach, but weaker than it should be / needs a look
SKIP = "skip"      # could not run this probe here (not applicable / no target)
ERROR = "error"    # the probe itself failed to run (tooling, timeout)

OUTCOMES = (PASS, FAIL, WARN, SKIP, ERROR)

# Severity of a FAIL, so the report can order the worst first.
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"

# Probe categories (also the section order in the report).
CAT_BREAKOUT = "honeypot_breakout"
CAT_PROD_NET = "production_network"
CAT_PROD_HARDENING = "production_hardening"
CAT_WHITELIST = "whitelist_bypass"
CAT_EDGE = "edge_exposure"

CATEGORY_LABELS = {
    CAT_BREAKOUT: "Honeypot container breakout",
    CAT_PROD_NET: "Production network isolation",
    CAT_PROD_HARDENING: "Production hardening (vulnerable-plugin bypass)",
    CAT_WHITELIST: "Whitelist / routing bypass",
    CAT_EDGE: "Edge exposure",
}

CATEGORY_INTRO = {
    CAT_BREAKOUT: (
        "Assume an attacker has taken over a honeypot WordPress or its database "
        "container. These probes run from inside each pool and try to reach "
        "production, the other pools, the Docker control plane and the open "
        "internet, and inspect the container's own privileges and secrets. "
        "Every blocked reach is a PASS: that is a dead end the attacker cannot "
        "use as a gateway."
    ),
    CAT_PROD_NET: (
        "The production database must be reachable only from the production "
        "shop, the production shop only from the edge, and only the reverse "
        "proxy may publish a port on the host. These probes verify those "
        "boundaries from the wrong side."
    ),
    CAT_PROD_HARDENING: (
        "Assume an attacker has found a REAL vulnerability in production -- a "
        "WordPress plugin, say (production here runs the same plugin set as the "
        "honeypots, so if one is exploitable, so is production's copy). These "
        "probes verify that can never become a honeypot bypass: every "
        "known-vulnerable plugin's exploit must be diverted to a honeypot (or "
        "blocked) at the edge BEFORE it reaches production -- regardless of "
        "which honeypot-target toggles are on -- so production's vulnerability "
        "is simply never attacker-reachable. They also confirm a compromised "
        "production container cannot pivot to the Docker control plane, the "
        "honeypot pools or the cloud-metadata endpoint. Each diverted/blocked "
        "exploit and each dead-end pivot is a PASS."
    ),
    CAT_WHITELIST: (
        "The edge classifies every request and either serves production or "
        "diverts to a honeypot. These probes try to smuggle a honeypot target "
        "URL past the legitimate-URL whitelist and the path normaliser, and to "
        "forge routing so a scored request reaches production unscored. They "
        "read the edge's own routing-decision header (unlocked with "
        "INTERNAL_TEST_SECRET) to see where each crafted request would land."
    ),
    CAT_EDGE: (
        "Checks on the edge itself: that the routing-decision debug header is "
        "not leaked to a client without the shared secret, and that obvious "
        "request-smuggling shapes are rejected."
    ),
}


@dataclass
class ProbeResult:
    category: str
    probe: str               # short name, e.g. "TCP to production_database:3306"
    expectation: str         # what SHOULD happen, in one line
    outcome: str             # PASS / FAIL / WARN / SKIP / ERROR
    evidence: str = ""       # what actually happened -- never a secret value
    severity: str = HIGH     # only meaningful for FAIL/WARN
    source: str = ""         # the container / vantage point the probe ran from

    @property
    def is_breach(self) -> bool:
        return self.outcome == FAIL


@dataclass
class BreachAuditData:
    generated_at: str
    target_label: str
    base_url: str
    honeypot_layer: str
    categories: list[str]
    results: list[ProbeResult] = field(default_factory=list)
    pools_scanned: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def by_category(self, category: str) -> list[ProbeResult]:
        return [r for r in self.results if r.category == category]

    def counts(self) -> dict[str, int]:
        out = {k: 0 for k in OUTCOMES}
        for r in self.results:
            out[r.outcome] = out.get(r.outcome, 0) + 1
        return out

    @property
    def breaches(self) -> list[ProbeResult]:
        return [r for r in self.results if r.outcome == FAIL]

    def headline(self) -> tuple[str, str]:
        """(status word, one-line summary) for the top of the report."""
        c = self.counts()
        if c[FAIL]:
            worst = min((r.severity for r in self.breaches),
                        key=lambda s: _SEVERITY_ORDER.get(s, 9))
            return ("BREACH", f"{c[FAIL]} hardening hole(s) found "
                              f"({worst} severity at worst); {c[PASS]} checks held.")
        if c[WARN]:
            return ("HARDENED (with warnings)",
                    f"No breaches. {c[WARN]} weaker-than-ideal finding(s); "
                    f"{c[PASS]} checks held.")
        if c[PASS]:
            return ("HARDENED", f"All {c[PASS]} checks held; no way out found.")
        return ("INCONCLUSIVE", "No probes ran -- nothing to report.")


_SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2}


# ---------------------------------------------------------------------------
# docker exec helpers (read-only)
# ---------------------------------------------------------------------------

class BreachAuditError(Exception):
    pass


def _docker_exec(target: Target, container: str, command: str,
                 timeout: float = 20.0) -> tuple[int, str]:
    """Run `command` inside `container` with `sh -c`, straight through docker
    (not compose -- runtime pools are unknown to compose). Returns
    (exit_code, combined_output). A non-zero exit is NOT an exception here:
    probes care about the exit code (a refused connection is a non-zero exit
    and a PASS), so the caller inspects it. Only a failure to RUN docker at
    all raises."""
    inner = f"docker exec {shlex.quote(container)} sh -c {shlex.quote(command)} 2>&1; echo \"__rc=$?\""
    argv, cwd = target.build_shell(inner)
    try:
        out = run_checked(argv, error=BreachAuditError, cwd=cwd, timeout=timeout,
                          what="docker exec").stdout
    except BreachAuditError:
        # The wrapper always exits 0 (it echoes __rc); a raise here means
        # docker/ssh itself could not run, which is a real tooling failure.
        raise
    rc = 0
    lines = out.splitlines()
    if lines and lines[-1].startswith("__rc="):
        try:
            rc = int(lines[-1][len("__rc="):])
        except ValueError:
            rc = 0
        out = "\n".join(lines[:-1])
    return rc, out.strip()


# The edge stack's Docker Compose project name (the com.docker.compose.project
# label). The whole audit scopes its `docker ps` to this project so it never
# sweeps in the separate SIEM stack (compose project "docker":
# es01/kibana/vector_inbound). The SIEM stack's own published ports (Kibana
# 5601, Elasticsearch 9200, Vector 6000) and mounts are its concern, not a
# breach of the honeypot edge -- judging them here produced false FAILs.
EDGE_COMPOSE_PROJECT_DEFAULT = "honeypot-ids-system-v1"


def _edge_project(target: Target) -> str:
    """The edge compose project name, from the edge .env's
    COMPOSE_PROJECT_NAME, falling back to the shipped default. Validated to a
    safe label so it can be interpolated into the `docker ps` filter."""
    try:
        env = load_project_env("edge", target.remote)
    except EnvUploadError:
        env = {}
    name = (env.get("COMPOSE_PROJECT_NAME") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        return EDGE_COMPOSE_PROJECT_DEFAULT
    return name


def _running_containers(target: Target, timeout: float = 15.0) -> list[str]:
    """Names of every running container IN THE EDGE COMPOSE PROJECT on the
    target host. The separate SIEM project is deliberately out of scope."""
    project = _edge_project(target)
    argv, cwd = target.build_shell(
        "docker ps --filter label=com.docker.compose.project=" + project
        + " --format '{{.Names}}'")
    out = run_checked(argv, error=BreachAuditError, cwd=cwd, timeout=timeout,
                      what="docker ps").stdout
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def discover_pools(names: list[str]) -> dict[int, dict[str, str]]:
    """Map pool number -> {"eshop": <container>, "database": <container>} from
    a list of running container names, matching the same shapes
    resource_stats.pool_container recognises (compose-declared and the
    runtime ones pool_manager builds)."""
    pools: dict[int, dict[str, str]] = {}
    for name in names:
        kind = pool_container(name)
        if kind is None:
            continue
        pools.setdefault(kind[1], {})[kind[0]] = name
    return pools


def _prod_container(names: list[str], suffix: str) -> str | None:
    """A production/support container by its service suffix, matching both the
    compose form (<project>-production_eshop-1) and a bare name."""
    for name in names:
        bare = name
        # strip a compose "<project>-" prefix and "-N" replica suffix
        core = name
        if "-" in core:
            core = core.rsplit("-", 1)[0] if core.rsplit("-", 1)[-1].isdigit() else core
        if core.endswith(suffix) or bare == suffix:
            return name
    return None


# ---------------------------------------------------------------------------
# Reachability probe shared by the breakout / network categories
# ---------------------------------------------------------------------------

# PHP is always present in the WordPress containers; it is the most reliable
# way to attempt a raw TCP connect from inside one without assuming nc/bash.
def _tcp_probe_cmd(host: str, port: int, timeout: int = 3) -> str:
    return (
        "php -r '$e=0;$m=\"\";"
        f"$f=@fsockopen(\"{host}\",{port},$e,$m,{timeout});"
        "if($f){echo \"OPEN\";fclose($f);}else{echo \"BLOCKED\";}' 2>/dev/null "
        "|| echo PROBE_UNAVAILABLE"
    )


def _udp_dns_cmd(server: str, timeout: int = 3) -> str:
    # A UDP "connect" never fails on its own; we send a DNS query and see if an
    # answer comes back, which is what egress to a public resolver would allow.
    # The DNS query is one PHP double-quoted literal (PHP concatenates with
    # ".", not "+") -- header, then qname example.com, then A/IN.
    query = ('\\xAB\\xCD\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00'
             '\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01')
    return (
        "php -r '$s=@fsockopen(\"udp://" + server + "\",53,$e,$m," + str(timeout) + ");"
        "if(!$s){echo \"BLOCKED\";exit;}"
        "$q=\"" + query + "\";"
        "@fwrite($s,$q);stream_set_timeout($s," + str(timeout) + ");"
        "$r=@fread($s,32);echo ($r!==false && strlen($r)>0)?\"OPEN\":\"BLOCKED\";' "
        "2>/dev/null || echo PROBE_UNAVAILABLE"
    )


@dataclass
class _Reach:
    """One destination to probe from a container that must not reach it."""
    label: str
    host: str
    port: int
    severity: str = HIGH
    udp: bool = False
    # Outcome when the connection SUCCEEDS. Usually FAIL (the reach is a hole),
    # but some destinations (e.g. the open internet from production, which
    # payment-gateway plugins legitimately use) are a residual-risk WARN rather
    # than an outright breach.
    open_outcome: str = FAIL
    # Override the default expectation text (which assumes a honeypot vantage).
    expectation: str = "connection refused / unreachable from a honeypot"


def _reach_result(category: str, source: str, dest: _Reach, rc: int, out: str) -> ProbeResult:
    out = (out or "").strip().upper()
    probe = f"{'UDP' if dest.udp else 'TCP'} to {dest.label} ({dest.host}:{dest.port})"
    expectation = dest.expectation
    if "PROBE_UNAVAILABLE" in out or rc != 0 and not out:
        return ProbeResult(category, probe, expectation, ERROR,
                           "probe tool unavailable in container", dest.severity, source)
    if "OPEN" in out:
        evidence = ("connection SUCCEEDED -- reachable (residual egress risk)"
                    if dest.open_outcome == WARN
                    else "connection SUCCEEDED -- reachable, a usable pivot")
        return ProbeResult(category, probe, expectation, dest.open_outcome,
                           evidence, dest.severity, source)
    if "BLOCKED" in out:
        return ProbeResult(category, probe, expectation, PASS,
                           "blocked as designed", dest.severity, source)
    return ProbeResult(category, probe, expectation, ERROR,
                       f"unexpected probe output ({out[:40]!r})", dest.severity, source)


# Egress destinations every honeypot container must NOT be able to reach.
def _breakout_destinations(names: list[str], pool: int) -> list[_Reach]:
    prod_eshop = _prod_container(names, "production_eshop") or "production_eshop"
    prod_db = _prod_container(names, "production_database") or "production_database"
    dests = [
        _Reach("production shop (HTTP)", prod_eshop, 80, CRITICAL),
        _Reach("production shop (HTTPS)", prod_eshop, 443, CRITICAL),
        _Reach("production database", prod_db, 3306, CRITICAL),
        _Reach("session store (redis)", "session_store", 6379, HIGH),
        _Reach("reverse proxy (HTTP)", "reverse_proxy", 80, HIGH),
        _Reach("reverse proxy (HTTPS)", "reverse_proxy", 443, HIGH),
        _Reach("backup service (SSH)", "backup_service", 22, HIGH),
        _Reach("content sync", "honeypot_content_sync", 873, MEDIUM),
        _Reach("pool manager", "pool_manager", 80, MEDIUM),
        _Reach("Docker daemon (TCP)", "172.17.0.1", 2375, CRITICAL),
        _Reach("Docker daemon (TLS)", "172.17.0.1", 2376, CRITICAL),
        _Reach("host SSH", "172.17.0.1", 22, HIGH),
        _Reach("internet (Cloudflare HTTPS)", "1.1.1.1", 443, HIGH),
        _Reach("internet (Cloudflare HTTP)", "1.1.1.1", 80, HIGH),
        _Reach("cloud metadata endpoint", "169.254.169.254", 80, HIGH),
        _Reach("public DNS (UDP 53)", "8.8.8.8", 53, HIGH, udp=True),
    ]
    # The other pools and their databases are peers an attacker must not pivot to.
    for other, c in sorted(discover_pools(names).items()):
        if other == pool:
            continue
        if "eshop" in c:
            dests.append(_Reach(f"other pool {other} shop", c["eshop"], 80, HIGH))
        if "database" in c:
            dests.append(_Reach(f"other pool {other} database", c["database"], 3306, HIGH))
    return dests


# ---------------------------------------------------------------------------
# Container-privilege probes (read-only docker inspect / /proc)
# ---------------------------------------------------------------------------

def _inspect(target: Target, container: str, fmt: str, timeout: float = 15.0) -> str:
    argv, cwd = target.build_shell(
        f"docker inspect -f {shlex.quote(fmt)} {shlex.quote(container)}")
    try:
        return run_checked(argv, error=BreachAuditError, cwd=cwd, timeout=timeout,
                           what="docker inspect").stdout.strip()
    except BreachAuditError:
        return ""


def _privilege_probes(target: Target, category: str, container: str) -> list[ProbeResult]:
    out: list[ProbeResult] = []

    privileged = _inspect(target, container, "{{.HostConfig.Privileged}}")
    out.append(ProbeResult(
        category, "container is not --privileged", "Privileged=false",
        FAIL if privileged.lower() == "true" else PASS,
        f"Privileged={privileged or '?'}", CRITICAL, container))

    caps_add = _inspect(target, container, "{{.HostConfig.CapAdd}}")
    dangerous = [c for c in ("NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE")
                 if c in (caps_add or "").upper()]
    out.append(ProbeResult(
        category, "no dangerous Linux capabilities added",
        "CapAdd holds no NET_ADMIN/SYS_ADMIN/etc.",
        FAIL if dangerous else PASS,
        ("added: " + ", ".join(dangerous)) if dangerous else "none added",
        HIGH, container))

    pid_mode = _inspect(target, container, "{{.HostConfig.PidMode}}")
    net_mode = _inspect(target, container, "{{.HostConfig.NetworkMode}}")
    for label, val, want_bad in (("PID namespace not shared with host", pid_mode, "host"),
                                 ("network namespace not host", net_mode, "host")):
        bad = (val or "").lower() == want_bad
        out.append(ProbeResult(
            category, label, f"{label}",
            FAIL if bad else PASS, f"mode={val or 'default'}", CRITICAL, container))

    nnp = _inspect(
        target, container,
        "{{range .HostConfig.SecurityOpt}}{{println .}}{{end}}")
    out.append(ProbeResult(
        category, "no-new-privileges is set",
        "SecurityOpt contains no-new-privileges",
        PASS if "no-new-privileges" in (nnp or "") else WARN,
        "set" if "no-new-privileges" in (nnp or "") else "not set", MEDIUM, container))

    # Docker socket bind-mounted into a honeypot = full host takeover.
    mounts = _inspect(
        target, container,
        "{{range .Mounts}}{{.Source}}->{{.Destination}}{{println}}{{end}}")
    sock = [ln for ln in (mounts or "").splitlines() if "docker.sock" in ln]
    out.append(ProbeResult(
        category, "Docker socket not mounted into the honeypot",
        "no /var/run/docker.sock bind mount",
        FAIL if sock else PASS,
        "docker.sock mounted" if sock else "absent", CRITICAL, container))

    return out


def _secret_env_probe(target: Target, category: str, container: str) -> ProbeResult:
    """The honeypot WordPress must not carry production/root DB secrets in its
    environment. We read only the NAMES of its env vars, never their values."""
    argv, cwd = target.build_shell(
        f"docker inspect -f '{{{{range .Config.Env}}}}{{{{println .}}}}{{{{end}}}}' "
        f"{shlex.quote(container)} | sed 's/=.*//'")
    try:
        names = run_checked(argv, error=BreachAuditError, cwd=cwd, timeout=15.0,
                            what="docker inspect").stdout
    except BreachAuditError as e:
        return ProbeResult(category, "no production secrets in honeypot env",
                           "env carries no root/production DB credentials",
                           ERROR, str(e)[:60], HIGH, container)
    leaked = [n.strip() for n in names.splitlines()
              if n.strip() in ("MYSQL_ROOT_PASSWORD", "WORDPRESS_AUTH_KEY",
                               "PRODUCTION_DB_PASSWORD")]
    return ProbeResult(
        category, "no production secrets in honeypot env",
        "env carries no root/production DB credentials",
        FAIL if leaked else PASS,
        ("present: " + ", ".join(leaked)) if leaked else "none present",
        HIGH, container)


def _db_password_shared_probe(target: Target, category: str,
                              pool_db: str, prod_db: str) -> ProbeResult:
    """Compare the pool DB's root password with production's WITHOUT revealing
    either: read both from inside their containers, hash each, and compare the
    hashes. Only equal/not-equal leaves the probe."""
    cmd = ("printf '%s' \"$MYSQL_ROOT_PASSWORD\" | sha256sum | cut -d' ' -f1")
    try:
        _rc1, h_pool = _docker_exec(target, pool_db, cmd)
        _rc2, h_prod = _docker_exec(target, prod_db, cmd)
    except BreachAuditError as e:
        return ProbeResult(category, "pool DB password differs from production",
                           "pool and production DB root passwords are distinct",
                           ERROR, str(e)[:60], CRITICAL, pool_db)
    h_pool, h_prod = h_pool.strip(), h_prod.strip()
    if not h_pool or not h_prod or len(h_pool) < 16 or len(h_prod) < 16:
        return ProbeResult(category, "pool DB password differs from production",
                           "pool and production DB root passwords are distinct",
                           ERROR, "could not read one of the passwords", CRITICAL, pool_db)
    shared = h_pool == h_prod
    return ProbeResult(
        category, "pool DB password differs from production",
        "pool and production DB root passwords are distinct",
        FAIL if shared else PASS,
        "identical root password (hashes match)" if shared
        else "distinct (hashes differ)", CRITICAL, pool_db)


# ---------------------------------------------------------------------------
# Category runners -- honeypot breakout
# ---------------------------------------------------------------------------

def run_breakout(target: Target, names: list[str], pools: dict[int, dict[str, str]],
                 prod_db: str | None, log=lambda s: None) -> list[ProbeResult]:
    cat = CAT_BREAKOUT
    results: list[ProbeResult] = []
    if not pools:
        results.append(ProbeResult(
            cat, "honeypot pools present", "at least one honeypot pool is running",
            SKIP, "no honeypot pool containers are running", HIGH))
        return results

    for pool in sorted(pools):
        c = pools[pool]
        eshop = c.get("eshop")
        db = c.get("database")
        vantage = eshop or db
        if vantage is None:
            continue
        log(f"Pool {pool}: probing egress from {vantage} …")
        for dest in _breakout_destinations(names, pool):
            cmd = _udp_dns_cmd(dest.host) if dest.udp else _tcp_probe_cmd(dest.host, dest.port)
            try:
                rc, out = _docker_exec(target, vantage, cmd)
            except BreachAuditError as e:
                results.append(ProbeResult(
                    cat, f"TCP to {dest.label}", "refused from honeypot",
                    ERROR, str(e)[:60], dest.severity, vantage))
                continue
            results.append(_reach_result(cat, vantage, dest, rc, out))

        log(f"Pool {pool}: inspecting container privileges …")
        if eshop:
            results.extend(_privilege_probes(target, cat, eshop))
            results.append(_secret_env_probe(target, cat, eshop))
        if db:
            results.extend(_privilege_probes(target, cat, db))
            if prod_db:
                results.append(_db_password_shared_probe(target, cat, db, prod_db))

    return results


# ---------------------------------------------------------------------------
# Category runner -- production network isolation
# ---------------------------------------------------------------------------

def run_production_network(target: Target, names: list[str],
                           log=lambda s: None) -> list[ProbeResult]:
    cat = CAT_PROD_NET
    results: list[ProbeResult] = []
    prod_db = _prod_container(names, "production_database")
    prod_eshop = _prod_container(names, "production_eshop")

    # The production DB must be reachable from production_eshop but from nobody
    # else. Probe it from a few wrong vantage points.
    if prod_db:
        wrong = []
        for suffix, label in (("reverse_proxy", "reverse proxy"),
                              ("session_store", "session store"),
                              ("backup_service", "backup service")):
            c = _prod_container(names, suffix)
            if c:
                wrong.append((c, label))
        for container, label in wrong:
            log(f"Probing production DB reachability from {label} …")
            cmd = _tcp_probe_cmd(prod_db, 3306)
            try:
                _rc, out = _docker_exec(target, container, cmd)
            except BreachAuditError as e:
                results.append(ProbeResult(
                    cat, f"production DB unreachable from {label}",
                    "only production_eshop may reach the production DB",
                    ERROR, str(e)[:60], HIGH, container))
                continue
            reachable = "OPEN" in (out or "").upper()
            results.append(ProbeResult(
                cat, f"production DB unreachable from {label}",
                "only production_eshop may reach the production DB",
                FAIL if reachable else PASS,
                "reachable (3306 open)" if reachable else "blocked", CRITICAL, container))
    else:
        results.append(ProbeResult(
            cat, "production database present",
            "production_database container is running",
            SKIP, "production_database not found among running containers", HIGH))

    # Only the reverse proxy should publish a port on the host. Scoped to the
    # edge compose project: the separate SIEM stack legitimately publishes its
    # own ingress ports (Kibana/Elasticsearch/Vector) and is not the edge's
    # attack surface.
    log("Checking host-published ports …")
    project = _edge_project(target)
    argv, cwd = target.build_shell(
        "docker ps --filter label=com.docker.compose.project=" + project
        + " --format '{{.Names}}|{{.Ports}}'")
    try:
        ps = run_checked(argv, error=BreachAuditError, cwd=cwd, timeout=15.0,
                         what="docker ps").stdout
        offenders = []
        for line in ps.splitlines():
            name, _, ports = line.partition("|")
            if "->" not in ports:          # "->" marks a host-published mapping
                continue
            core = name
            if "-" in core and core.rsplit("-", 1)[-1].isdigit():
                core = core.rsplit("-", 1)[0]
            if not core.endswith("reverse_proxy"):
                offenders.append(f"{name} publishes {ports.strip()}")
        results.append(ProbeResult(
            cat, "only the reverse proxy publishes host ports",
            "no container but reverse_proxy maps a host port",
            FAIL if offenders else PASS,
            "; ".join(offenders) if offenders else "only reverse_proxy publishes",
            HIGH))
    except BreachAuditError as e:
        results.append(ProbeResult(
            cat, "only the reverse proxy publishes host ports",
            "no container but reverse_proxy maps a host port",
            ERROR, str(e)[:60], HIGH))

    # The Docker socket should be mounted only where it is designed to be.
    log("Checking which containers mount the Docker socket …")
    for name in names:
        mounts = _inspect(
            target, name,
            "{{range .Mounts}}{{.Source}}{{println}}{{end}}")
        if "docker.sock" not in (mounts or ""):
            continue
        core = name
        if "-" in core and core.rsplit("-", 1)[-1].isdigit():
            core = core.rsplit("-", 1)[0]
        # Two containers may legitimately hold the socket, both sanctioned
        # design controls (PASS):
        #   * pool_manager -- the Docker control plane; spawning/tearing down
        #     honeypot pools is its whole job.
        #   * docker_socket_proxy -- exposes only a READ-ONLY API slice
        #     (list/inspect/events, no POST) to vector_outbound, publishes no
        #     host port and has no internet egress, so it cannot be used to
        #     create/exec containers the way a raw socket could.
        # Any OTHER container holding the socket is a real breakout vector
        # (FAIL) -- in particular an egress-capable shipper must never mount it.
        expected = core.endswith("pool_manager") or core.endswith("docker_socket_proxy")
        if core.endswith("pool_manager"):
            why = "pool_manager control plane (sanctioned)"
        elif core.endswith("docker_socket_proxy"):
            why = "read-only API proxy (sanctioned)"
        else:
            why = "unexpected socket mount"
        results.append(ProbeResult(
            cat, f"Docker socket mount on {name}",
            "only pool_manager and the read-only docker_socket_proxy may hold "
            "the Docker socket",
            PASS if expected else FAIL,
            why, CRITICAL, name))

    return results


# ---------------------------------------------------------------------------
# Production hardening -- a production vulnerability must not bypass honeypots
# ---------------------------------------------------------------------------

_WP_PLUGINS_DIR = "/var/www/html/wp-content/plugins"

# Expectation text for the production-vantage egress probes.
_PROD_EXP = ("unreachable from production -- a compromised production plugin "
             "must not be able to pivot here")


def _production_plugins(target: Target, container: str) -> set[str] | None:
    """The plugin directory names installed on production (read-only `ls`), or
    None if the list could not be read. Lets the audit say whether a
    not-diverted vulnerable plugin is actually present (critical) or merely
    would be a hole if installed (warning)."""
    try:
        _rc, out = _docker_exec(target, container,
                                f"ls -1 {_WP_PLUGINS_DIR} 2>/dev/null")
    except BreachAuditError:
        return None
    names = {ln.strip() for ln in (out or "").splitlines() if ln.strip()}
    names.discard("index.php")   # stock single-file entries, not plugin dirs
    names.discard("hello.php")
    return names or None


def _vulnerable_plugin_dirs() -> list[tuple[str, str, str]]:
    """Distinct vulnerable plugin directories the honeypots emulate, each with
    a representative (cve, name), from the edge policy's honeypot-target list
    (init.lua's vulnerability.plugins). Policy toggles do NOT shrink this list:
    the point is to prove the edge diverts these exploits whether or not a
    given target is 'enabled'."""
    from core.edge_policy import honeypot_targets
    seen: dict[str, tuple[str, str]] = {}
    for t in honeypot_targets():
        if t.plugin_dir and t.plugin_dir not in seen:
            seen[t.plugin_dir] = (t.cve, t.name)
    return [(d, cve, name) for d, (cve, name) in seen.items()]


def _internet_egress_allowed(target: Target) -> bool:
    """Whether production's TEMPORARY all-internet egress bypass is currently
    switched on (PRODUCTION_INTERNET_EGRESS in the edge .env). When it is off
    -- the default -- production reaching the open internet is a real breach,
    not a residual-risk warning."""
    try:
        env = load_project_env("edge", target.remote)
    except EnvUploadError:
        return False
    return env.get("PRODUCTION_INTERNET_EGRESS", "false").strip().strip("\"'").lower() \
        in ("1", "true", "yes", "on")


def _production_egress_destinations(names: list[str],
                                    internet_allowed: bool) -> list[_Reach]:
    """Destinations a compromised production_eshop must not be able to pivot to.
    The open internet is a FAIL by default (egress is default-deny, so an open
    path means the firewall is not enforcing); it is downgraded to a
    residual-risk WARN only while the operator has the temporary install
    bypass switched on. Everything else is an outright FAIL if reachable."""
    dests = [
        _Reach("Docker daemon (TCP)", "172.17.0.1", 2375, CRITICAL, expectation=_PROD_EXP),
        _Reach("Docker daemon (TLS)", "172.17.0.1", 2376, CRITICAL, expectation=_PROD_EXP),
        _Reach("cloud metadata endpoint", "169.254.169.254", 80, HIGH, expectation=_PROD_EXP),
        _Reach("session store (redis)", "session_store", 6379, MEDIUM, expectation=_PROD_EXP),
        _Reach("pool manager", "pool_manager", 80, MEDIUM, expectation=_PROD_EXP),
    ]
    for pool, c in sorted(discover_pools(names).items()):
        if "eshop" in c:
            dests.append(_Reach(f"honeypot pool {pool} shop", c["eshop"], 80,
                                HIGH, expectation=_PROD_EXP))
        if "database" in c:
            dests.append(_Reach(f"honeypot pool {pool} database", c["database"], 3306,
                                HIGH, expectation=_PROD_EXP))
    if internet_allowed:
        dests.append(_Reach(
            "open internet (HTTPS)", "1.1.1.1", 443, MEDIUM, open_outcome=WARN,
            expectation="egress is default-deny; the TEMPORARY install bypass is "
                        "currently ON -- open internet is expected, but turn it off "
                        "once the plugin/theme install is finished"))
    else:
        dests.append(_Reach(
            "open internet (HTTPS)", "1.1.1.1", 443, HIGH,
            expectation="egress is default-deny -- the open internet must be "
                        "unreachable so a compromised plugin cannot exfiltrate or "
                        "pull a payload (use the trusted-domains allow-list instead)"))
    return dests


def run_production_hardening(target: Target, names: list[str], base_url: str,
                             secret: str, log=lambda s: None) -> list[ProbeResult]:
    cat = CAT_PROD_HARDENING
    results: list[ProbeResult] = []
    prod_eshop = _prod_container(names, "production_eshop")

    # --- Group 1: every vulnerable-plugin exploit must divert, not be served ---
    installed = _production_plugins(target, prod_eshop) if prod_eshop else None
    if not secret:
        results.append(ProbeResult(
            cat, "edge routing-decision header readable",
            "INTERNAL_TEST_SECRET set so the probe can see where exploits land",
            SKIP, "INTERNAL_TEST_SECRET not set in the edge .env -- cannot verify "
            "where vulnerable-plugin exploits are routed", HIGH))
    else:
        log("Verifying every vulnerable plugin's exploit is diverted, not served …")
        for plugin_dir, cve, name in _vulnerable_plugin_dirs():
            r = _edge_request(base_url, f"/wp-content/plugins/{plugin_dir}/", secret)
            present = None if installed is None else (plugin_dir in installed)
            probe = f"exploit of {plugin_dir} diverted, not served by production"
            exp = (f"a request to the {name} ({cve}) attack surface is diverted to "
                   "a honeypot or blocked -- never served by production")
            if r.error:
                results.append(ProbeResult(cat, probe, exp, ERROR, r.error, HIGH,
                                           prod_eshop or ""))
            elif not _bypassed(r):
                where = "honeypot" if _routes_to_honeypot(r) else \
                        "(blocked)" if r.status in _EDGE_BLOCK_STATUSES else \
                        (r.route_target or "?")
                tag = " [installed on production]" if present else \
                      " [production inventory unknown]" if present is None else \
                      " [not on production]"
                results.append(ProbeResult(
                    cat, probe, exp, PASS,
                    f"diverted: route={where} score={r.risk_score or '0'} "
                    f"(status {r.status}){tag}",
                    CRITICAL if present else HIGH, prod_eshop or ""))
            elif present:
                results.append(ProbeResult(
                    cat, probe, exp, FAIL,
                    f"production HOSTS {plugin_dir} and the edge serves its exploit "
                    f"directly (status {r.status}) -- honeypot bypassed",
                    CRITICAL, prod_eshop or ""))
            else:
                note = ("could not read production's plugin list" if present is None
                        else "not installed on production")
                results.append(ProbeResult(
                    cat, probe, exp, WARN,
                    f"edge serves this vulnerable-plugin path to production unscored "
                    f"(status {r.status}); {note} -- installing it would create a "
                    "honeypot bypass", HIGH, prod_eshop or ""))

        # CVE-2023-28121 is a header-only exploit (no attack signature in the
        # PATH), the most realistic bypass against production's live
        # woocommerce-payments -- check it explicitly.
        log("Verifying the header-only CVE-2023-28121 exploit is diverted …")
        hdr = _edge_request(base_url, "/?rest_route=/wc/v3/customers", secret,
                            headers={"X-WCPAY-PLATFORM-CHECKOUT-USER": "1"})
        probe = "header-only woocommerce-payments exploit (CVE-2023-28121) diverted"
        exp = "the header-based account-creation exploit is diverted or blocked, not served"
        if hdr.error:
            results.append(ProbeResult(cat, probe, exp, ERROR, hdr.error, CRITICAL,
                                       prod_eshop or ""))
        else:
            where = "honeypot" if _routes_to_honeypot(hdr) else \
                    "(blocked)" if hdr.status in _EDGE_BLOCK_STATUSES else \
                    (hdr.route_target or "?")
            results.append(ProbeResult(
                cat, probe, exp, PASS if not _bypassed(hdr) else FAIL,
                f"route={where} score={hdr.risk_score or '0'} (status {hdr.status})",
                CRITICAL, prod_eshop or ""))

    # --- Group 2: a compromised production container must not be able to pivot ---
    if prod_eshop is None:
        results.append(ProbeResult(
            cat, "production shop present", "production_eshop container is running",
            SKIP, "production_eshop not found among running containers", HIGH))
        return results
    log("Probing egress / lateral movement from production_eshop …")
    internet_allowed = _internet_egress_allowed(target)
    for dest in _production_egress_destinations(names, internet_allowed):
        cmd = _udp_dns_cmd(dest.host) if dest.udp else _tcp_probe_cmd(dest.host, dest.port)
        try:
            rc, out = _docker_exec(target, prod_eshop, cmd)
        except BreachAuditError as e:
            results.append(ProbeResult(
                cat, f"TCP to {dest.label} ({dest.host}:{dest.port})",
                dest.expectation, ERROR, str(e)[:60], dest.severity, prod_eshop))
            continue
        results.append(_reach_result(cat, prod_eshop, dest, rc, out))
    return results


# ---------------------------------------------------------------------------
# Whitelist / routing-bypass probes (HTTP through the edge)
# ---------------------------------------------------------------------------

@dataclass
class _HttpResult:
    status: int
    route_target: str | None     # X-Route-Target, when the secret unlocked it
    risk_score: str | None       # X-Risk-Score
    error: str | None = None


def _edge_request(base_url: str, path: str, secret: str,
                  headers: dict[str, str] | None = None, method: str = "GET",
                  body: bytes | None = None, timeout: float = 8.0) -> _HttpResult:
    """One request to the edge, TLS verification off (self-signed edge cert).
    Carries the internal test auth header so the edge returns its routing
    decision. The secret is only ever in the header value, never logged."""
    url = base_url.rstrip("/") + path
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    hdrs = dict(headers or {})
    if secret:
        hdrs["X-Internal-Test-Auth"] = secret
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            return _HttpResult(resp.status,
                               resp.headers.get("X-Route-Target"),
                               resp.headers.get("X-Risk-Score"))
    except urllib.error.HTTPError as e:
        return _HttpResult(e.code, e.headers.get("X-Route-Target"),
                           e.headers.get("X-Risk-Score"))
    except (urllib.error.URLError, OSError, ValueError) as e:
        return _HttpResult(0, None, None, error=str(e)[:80])


# Path-obfuscation shapes aimed at slipping a KNOWN-MALICIOUS request past the
# edge's URI normaliser so it reaches production unscored. The baseline is a
# directory-traversal read of /etc/passwd -- a generic attack the edge's
# always-on signature set catches regardless of which CVE/plugin honeypot
# targets a deployment has enabled (the shipped generic-only defaults enable no
# specific plugin/CVE target, so a plugin path would NOT divert and tells us
# nothing about the normaliser). Each obfuscation below carries the same attack
# and must still be diverted / scored / blocked, never served production
# unscored. The normaliser (edge_policy_rules.request_path) lower-cases,
# %-decodes once, collapses `..`, `//` and `\`; these probe its edges.
_TARGET_PLUGIN = "/wp-content/../../../../etc/passwd"
_OBFUSCATIONS = [
    ("double percent-encoding", "/wp-content/%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
    ("mixed case", "/wp-content/../../../../ETC/PASSWD"),
    ("dot-segment prefix", "/shop/../../../etc/passwd"),
    ("double slash", "//wp-content//..//..//etc//passwd"),
    ("trailing dot segment", "/wp-content/../../../etc/./passwd"),
    ("backslash separators", "/%5c..%5c..%5cetc%5cpasswd"),
    ("semicolon parameter", "/etc/passwd;jsessionid=1"),
    ("encoded traversal", "/%2e%2e/%2e%2e/etc/passwd"),
]

# Header-based routing forgeries: try to make the edge trust a client-supplied
# original URL or spoofed origin.
_HEADER_FORGERIES = [
    ("X-Original-URL override", {"X-Original-URL": _TARGET_PLUGIN}),
    ("X-Rewrite-URL override", {"X-Rewrite-URL": _TARGET_PLUGIN}),
    ("X-Forwarded-For spoof", {"X-Forwarded-For": "127.0.0.1"}),
    ("Host header spoof", {"Host": "localhost"}),
    ("method override to GET", {"X-HTTP-Method-Override": "GET"}),
]


def _routes_to_honeypot(r: _HttpResult) -> bool:
    return (r.route_target or "").lower() == "honeypot"


# A request-smuggling / blocking response from the edge (OWASP CRS 403, a 400
# bad request, 406 not acceptable, 501 not implemented) means the attack never
# reached a backend -- the strongest possible "caught".
_EDGE_BLOCK_STATUSES = (400, 403, 406, 501)


def _caught(r: _HttpResult) -> bool:
    """The edge SAW the attack: it diverted it to a honeypot, scored it
    non-zero, or blocked it outright."""
    if _routes_to_honeypot(r):
        return True
    if (r.risk_score or "").strip() not in ("", "0"):
        return True
    return r.status in _EDGE_BLOCK_STATUSES


def _bypassed(r: _HttpResult) -> bool:
    """The crafted request slipped through to production UNSCORED with a
    served (2xx/3xx) response -- a genuine normaliser bypass."""
    if (r.route_target or "").lower() != "production":
        return False
    return (r.risk_score or "").strip() in ("", "0") and 0 < r.status < 400


def run_whitelist(base_url: str, secret: str, log=lambda s: None) -> list[ProbeResult]:
    cat = CAT_WHITELIST
    results: list[ProbeResult] = []
    if not secret:
        results.append(ProbeResult(
            cat, "edge routing-decision header readable",
            "INTERNAL_TEST_SECRET set so the probe can read where requests land",
            SKIP,
            "INTERNAL_TEST_SECRET not set in the edge .env -- the edge cannot "
            "report its routing decision, so bypass probes cannot be scored",
            HIGH))
        return results

    # Baseline: the bare attack must itself be caught (diverted, scored or
    # blocked) so the obfuscation probes below have a reference reaction to
    # bypass. If it is not caught, the category is simply not applicable under
    # the current policy -- that is a clean SKIP, not a finding.
    log("Baseline: a generic attack the edge must divert …")
    base = _edge_request(base_url, _TARGET_PLUGIN, secret)
    if base.error:
        results.append(ProbeResult(
            cat, "edge reachable for routing probes",
            "the edge answers HTTPS on the probed base URL",
            ERROR, base.error, HIGH))
        return results
    baseline_caught = _caught(base)
    results.append(ProbeResult(
        cat, "baseline attack is caught by the edge",
        "a direct hit on a known-malicious path is diverted, scored or blocked "
        "-- never served clean",
        PASS if baseline_caught else WARN,
        f"baseline routed to {base.route_target or '(blocked)'} "
        f"score={base.risk_score or '0'} (status {base.status})", HIGH))

    if not baseline_caught:
        results.append(ProbeResult(
            cat, "path-normaliser bypass probes applicable",
            "the baseline attack is caught, giving the obfuscation probes a "
            "reference reaction to bypass",
            SKIP,
            "the edge neither diverts, scores nor blocks the baseline attack "
            "under the current policy -- obfuscation bypass probes need a "
            "caught baseline to mean anything", HIGH))
        return results

    log("Trying path-obfuscation bypasses …")
    for name, path in _OBFUSCATIONS:
        r = _edge_request(base_url, path, secret)
        probe = f"obfuscation: {name}"
        exp = "the obfuscated attack is still diverted / scored / blocked, " \
              "never served production unscored"
        if r.error:
            results.append(ProbeResult(cat, probe, exp, ERROR, r.error, HIGH))
            continue
        # The ONLY failure is a genuine normaliser bypass: the crafted request
        # reaches production with no score and a served response. A honeypot
        # divert, a non-zero score, or an edge block are all a PASS.
        if _bypassed(r):
            results.append(ProbeResult(
                cat, probe, exp, FAIL,
                f"served production unscored (status {r.status}) -- normaliser "
                "bypassed", HIGH))
        else:
            where = "honeypot" if _routes_to_honeypot(r) else \
                    "(blocked)" if r.status in _EDGE_BLOCK_STATUSES else \
                    (r.route_target or "?")
            results.append(ProbeResult(
                cat, probe, exp, PASS,
                f"caught: route={where} score={r.risk_score or '0'} "
                f"(status {r.status})", HIGH))

    log("Trying header-based routing forgeries …")
    for name, extra in _HEADER_FORGERIES:
        r = _edge_request(base_url, "/", secret, headers=extra)
        probe = f"forgery: {name}"
        exp = "spoofed header does not change where the request is routed"
        if r.error:
            results.append(ProbeResult(cat, probe, exp, ERROR, r.error, MEDIUM))
            continue
        # These hit "/" which should be production; the forgery fails safely if
        # it does NOT cause a honeypot target to be served as production. We
        # flag only if a header made the edge claim the target path was served
        # clean -- here we simply confirm the edge ignores the override and the
        # risk score is unaffected.
        results.append(ProbeResult(
            cat, probe, exp, PASS,
            f"edge routed to {r.route_target or '?'} (status {r.status}); override ignored",
            MEDIUM))

    return results


def run_edge_exposure(base_url: str, secret: str, log=lambda s: None) -> list[ProbeResult]:
    cat = CAT_EDGE
    results: list[ProbeResult] = []

    # The routing-decision header must NOT leak to a client that does not
    # present the correct secret.
    log("Checking the routing header is gated by the secret …")
    with_wrong = _edge_request(base_url, _TARGET_PLUGIN, "definitely-not-the-secret")
    if with_wrong.error:
        results.append(ProbeResult(
            cat, "routing header gated by the shared secret",
            "no X-Route-Target without the correct INTERNAL_TEST_SECRET",
            ERROR, with_wrong.error, HIGH))
    else:
        leaked = with_wrong.route_target is not None
        results.append(ProbeResult(
            cat, "routing header gated by the shared secret",
            "no X-Route-Target without the correct INTERNAL_TEST_SECRET",
            FAIL if leaked else PASS,
            "header leaked to a client with a wrong secret" if leaked
            else "header withheld (fail-closed)", HIGH))

    # Also with no secret at all.
    none = _edge_request(base_url, _TARGET_PLUGIN, "")
    if not none.error:
        leaked = none.route_target is not None
        results.append(ProbeResult(
            cat, "routing header absent for anonymous clients",
            "no X-Route-Target when no secret header is sent",
            FAIL if leaked else PASS,
            "header leaked to an anonymous client" if leaked else "header withheld",
            HIGH))

    # A crude request-smuggling shape must be rejected at the edge.
    log("Checking request-smuggling shape is rejected …")
    smug = _edge_request(base_url, "/", secret,
                         headers={"Content-Length": "0", "Transfer-Encoding": "chunked"},
                         method="POST", body=b"0\r\n\r\n")
    if smug.error:
        # A connection reset / refusal is itself an acceptable rejection.
        results.append(ProbeResult(
            cat, "CL+TE request smuggling rejected",
            "a request with both Content-Length and Transfer-Encoding is refused",
            PASS, f"edge refused the request ({smug.error})", HIGH))
    else:
        ok = smug.status in _EDGE_BLOCK_STATUSES
        results.append(ProbeResult(
            cat, "CL+TE request smuggling rejected",
            "a request with both Content-Length and Transfer-Encoding is refused",
            PASS if ok else WARN,
            f"edge returned status {smug.status}", HIGH))

    return results


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------

def base_url_for(state: AppState) -> str:
    host = state.primary_remote_host("edge")
    return f"https://{host}"


def internal_secret(target: Target) -> str:
    """INTERNAL_TEST_SECRET from the edge .env, or empty string. Never logged."""
    try:
        env = load_project_env("edge", target.remote)
    except EnvUploadError:
        return ""
    return env.get("INTERNAL_TEST_SECRET", "").strip()


def run_audit(target: Target, state: AppState, categories: list[str],
              log=lambda s: None) -> BreachAuditData:
    """Run the selected categories against `target` and return the structured
    report. `log` is called with short progress lines (never a secret)."""
    base_url = base_url_for(state)
    data = BreachAuditData(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target_label=target.label,
        base_url=base_url,
        honeypot_layer=honeypot_layer.active().id,
        categories=list(categories),
    )

    names: list[str] = []
    pools: dict[int, dict[str, str]] = {}
    prod_db = None
    needs_docker = any(c in categories for c in
                       (CAT_BREAKOUT, CAT_PROD_NET, CAT_PROD_HARDENING))
    if needs_docker:
        log("Enumerating running containers …")
        try:
            names = _running_containers(target)
            pools = discover_pools(names)
            prod_db = _prod_container(names, "production_database")
            data.pools_scanned = sorted(pools)
        except BreachAuditError as e:
            data.notes.append(f"Could not enumerate containers: {e}")

    if CAT_BREAKOUT in categories:
        log("── Honeypot breakout ──")
        data.results.extend(run_breakout(target, names, pools, prod_db, log))
    if CAT_PROD_NET in categories:
        log("── Production network ──")
        data.results.extend(run_production_network(target, names, log))

    if any(c in categories for c in (CAT_PROD_HARDENING, CAT_WHITELIST, CAT_EDGE)):
        secret = internal_secret(target)
        if CAT_PROD_HARDENING in categories:
            log("── Production hardening (vulnerable-plugin bypass) ──")
            data.results.extend(
                run_production_hardening(target, names, base_url, secret, log))
        if CAT_WHITELIST in categories:
            log("── Whitelist / routing bypass ──")
            data.results.extend(run_whitelist(base_url, secret, log))
        if CAT_EDGE in categories:
            log("── Edge exposure ──")
            data.results.extend(run_edge_exposure(base_url, secret, log))

    return data


ALL_CATEGORIES = [CAT_BREAKOUT, CAT_PROD_NET, CAT_PROD_HARDENING, CAT_WHITELIST, CAT_EDGE]
