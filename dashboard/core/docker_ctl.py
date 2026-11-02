"""Command construction (and simple synchronous helpers) for controlling
the two projects' docker-compose stacks, locally or over SSH on a remote
host.

Command *construction* is kept separate from *execution* on purpose: the
UI layer runs long commands (up/restart/purge) through QProcess for live,
non-blocking output streaming, but status polling (`ps`) is short-lived
enough to run synchronously from a background QThread. Both paths need
the same argv/cwd, hence this module returns argv+cwd rather than running
anything itself except the small `ps`/reachability synchronous helpers.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass

from core import honeypot_layer, ssh
from core.proc import succeeds
from core.projects import PROJECT_IDS, Project, project as project_for
from core.state import AppState, RemoteConfig

# Kept for callers that only need the label of a project id; the full
# descriptor is core.projects.PROJECTS.
PROJECT_LABELS = {pid: project_for(pid).label for pid in PROJECT_IDS}

# Label on every container and volume ids/images/pool_manager creates.
RUNTIME_POOL_LABEL = "honeypot.pool.managed-by=pool_manager"

# A runtime pool's serving container: honeypot_eshop_N (wordpress layer) or
# honeypot_database_N (database layer). pool_manager names these directly via
# the Docker API, so -- unlike compose-created containers -- they have no
# project-prefixed name. The short-lived helper containers it spawns during a
# scale-up (template copy, clone+scrub, wp-cli seed) carry the same pool label
# but get random Docker-assigned names and are removed on completion, so this
# pattern deliberately keeps only the actual pools out of a mid-provision poll.
_POOL_SERVING_NAME_RE = re.compile(r"^honeypot_(?:eshop|database)_\d+$")
# Extracts the code out of `docker ps`'s "Exited (N) ..." status, since its
# JSON (unlike `docker compose ps`'s) carries no separate ExitCode field.
_EXIT_CODE_RE = re.compile(r"Exited \((\d+)\)")


def _pool_record(raw: dict) -> dict | None:
    """Reshape one `docker ps --format json` record for a runtime honeypot
    pool onto the field names `docker compose ps --format json` uses -- the
    vocabulary container_status.classify()/status_detail() and the Health
    diagram read. Returns None for anything that isn't a pool's serving
    container (e.g. a transient provisioning helper). `docker ps` gives
    HealthStatus (compose calls it Health) and no ExitCode (parsed from
    Status here); CreatedAt is the same Go time format compose emits, so
    the Health page's uptime parsing handles it unchanged."""
    name = (raw.get("Names") or "").split(",")[0].strip()
    if not _POOL_SERVING_NAME_RE.match(name):
        return None
    status = raw.get("Status", "")
    code = _EXIT_CODE_RE.search(status)
    return {
        "Service": name,   # unique per pool -> its own node, not collapsed with another
        "Name": name,
        "State": raw.get("State", ""),
        "Health": raw.get("HealthStatus", ""),
        "Status": status,
        "ExitCode": code.group(1) if code else "0",
        "CreatedAt": raw.get("CreatedAt", ""),
        "Image": raw.get("Image", ""),
    }


# The edge stack's log shipper to the SIEM (profiles: [elk]) and the .env
# values that say whether it has anywhere to ship to.
SIEM_SHIPPER_SERVICE = "vector_outbound"
VECTOR_HOST_PLACEHOLDERS = {"", "your-siem-vm.example.com"}
_TRUE = {"1", "true", "yes", "on"}


def siem_shipping(env) -> tuple[bool, str]:
    """(enabled, why not) for the edge's vector_outbound, from its .env
    (anything with .get(key, default)). It ships only when ELK_ENABLED is on
    and VECTOR_HOST is a real address: with the .env.example placeholder it
    can't resolve the host and drops every batch."""
    if env.get("ELK_ENABLED", "false").strip().strip("\"'").lower() not in _TRUE:
        return False, "ELK_ENABLED is not true"
    host = env.get("VECTOR_HOST", "").strip().strip("\"'")
    if host.lower() in VECTOR_HOST_PLACEHOLDERS:
        return False, f"VECTOR_HOST is not set ({host or 'empty'})"
    return True, ""


@dataclass
class Target:
    project: str  # "edge" | "siem"
    remote: RemoteConfig | None = None  # None == local

    @property
    def spec(self) -> Project:
        return project_for(self.project)

    @property
    def is_remote(self) -> bool:
        return self.remote is not None

    @property
    def compose_file(self) -> str | None:
        """The compose file to use when it isn't the directory's default
        docker-compose.yml: the edge stack's database proxy layer (see
        core/honeypot_layer.py). None means the default file."""
        if self.project != "edge":
            return None
        file = honeypot_layer.active().compose_file
        return None if file == "docker-compose.yml" else file

    @property
    def label(self) -> str:
        base = self.spec.label
        if self.compose_file:
            base = f"{base}, {honeypot_layer.active().short_label}"
        return f"{base} (remote: {self.remote.display_name})" if self.is_remote else f"{base} (local)"

    @property
    def key(self) -> str:
        """Stable identity for status-poller result lookup. MUST stay unique
        per remote host now that a project can drive several -- keying only on
        local/remote would collapse every remote's status into one node."""
        if not self.is_remote:
            return f"{self.project}-local"
        return f"{self.project}-remote-{self.remote.address}:{self.remote.port}"

    @property
    def host(self) -> str:
        """Where this target's published ports are reachable FROM THIS
        MACHINE -- the remote host's address, or loopback for local."""
        return self.remote.host if self.is_remote else "127.0.0.1"

    def _local_dir(self) -> str:
        return str(self.spec.compose_dir)

    def remote_compose_dir(self) -> str:
        """The directory docker-compose.yml lives in on the remote host.
        RemoteConfig.remote_path is the PROJECT ROOT (the same thing
        "Upload entire project to remote" syncs), so SIEM's "docker/"
        subdirectory gets appended here exactly as Project.compose_dir
        already does locally -- the user never types it. An EMPTY
        remote_path mirrors this machine's own checkout layout, which
        already has the subdirectory baked in."""
        if not self.remote.remote_path:
            return self._local_dir()
        return self.spec.remote_compose_dir(self.remote.remote_path)

    def remote_env_path(self) -> str:
        """`.env` sits right next to docker-compose.yml on the remote host."""
        return f"{self.remote_compose_dir()}/.env"

    @staticmethod
    def _global_flags(compose_args: tuple[str, ...], compose_file: str | None = None) -> list[str]:
        """Flags inserted between `docker compose` and the subcommand.

        -f <file> (edge stack, database proxy layer only): see compose_file.

        --profile '*' (always): activates every profile, e.g. the edge
        project's `vector_outbound` service, which is `profiles: [elk]` --
        confirmed live that without it, `docker compose down`/`up`/
        `restart` silently exclude profiled services from their scope
        entirely (docker compose ps does NOT have this filtering, which is
        why the dashboard's status display looked fine while Stop/Purge
        quietly left `vector_outbound` running). Harmless for ps/logs, so
        applied unconditionally.

        --ansi always (logs only): docker compose's default --ansi auto
        disables ANSI color whenever stdout isn't a TTY, which QProcess's
        pipes never are. Scoped to `logs` so it can never affect
        machine-parsed output like `ps --format json`. See ui/ansi.py for
        the LogPanel-side rendering of the resulting escape codes.
        """
        flags = ["--profile", "*"]
        if compose_file:
            flags = ["-f", compose_file, *flags]
        if compose_args and compose_args[0] == "logs":
            flags += ["--ansi", "always"]
        return flags

    @staticmethod
    def _augment_args(compose_args: tuple[str, ...]) -> tuple[str, ...]:
        """--remove-orphans, appended for `up`/`down` only (a subcommand
        option, so it goes after the subcommand, unlike _global_flags()).

        Confirmed live this is a real gap: renaming a service in
        docker-compose.yml leaves its OLD container running forever
        afterward -- compose only manages containers for services
        CURRENTLY defined in the file, so a plain `down`/`up` doesn't know
        the old one exists. That orphan then held a network and a named
        volume across a subsequent Purge (`down -v` logged "Resource is
        still in use" and silently left them behind). --remove-orphans
        makes both directions self-healing.

        `up` also gets --build: without it compose keeps running whatever
        image of a locally built service (pool_manager, ...) it built
        first, so a fixed manager.py never reached the container (a pool
        build kept failing on a FLUSH PRIVILEGES already removed from the
        source). The build cache makes this a no-op when nothing changed."""
        if compose_args and compose_args[0] == "up":
            return (*compose_args, "--build", "--remove-orphans")
        if compose_args and compose_args[0] == "down":
            return (*compose_args, "--remove-orphans")
        return compose_args

    def siem_shipping(self) -> tuple[bool, str]:
        """siem_shipping() for this target's .env (edge only; the SIEM stack
        has no shipper). An unreadable .env counts as enabled, so a failed
        SSH read never silently switches log shipping off."""
        if self.project != "edge":
            return True, ""
        from core.env_upload import load_project_env   # env_upload imports this module
        try:
            env = load_project_env(self.project, self.remote, timeout=8.0)
        except Exception:  # noqa: BLE001
            return True, ""
        return siem_shipping(env)

    def _shipper_args(self, compose_args: tuple[str, ...]) -> tuple[str, ...]:
        """A whole-stack `up` of the edge keeps vector_outbound at zero
        replicas while log shipping isn't configured. --profile '*' would
        otherwise start it regardless of ELK_ENABLED, and with the
        placeholder VECTOR_HOST it only logs DNS errors and drops events.
        Scaling to 0 also stops one left running from an earlier start. An
        `up` of named services is left alone."""
        if (self.project != "edge" or not compose_args or compose_args[0] != "up"
                or any(not a.startswith("-") for a in compose_args[1:])):
            return compose_args
        enabled, _why = self.siem_shipping()
        if enabled:
            return compose_args
        return (*compose_args, "--scale", f"{SIEM_SHIPPER_SERVICE}=0")

    def build(self, *compose_args: str) -> tuple[list[str], str | None]:
        """Returns (argv, cwd). cwd is None for remote (the ssh command
        does its own `cd`)."""
        global_flags = self._global_flags(compose_args, self.compose_file)
        compose_args = self._augment_args(self._shipper_args(compose_args))

        if not self.is_remote:
            return ["docker", "compose", *global_flags, *compose_args], self._local_dir()

        remote_cmd = "docker compose " + " ".join(shlex.quote(a) for a in (*global_flags, *compose_args))
        return self.build_shell(remote_cmd)

    def build_shell(self, command: str) -> tuple[list[str], str | None]:
        """Like build(), but for callers that need more than one `docker
        compose` invocation chained in one shell line (e.g. piping one
        container's stdout into another's stdin -- see core/backup_ctl.py's
        WP-file restore). `command` is a raw POSIX shell one-liner the
        caller has already assembled (arguments already shlex.quote'd),
        run in the compose directory as-is.

        COMPOSE_FILE is exported first when this target uses a non-default
        compose file, so the raw `docker compose` calls in `command` follow
        the chosen honeypot layer just like build() does."""
        if self.compose_file:
            command = f"export COMPOSE_FILE={shlex.quote(self.compose_file)}; {command}"
        if not self.is_remote:
            return ["sh", "-c", command], self._local_dir()

        remote_cmd = f"cd {shlex.quote(self.remote_compose_dir())} && {command}"
        return ssh.ssh_argv(self.remote, remote_cmd), None

    def build_purge(self) -> tuple[list[str], str | None]:
        """`down -v`. For the edge stack, first the honeypot pools pool_manager
        built at runtime: they carry no compose labels (so `down` leaves them
        running, still attached to the stack's networks, which then cannot be
        removed) and their volumes are not compose volumes. pool_manager is
        stopped first so it does not rebuild a spare in between."""
        if self.project != "edge":
            return self.build("down", "-v")
        compose = "docker compose " + " ".join(
            shlex.quote(a) for a in self._global_flags(("down",)))
        label = shlex.quote(f"label={RUNTIME_POOL_LABEL}")
        # One brace group, so a failed `cd` (remote) skips all of it.
        return self.build_shell(
            f"{{ {compose} stop pool_manager; "
            f"c=$(docker ps -aq --filter {label}); [ -z \"$c\" ] || docker rm -f -v $c; "
            f"v=$(docker volume ls -q --filter {label}); [ -z \"$v\" ] || docker volume rm -f $v; "
            f"{compose} down -v --remove-orphans; }}")

    def build_redeploy(self) -> tuple[list[str], str | None]:
        """Rebuild every image and replace every container, keeping the data
        volumes: what applies changed .env values (new credentials included)
        and changed images. `down` + `up --build` rather than `up
        --force-recreate`, so networks are recreated too. For the edge stack
        the runtime honeypot pools go first (their containers and volumes --
        pools are disposable and pool_manager rebuilds them from the current
        design and passwords), pool_manager stopped beforehand so it can't
        rebuild one in between; plain `down` would leave them running with the
        old configuration (see build_purge())."""
        compose = "docker compose " + " ".join(shlex.quote(a) for a in self._global_flags(("up",)))
        down = " ".join(shlex.quote(a) for a in self._augment_args(("down",)))
        up = " ".join(shlex.quote(a) for a in self._augment_args(self._shipper_args(("up", "-d"))))
        pools = ""
        if self.project == "edge":
            label = shlex.quote(f"label={RUNTIME_POOL_LABEL}")
            pools = (f"{compose} stop pool_manager; "
                     f"c=$(docker ps -aq --filter {label}); [ -z \"$c\" ] || docker rm -f -v $c; "
                     f"v=$(docker volume ls -q --filter {label}); [ -z \"$v\" ] || docker volume rm -f $v; ")
        # One brace group, so a failed `cd` (remote) skips all of it.
        return self.build_shell(f"{{ {pools}{compose} {down} && {compose} {up}; }}")

    def prune_orphan_rules(self, timeout: float = 20.0) -> str:
        """Drop host iptables rules orphaned by a previous teardown, just
        before a local `up`/redeploy. Docker does not reliably remove its
        raw-table anti-spoof DROP rules when a network goes away; the leftover
        `! -i <dead-bridge>` match then blackholes the reused container IP on
        the next `up` (production_db_seed could not reach production_database
        and timed out). The rules live in the host's own netns, so this is a
        no-op for a remote target. Never raises -- returns the script's output
        (or a short note) for the caller to echo into the deploy log. See
        ids/scripts/prune_orphan_iptables.sh."""
        if self.is_remote:
            return ""
        from core import paths  # local import: paths pulls in nothing from here
        script = paths.EDGE_DIR / "scripts" / "prune_orphan_iptables.sh"
        try:
            result = subprocess.run(
                ["sh", str(script)],
                capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return f"[prune-iptables] skipped ({exc})\n"
        return result.stdout + result.stderr

    # ---- one-shot synchronous helpers (call from a background thread) ----

    def ps(self, timeout: float = 15.0) -> list[dict]:
        """Live container status. Returns [] on any failure (host
        unreachable, docker not running, etc.) -- callers treat that the
        same as "nothing running", which is the honest state to show."""
        argv, cwd = self.build("ps", "-a", "--format", "json")
        try:
            result = subprocess.run(
                argv, cwd=cwd, capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return []
        if result.returncode != 0:
            return []
        containers = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        # Pools the pool_manager spins up at runtime carry no
        # com.docker.compose.* labels (see build_purge()), so the
        # `docker compose ps` above never lists them -- fold them in by
        # their own label so the Global Visualization draws a node per pool.
        if self.project == "edge":
            containers.extend(self._runtime_pool_containers(timeout))
        return containers

    def _runtime_pool_containers(self, timeout: float = 15.0) -> list[dict]:
        """Runtime honeypot pools (honeypot_eshop_N / honeypot_database_N),
        found by their pool_manager label and reshaped onto compose-ps field
        names so they merge cleanly with ps(). Compose-declared pools (1-3)
        don't carry this label, so the two sets are disjoint -- no node is
        drawn twice. Returns [] on any failure, same contract as ps()."""
        label = shlex.quote(f"label={RUNTIME_POOL_LABEL}")
        argv, cwd = self.build_shell(
            f"docker ps -a --filter {label} --format '{{{{json .}}}}'")
        try:
            result = subprocess.run(
                argv, cwd=cwd, capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return []
        if result.returncode != 0:
            return []
        pools = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec = _pool_record(raw)
            if rec is not None:
                pools.append(rec)
        return pools

    def remote_compose_file_exists(self, timeout: float = 8.0) -> bool:
        """For remote targets only: does remote_compose_dir() actually
        contain a compose file? Purely informational (see
        RemoteConfigWidget._test_connection()) -- a brand new remote host
        legitimately has none until "Upload entire project" puts one
        there, so this never blocks anything."""
        if not self.is_remote:
            return True
        d = shlex.quote(self.remote_compose_dir())
        check_cmd = f"[ -f {d}/docker-compose.yml ] || [ -f {d}/compose.yaml ] || [ -f {d}/compose.yml ]"
        return self._ssh_succeeds(check_cmd, timeout)

    def is_reachable(self, timeout: float = 8.0) -> bool:
        """For remote targets: can we even SSH in? Local is always
        reachable (a missing `docker` surfaces via ps() returning [])."""
        if not self.is_remote:
            return True
        return self._ssh_succeeds("true", timeout)

    def _ssh_succeeds(self, remote_cmd: str, timeout: float) -> bool:
        return succeeds(ssh.ssh_argv(self.remote, remote_cmd, timeout=timeout), timeout=timeout + 2)


def remote_for(project: str, state: AppState) -> RemoteConfig | None:
    """The project's PRIMARY (first configured) remote, or None when it runs
    purely locally -- i.e. exactly what Target(remote=...) wants for the
    single-target features that still assume one host."""
    return state.primary_remote(project)


def target_for(project: str, state: AppState) -> Target:
    """The ONE target a single-target feature should talk to for `project`:
    its primary remote host when one is configured, otherwise local. Used by
    pages that don't offer a local/remote choice (Patterns, Kibana, the
    security feed)."""
    return Target(project=project, remote=remote_for(project, state))


def targets_for(project: str, state: AppState) -> list[Target]:
    """All targets to show for a project: always the local stack, plus one
    Target per configured remote host (in the order they appear in
    Settings)."""
    result = [Target(project=project, remote=None)]
    result += [Target(project=project, remote=r)
               for r in state.configured_remotes(project)]
    return result


def all_targets(state: AppState) -> list[Target]:
    return [t for pid in PROJECT_IDS for t in targets_for(pid, state)]
