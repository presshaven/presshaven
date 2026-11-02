"""Dashboard app state persistence -- window geometry, remote-connection
settings, wizard-completion flag. Plain JSON file next to the app rather
than QSettings' platform-specific registry/plist/ini backends, so the
whole app's state is one inspectable, greppable file (state.json,
gitignored)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields

from core.paths import STATE_FILE


@dataclass
class RemoteConfig:
    enabled: bool = False
    host: str = ""
    port: int = 22
    user: str = ""
    key_path: str = ""
    # Path to the project directory (containing docker-compose.yml, or for
    # siem the elk_dockerized/docker subdir) on the REMOTE host.
    remote_path: str = ""
    # Optional human label so a project's list of hosts stays legible when
    # several share a user/host spelling; falls back to the host (see
    # display_name). Purely cosmetic -- never part of the ssh destination.
    name: str = ""

    def is_configured(self) -> bool:
        return bool(self.enabled and self.host and self.user and self.key_path)

    @property
    def address(self) -> str:
        """``user@host`` -- the ssh/scp/rsync destination spelling."""
        return f"{self.user}@{self.host}"

    @property
    def display_name(self) -> str:
        """A short label for menus/combos/group titles: the operator's name
        if set, else the host, else a generic placeholder for a blank row."""
        return self.name or self.host or "remote"

    def is_empty(self) -> bool:
        """True for a row the user never filled in -- distinguishes an
        untouched default from a real (possibly disabled) host, so blank
        rows can be dropped on save and on legacy migration."""
        return not (self.host or self.user or self.key_path
                    or self.remote_path or self.name or self.enabled)

    @classmethod
    def from_dict(cls, data: dict) -> "RemoteConfig":
        """Tolerates unknown keys (a state.json/export bundle written by a
        newer or older dashboard) instead of crashing the whole load over
        one unrecognized field; missing keys take the field defaults."""
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


def parse_remotes(value) -> list[RemoteConfig]:
    """Normalize a stored ``remote_<project>`` value into a list.

    Accepts the current format (a list of host dicts) and the legacy
    single-host format (one dict), so a state.json or settings bundle from
    before per-project host lists still loads. A legacy dict is kept only
    when it was ever actually filled in -- an untouched default collapses to
    an empty list rather than seeding a phantom blank host."""
    if isinstance(value, list):
        remotes = [RemoteConfig.from_dict(v) for v in value if isinstance(v, dict)]
        return [r for r in remotes if not r.is_empty()]
    if isinstance(value, dict):
        cfg = RemoteConfig.from_dict(value)
        return [] if cfg.is_empty() else [cfg]
    return []


@dataclass
class AppState:
    first_run_complete: bool = False
    window_geometry_b64: str = ""
    last_page: str = "services"
    # Per-project lists of SSH hosts (edge/siem) the dashboard can drive in
    # addition to the always-present local stack. Empty = local only. See
    # remotes_for()/configured_remotes()/primary_remote() and the Settings
    # "remote (SSH)" list editors.
    remote_edge: list = field(default_factory=list)
    remote_siem: list = field(default_factory=list)
    # How often (ms) StatusPoller re-runs `docker compose ps` for every
    # configured target. Adjustable from Settings -- lower for snappier
    # health-diagram updates, higher to reduce SSH round-trips against a
    # remote target on a slow/metered link.
    poll_interval_ms: int = 5000
    # Notify (system tray balloon) when a container transitions into
    # unhealthy/exited-with-error. Off by default so a first-run headless
    # environment without a tray isn't surprised by anything; the tray
    # icon itself only appears when the platform actually supports one.
    tray_notifications_enabled: bool = True
    # Whether the SIEM Analytics page's embedded browser uses a persistent (named)
    # QWebEngineProfile -- cookies survive app restarts, so logging into
    # Kibana once doesn't mean doing it again on every dashboard launch --
    # vs. the off-the-record default every other embedded browser in this
    # app uses (see browser_widget.py). On by default: Kibana is the one
    # place in this app where staying logged in is the obviously-wanted
    # behavior, unlike the Attack Simulation page's eshop browser, where an
    # ephemeral session is the whole point.
    kibana_remember_credentials: bool = True
    # "docs" (the default, matching the docs-astro design), "system"
    # (follow the OS), "console_dark"/"console_light", "light"/"dark"
    # (Solarized), or "hc_light"/"hc_dark" -- see ui/theme.py.
    theme: str = "docs"
    # User-customized navigation layout: {group: {"visible": [page_id, ...],
    # "overflow": [page_id, ...]}} -- the rail's drag-and-drop order and which
    # pages live in each category's "⋮" panel. Missing/invalid entries fall
    # back to ui/main_window.py's NAV_GROUPS/NAV_OVERFLOW defaults.
    nav_layout: dict = field(default_factory=dict)
    # Cross-session history of notable security events (honeypot
    # diversions, CVE/high-severity signals, missing required
    # dependencies), capped at security_feed.MAX_EVENTS -- see
    # ui/security_feed.py. Each entry: {timestamp, kind, label, detail,
    # color, score}.
    security_events: list = field(default_factory=list)
    # Knowledge Base page (ui/page_learn.py): ids of guided-lab steps the user has
    # ticked off (core/learning.LABS), and whether the one-time welcome
    # that opens the Knowledge Base page on first launch has been shown.
    learn_completed_steps: list = field(default_factory=list)
    learn_welcome_shown: bool = False
    # Honeypot layer of the ids stack: "reverse_proxy" (default) or
    # "database" -- see core/honeypot_layer.py. Picked on the Workloads page.
    honeypot_layer: str = "reverse_proxy"
    # Security-alert policy (core/alert_policy.AlertPolicy.to_dict()): which
    # proxy events raise a desktop notification / webhook. Edited on the
    # Connectors & Config page's Alerts tab.
    alert_policy: dict = field(default_factory=dict)
    # Forensics Analysis page: recent queries (most recent first) and named
    # saved searches -- see core/log_query.py.
    log_search_history: list = field(default_factory=list)
    log_saved_searches: list = field(default_factory=list)

    def remotes_for(self, project: str) -> list[RemoteConfig]:
        """Every configured-or-not SSH host for a project (edge/siem), as
        edited in Settings. Unknown project -> empty list."""
        return getattr(self, f"remote_{project}", [])

    def set_remotes(self, project: str, remotes: list[RemoteConfig]) -> None:
        setattr(self, f"remote_{project}", list(remotes))

    def configured_remotes(self, project: str) -> list[RemoteConfig]:
        """Only the hosts that are enabled AND fully filled in -- the ones
        targets_for() actually drives alongside the local stack."""
        return [r for r in self.remotes_for(project) if r.is_configured()]

    def primary_remote(self, project: str) -> "RemoteConfig | None":
        """The first usable remote, for the single-remote consumers (env
        upload/browse, breach-audit host, etc.) that still assume one. None
        when the project has no configured host."""
        configured = self.configured_remotes(project)
        return configured[0] if configured else None

    def primary_remote_host(self, project: str, default: str = "localhost") -> str:
        """Hostname of primary_remote(), or ``default`` when the project runs
        locally -- the spelling the breach/probe pages aim network checks at."""
        primary = self.primary_remote(project)
        return primary.host if primary else default

    @classmethod
    def load(cls) -> "AppState":
        """Reads STATE_FILE; any missing/unparseable file or field falls
        back to the dataclass defaults, so a state.json from an older
        version always loads."""
        if not STATE_FILE.exists():
            return cls()
        try:
            raw = json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return cls()
        if not isinstance(raw, dict):
            return cls()

        state = cls()
        for f in fields(cls):
            if f.name not in raw:
                continue
            value = raw[f.name]
            if f.name.startswith("remote_"):
                # New format is a list of host dicts; a legacy single-host
                # dict is migrated in (see parse_remotes).
                setattr(state, f.name, parse_remotes(value))
            else:
                setattr(state, f.name, value)
        return state

    def save(self) -> None:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(asdict(self), indent=2))
