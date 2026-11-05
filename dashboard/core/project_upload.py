"""Syncs an entire project directory (not just .env) to its configured
remote host via rsync over SSH, so a fresh remote host actually has
everything needed to run `docker compose up` there -- core/env_upload.py's
upload_env() only sends the .env for a quick config-only push.

rsync (not scp -r) is deliberate: delta-transfer (a first sync moves
everything, a re-sync only moves what changed), native machine-readable
progress reporting (--info=progress2), and --exclude support so runtime/
log/backup data isn't blindly copied alongside actual project code -- see
EXCLUDE_PATTERNS, sized against this repo's real directory footprint
(confirmed live: ids/backups/ alone is 1.2GB, suricata_logs/
378MB -- neither belongs in a "deploy the project" sync).
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path

from core import ssh
from core.proc import run_checked
from core.state import RemoteConfig


class ProjectUploadError(Exception):
    pass


# Runtime-generated data (backups, logs, DB/Redis volumes), a pure
# reference snapshot kept only for local diffing, and local dev/VCS cruft
# -- none of it is "the project," all of it can be large, and none of it
# is needed for a remote host to actually run the stack. .env is handled
# separately by core/env_upload.py's own dedicated action, not swept up
# here, so the two features stay independently controllable.
EXCLUDE_PATTERNS = [
    ".git/", "__pycache__/", "*.pyc", "venv/", "node_modules/",
    "backups/",
    "suricata_logs/", "nginx_logs/",
    "production_eshop_files_fresh_for_diff/",  # scripts/fetch_pristine_wordpress.sh
    "redis_data/",
    "honeypot_database_data/", "honeypot_database_data_2/", "honeypot_database_data_3/",
    "production_database_data/", "production_mysql_data/",
    "vector/data/", "vector/logs/",
    ".env",
]


def build_rsync_argv(local_dir: Path, remote: RemoteConfig, timeout: float = 10.0) -> list[str]:
    argv = ["rsync", "-az", "--info=progress2", "-e", ssh.ssh_command_string(remote, timeout)]
    for pattern in EXCLUDE_PATTERNS:
        argv += ["--exclude", pattern]
    # Trailing slash on the source: copies the DIRECTORY'S CONTENTS into
    # remote_path, not the directory itself nested one level deeper --
    # remote_path is meant to BE the project root on the remote host
    # (matching local_dir here, EDGE_DIR/SIEM_DIR -- the whole project,
    # not wherever docker-compose.yml itself happens to live). For SIEM,
    # Target.build() (docker_ctl.py) appends "/docker" onto remote_path
    # internally when actually running compose commands there, the same
    # way Project.compose_dir already does locally -- this sync target
    # stays remote_path itself since it's syncing the WHOLE project
    # (docker/ included, as one of several sibling directories), not just
    # the compose-file directory.
    local_src = str(local_dir).rstrip("/") + "/"
    remote_dst = f"{remote.address}:{remote.remote_path.rstrip('/')}/"
    argv += [local_src, remote_dst]
    return argv


# rsync --itemize-changes line: 11 flag characters (YXcstpoguax), a space,
# then the path. Y is "<" for a file sent to the remote; X is the type.
_ITEMIZE_RE = re.compile(r"^([<>ch.*])([fdLDS])([.+?a-zA-Z]{9}) (.+)$")


def build_changes_argv(local_dir: Path, remote: RemoteConfig, timeout: float = 10.0) -> list[str]:
    """Dry run of the whole-project sync: same excludes and destination, but
    `-n --itemize-changes` so rsync only LISTS what it would send. Compared by
    size + modification time (rsync's default, and what the real sync -a
    preserves), so it does not read file contents on either side."""
    argv = build_rsync_argv(local_dir, remote, timeout)
    argv[1] = "-azn"                       # was "-az"; -n = dry run
    argv.insert(2, "--itemize-changes")
    argv.remove("--info=progress2")        # no progress needed for a listing
    return argv


def parse_changed_files(rsync_output: str) -> list[str]:
    """Paths (relative to the project root) of the files an --itemize-changes
    dry run would transfer, sorted. Directory-only changes (a touched mtime),
    and anything that is not a file or symlink sent to the remote, are
    skipped; non-itemize lines in the stream (ssh banners) never match."""
    files = []
    for line in rsync_output.splitlines():
        m = _ITEMIZE_RE.match(line.rstrip("\r"))
        if not m:
            continue
        direction, kind, _flags, path = m.groups()
        if direction == "<" and kind in ("f", "L"):
            files.append(path)
        elif direction == "c" and kind == "L":
            files.append(path)
    return sorted(set(files))


def build_selective_rsync_argv(local_dir: Path, remote: RemoteConfig,
                               files_from: str, timeout: float = 10.0) -> list[str]:
    """The real sync, restricted to the paths listed (one per line, relative to
    the project root) in the file `files_from`. Same flags, excludes and
    destination as build_rsync_argv(); --files-from also creates any missing
    parent directories on the remote."""
    argv = build_rsync_argv(local_dir, remote, timeout)
    argv.insert(-2, f"--files-from={files_from}")
    return argv


def remote_dir_has_content(remote: RemoteConfig, timeout: float = 8.0) -> bool:
    """True if remote_path already exists and is non-empty -- used to ask
    "overwrite?" before syncing into it, rather than silently merging into
    whatever's already there."""
    if not remote.is_configured():
        raise ProjectUploadError("Remote connection is not fully configured.")

    remote_dir = remote.remote_path.rstrip("/")
    check_cmd = (
        f"[ -d {shlex.quote(remote_dir)} ] && "
        f"[ -n \"$(ls -A {shlex.quote(remote_dir)} 2>/dev/null)\" ] && echo YES || echo NO"
    )
    argv = ssh.ssh_argv(remote, check_cmd, timeout=timeout)
    result = run_checked(argv, error=ProjectUploadError, timeout=timeout + 5, what="ssh")
    return result.stdout.strip() == "YES"


_PROGRESS_RE = re.compile(r"(\d{1,3})%")


def parse_progress_percent(rsync_output_chunk: str) -> int | None:
    """Pulls the most recent percentage out of a chunk of rsync
    --info=progress2 output (e.g. "  1,234,567  43%   12.3MB/s..."). Pure
    function so it's testable without actually running rsync -- returns
    None if the chunk has no percentage in it (most lines, between
    periodic progress updates)."""
    matches = _PROGRESS_RE.findall(rsync_output_chunk)
    if not matches:
        return None
    return min(int(matches[-1]), 100)
