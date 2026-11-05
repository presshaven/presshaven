"""Transfers a project's .env content to/from its configured remote host
over SSH (core/ssh.py's option convention -- system ssh/scp binaries, so
the user's ssh_config/known_hosts apply exactly as from a terminal).

Two shapes, for two different UI flows:
  - upload_env(local_path, remote):    send an existing LOCAL FILE (scp) --
    used by the "Upload local .env to remote" button, which starts from a
    file already on disk.
  - download_env_text(remote) / upload_env_text(text, remote): fetch/send
    TEXT directly over an ssh pipe, no local file involved at any point --
    used by the wizard's remote-prefill env pages and the Connectors & Config page's
    Local/Remote toggle, where the content is fetched, edited in memory in
    the same EnvEditorWidget used for local files, and saved straight back
    to the remote host without ever touching local disk.

load_project_env() is the read-only convenience on top of both: "give me
this project's .env as an EnvFile, wherever it currently lives".
"""
from __future__ import annotations

import shlex
from pathlib import Path

from core import ssh
from core.docker_ctl import Target
from core.env_file import EnvFile
from core.proc import run_checked
from core.projects import project as project_for
from core.state import RemoteConfig


class EnvUploadError(Exception):
    pass


def remote_env_path(project: str, remote: RemoteConfig) -> str:
    """Where the project's .env lives on the remote host -- right beside
    docker-compose.yml, via Target.remote_compose_dir() (which already
    encodes SIEM's `docker/` subdirectory, so it isn't hardcoded again
    here -- an earlier version did exactly that and silently broke edge's
    remote .env upload)."""
    return Target(project=project, remote=remote).remote_env_path()


def apply_sink_override(text: str, project: str, remote: RemoteConfig) -> str:
    """The .env `text` with this remote's separate Vector sink applied.

    Only for the edge project (the SIEM stack has no outbound sink), and only
    when the remote has one configured -- otherwise `text` is returned
    byte-for-byte unchanged. Sets VECTOR_HOST, and VECTOR_PORT when a port is
    given, leaving every other line (comments, secrets, ordering) as it was."""
    sink = remote.sink_host.strip()
    if project != "edge" or not sink:
        return text
    env = EnvFile.from_text(text, path=Path(".env"))
    env.set("VECTOR_HOST", sink)
    if remote.sink_port > 0:
        env.set("VECTOR_PORT", str(remote.sink_port))
    return env.render()


def _require_configured(remote: RemoteConfig) -> None:
    if not remote.is_configured():
        raise EnvUploadError("Remote connection is not fully configured.")


def upload_env(local_path: Path, project: str, remote: RemoteConfig, timeout: float = 15.0) -> None:
    """Sends an existing LOCAL FILE to the remote host via scp. Raises
    EnvUploadError with a human-readable message on any failure (not
    configured, local file missing, scp itself failing/timing out)."""
    _require_configured(remote)
    if not local_path.exists():
        raise EnvUploadError(f"Local file not found: {local_path}")
    if project == "edge" and remote.sink_host.strip():
        # A separate SIEM sink means the file must be rewritten on the way out,
        # so send the adjusted text rather than the file as-is.
        upload_env_text(apply_sink_override(local_path.read_text(), project, remote),
                        project, remote, timeout=timeout)
        return
    argv = ssh.scp_argv(remote, str(local_path), remote_env_path(project, remote), timeout=timeout)
    run_checked(argv, error=EnvUploadError, timeout=timeout + 5, what="scp")


def download_env_text(project: str, remote: RemoteConfig, timeout: float = 15.0) -> str:
    """Fetches the remote .env's content via `ssh ... cat <path>` straight
    to stdout -- no local temp file. Returns "" if the remote file doesn't
    exist yet (a fresh remote host), which callers treat like a missing
    local file (an empty EnvFile ready to be filled in). Raises
    EnvUploadError only for actual connection failures."""
    _require_configured(remote)
    # `|| true` (and discarding cat's stderr) means the ssh command itself
    # always exits 0 for "connected fine, file just isn't there yet" --
    # only a real connection failure (bad host/key/auth) should raise.
    remote_cmd = f"cat {shlex.quote(remote_env_path(project, remote))} 2>/dev/null || true"
    argv = ssh.ssh_argv(remote, remote_cmd, timeout=timeout)
    return run_checked(argv, error=EnvUploadError, timeout=timeout + 5, what="ssh").stdout


def upload_env_text(text: str, project: str, remote: RemoteConfig, timeout: float = 15.0) -> None:
    """Writes `text` directly to the remote .env over SSH stdin -- no
    local file involved. The counterpart of download_env_text() for
    content that was fetched from remote and edited in memory."""
    _require_configured(remote)
    text = apply_sink_override(text, project, remote)
    remote_cmd = f"cat > {shlex.quote(remote_env_path(project, remote))}"
    argv = ssh.ssh_argv(remote, remote_cmd, timeout=timeout)
    run_checked(argv, error=EnvUploadError, timeout=timeout + 5, input=text, what="ssh")


def load_project_env(project: str, remote: RemoteConfig | None, timeout: float = 15.0) -> EnvFile:
    """The project's .env as an EnvFile: read from the local checkout when
    `remote` is None, otherwise fetched over SSH. A missing file either way
    yields an empty EnvFile (not an error); only a failed remote
    connection raises EnvUploadError. The returned EnvFile's .path is the
    LOCAL path in both cases, for display -- don't .save() a
    remote-fetched one, use upload_env_text()."""
    spec = project_for(project)
    if remote is None:
        return EnvFile.load(spec.env_file)
    return EnvFile.from_text(download_env_text(project, remote, timeout=timeout), path=spec.env_file)
