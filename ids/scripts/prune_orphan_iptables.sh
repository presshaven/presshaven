#!/bin/sh

# prune_orphan_iptables.sh -- remove host iptables/ip6tables rules that
# reference a Docker bridge (br-*) which no longer exists.
#
# WHY THIS EXISTS
# ---------------
# Docker (this host runs engine 29.x; the behaviour is 28+) installs an
# anti-IP-spoofing rule in the *raw* table for every container IP:
#
#     -A PREROUTING -d <ip>/32 ! -i <its-bridge> -j DROP
#
# i.e. "drop any packet to this container IP unless it arrives on that
# container's own bridge". Correct -- while the bridge exists.
#
# When a user network is torn down (`docker compose down`), Docker on this
# WSL2 host does NOT reliably remove these raw-table rules. The bridge
# interface is gone, so `! -i <dead-bridge>` is now TRUE for EVERY packet ->
# all traffic to that IP is dropped UNCONDITIONALLY. Because the compose
# networks pin their subnets, the next `up` reuses the same addresses (e.g.
# production_db_seed is handed 172.20.0.4) and inherits the orphaned DROP, so
# the seed can never reach production_database and times out:
#   "production_database:3306 still not accepting connections ... giving up".
# The database itself is healthy; the reply packets are blackholed on the way
# back to the seed's IP.
#
# WHAT IT DOES
# ------------
# Prunes exactly that class of orphan: any rule, in any table, that references
# a br-* interface not currently present (`ip link show` fails). A positive
# match on a dead bridge can never fire (harmless clutter); a *negated* match
# on one silently blackholes an IP (the bug). Both are removed; rules for live
# bridges are never touched. The rule is rebuilt as a `-D` delete from its own
# `iptables-save` line, so the exact match (including `! -i`) is preserved.
#
# Idempotent and safe to run before every `docker compose up`. Needs root; it
# re-execs through `sudo -n` when passwordless sudo is available, and SKIPS
# (non-fatal, exit 0) otherwise so a deploy is never blocked by it.

set -u

log() { printf '[prune-iptables] %s\n' "$*"; }

# --- ensure root, or skip gracefully (never block the deploy) ---
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        # Re-exec as root via sh so no execute bit / shebang path is required.
        # After this, id -u is 0 and this branch is not re-entered.
        exec sudo -n sh "$0" "$@"
    fi
    log "not root and no passwordless sudo; skipping orphan prune (non-fatal)"
    exit 0
fi

iface_exists() { ip link show "$1" >/dev/null 2>&1; }

# $1 = *-save command, $2 = the matching iptables command
prune_family() {
    _save=$1
    _cmd=$2
    command -v "$_save" >/dev/null 2>&1 || return 0
    command -v "$_cmd" >/dev/null 2>&1 || return 0

    _table=""
    # Snapshot the ruleset (the pipe is read line by line); each matching rule
    # is deleted from the live table as we go.
    "$_save" 2>/dev/null | while IFS= read -r _line; do
        case $_line in
            \**)
                _table=${_line#\*}
                ;;
            -A*)
                # A br-* token only ever appears here as an interface name
                # (-i / -o / ! -i / ! -o), so scanning tokens is sufficient.
                _dead=""
                for _tok in $_line; do
                    case $_tok in
                        br-*)
                            if ! iface_exists "$_tok"; then
                                _dead=$_tok
                                break
                            fi
                            ;;
                    esac
                done
                [ -n "$_dead" ] || continue

                # Rebuild as a delete, preserving the original spacing
                # (including "! -i"), which `iptables -D` accepts verbatim.
                # shellcheck disable=SC2086
                if "$_cmd" -t "$_table" -D ${_line#-A } 2>/dev/null; then
                    log "removed ($_save/$_table, dead bridge $_dead): ${_line#-A }"
                else
                    log "WARN could not remove ($_cmd -t $_table -D ${_line#-A })"
                fi
                ;;
        esac
    done
}

prune_family iptables-save iptables
prune_family ip6tables-save ip6tables

log "done"
exit 0
