#!/bin/bash
# replicate_user_to_honeypot.sh - Copies ONE adversary's own WordPress account
# from production into the honeypot pool they have just been diverted to, so
# they remain logged in on the pool exactly as they were on production and
# nothing hints they have been moved into a honeypot ("account persistence",
# request 26).
#
# Run by the `honeypot_user_sync` service (docker-compose.yml) as a long-lived
# consumer: it BLPOPs jobs off the Redis list `honeypot_user_copy_queue`, which
# the reverse proxy (edge) RPUSHes to at the moment it routes a
# suspicious-but-authenticated visitor to a pool (gdpr_handler.enqueue_user_
# replication). Each job is a JSON object: {"user":"<login>","pool":<N>,...}.
#
# WHAT GETS COPIED (deliberately a single self-owned account, nothing else):
#   wp_users    - the ONE row WHERE user_login = <job user> (id, login, the
#                  password hash, email, display name, registration date...).
#   wp_usermeta - every row WHERE user_id = <that row's ID> (profile fields and,
#                  crucially, the wp_capabilities / wp_user_level rows that ARE
#                  the user's role -- so a subscriber stays a subscriber, an
#                  editor stays an editor, per request 26's clarification).
#
# WHY THIS RELAXES THE "NO REAL USERS IN A HONEYPOT" INVARIANT, AND HOW IT STAYS
# SAFE: honeypot pool databases normally have wp_users/wp_usermeta WIPED at seed
# (honeypot_database_migrations/01_clean-honeypot-data.sql) and the ongoing
# content sync (replicate_content_to_honeypot.sh) NEVER copies them -- real
# customer/account data must not reach a honeypot. This script deliberately
# makes ONE narrow exception: it copies the adversary's OWN account, and only
# ever that. The `user` in every job is a PRODUCTION-VERIFIED login (the edge
# derives it from production's own X-Auth-User header, never the spoofable
# gdpr_token username -- see gdpr_handler.lua / nginx.conf), so a client cannot
# name someone else's account to have its hash/email copied into a honeypot it
# controls. As defence-in-depth this script ALSO rejects any login that is not a
# syntactically valid WordPress user_login before it ever reaches SQL.
#
# NON-DESTRUCTIVE / IDEMPOTENT APPLY: the copy is keyed on the production row's
# own primary keys. On the pool it DELETEs that user's existing rows (scoped by
# the same ID) and REPLACE-INTOs fresh copies inside one short transaction, so
# re-processing the same user (the edge may enqueue on several requests before
# the first copy lands) converges to the same result and never duplicates or
# half-copies. A user not yet present on production is skipped; the pool's
# honeypot-account-autologin mu-plugin no-ops until the rows exist, then logs
# the account in.
#
# ISOLATION: like replicate_content_to_honeypot.sh, the pool connection uses
# --local-infile=0 so a rogue MySQL server on a compromised pool cannot read
# this container's environment (production's and Redis's passwords); production
# is read with --single-transaction so it is never locked.

set -u

MYSQL_USER="production_user"
MYSQL_DATABASE="production_database"
PROD_HOST="production_database"

REDIS_HOST="${REDIS_HOST:-session_store}"
# How long each BLPOP blocks before the loop comes round again (to log a
# heartbeat and re-check Redis health). 0 would block forever; a finite timeout
# keeps the consumer responsive to shutdown without busy-looping.
USER_SYNC_BLOCK_SECONDS="${USER_SYNC_BLOCK_SECONDS:-15}"
USER_COPY_QUEUE="honeypot_user_copy_queue"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

log() {
    echo "[user-sync $(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
}

# Pool number -> that pool's own DB user password (never production's
# MYSQL_PASSWORD, which only reads production). Identical contract to
# replicate_content_to_honeypot.sh's pool_password().
pool_password() {
    case "$1" in
        1) echo "${MYSQL_PASSWORD_POOL_1:-}" ;;
        2) echo "${MYSQL_PASSWORD_POOL_2:-}" ;;
        3) echo "${MYSQL_PASSWORD_POOL_3:-}" ;;
        # Runtime pools get a random password from pool_manager, kept in Redis.
        *) redis-cli -h "$REDIS_HOST" -a "$REDIS_PASSWORD" GET "honeypot_pool:pw:$1" 2>/dev/null ;;
    esac
}

pool_host() {
    echo "honeypot_database_$1"
}

# --default-character-set=binary for the same serialized-blob reason documented
# at length in replicate_content_to_honeypot.sh: some usermeta values are
# PHP-serialized (wp_capabilities, session tokens) and must transfer byte-exact.
prod_mysql() {
    mysql -h "$PROD_HOST" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" --default-character-set=binary -N "$@"
}

prod_mysqldump() {
    mysqldump -h "$PROD_HOST" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" \
        --default-character-set=binary \
        --single-transaction --no-create-info --skip-add-drop-table \
        --skip-triggers --skip-add-locks --skip-comments --compact \
        --no-tablespaces "$@"
}

# A syntactically valid WordPress user_login, as sanitize_user() would leave it:
# letters, digits, space, and . _ - @ only. No quotes or backslashes, so the
# value is safe to embed in the SQL WHERE clauses below. Returns 0 (valid) or 1.
is_valid_login() {
    case "$1" in
        "" ) return 1 ;;
    esac
    # Reject anything outside the allow-listed character class.
    printf '%s' "$1" | grep -qE '^[A-Za-z0-9 ._@-]+$'
}

# Copy a single production account into one pool. Args: <login> <pool_num>.
replicate_user() {
    local login="$1" pool_num="$2" db_host db_pass user_id sql_file="$WORKDIR/user_sync.sql"

    if ! is_valid_login "$login"; then
        log "rejecting job: '$login' is not a valid WordPress login -- ignored"
        return 0
    fi
    case "$pool_num" in
        ''|*[!0-9]*) log "rejecting job: pool '$pool_num' is not a number -- ignored"; return 0 ;;
    esac

    db_host=$(pool_host "$pool_num")
    db_pass=$(pool_password "$pool_num")
    if [ -z "$db_pass" ]; then
        log "pool $pool_num: no DB password known -- cannot copy user '$login', skipping"
        return 0
    fi

    # Resolve the production user ID so wp_usermeta can be scoped to it. A
    # missing user (not on production) is a no-op -- the autologin mu-plugin
    # waits for the rows, so there is nothing to do yet.
    user_id=$(prod_mysql "$MYSQL_DATABASE" -e \
        "SELECT ID FROM wp_users WHERE user_login='$login' LIMIT 1")
    if [ -z "$user_id" ] || [ "$user_id" = "NULL" ]; then
        log "user '$login' not found on production -- nothing to copy for pool $pool_num"
        return 0
    fi
    case "$user_id" in
        ''|*[!0-9]*) log "unexpected non-numeric user id '$user_id' for '$login' -- skipping"; return 0 ;;
    esac

    {
        echo "SET FOREIGN_KEY_CHECKS=0;"
        echo "START TRANSACTION;"
        # Scoped to THIS user's own id only -- never touches any other account,
        # nor any content/order rows (same "destroy nothing else" principle the
        # content sync follows).
        echo "DELETE FROM wp_usermeta WHERE user_id=$user_id;"
        echo "DELETE FROM wp_users WHERE ID=$user_id;"
    } > "$sql_file"

    # Parent (wp_users) before children (wp_usermeta). --replace keeps the apply
    # idempotent regardless of any row the pool might already hold for this id.
    prod_mysqldump --replace --where="user_login='$login'" \
        "$MYSQL_DATABASE" wp_users >> "$sql_file" || { log "dump of wp_users for '$login' failed"; return 0; }
    prod_mysqldump --replace --where="user_id=$user_id" \
        "$MYSQL_DATABASE" wp_usermeta >> "$sql_file" || { log "dump of wp_usermeta for '$login' failed"; return 0; }

    {
        echo "COMMIT;"
        echo "SET FOREIGN_KEY_CHECKS=1;"
    } >> "$sql_file"

    if mysql --local-infile=0 -h "$db_host" -u"$MYSQL_USER" -p"$db_pass" \
            --default-character-set=binary "$MYSQL_DATABASE" < "$sql_file"; then
        log "copied account '$login' (id=$user_id) into pool $pool_num ($db_host)"
    else
        log "pool $pool_num ($db_host): copying account '$login' FAILED -- edge will re-enqueue on the next diverted request"
    fi
    return 0
}

# Extract a scalar field from a flat one-level JSON object without jq (not in
# this EL7-based image). `field_name` -> value, string or number. Returns the
# raw value with surrounding quotes stripped, or empty if absent.
json_field() {
    local json="$1" key="$2"
    # Try quoted (string) form first, then bare (numeric) form.
    printf '%s' "$json" \
        | grep -oE "\"$key\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+)" \
        | head -n1 \
        | sed -E "s/\"$key\"[[:space:]]*:[[:space:]]*//; s/^\"//; s/\"$//"
}

process_job() {
    local job="$1" user pool
    if [ -z "$job" ]; then
        return 0
    fi
    user=$(json_field "$job" "user")
    pool=$(json_field "$job" "pool")
    if [ -z "$user" ] || [ -z "$pool" ]; then
        log "malformed job (missing user/pool), ignored: $job"
        return 0
    fi
    replicate_user "$user" "$pool"
}

log "honeypot user sync starting -- consuming $USER_COPY_QUEUE (block ${USER_SYNC_BLOCK_SECONDS}s)"

while true; do
    # BLPOP prints two lines on a pop: the key name, then the value. On timeout
    # it prints nothing and exits 0. 2>/dev/null hides redis-cli's
    # "using a password on the command line" warning without --no-auth-warning
    # (fatal on this image's old redis-cli -- see replicate_content_to_honeypot.sh).
    popped=$(redis-cli -h "$REDIS_HOST" -a "$REDIS_PASSWORD" \
        BLPOP "$USER_COPY_QUEUE" "$USER_SYNC_BLOCK_SECONDS" 2>/dev/null) || {
            log "redis BLPOP failed (Redis unreachable?) -- retrying shortly"
            sleep 2
            continue
        }
    # Second line (if any) is the job JSON.
    job=$(printf '%s\n' "$popped" | sed -n '2p')
    [ -z "$job" ] && continue   # timeout with no job: loop and block again
    process_job "$job"
done
