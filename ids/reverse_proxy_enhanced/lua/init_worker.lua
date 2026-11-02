-- init_worker.lua - Per-worker initialization for Nginx Lua
-- This module initializes worker-specific components and background tasks

local cjson = require "cjson"
local suricata_rules = require "suricata_rules"
local threat_intel = require "threat_intel"

-- Try to load optional modules
local health_check_ok, health_check = pcall(require, "health_check")
if not health_check_ok then
    ngx.log(ngx.WARN, "health_check module not available, health checks will be disabled")
    health_check = nil
end

-- Worker-specific initialization
local function init_worker()
    -- Initialize random seed for this worker
    math.randomseed(ngx.time() + ngx.worker.pid())
    
    -- Ready honeypot pool numbers: Redis-backed (honeypot_pool:ready), so pools
    -- pool_manager creates later are health-checked and replicated to as well.
    local function current_pool_ids()
        local ok, pool_router = pcall(require, "pool_router")
        if ok then
            return pool_router.get_pool_ids()
        end
        return { 1, 2, 3 }
    end

    -- No connection pre-warming. It used to open 20 keepalive connections to
    -- production (5 per pool) from EVERY worker at start-up and on every
    -- reload -- a burst of a few hundred `HEAD /robots.txt` lines in the
    -- eshop logs -- but the hardened WordPress image runs KeepAlive Off and
    -- one request per Apache child (mpm-black-october.conf), so each warmed
    -- connection was closed the moment it was answered and nothing stayed
    -- warm. Worker 0's periodic health check below is the only probe now.
    
    -- Set up periodic tasks only in worker 0 to avoid duplication
    if ngx.worker.id() == 0 then
        -- Schedule periodic health checks for production and all honeypot pool
        -- backends. The health status written here (to the shared
        -- ngx.shared.threat_intel dict, visible to every worker) is read by
        -- pool_router.lua's is_pool_healthy()/find_healthy_pool() to decide
        -- whether to fall back to a different honeypot pool when the assigned
        -- one is unhealthy -- production has no equivalent fallback target
        -- (there is only one production instance), so its health status is
        -- monitoring/logging-only; nginx's own upstream max_fails/fail_timeout
        -- (nginx.conf) independently provides production failover.
        --
        -- This registration used to sit OUTSIDE this worker-0 guard, so every
        -- nginx worker process ran its own independent copy of this timer --
        -- with N workers, each backend got checked ~N times every interval
        -- instead of once, and because all workers' timers fire at roughly
        -- the same relative offset (they all start at ~the same time), their
        -- checks landed in the same narrow instant. That let a single moment
        -- of real, transient backend contention trip "3 consecutive
        -- failures" across *different workers'* simultaneous checks almost
        -- instantly, rather than requiring genuine sustained unavailability
        -- across ~3 real intervals as the threshold is meant to represent --
        -- confirmed as the root cause of a real false-positive UNHEALTHY
        -- event in check-me.log (repo root), which fired while a legitimate
        -- user's page load was in progress. Moving this inside the worker-0
        -- guard (matching the AbuseIPDB/session-cleanup/Suricata-log-parser
        -- tasks below, which were already correctly scoped this way) fixes
        -- both the redundant load and the false-positive race.
        -- Keep the shared-dict copy of the ready-pool list fresh: pool_manager
        -- adds/removes pools at runtime.
        local pr_ok, pool_router_mod = pcall(require, "pool_router")
        if pr_ok then
            ngx.timer.at(1, function() pcall(pool_router_mod.refresh_pool_list) end)
            ngx.timer.every(5, function() pcall(pool_router_mod.refresh_pool_list) end)
        end

        if health_check then
            local interval = health_check.HEALTH_CHECK_INTERVAL or 10
            local ok, err = ngx.timer.every(interval, function()
                pcall(function()
                    -- Production instance – uses root path (WordPress returns 200-399).
                    health_check.perform_health_check("production_backend", "http://production_eshop")

                    -- Refresh the ready-pool list straight from Redis before
                    -- probing. current_pool_ids() otherwise reads the shared-dict
                    -- mirror, which the 5 s refresh timer above only catches up
                    -- to every 5 s -- so a pool pool_manager destroyed mid-pass
                    -- (e.g. the scale-down right after a Segmentation Validation
                    -- run) lingered in that mirror and got probed once after its
                    -- honeypot_eshop_N container was already gone, logging an
                    -- alarming but meaningless "[HEALTH] ... check failed:
                    -- connection refused" WARN for a pool that no longer exists.
                    -- destroy() SREMs the pool from Redis' ready set first, so a
                    -- fresh read here never includes it. (Falls back to the
                    -- mirror on a Redis error -- refresh_pool_list leaves the
                    -- dict untouched and returns false.)
                    if pr_ok then pcall(pool_router_mod.refresh_pool_list) end

                    -- Each honeypot pool instance checked independently so that a
                    -- single unhealthy pool does not affect the health status of others.
                    for _, i in ipairs(current_pool_ids()) do
                        health_check.perform_health_check(
                            "honeypot_backend_" .. i,
                            "http://honeypot_eshop_" .. i)
                    end
                end)
            end)
            if not ok then
                ngx.log(ngx.ERR, "Failed to schedule health checks: ", err)
            end
        end

        -- WordPress install-state probe. Feeds wp_install_state.lua's cache,
        -- which pattern_analyzer.lua/router.lua consult so that
        -- /wp-admin/install.php is treated as legitimate traffic (not an
        -- attack) until production has actually completed its first-run
        -- setup wizard -- see wp_install_state.lua's header comment. 30s is
        -- frequent enough to notice a freshly-completed install promptly,
        -- infrequent enough that this is a negligible amount of extra load
        -- (one GET, same cost class as the HEAD health check just above).
        local wp_install_state_ok, wp_install_state = pcall(require, "wp_install_state")
        if wp_install_state_ok then
            local ok, err = ngx.timer.every(30, function()
                pcall(function()
                    wp_install_state.refresh("production_backend", "http://production_eshop")
                end)
            end)
            if not ok then
                ngx.log(ngx.ERR, "Failed to schedule WordPress install-state probe: ", err)
            end
        else
            ngx.log(ngx.WARN, "wp_install_state module not available, install.php fast path disabled")
        end

        -- AbuseIPDB bulk blacklist feed. Populates threat_intel.threat_ips
        -- with high-confidence IPs from the free-tier /blacklist endpoint.
        local abuseipdb_ok, abuseipdb_client = pcall(require, "abuseipdb_client")
        if not abuseipdb_ok then
            ngx.log(ngx.WARN, "abuseipdb_client module not available, AbuseIPDB integration disabled")
        end
        
        -- Start session cleanup task
        local function cleanup_expired_sessions()
            local red, err = _G.redis_pool.get_connection()
            if not red then
                ngx.log(ngx.ERR, "Failed to connect to Redis for session cleanup: ", err)
                return
            end
            
            local current_time = ngx.time()
            local sessions_dict = ngx.shared.sessions
            local keys = sessions_dict:get_keys(1000)
            local cleaned = 0
            
            for _, key in ipairs(keys) do
                local session_data = sessions_dict:get(key)
                if session_data then
                    local session = cjson.decode(session_data)
                    if session.last_activity and (current_time - session.last_activity) > _G.config.session.max_idle_time then
                        sessions_dict:delete(key)
                        -- `key` here is already the full "session:<id>" dict
                        -- key (that's how session_handler.lua stores it) --
                        -- prepending "session:" again produced
                        -- "session:session:<id>", which never matched the
                        -- real Redis key, so this red:del() was always a
                        -- silent no-op. Harmless in practice (the Redis
                        -- record has its own matching TTL via setex and
                        -- expires on its own), but not what this was meant
                        -- to do.
                        red:del(key)
                        cleaned = cleaned + 1
                    end
                end
            end
            
            if cleaned > 0 then
                ngx.log(ngx.INFO, "Cleaned up ", cleaned, " expired sessions")
            end
            
            _G.redis_pool.close_connection(red)
        end
        
        -- Start Suricata log parser.
        --
        -- Reads eve.json (structured JSON alerts), not fast.log. The
        -- previous version regex-parsed fast.log's flat-text format with a
        -- pattern whose capture-group count (8) didn't match its
        -- destination variable count (7) -- Lua silently drops the last
        -- matched value when destructuring into fewer variables than
        -- there are captures, so every field from `priority` onward was
        -- shifted by one position. `src_ip` actually received the
        -- classification TEXT (e.g. "Attempted Denial of Service"), never
        -- a real IP address -- confirmed live against a real fast.log line
        -- before this fix. That meant threat_ips was keyed by that string
        -- instead of the user's IP, so Suricata alerts never actually
        -- reached the real user's IP reputation record, silently, the
        -- whole time. eve.json's fields are named JSON keys, not
        -- positionally inferred, so this bug class can't recur. See
        -- suricata_rules.lua for the pure parsing/scoring logic and its
        -- unit tests (tests/test_suricata_rules.lua).
        local function parse_suricata_logs()
            local red, err = _G.redis_pool.get_connection()
            if not red then
                ngx.log(ngx.ERR, "Failed to connect to Redis for Suricata log parsing: ", err)
                return
            end

            local alert_file = "/var/log/suricata/eve.json"
            local file = io.open(alert_file, "r")
            if file then
                -- Where to resume from. This used to be
                -- `red:get(...) or 0`, which conflated three very
                -- different answers into "start from byte 0":
                --   * a Redis ERROR (nil, err -- e.g. the 1s read timeout
                --     under host contention): the key is still there, we
                --     just didn't get it. Restarting from 0 then rescans
                --     the ENTIRE file -- 600MB+ after a day, since nothing
                --     rotates eve.json -- synchronously, inside nginx
                --     worker 0's event loop. Every request that worker
                --     serves and every other timer (health checks, the
                --     Redis-backed replication-flag mirror) stalls for the
                --     duration, which is how one 1s Redis blip cascaded
                --     into a burst of cosocket timeouts a minute later.
                --     Now: skip this cycle, try again in 30s.
                --   * the key genuinely MISSING (ngx.null -- first run
                --     after session_store's start-time `rm -rf /data/*`):
                --     there is no history worth replaying. suricata_alerts
                --     is capped at the last 1000 entries and threat_ips
                --     scores are time-decayed, so scanning hours of stale
                --     events to rebuild them is the same full-file stall as
                --     above for no benefit. Now: start at the current end
                --     of the file and only ever process new events.
                --   * the stored position being PAST the end of the file
                --     (eve.json truncated/rotated underneath us): seeking
                --     there reads nothing, forever. Now: restart from 0.
                local file_size = file:seek("end")
                local stored, get_err = red:get("suricata_eve_log_position")
                if stored == nil then
                    ngx.log(ngx.WARN, "Suricata log parser: could not read resume position from Redis: ",
                            get_err, " -- skipping this cycle")
                    file:close()
                    _G.redis_pool.close_connection(red)
                    return
                end

                local last_position = tonumber(stored)  -- ngx.null -> nil
                if not last_position then
                    last_position = file_size
                    ngx.log(ngx.INFO, "Suricata log parser: no resume position stored, starting at current end of ",
                            alert_file, " (", file_size, " bytes) -- not replaying history")
                elseif last_position > file_size then
                    ngx.log(ngx.WARN, "Suricata log parser: stored position ", last_position, " is past the end of ",
                            alert_file, " (", file_size, " bytes) -- file was truncated/rotated, restarting from 0")
                    last_position = 0
                end
                file:seek("set", last_position)

                -- Hard cap on how much of the file one cycle may consume.
                -- File reads here are plain blocking io, not cosockets:
                -- everything in this worker (requests AND the other
                -- timers) waits until this loop returns. 8MB is a few
                -- seconds of Suricata output at the very busiest, so a
                -- normal 30s cycle never comes near it -- it only bites
                -- when catching up after a long stall, where it turns one
                -- multi-second freeze into several short ones 30s apart.
                -- `consumed` counts only lines that were fully processed
                -- (each line plus its "\n"), so last_position + consumed
                -- is always the exact byte to resume from -- whether the
                -- loop ended at EOF, at the cap, or at a partial line.
                local MAX_BYTES_PER_CYCLE = 8 * 1024 * 1024
                local consumed = 0

                local alerts_processed = 0
                for line in file:lines() do
                    local line_len = #line + 1
                    if last_position + consumed + line_len > file_size then
                        -- Suricata is mid-write on this line (no trailing
                        -- newline yet when we measured the file): leave it
                        -- for next cycle rather than feeding a truncated
                        -- JSON object to the decoder and then skipping
                        -- past it for good.
                        break
                    end
                    if consumed + line_len > MAX_BYTES_PER_CYCLE then
                        ngx.log(ngx.WARN, "Suricata log parser: hit the ", MAX_BYTES_PER_CYCLE,
                                "-byte per-cycle cap -- resuming from byte ", last_position + consumed,
                                " next cycle")
                        break
                    end
                    consumed = consumed + line_len
                    -- Cheap substring pre-check before paying for a JSON
                    -- decode -- eve.json interleaves alert/flow/netflow/
                    -- http/dns/tls/... event types in one file, and
                    -- flow/netflow accounting events vastly outnumber
                    -- alerts in practice.
                    if suricata_rules.is_alert_line(line) then
                        local ok, decoded = pcall(cjson.decode, line)
                        local alert = ok and suricata_rules.extract_alert(decoded) or nil

                        if alert then
                            -- Store the raw alert (forensic record, same
                            -- 1000-entry cap as before) regardless of
                            -- whether it ends up feeding IP reputation
                            -- below -- still useful for debugging/
                            -- visibility (dashboard's Redis page raw
                            -- alerts list) either way.
                            red:lpush("suricata_alerts", cjson.encode(alert))
                            red:ltrim("suricata_alerts", 0, 1000)

                            if suricata_rules.is_private_ip(alert.src_ip) then
                                -- Suricata runs with network_mode: host +
                                -- interface "any" (see suricata_rules.lua's
                                -- module docstring KNOWN CAVEAT), so it sees
                                -- every hop of a proxied request, not just
                                -- the client->reverse_proxy leg. A private/
                                -- loopback src_ip here is a container-to-
                                -- container hop (e.g. reverse_proxy ->
                                -- production_eshop/honeypot_eshop_N), never
                                -- a genuine external actor -- confirmed
                                -- live: this was writing reverse_proxy's own
                                -- bridge address into threat_ips at score
                                -- 100 instead of (or in addition to) the
                                -- real client/user IP. That address can
                                -- never match a future request's real
                                -- remote_ip anyway (check_ip_reputation()
                                -- always looks up ngx.var.remote_addr,
                                -- nginx's own client-facing view), so
                                -- writing it was pure noise with no actual
                                -- reputation-gating effect -- just a
                                -- misleading entry in threat_ips.
                                ngx.log(ngx.INFO, "Suricata alert not attributed to IP reputation -- src_ip ",
                                        alert.src_ip, " is private/internal (container-to-container hop, not ",
                                        "an attributable external client): ", alert.signature)
                            else
                                -- Update threat intelligence (threat_intel.load
                                -- handles the ngx.null-on-missing-key decode safely).
                                local threat_ips = threat_intel.load(red)

                                -- raw_score is graded by Suricata's own
                                -- severity field (suricata_rules.
                                -- severity_to_score), not a flat +20 per
                                -- alert regardless of what fired -- a
                                -- single confirmed CVE-exploit-attempt
                                -- (priority 1 in local.rules) now moves an
                                -- IP most of the way to Stage 6's >50
                                -- honeypot-diversion threshold on its own; a
                                -- low-priority scan/recon signature
                                -- contributes much less, so noisy
                                -- background scanning doesn't force
                                -- honeypot diversion as readily as a real
                                -- exploit attempt does. Named raw_score
                                -- (not score) to distinguish it from the
                                -- time-decayed number check_ip_reputation()
                                -- actually adds to a request's score (see
                                -- suricata_rules.decayed_score()) -- this
                                -- stored value only ever goes up, capped at
                                -- 100; what's logged/applied per-request is
                                -- smaller once any time has passed. The
                                -- reason string carries the actual matched
                                -- signature (e.g. "suricata: CVE-2023-28121
                                -- ...") through to router.lua's Stage 6
                                -- honeypot_reason instead of a generic
                                -- "bad_ip_reputation".
                                local previous = threat_ips[alert.src_ip]
                                threat_ips[alert.src_ip] = {
                                    raw_score = suricata_rules.next_score(
                                        previous and previous.raw_score, alert.severity),
                                    reason = suricata_rules.build_reason(alert),
                                    updated = ngx.time(),
                                    alert_count = (previous and previous.alert_count or 0) + 1,
                                    -- Uncapped offense count driving decay_policy's
                                    -- escalation (slower decay / permaflag for repeat
                                    -- offenders). Preserved across this rebuild via
                                    -- `previous`. See lua/decay_policy.lua.
                                    offenses = (previous and previous.offenses or 0) + 1,
                                }

                                threat_intel.persist(red, threat_ips)

                                ngx.log(ngx.WARN, "Suricata alert processed: ", alert.src_ip, " -> ", alert.signature,
                                        " (severity ", alert.severity or "?", ", raw_score now ",
                                        threat_ips[alert.src_ip].raw_score, ")")
                            end

                            alerts_processed = alerts_processed + 1
                        end
                    end
                end

                -- Persist the resume position -- see `consumed` above for
                -- why this is computed rather than read back via
                -- file:seek() (lines() has already pulled in whichever line
                -- the loop broke on, so seek() would skip it).
                local ok, set_err = red:set("suricata_eve_log_position", last_position + consumed)
                if not ok then
                    ngx.log(ngx.WARN, "Suricata log parser: could not persist resume position to Redis: ",
                            set_err, " -- the same events may be processed again next cycle")
                end
                file:close()

                if alerts_processed > 0 then
                    ngx.log(ngx.INFO, "Processed ", alerts_processed, " Suricata alerts")
                end
            else
                -- Deliberately NOT silent: a missing/unreadable eve.json
                -- (wrong volume mount, permissions, Suricata not started
                -- yet) used to fail exactly like "no new alerts this
                -- cycle" -- indistinguishable, and this pipeline sat
                -- completely inert for a long time before that was
                -- noticed. Rate-limited to once per 10 minutes (via the
                -- threat_intel shared dict as a cheap timestamp store) so
                -- a genuinely missing mount is still diagnosable quickly
                -- without spamming the log every 30s forever.
                local threat_intel_shared = ngx.shared.threat_intel
                local last_warned = threat_intel_shared and threat_intel_shared:get("suricata_file_missing_warned")
                if not last_warned or (ngx.time() - last_warned) > 600 then
                    ngx.log(ngx.WARN, "Suricata log parser: could not open ", alert_file,
                            " -- check the reverse_proxy service's volume mounts and that suricata_ids is running")
                    if threat_intel_shared then
                        threat_intel_shared:set("suricata_file_missing_warned", ngx.time())
                    end
                end
            end

            _G.redis_pool.close_connection(red)
        end
        
        -- Start rate limit cleanup
        local function cleanup_rate_limits()
            local rate_limit_dict = ngx.shared.rate_limit
            local current_time = ngx.time()
            local keys = rate_limit_dict:get_keys(1000)
            local cleaned = 0
            
            for _, key in ipairs(keys) do
                local data = rate_limit_dict:get(key)
                if data then
                    local rate_data = cjson.decode(data)
                    if rate_data.expires and current_time > rate_data.expires then
                        rate_limit_dict:delete(key)
                        cleaned = cleaned + 1
                    end
                end
            end
            
            if cleaned > 0 then
                ngx.log(ngx.DEBUG, "Cleaned up ", cleaned, " expired rate limit entries")
            end
        end

        -- Mirror honeypot content-replication state from Redis into the
        -- shared dict pool_router.lua's is_pool_healthy() actually reads on
        -- the hot path. scripts/replicate_content_to_honeypot.sh sets/clears
        -- honeypot_pool_replicating:<N> in Redis (the only thing an external
        -- container can reach -- ngx.shared dicts are per-worker-process,
        -- not writable from outside Nginx); this timer is what turns that
        -- into a value is_pool_healthy() can read without a Redis round-trip
        -- per request, same "no Redis on the hot path" convention as every
        -- other shared-dict cache in this codebase (health_check.lua,
        -- pool_router.lua's own LOCAL_CACHE_TTL). 5s keeps the window where
        -- a pool is treated as healthy-but-actually-replicating short.
        local function mirror_replication_flags()
            local red, err = _G.redis_pool.get_connection()
            if not red then
                ngx.log(ngx.WARN, "Failed to connect to Redis for replication-flag mirroring: ", err)
                return
            end

            local threat_intel_shared = ngx.shared.threat_intel

            for _, i in ipairs(current_pool_ids()) do
                local replicating = red:get("honeypot_pool_replicating:" .. i)
                local flag = (replicating and replicating ~= ngx.null) and "1" or "0"
                if threat_intel_shared then
                    threat_intel_shared:set("replicating:honeypot_backend_" .. i, flag)
                end
            end

            -- Mirror the site-wide scheduled-maintenance flag the same way.
            -- The WordPress Update dashboard page SETs honeypot_maintenance in
            -- Redis (with a TTL so it fails safe -- see maintenance.lua) while a
            -- core/WooCommerce upgrade runs; access_by_lua_block reads this
            -- mirrored shared-dict value at the very top of the pipeline and
            -- serves a 503 maintenance page for ALL traffic until it clears.
            -- A missing/expired key mirrors to "0" so the site comes back on
            -- its own even if the dashboard dies mid-update.
            if threat_intel_shared then
                local maint = red:get("honeypot_maintenance")
                local maint_flag = (maint and maint ~= ngx.null) and "1" or "0"
                threat_intel_shared:set("maintenance", maint_flag)
            end

            -- Mirror the dashboard's edge policy (legitimate URL whitelist +
            -- honeypot target URLs, see edge_policy_rules.lua). A missing key
            -- drops the shared-dict copy and every worker falls back to the
            -- built-in defaults.
            if threat_intel_shared then
                pcall(require("edge_policy").mirror, red, threat_intel_shared)
            end

            _G.redis_pool.close_connection(red)
        end

        -- Schedule periodic tasks

        -- AbuseIPDB bulk blacklist feed: opt-in (config.abuseipdb.
        -- blacklist_enabled, off by default -- see init.lua/.env.example),
        -- separate from the API key alone being configured. One delayed
        -- run shortly after startup (so it doesn't compete with connection
        -- pre-warming), then every blacklist_refresh_hours -- but
        -- fetch_blacklist() itself is Redis-cache-aware (abuseipdb_client.
        -- lua) and skips the actual API call whenever the cache is still
        -- fresh, so neither this initial call NOR a reverse_proxy restart
        -- forces a real request against a possibly tiny daily quota.
        if abuseipdb_ok and abuseipdb_client.is_blacklist_enabled() then
            local refresh_seconds = (_G.config.abuseipdb.blacklist_refresh_hours or 24) * 3600

            local ok, err = ngx.timer.at(15, function(premature)
                if premature then return end
                pcall(abuseipdb_client.fetch_blacklist)
            end)
            if not ok then
                ngx.log(ngx.ERR, "Failed to schedule initial AbuseIPDB blacklist fetch: ", err)
            end

            local ok, err = ngx.timer.every(refresh_seconds, function()
                pcall(abuseipdb_client.fetch_blacklist)
            end)
            if not ok then
                ngx.log(ngx.ERR, "Failed to create AbuseIPDB blacklist timer: ", err)
            end
        elseif abuseipdb_ok and abuseipdb_client.is_enabled() then
            ngx.log(ngx.INFO, "[ABUSEIPDB] Blacklist pull disabled (ABUSEIPDB_BLACKLIST_ENABLED=false) -- "
                    .. "on-demand check/report-back remain active")
        else
            ngx.log(ngx.INFO, "[ABUSEIPDB] Integration disabled (no API key configured)")
        end

        local ok, err = ngx.timer.every(_G.config.session.cleanup_interval, function()
            pcall(cleanup_expired_sessions)
        end)
        if not ok then
            ngx.log(ngx.ERR, "Failed to create session cleanup timer: ", err)
        end
        
        local ok, err = ngx.timer.every(30, function() -- Every 30 seconds
            pcall(parse_suricata_logs)
        end)
        if not ok then
            ngx.log(ngx.ERR, "Failed to create Suricata log parser timer: ", err)
        end
        
        local ok, err = ngx.timer.every(60, function() -- Every minute
            pcall(cleanup_rate_limits)
        end)
        if not ok then
            ngx.log(ngx.ERR, "Failed to create rate limit cleanup timer: ", err)
        end

        local ok, err = ngx.timer.every(5, function() -- Every 5 seconds
            pcall(mirror_replication_flags)
        end)
        if not ok then
            ngx.log(ngx.ERR, "Failed to create replication-flag mirror timer: ", err)
        end

        ngx.log(ngx.INFO, "Background tasks initialized in worker 0")
    end
    
    -- Initialize worker-specific data
    local worker_info = {
        worker_id = ngx.worker.id(),
        worker_pid = ngx.worker.pid(),
        start_time = ngx.time()
    }
    
    ngx.log(ngx.INFO, "Worker ", worker_info.worker_id, " (PID: ", worker_info.worker_pid, ") initialized")
end

-- Execute worker initialization
init_worker()