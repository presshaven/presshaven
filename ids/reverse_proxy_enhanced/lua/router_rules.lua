-- router_rules.lua - Pure routing predicates used by router.lua
--
-- PURPOSE:
--   Holds the standalone "is this request/session suspicious in way X"
--   predicates that router.lua's decide_route() consults. Factored out with
--   the same intent as pattern_rules.lua: no ngx.* dependency, no reliance on
--   _G.config/_G.utils, plain-`lua`-interpreter testable (see
--   tests/test_router_rules.lua).
--
--   decide_route() itself is NOT moved here. Its staged pipeline deeply
--   interleaves session mutation with Redis I/O (pool_router, AbuseIPDB
--   report-back via assign_honeypot_pool) at almost every stage -- forcing
--   that into a pure core would mean either faking a large I/O surface in
--   tests or fundamentally restructuring the routing algorithm, both of
--   which risk introducing a subtle bug in the single most safety-critical
--   function in this codebase (get honeypot/production separation wrong and
--   the entire deception layer is compromised). router.lua stays the
--   adapter for that function; only the self-contained predicate checks
--   below move here.
--
-- NOTE ON is_static_asset: this used to have two independently-maintained
-- copies (router.lua and pattern_analyzer.lua) that disagreed on whether to
-- strip the query string before matching -- router.lua's stripped it,
-- pattern_analyzer.lua's (now pattern_rules.lua's) didn't, so a request like
-- "style.css?v=123" was classified as static by one and not the other.
-- This module's version (query-string-stripping, the more correct
-- behaviour) is now the single implementation router.lua uses; pattern_rules
-- still has its own copy since the two modules must stay independently
-- requireable, but see pattern_rules.lua's is_static_asset docstring, which
-- now cross-references this one.

local pattern_utils = require "lua_pattern_utils"

local decay_policy = require "decay_policy"

local _M = {}

-- escape_pattern: see lua_pattern_utils.lua for the implementation and the
-- is_vulnerable_plugin_access() hyphen-escaping bug this fixes. Re-exported
-- here for backward compatibility with anything already calling
-- router_rules.escape_pattern() directly.
local escape_pattern = pattern_utils.escape_pattern
_M.escape_pattern = escape_pattern

-- Re-exported for the same reason: decide_route()'s install.php
-- not-yet-installed fast path needs the exact same matcher
-- pattern_analyzer.lua uses, so the two can never quietly disagree (see
-- lua_pattern_utils.lua's own comment on this function, and this file's
-- NOTE ON is_static_asset above for the exact bug class that already
-- happened once from independently-maintained copies).
_M.is_install_wizard_uri = pattern_utils.is_install_wizard_uri

-- ---------------------------------------------------------------------------
-- is_static_asset(uri, static_asset_patterns)
--
-- @param uri                     string|nil
-- @param static_asset_patterns   table|nil  List of Lua patterns (from
--                                            _G.config.threat.static_asset_patterns).
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_static_asset(uri, static_asset_patterns)
    if not uri then
        return false
    end

    local uri_lower = string.lower(uri)

    -- Strip query string for pattern matching (e.g. "style.css?v=123" should
    -- still match "%.css$").
    local uri_path = uri_lower:match("^([^?]+)") or uri_lower

    if static_asset_patterns then
        for _, pattern in ipairs(static_asset_patterns) do
            if string.find(uri_path, pattern) then
                return true
            end
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- is_vulnerable_plugin_access(uri, vulnerable_plugins, static_asset_patterns)
--
-- @param uri                     string|nil
-- @param vulnerable_plugins      table  List of plugin slugs (from
--                                       _G.config.vulnerability.plugins).
-- @param static_asset_patterns   table|nil
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_vulnerable_plugin_access(uri, vulnerable_plugins, static_asset_patterns)
    if not uri then
        return false
    end

    -- Don't flag static assets from plugins as vulnerable.
    if _M.is_static_asset(uri, static_asset_patterns) then
        return false
    end

    local uri_lower = string.lower(uri)

    for _, plugin in ipairs(vulnerable_plugins or {}) do
        if string.find(uri_lower, "/wp%-content/plugins/" .. escape_pattern(plugin) .. "/") then
            return true
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- is_admin_access(uri)
--
-- Detects requests to the actual WordPress/generic admin PANEL -- pages
-- that only make sense for an authenticated admin or someone probing for
-- one (WSTG-ATHN-04's basis for router.lua's Stage 7 repeated-probing
-- escalation, and session_rules.lua's "direct_admin_access" first-request
-- signal).
--
-- Deliberately excludes admin-ajax.php even though it lives under
-- /wp-admin/: it's WordPress's public, unauthenticated AJAX gateway, hit
-- automatically by ordinary frontend JS on essentially every WooCommerce
-- page load (cart fragments, stock/price sync, "recently viewed", ...) --
-- not a signal that someone is trying to reach the admin panel. Confirmed
-- live this was escalating an entirely normal shopper straight to the
-- honeypot after their third product-page view, since each page load
-- fires its own admin-ajax.php call and Stage 7 escalates at the third
-- occurrence within a session. admin-ajax.php gets its own dedicated,
-- appropriately-scoped analysis elsewhere (pattern_analyzer.lua's Stage 6b,
-- upload_handler.lua, the CVE action-name checks in Stage 3) -- it doesn't
-- need (and must not get) blanket treatment as "admin area access" here.
--
-- @param uri  string|nil
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_admin_access(uri)
    if not uri then
        return false
    end

    local uri_lower = string.lower(uri)

    if string.find(uri_lower, "/wp%-admin/admin%-ajax%.php") then
        return false
    end

    local admin_patterns = {
        "/wp%-admin/",
        "/wp%-login%.php",
        "/admin/",
        "/administrator/",
        "/wp%-config%.php"
    }

    for _, pattern in ipairs(admin_patterns) do
        if string.find(uri_lower, pattern) then
            return true
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- is_studio_passthrough(configured_secret, header_secret, header_backend)
--
-- True only for a dashboard "WordPress Studio" request: one that presents the
-- internal-test shared secret AND asks (X-Studio-Backend: production) to be
-- force-routed to production. The nginx access phase uses this to send the
-- embedded wp-admin panel straight to production and skip scoring/routing, so
-- an operator editing content/settings is never diverted into a honeypot
-- mid-edit (the /wp-admin/* count path would otherwise divert after ~3 hits)
-- and never poisons their own IP's reputation.
--
-- Fail-closed, exactly like the X-Route-Target debug headers and
-- /internal-threat-reset: if no secret is configured, or the presented secret
-- does not match, or the backend header is not "production", it returns false
-- and the request is scored normally. No external client that lacks the secret
-- can reach production this way. Pure (no ngx.*) so it is testable standalone.
--
-- @param configured_secret string|nil  _G.config.internal_test_secret
-- @param header_secret      string|nil  X-Internal-Test-Auth request header
-- @param header_backend     string|nil  X-Studio-Backend request header
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_studio_passthrough(configured_secret, header_secret, header_backend)
    if not configured_secret or configured_secret == "" then
        return false
    end
    if header_secret ~= configured_secret then
        return false
    end
    return header_backend == "production"
end

-- ---------------------------------------------------------------------------
-- studio_honeypot_target(configured_secret, header_secret, header_backend, header_pool, max_pool)
--
-- The dashboard "Targeted Access" page's counterpart to is_studio_passthrough:
-- the same secret-gated passthrough, but for jumping straight into ONE
-- honeypot pool's wp-admin (X-Studio-Backend: honeypot + X-Studio-Pool: <N>)
-- instead of production, so an operator can confirm what a specific pool is
-- actually serving -- e.g. that a WordPress Studio propagation landed --
-- without scoring/session routing ever diverting or mis-targeting the check.
--
-- Fail-closed exactly like is_studio_passthrough: a wrong/missing secret, a
-- backend header that isn't "honeypot", or a pool number that doesn't parse
-- as a positive integer within 1..max_pool all return nil. max_pool is the
-- number of statically-declared nginx `upstream honeypot_backend_N` blocks
-- (see pool_router_rules.STATIC_POOL_COUNT) -- a pool created later at
-- runtime has no static upstream a single request can be force-routed to.
--
-- @param configured_secret string|nil  _G.config.internal_test_secret
-- @param header_secret      string|nil  X-Internal-Test-Auth request header
-- @param header_backend     string|nil  X-Studio-Backend request header
-- @param header_pool        string|nil  X-Studio-Pool request header
-- @param max_pool           number|nil  pool_router_rules.STATIC_POOL_COUNT
-- @return string|nil  "honeypot_backend_<N>" upstream name, or nil
-- ---------------------------------------------------------------------------
function _M.studio_honeypot_target(configured_secret, header_secret, header_backend, header_pool, max_pool)
    if not configured_secret or configured_secret == "" then
        return nil
    end
    if header_secret ~= configured_secret then
        return nil
    end
    if header_backend ~= "honeypot" then
        return nil
    end
    local pool_num = tonumber(header_pool)
    if not pool_num or pool_num ~= math.floor(pool_num) or pool_num < 1 then
        return nil
    end
    if not max_pool or pool_num > max_pool then
        return nil
    end
    return "honeypot_backend_" .. pool_num
end

-- ---------------------------------------------------------------------------
-- is_rapid_automation(session_data, pattern_result, current_time)
--
-- @param session_data  table|nil
-- @param pattern_result table|nil
-- @param current_time  number  e.g. ngx.time()
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_rapid_automation(session_data, pattern_result, current_time)
    if not session_data then
        return false
    end

    -- Check request frequency.
    if session_data.created_at and session_data.request_count then
        local session_duration = current_time - session_data.created_at
        if session_duration > 0 then
            local requests_per_second = session_data.request_count / session_duration
            if requests_per_second > 20 then
                return true
            end
        end
    end

    -- Check for automation tool signatures.
    if pattern_result and pattern_result.details then
        for _, detail in ipairs(pattern_result.details) do
            if string.find(detail, "automation_detected") then
                return true
            end
        end
    end

    -- Check timing patterns.
    if session_data.last_activity then
        local time_diff = current_time - session_data.last_activity
        if time_diff < 1 and session_data.request_count and session_data.request_count > 50 then
            return true
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- decayed_score(session_data, current_time, half_life_seconds)
--
-- A honeypot-bound session's stored peak risk_score (session_data.
-- risk_score, set via math.max() elsewhere in router.lua so it only ever
-- ratchets UP on a new suspicious signal), exponentially decayed based on
-- how long it's been since the LAST suspicious signal
-- (session_data.last_threat_time, only touched when a signal actually
-- fires -- a genuinely clean request never moves it). Used by router.lua's
-- Stage 2 to decide whether a previously-flagged session has earned its
-- way back to production: a single clean request barely moves this (the
-- elapsed time since last_threat_time is ~0), but sustained clean behavior
-- over multiple half-lives brings it down.
--
-- Deliberately does NOT get called on every request to progressively
-- shrink the STORED value -- that would compound incorrectly across
-- repeated evaluations. The stored peak stays fixed; only this computed,
-- never-persisted view of it decays.
--
-- @param session_data      table|nil
-- @param current_time      number  e.g. ngx.time()
-- @param half_life_seconds number  e.g. _G.config.threat.score_decay_half_life_seconds
-- @return number  the decayed score (never negative, never above the stored peak)
-- ---------------------------------------------------------------------------
function _M.decayed_score(session_data, current_time, half_life_seconds, cfg)
    if not session_data then
        return 0
    end

    local peak = session_data.risk_score or 0
    if peak <= 0 then
        return 0
    end

    local anchor = session_data.last_threat_time or session_data.updated_at or session_data.created_at
    if not anchor or not half_life_seconds or half_life_seconds <= 0 then
        return peak
    end

    local elapsed = current_time - anchor
    if elapsed <= 0 then
        return peak
    end

    -- Escalation-aware decay: a session that has fired more attack signals
    -- (session_data.offenses, bumped by router.lua each time a genuinely new
    -- signal ratchets the peak up) fades more slowly, and past the permaflag
    -- thresholds not at all -- so a user can no longer alternate
    -- "run pattern" / "wait" to keep re-earning production access. `cfg` is
    -- _G.config.threat, passed in by router.lua to keep this module pure
    -- (nil cfg = plain base-rate decay, as the unit tests use). See
    -- lua/decay_policy.lua.
    return decay_policy.decay(peak, elapsed, half_life_seconds, session_data.offenses, cfg)
end

-- ---------------------------------------------------------------------------
-- is_suspicious_upload(method, uri, content_type, args)
--
-- @param method        string|nil  e.g. ngx.var.request_method
-- @param uri           string|nil  e.g. ngx.var.request_uri
-- @param content_type  string|nil  e.g. ngx.var.content_type
-- @param args          string|nil  e.g. ngx.var.args
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_suspicious_upload(method, uri, content_type, args)
    if method ~= "POST" then
        return false
    end

    uri = uri or ""
    content_type = content_type or ""
    args = args or ""

    if string.find(string.lower(uri), "upload") or
       string.find(string.lower(content_type), "multipart/form%-data") then

        local suspicious_upload_patterns = {
            "%.php", "%.jsp", "%.asp", "%.exe", "%.sh", "%.bat", "%.cmd"
        }

        for _, pattern in ipairs(suspicious_upload_patterns) do
            if string.find(string.lower(args), pattern) then
                return true
            end
        end

        if string.find(args, "dnd_codedropz_upload") or
           string.find(args, "mwb_wgm_preview_mail") or
           string.find(args, "pc_added_uploaded_image") then
            return true
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- check_geographic_anomalies(session_data, current_ip)
--
-- @param session_data  table|nil
-- @param current_ip    string
-- @return table  { anomaly_detected, anomaly_type, score_increase }
-- ---------------------------------------------------------------------------
function _M.check_geographic_anomalies(session_data, current_ip)
    if session_data and session_data.ip_address and session_data.ip_address ~= current_ip then
        return {
            anomaly_detected = true,
            anomaly_type = "ip_change",
            score_increase = 15
        }
    end

    return {
        anomaly_detected = false,
        score_increase = 0
    }
end

-- ---------------------------------------------------------------------------
-- analyze_behavior_patterns(session_data, current_time, request_uri)
--
-- @param session_data  table|nil
-- @param current_time  number  e.g. ngx.time()
-- @param request_uri   string|nil  e.g. ngx.var.request_uri
-- @return table  { score, patterns[] }
-- ---------------------------------------------------------------------------
function _M.analyze_behavior_patterns(session_data, current_time, request_uri)
    if not session_data then
        return { score = 0, patterns = {} }
    end

    local behavior_score = 0
    local patterns = {}

    if session_data.request_count then
        if session_data.created_at then
            local session_age = current_time - session_data.created_at
            if session_age > 0 and session_data.request_count / session_age > 3 then
                behavior_score = behavior_score + 20
                table.insert(patterns, "high_request_frequency")
            end
        end

        if session_data.request_count == 1 and _M.is_admin_access(request_uri) then
            behavior_score = behavior_score + 15
            table.insert(patterns, "direct_admin_access")
        end
    end

    if session_data.suspicious_activities then
        local recent_activities = 0

        for _, activity in ipairs(session_data.suspicious_activities) do
            if current_time - activity.timestamp < 300 then
                recent_activities = recent_activities + 1
            end
        end

        if recent_activities >= 3 then
            behavior_score = behavior_score + 25
            table.insert(patterns, "multiple_recent_suspicious_activities")
        end
    end

    return {
        score = behavior_score,
        patterns = patterns
    }
end

-- ---------------------------------------------------------------------------
-- decision_trace(fresh_score, decayed_base, session_data, pattern_result,
--                half_life_seconds, cfg)
--
-- The "why" behind one routing decision, as flat strings for nginx's
-- `security` access log (nginx.conf's log_format security), which Vector
-- parses into Kibana fields. Without it the log only carried the final
-- effective score, so Kibana could show *that* a request went to the
-- honeypot but not what this request contributed, how much was carried over
-- from the session's decaying history, or whether the URI itself looked like
-- an attack.
--
--   request_score  this request's own fresh score, before accumulation
--   decayed_score  the session's carried-over score after decay (0 if none)
--   offenses       recorded attack signals on the session so far
--   decay_state    "none"        no prior score to decay
--                  "off"         decay disabled (half-life <= 0)
--                  "permaflagged" a confirmed flagged user: never decays
--                  "decaying"    prior score fading toward production
--   uri_class      "attack_pattern" if any URI/CVE pattern matched, else "safe"
--   patterns       matched pattern/CVE names joined with "|", or "-"
--
-- Values are sanitised (no quotes, spaces or backslashes) so they can't break
-- the quoted key="value" log format.
-- ---------------------------------------------------------------------------
local function log_safe(v)
    v = tostring(v == nil and "-" or v)
    v = v:gsub('[%s"\\]', "_")
    if v == "" then return "-" end
    if #v > 200 then v = v:sub(1, 200) end
    return v
end

function _M.decision_trace(fresh_score, decayed_base, session_data, pattern_result,
                           half_life_seconds, cfg)
    session_data = session_data or {}
    pattern_result = pattern_result or {}
    cfg = cfg or {}
    local offenses = tonumber(session_data.offenses) or 0
    local peak = tonumber(session_data.risk_score) or 0

    local decay_state
    if peak <= 0 then
        decay_state = "none"
    elseif decay_policy.is_permaflagged(peak, offenses, cfg.permaflag_score, cfg.permaflag_offenses) then
        decay_state = "permaflagged"
    elseif not half_life_seconds or half_life_seconds <= 0 then
        decay_state = "off"
    else
        decay_state = "decaying"
    end

    local names, seen = {}, {}
    for _, list in ipairs({ pattern_result.patterns_matched or {}, pattern_result.cve_matched or {} }) do
        for _, p in ipairs(list) do
            local name = type(p) == "table" and (p.cve or p.name or p.id) or p
            name = name and log_safe(name)
            if name and name ~= "-" and not seen[name] then
                seen[name] = true
                names[#names + 1] = name
            end
        end
    end

    return {
        request_score = tostring(math.floor((tonumber(fresh_score) or 0) + 0.5)),
        decayed_score = tostring(math.floor((tonumber(decayed_base) or 0) + 0.5)),
        offenses      = tostring(offenses),
        decay_state   = decay_state,
        uri_class     = (#names > 0) and "attack_pattern" or "safe",
        patterns      = (#names > 0) and log_safe(table.concat(names, "|")) or "-",
    }
end

return _M
