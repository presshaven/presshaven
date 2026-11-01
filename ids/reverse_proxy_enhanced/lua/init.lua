-- init.lua - Nginx Lua initialization module
--
-- PURPOSE:
--   Runs once in the Nginx master process (init_by_lua_file phase) before any
--   worker is spawned.  Sets up the global configuration table (_G.config),
--   utility functions (_G.utils), the Redis connection-pool helpers
--   (_G.redis_pool), and pre-populates the Lua shared dictionaries with
--   seed threat-intelligence data.
--
-- GLOBALS EXPORTED:
--   _G.config       – Nested table with all tunable parameters (see below).
--   _G.utils        – Stateless utility functions (IP whitelist check, UUID
--                     generation, risk-score calculation, event logging).
--   _G.redis_pool   – get_connection() / close_connection() wrappers that
--                     maintain a per-worker keepalive pool to the Redis
--                     session_store service.
--
-- SHARED DICTIONARIES (declared in nginx.conf lua_shared_dict directives):
--   sessions        – Worker-local cache of session JSON blobs (10 MB).
--                     Reduces Redis round-trips on hot paths.
--   threat_intel    – Threat-intelligence data: flagged IPs, flagged
--                     user-agents, and backend health-check results (10 MB).
--   rate_limit      – Per-IP request-rate counters for botnet detection (10 MB).
--   honeypot_routes – Per-IP pool assignments cached locally for 5 min (1 MB).
--
-- CONFIGURATION GUIDE:
--   All values can be overridden at deploy time via environment variables
--   injected through docker-compose.yml.  The password fields specifically
--   MUST be set via env vars; never hardcode secrets in this file.

local cjson = require "cjson"
local redis = require "resty.redis"

-- Session cookie signing key (see _G.config.session.signing_key below). Made
-- here, in the master before workers fork, so every worker shares it.
local SESSION_SIGNING_KEY = os.getenv("SESSION_SIGNING_KEY") or ""
local SESSION_SIGNING_KEY_STABLE = SESSION_SIGNING_KEY ~= ""
if not SESSION_SIGNING_KEY_STABLE then
    local resty_random = require "resty.random"
    SESSION_SIGNING_KEY = require("resty.string").to_hex(
        resty_random.bytes(32, true) or resty_random.bytes(32))
end

-- ---------------------------------------------------------------------------
-- Trusted payment/OAuth callback domains (see pattern_rules.lua). Start from
-- the baked-in provider list, then add (1) extra domains from the optional
-- comma-separated TRUSTED_CALLBACK_DOMAINS env var and (2) the shop's own host
-- parsed from WP_SITE_URL, so a legitimate return/redirect URL to the shop
-- itself is never treated as an external callback. Built once in the master.
local function build_trusted_callback_domains()
    local domains = {}
    for _, d in ipairs(require("pattern_rules").TRUSTED_CALLBACK_DOMAINS) do
        domains[#domains + 1] = d
    end
    local extra = os.getenv("TRUSTED_CALLBACK_DOMAINS") or ""
    for d in extra:gmatch("[^,%s]+") do
        domains[#domains + 1] = d:lower()
    end
    -- Host portion of WP_SITE_URL (strip scheme, path, userinfo and port).
    local site = os.getenv("WP_SITE_URL") or ""
    local authority = site:match("^%a[%w%+%.%-]*://([^/?#]+)") or site:match("^([^/?#]+)")
    if authority and authority ~= "" then
        local hostport = authority:match("@([^@]*)$") or authority
        local host = (hostport:match("^([^:]+)") or hostport):lower():gsub("%.$", "")
        -- Skip loopback placeholders: "localhost" is the dev default, never a
        -- real shop host, and allowlisting it would whitelist SSRF to the proxy.
        if host ~= "" and host ~= "localhost"
            and host ~= "127.0.0.1" and host ~= "[::1]" then
            domains[#domains + 1] = host
        end
    end
    return domains
end
local TRUSTED_CALLBACK_DOMAINS = build_trusted_callback_domains()

-- ---------------------------------------------------------------------------
-- _G.config – Central configuration table
--
-- All sub-tables and their fields are documented inline below.
-- Callers reference values as e.g. _G.config.threat.honeypot_threshold.
-- ---------------------------------------------------------------------------
_G.config = {

    -- -----------------------------------------------------------------------
    -- redis: Connection parameters for the session_store Redis container.
    --
    --   host       – Docker service name; resolved by Docker's embedded DNS.
    --   port       – Default Redis port (no TLS; traffic stays on Docker
    --                bridge networks, never leaves the host).
    --   password   – Read from REDIS_PASSWORD env var injected by docker-compose.
    --                Fallback value is for local development only; MUST be
    --                changed in any internet-facing deployment.
    --   timeout    – Connect/send timeout in milliseconds.  Redis on the
    --                same host typically responds in < 1 ms, so 1 s only
    --                ever trips when something is genuinely wrong.
    --   read_timeout – Reply timeout in milliseconds. Deliberately looser
    --                than `timeout`: confirmed live (session_store's own
    --                slowlog empty, no AOF/fork warnings) that the sporadic
    --                "lua tcp socket read timed out, upstream:
    --                session_store:6379" errors were not Redis being slow
    --                to execute anything, but the reply not being delivered
    --                within 1 s while the host (4 CPUs shared with ES,
    --                Kibana, Suricata, 4x MySQL, 4x PHP) was under load --
    --                a scheduling stall, not a Redis one. Failing a whole
    --                background cycle (Suricata parsing, replication-flag
    --                mirroring) over a 1 s hiccup is worse than waiting a
    --                bit longer, and per-request Redis use is off the hot
    --                path (see init_worker.lua's mirror_replication_flags
    --                note), so this doesn't add latency to normal requests.
    --   pool_size  – Max keepalive connections per Nginx worker to Redis.
    --                100 connections × N workers; tune based on worker count.
    --   backlog    – Nginx connection backlog size (nil = use system default).
    -- -----------------------------------------------------------------------
    redis = {
        host = "session_store",
        port = 6379,
        password = os.getenv("REDIS_PASSWORD") or "session_redis_password",  -- Fallback for backwards compatibility
        -- 2000/5000 (was 1000/3000): confirmed live that under a post-startup
        -- load burst (all 4 DBs bootstrapping + 4 PHP + ES/Kibana on shared
        -- CPUs) even the AUTH reply occasionally missed the old 3 s read
        -- window, logging "Failed to authenticate with Redis: timeout" from a
        -- background timer. Redis itself isn't slow (empty slowlog) -- it's a
        -- host scheduling stall -- so widening the window a bit, plus the
        -- single reconnect retry get_connection() now does, absorbs the
        -- hiccup instead of failing a whole background cycle. Off the hot path
        -- (see init_worker.lua's mirror_replication_flags note), so no
        -- per-request latency cost.
        timeout = 2000,
        read_timeout = 5000,
        pool_size = 100,
        backlog = nil
    },

    -- -----------------------------------------------------------------------
    -- session: HTTP session management parameters.
    --
    --   cookie_name        – Name of the session-tracking cookie set by Nginx.
    --                        "SERVERID" mimics an ordinary load-balancer
    --                        stickiness cookie (HAProxy's default name) so it
    --                        reveals nothing in DevTools. It used to be
    --                        "HONEYPOT_SESSION", which gave the deception away
    --                        in the blind pentest. nginx.conf's `security`
    --                        log_format hardcodes $cookie_SERVERID; keep the two
    --                        in sync.
    --   max_idle_time      – Session TTL in seconds after the last request.
    --                        3600 s (1 hour) matches typical WooCommerce checkout
    --                        session durations so honeypot sessions feel realistic.
    --   cleanup_interval   – How often (seconds) the background session-cleanup
    --                        timer in init_worker.lua runs to evict expired
    --                        entries from the local shared dict.
    --   signing_key        – HMAC key for the signed SERVERID cookie
    --                        ("<session id>.<HMAC>", see
    --                        session_identity_rules.lua). From
    --                        SESSION_SIGNING_KEY; when that is unset a random
    --                        key is made at start-up, so cookies issued before
    --                        a restart stop verifying (their sessions are then
    --                        recovered by fingerprint) and a bad signature
    --                        can't be told apart from tampering.
    --   signing_key_stable – true when the key came from SESSION_SIGNING_KEY;
    --                        only then is a bad signature scored as tampering.
    --   recovery_uses_ip   – Include the client IP in the passive fingerprint
    --                        that recovers a session after its cookie was
    --                        cleared (SESSION_RECOVERY_USES_IP, default true).
    --                        Without it, all visitors with the same browser
    --                        build would share one session. The IP never tells
    --                        two sessions apart on its own.
    --   tamper_score       – Risk score added to a request whose session
    --                        cookie was edited or forged.
    -- -----------------------------------------------------------------------
    session = {
        cookie_name = "SERVERID",
        max_idle_time = 3600,
        cleanup_interval = 300,
        signing_key = SESSION_SIGNING_KEY,
        signing_key_stable = SESSION_SIGNING_KEY_STABLE,
        recovery_uses_ip = (os.getenv("SESSION_RECOVERY_USES_IP") or "true"):lower() ~= "false",
        -- Seconds after a session's last request during which a cookie-less
        -- client with the same fingerprint is recovered into it.
        recovery_window = tonumber(os.getenv("SESSION_RECOVERY_WINDOW")) or 900,
        tamper_score = 50
    },

    -- -----------------------------------------------------------------------
    -- gdpr: consent-gated second identifier that runs ALONGSIDE the SERVERID
    -- session cookie (never replacing it). See lua/gdpr_rules.lua and
    -- lua/gdpr_handler.lua for the full design; ids/GDPR.md for the overview.
    --
    --   enabled          – GDPR_ENABLED (default true). false disables the
    --                      whole subsystem cleanly (no token processing, the
    --                      client script becomes inert).
    --   private_key_b64  – GDPR_PRIVATE_KEY: base64 of the RSA private key in
    --                      DER (PKCS#8). The PUBLIC key handed to browsers is
    --                      derived from it at start-up, so there is only one
    --                      secret to manage and the two can never drift. The
    --                      private key NEVER reaches the client. Blank = the
    --                      subsystem disables itself (fails safe, not open).
    --   timestamp_window – GDPR_TIMESTAMP_WINDOW (default 300s): how far from
    --                      "now" a token's embedded timestamp may be. The
    --                      client re-stamps well inside this; a captured,
    --                      replayed token stops matching once it ages out.
    --   binding_ttl      – GDPR_BINDING_TTL (default 3600s): how long a
    --                      honeypot<->signature binding lives in Redis. It is
    --                      PROLONGED on every match, so an active returning
    --                      user never ages out, but an abandoned one does --
    --                      and nothing identifiable is stored either way (only
    --                      the one-way signature, as a Redis key with this TTL).
    -- -----------------------------------------------------------------------
    gdpr = {
        enabled = (os.getenv("GDPR_ENABLED") or "true"):lower() ~= "false",
        private_key_b64 = os.getenv("GDPR_PRIVATE_KEY") or "",
        timestamp_window = tonumber(os.getenv("GDPR_TIMESTAMP_WINDOW")) or 300,
        binding_ttl = tonumber(os.getenv("GDPR_BINDING_TTL")) or 3600,
    },

    -- -----------------------------------------------------------------------
    -- threat: Risk-scoring and routing parameters.
    --
    --   ip_whitelist       – CIDR ranges or exact IPs that receive a negative
    --                        reputation score (−20) and are never diverted to
    --                        the honeypot.  Should include the operator's admin
    --                        IP, Tailscale tunnel range, and the university/lab
    --                        network used for testing.
    --   max_risk_score   – Hard cap on the accumulated score (100).  Prevents
    --                        a single extremely high-scoring request from
    --                        distorting per-session rolling averages.
    --   honeypot_threshold – Minimum total score that triggers honeypot routing.
    --                        Raised from 50 to 80 after tuning to eliminate
    --                        false-positives on aggressive but legitimate REST
    --                        API clients (WooCommerce mobile app, Stripe webhooks).
    --   score_decay_half_life_seconds – How long a honeypot-bound session's
    --                        stored peak risk_score takes to decay to half
    --                        its value once no new suspicious signal has
    --                        occurred (router.lua Stage 2's "allow production
    --                        again" re-check, router_rules.decayed_score()).
    --                        Added after confirming live that the un-stick
    --                        check previously used only the CURRENT request's
    --                        own score -- a single clean request (e.g. just
    --                        loading "/") fully reset a session that had JUST
    --                        triggered a CVE match moments earlier, letting an
    --                        user freely alternate "run pattern" / "visit
    --                        homepage" to re-run every pattern against
    --                        production from a clean slate every time. 300s (5
    --                        min) means a session can't be un-stuck by one
    --                        click, but a genuinely-reformed/false-positived
    --                        session isn't bound forever either.
    -- -----------------------------------------------------------------------
    threat = {
        ip_whitelist = {
            "127.0.0.1/32",
            "::1/128",          -- IPv6 loopback
            "100.64.0.0/10",    -- Tailscale
            "fd7a:115c:a1e0::/48", -- Tailscale IPv6
            "10.0.0.0/8",       -- Private networks
        },
        max_risk_score = 100,
        honeypot_threshold = 80,  -- Raised from 50 to prevent false positives
        -- Per-address reputation (Suricata alerts, AbuseIPDB) on shared
        -- addresses -- see lua/shared_ip_rules.lua. Everything a client does
        -- itself is scored on its session; the address only adds at most
        -- ip_reputation_cap per request (10 = never enough on its own to
        -- count as a new signal in router.lua's accumulation, so it can't
        -- divert anyone), and nothing at all once shared_ip_sessions
        -- distinct sessions were active on it within shared_ip_window s.
        ip_reputation_cap = tonumber(os.getenv("IP_REPUTATION_CAP")) or 10,
        shared_ip_sessions = tonumber(os.getenv("SHARED_IP_SESSIONS")) or 2,
        shared_ip_window = tonumber(os.getenv("SHARED_IP_WINDOW")) or 3600,
        -- THREAT_DECAY_ENABLED=false turns threat decay OFF entirely: a
        -- half-life of 0 makes every decay path (router_rules/suricata_rules
        -- decayed_score, decay_policy.decay) return the stored peak unchanged,
        -- so a session's / IP's risk score persists indefinitely once earned.
        -- Default true, using SCORE_DECAY_HALF_LIFE_SECONDS (or 300).
        score_decay_half_life_seconds = (function()
            local enabled = (os.getenv("THREAT_DECAY_ENABLED") or "true"):lower()
            if enabled == "false" or enabled == "0" or enabled == "no" then
                return 0
            end
            return tonumber(os.getenv("SCORE_DECAY_HALF_LIFE_SECONDS")) or 300
        end)(),
        -- Escalation of the decay above (see lua/decay_policy.lua): decay is
        -- slowed based on how much abuse a source has actually committed,
        -- tracked as an uncapped `offenses` count (bumped once per recorded
        -- attack -- CVE/pattern/admin/upload signals on the session, and each
        -- threat_ips write on the IP -- so it keeps climbing after the 0-100
        -- score has already pinned at 100).
        --   decay_offense_slowdown: each offense multiplies the half-life by
        --     (1 + this), e.g. 0.75 -> 1 offense = 1.75x slower, 4 = 4x.
        --   permaflag_offenses: at/above this many offenses the score stops
        --     decaying entirely -- a repeat user stays flagged forever.
        --   permaflag_score: a single request whose score reaches this (i.e. a
        --     high-risk pattern that maxes it out) also permaflags on its
        --     own, without waiting for the offense count. Default == the max
        --     score, so "matched a real pattern" == "permanently flagged".
        decay_offense_slowdown = tonumber(os.getenv("DECAY_OFFENSE_SLOWDOWN")) or 0.75,
        permaflag_offenses = tonumber(os.getenv("PERMAFLAG_OFFENSES")) or 5,
        permaflag_score = tonumber(os.getenv("PERMAFLAG_SCORE")) or 100,
        static_asset_patterns = {
            "robots%.txt",
            "sitemap%.xml",
            "%.css",
            "%.js",
            "%.jpg",
            "%.jpeg",
            "%.png",
            "%.gif",
            "%.svg",
            "%.woff",
            "%.woff2",
            "%.ttf",
            "%.eot",
            "%.otf",
            "%.ico",
            "%.webp",
            "%.webm",
            "%.mp4",
            "%.mp3",
            "%.pdf",
            "%.zip",
            "%.tar",
            "%.gz",
            "%.map",
            "/fonts/",
            "/images/",
            "/assets/",
            "/wp%-content/themes/",
            "/wp%-content/plugins/.*%.css",
            "/wp%-content/plugins/.*%.js",
            "/wp%-includes/css/",
            "/wp%-includes/js/",
            "/wp%-includes/fonts/"
        },
        -- suspicious_patterns: Generic OWASP WSTG-INPV attack signatures, tested
        -- against the lower-cased request URI; a match adds +15 to the risk
        -- score. More specific checks with individual scores live in
        -- pattern_rules.analyze_uri_patterns().
        -- Defined (and unit tested) in pattern_rules.lua: each entry says how it
        -- matches (literal text, file extension, parameter name, path segment
        -- or a real Lua pattern), so dots and dashes are never wildcards.
        suspicious_patterns = require("pattern_rules").SUSPICIOUS_PATTERNS,

        -- trusted_callback_domains: Allowlist of registrable domains that a
        -- payment-gateway return/notify callback or OAuth redirect URI may point
        -- at (built above: baked provider list + TRUSTED_CALLBACK_DOMAINS env +
        -- the shop's own WP_SITE_URL host). An absolute http(s)/ftp URL in a
        -- request URI pointing anywhere else is blocked OUTRIGHT with a 403 in
        -- nginx.conf's access phase (before scoring or routing) -- never scored,
        -- so a callback link planted and sent to an innocent visitor cannot
        -- divert or mislabel them. Legitimate WooCommerce gateway/OAuth callbacks
        -- point at a trusted host and pass.
        trusted_callback_domains = TRUSTED_CALLBACK_DOMAINS,

        -- static_asset_patterns: URI suffixes and path prefixes that identify
        -- static assets (CSS, JS, images, fonts).  Requests matching any of
        -- these are short-circuited through the production backend without threat
        -- scoring, session lookup, or pool-router evaluation.  This keeps
        -- per-asset-request overhead near zero on heavily-loaded pages.
        -- NOTE: Keep in sync with the static-asset location block in nginx.conf.
    },

    -- -----------------------------------------------------------------------
    -- vulnerability: Plugin list and CVE detection patterns.
    --
    --   plugins      – List of plugin directory names (as they appear in the
    --                  URL path /wp-content/plugins/<name>/) that are
    --                  intentionally installed in the honeypot instances but
    --                  absent from the production instance.  Any non-static file
    --                  access inside one of these directories is a honeypot
    --                  target (router.lua Stage 1c): diverted regardless of the
    --                  risk score, or scored, per the dashboard edge policy
    --                  (edge_policy.lua), which can also disable a plugin.
    --
    --   cve_patterns – Map of CVE ID → Lua string pattern.  pattern_analyzer.lua
    --                  checks these against the URI, query string, and request
    --                  headers.  A match is a honeypot target (router.lua Stage
    --                  1c): diverted directly or scored +target_score (default
    --                  40), per the dashboard edge policy (edge_policy.lua).
    --                  Patterns use Lua magic-character escaping (%- for literal
    --                  hyphen, %[ %] for brackets, etc.).
    -- -----------------------------------------------------------------------
    -- -----------------------------------------------------------------------
    -- abuseipdb: AbuseIPDB threat-intelligence integration parameters.
    --
    --   api_key             – Read from ABUSEIPDB_API_KEY env var.  When nil or
    --                         the placeholder value, abuseipdb_client disables
    --                         itself (bulk feed, on-demand checks, report-back
    --                         all become no-ops) so the system runs fine
    --                         without a key configured.
    --   confidence_minimum  – AbuseIPDB confidence score (0-100) threshold used
    --                         when pulling the bulk /blacklist feed.  Only IPs
    --                         at or above this confidence are imported into
    --                         threat_intel.
    --   daily_check_limit   – Free-tier daily cap on on-demand /check calls.
    --                         abuseipdb_client tracks a counter in the
    --                         threat_intel shared dict keyed by UTC date and
    --                         refuses further checks once the cap is reached.
    -- -----------------------------------------------------------------------
    abuseipdb = {
        api_key = os.getenv("ABUSEIPDB_API_KEY"),
        confidence_minimum = tonumber(os.getenv("ABUSEIPDB_CONFIDENCE_MINIMUM")) or 90,
        daily_check_limit = tonumber(os.getenv("ABUSEIPDB_DAILY_CHECK_LIMIT")) or 1000,
        -- blacklist_enabled: separate opt-in from just "is an API key
        -- configured" (abuseipdb_client.is_enabled()) -- the bulk
        -- /blacklist pull is the single biggest quota consumer of the
        -- three AbuseIPDB integrations (bulk pull vs. one-IP-at-a-time
        -- check/report), and free-tier accounts can have a real daily cap
        -- as low as single digits. Defaults OFF: on-demand check/report
        -- stay available (their own, much cheaper, per-IP quota already
        -- tracked via daily_check_limit) even when this is off.
        blacklist_enabled = (os.getenv("ABUSEIPDB_BLACKLIST_ENABLED") or "false") == "true",
        -- blacklist_refresh_hours: minimum age (in the Redis-backed cache,
        -- see abuseipdb_client.lua's load_cached_blacklist()) before a
        -- fresh /blacklist call is allowed at all -- restarting
        -- reverse_proxy no longer forces a fresh API call by itself.
        -- Default 24h keeps this to at most 1 call/day even under
        -- frequent restarts, leaving headroom under a small daily quota.
        blacklist_refresh_hours = tonumber(os.getenv("ABUSEIPDB_BLACKLIST_REFRESH_HOURS")) or 24
    },

    -- -----------------------------------------------------------------------
    -- body_guard: request body guard (body_guard.lua), the edge layer of the
    -- PHP2Shell / Node2Shell interim mitigations.
    --
    --   mode       – "enforce" (strip hostile bodies, add score), "observe"
    --                (log only) or "off". BODY_GUARD_MODE env var.
    --   score      – Added to the request's risk score for a parser-shaped
    --                body. 100 = straight to the honeypot.
    --   soft_score – For weaker evidence: a compressed request body or a
    --                hostile query string.
    --   limits     – See body_guard_rules.DEFAULT_LIMITS.
    -- -----------------------------------------------------------------------
    body_guard = {
        mode = (os.getenv("BODY_GUARD_MODE") or "enforce"):lower(),
        score = 100,
        soft_score = 40,
        limits = require("body_guard_rules").DEFAULT_LIMITS,
    },

    -- internal_test_secret: shared secret gating the X-Route-Target /
    -- X-Risk-Score response headers (see nginx.conf's two
    -- header_filter_by_lua_block sites). Those headers exist so the
    -- testing/scenario_*.sh scripts can externally verify routing
    -- decisions, but shipping them on every response to every client
    -- hands a real user (or a blind pentest) the routing/risk-score
    -- oracle for free -- see BLIND_PENTEST_PROTOCOL.md §8.2. When this is
    -- set, the headers are only emitted for requests carrying a matching
    -- X-Internal-Test-Auth header; when unset/empty, the headers are never
    -- emitted (fail closed, not fail open).
    internal_test_secret = os.getenv("INTERNAL_TEST_SECRET") or "",

    vulnerability = {
        plugins = {
            "woocommerce-payments",           -- CVE-2023-28121
            "abandoned-cart-lite",            -- CVE-2023-2986
            "drag-and-drop-multiple-file-upload", -- CVE-2025-4403
            "cwmp",                           -- CVE-2025-2266
            "gift-voucher",                   -- CVE-2025-47577, CVE-2024-8425
            "advanced-form-integration",      -- CVE-2024-2387
            "pagseguro-connect-woocommerce",  -- CVE-2025-10142
            "wp-file-upload",                 -- CVE-2024-50508
            "bricks",                         -- CVE-2024-25600
            "wp-automatic",                   -- CVE-2024-27956
            "ultimate-member",                -- CVE-2024-1071
            "bookingpress-appointment-booking", -- CVE-2022-0739
            "layerslider"                     -- CVE-2024-2879
        },
        cve_patterns = {
            -- CVE-2023-28121: WooCommerce Payments header-based auth bypass.
            -- Matches both header name (case-insensitive via Lua lower()) and
            -- the REST API user-creation endpoint.
            ["CVE-2023-28121"] = "X%-WCPAY%-PLATFORM%-CHECKOUT%-USER",

            -- CVE-2023-2986: Abandoned Cart Lite checkout token forgery.
            -- The wcal_action=checkout_link query parameter triggers the
            -- vulnerable code path.
            ["CVE-2023-2986"] = "wcal_action=checkout_link",

            -- CVE-2025-4403: DnD file upload MIME-type bypass.
            -- The dnd-wc-upload-file action name appears in POST bodies.
            ["CVE-2025-4403"] = "dnd%-wc%-upload%-file",

            -- CVE-2025-2266: CWMP unauthenticated WordPress options write.
            -- The cwmpUpdateOptions action is posted without a nonce check.
            ["CVE-2025-2266"] = "cwmpUpdateOptions",

            -- CVE-2025-47577 / CVE-2024-8425: Gift Voucher file upload RCE.
            -- Both CVEs share the same vulnerable AJAX action.
            ["CVE-2025-47577"] = "mwb_wgm_preview_mail",
            ["CVE-2024-8425"]  = "mwb_wgm_preview_mail",

            -- CVE-2024-2387: AFI SQL injection via integration_id parameter.
            -- Single-quote after the parameter value is the injection trigger.
            ["CVE-2024-2387"] = "integration_id.*'",

            -- CVE-2025-10142: PagSeguro Connect file path traversal.
            -- The pc_added_uploaded_image action accepts an unsanitised path.
            ["CVE-2025-10142"] = "pc_added_uploaded_image",

            -- CVE-2024-50508: WP File Upload directory traversal.
            -- The file[path] parameter is passed directly to a filesystem call.
            ["CVE-2024-50508"] = "file%[path%]",

            -- CVE-2024-25600: Bricks Builder unauthenticated RCE via the
            -- render_element REST endpoint (eval of user PHP).
            ["CVE-2024-25600"] = "bricks/v1/render_element",

            -- CVE-2024-27956: WP Automatic SQL injection through csv.php.
            ["CVE-2024-27956"] = "wp%-automatic/inc/csv%.php",

            -- CVE-2024-1071: Ultimate Member SQLi via the um_get_members AJAX
            -- action's directory_id parameter.
            ["CVE-2024-1071"] = "um_get_members",

            -- CVE-2022-0739: BookingPress SQLi via the front-category-services
            -- AJAX action's total_service parameter.
            ["CVE-2022-0739"] = "bookingpress_front_get_category_services",

            -- CVE-2024-2879: LayerSlider SQLi via the ls_get_popup_markup AJAX
            -- action's id parameter.
            ["CVE-2024-2879"] = "ls_get_popup_markup"
        }
    }
}

-- ---------------------------------------------------------------------------
-- _G.utils – Stateless utility helpers shared across all Lua modules.
-- ---------------------------------------------------------------------------
_G.utils = {}

--- Check whether an IP address (IPv4 or IPv6) falls within any range in
--- _G.config.threat.ip_whitelist. Real bit-level CIDR matching, including
--- non-octet-aligned prefixes like /10 and IPv4-mapped IPv6 clients; see
--- ip_rules.lua and tests/test_ip_rules.lua.
---
--- @param  ip  string  Client address as nginx reports it ($remote_addr).
--- @return boolean  true if the IP is whitelisted.
function _G.utils.is_ip_whitelisted(ip)
    return require("ip_rules").in_any(ip, _G.config.threat.ip_whitelist)
end

--- URL-decode a string (percent-encoding and "+" as space).
--- Shared by pattern_analyzer.lua (URI pattern matching) and the
--- prompt-injection probe stage so both operate on decoded text instead of
--- each maintaining their own copy of this logic.
---
--- @param str string
--- @return string
function _G.utils.url_decode(str)
    if not str then return "" end
    str = string.gsub(str, "%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    str = string.gsub(str, "+", " ")
    return str
end

--- Generate a random UUID v4 string.
--- Used for session IDs and internal correlation tokens.
--- NOTE: Relies on Lua's math.random which is seeded per-worker in
--- init_worker.lua (math.randomseed(ngx.time() + ngx.worker.pid())).
--- Not cryptographically secure; use only for non-secret identifiers.
---
--- @return string  UUID string in 8-4-4-4-12 hex format.
function _G.utils.generate_uuid()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return string.gsub(template, '[xy]', function(c)
        local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
        return string.format('%x', v)
    end)
end

--- Compute a combined risk score from individual sub-scores.
--- Used by pattern_analyzer.lua as a final normalisation step.
---
--- Scoring weights:
---   patterns_matched  × 10 per pattern   (URI/header pattern hits)
---   cve_matched       × 25 per CVE        (CVE-specific pattern hits)
---   ip_reputation     raw value            (from threat_intel shared dict)
---
--- The result is clamped to max_risk_score (100) to prevent runaway values.
---
--- @param patterns_matched  integer  Number of generic patterns matched.
--- @param cve_matched       integer  Number of CVE-specific patterns matched.
--- @param ip_reputation     integer  IP reputation score (can be negative for
---                                   whitelisted IPs).
--- @return integer  Normalised risk score in [0..max_risk_score].
function _G.utils.calculate_risk_score(patterns_matched, cve_matched, ip_reputation)
    local base_score = 0
    
    -- Pattern matching score
    base_score = base_score + (patterns_matched * 10)
    
    -- CVE matching score (higher impact)
    base_score = base_score + (cve_matched * 25)
    
    -- IP reputation score
    base_score = base_score + (ip_reputation or 0)
    
    return math.min(base_score, _G.config.threat.max_risk_score)
end

--- Append a structured security event to the Nginx error log.
--- The JSON-encoded entry is readable by Vector (nginx_error_in source in
--- vector.yaml) and forwarded to Elasticsearch via the Vector aggregator.
---
--- @param event_type  string  Short identifier (e.g. "cve_pattern_detected").
--- @param details     table   Arbitrary key-value context for the event.
function _G.utils.log_security_event(event_type, details)
    -- lua-cjson can't tell an empty array from an empty object -- a Lua
    -- table with zero elements is genuinely ambiguous -- and defaults to
    -- encoding it as `{}`. Confirmed live: this locks Elasticsearch's
    -- mapping for that field as `object` from whichever event reaches it
    -- first, silently dropping every later event whose same field (e.g.
    -- high_risk_request's/routing_to_honeypot's `cves`, or `patterns`/
    -- `signals`) actually has real array contents -- the same class of
    -- mapping-conflict bug the SIEM's vector.yaml already works around for
    -- Docker labels. Every field this function is ever called with is
    -- list-shaped when empty (never a genuinely-empty *object*), so
    -- tagging every empty-table value here to encode as `[]` is safe and
    -- fixes this at the source instead of downstream in Vector.
    if details then
        for _, v in pairs(details) do
            if type(v) == "table" and next(v) == nil then
                setmetatable(v, cjson.empty_array_mt)
            end
        end
    end

    local log_entry = {
        timestamp = ngx.time(),
        event_type = event_type,
        details = details,
        server_time = os.date("%Y-%m-%d %H:%M:%S")
    }

    ngx.log(ngx.WARN, "SECURITY_EVENT: ", cjson.encode(log_entry))
end

-- ---------------------------------------------------------------------------
-- _G.redis_pool – Redis keepalive connection management.
--
-- Wraps lua-resty-redis to provide a simple borrow/return interface.
-- All modules that need Redis call _G.redis_pool.get_connection() and MUST
-- call _G.redis_pool.close_connection() when done, even on error paths, to
-- return the socket to the keepalive pool and avoid connection leaks.
--
-- Connection lifecycle:
--   1. get_connection() checks the per-worker keepalive pool first (no TCP
--      handshake if a connection is available).
--   2. If the pool is empty, a new TCP connection is made and AUTH is sent.
--   3. close_connection() puts the socket back into the keepalive pool with
--      a 10-second idle timeout.  The pool holds up to pool_size sockets
--      per Nginx worker process.
-- ---------------------------------------------------------------------------
_G.redis_pool = {}

--- Borrow a Redis connection from the worker-local keepalive pool.
--- @return redis|nil, string|nil  Connection object or nil + error message.
function _G.redis_pool.get_connection()
    -- One connect+auth attempt. Returns (red, nil) or (nil, err). A pooled
    -- socket that has silently gone bad surfaces here as a connect or AUTH
    -- error/timeout, which is exactly the transient case the retry below
    -- absorbs.
    local function attempt()
        local red = redis:new()
        -- set_timeouts(connect, send, read) -- see the config block's
        -- read_timeout note for why the reply timeout is the looser one.
        red:set_timeouts(_G.config.redis.timeout, _G.config.redis.timeout, _G.config.redis.read_timeout)

        local ok, err = red:connect(_G.config.redis.host, _G.config.redis.port)
        if not ok then
            return nil, "connect: " .. tostring(err)
        end

        -- Authenticate if password is set. AUTH is sent even on
        -- keepalive-reused connections because resty-redis does not track
        -- auth state across the keepalive pool boundary.
        if _G.config.redis.password then
            local res, aerr = red:auth(_G.config.redis.password)
            if not res then
                return nil, "auth: " .. tostring(aerr)
            end
        end
        return red, nil
    end

    -- Retry once on a transient connect/auth failure (typically a "timeout"
    -- from a momentary host scheduling stall, or a stale pooled socket). A
    -- second, genuinely-failing attempt is logged and returned so callers
    -- still degrade gracefully; the retry just stops a single hiccup from
    -- failing a whole background cycle.
    local red, err = attempt()
    if red then
        return red, nil
    end
    red, err = attempt()
    if red then
        return red, nil
    end
    ngx.log(ngx.ERR, "Redis get_connection failed after retry: ", err)
    return nil, err
end

--- Return a Redis connection to the worker-local keepalive pool.
--- Always call this after get_connection(), even when an error occurred,
--- to prevent socket leaks that would exhaust the file-descriptor limit.
--- @param red  redis  Connection object returned by get_connection().
function _G.redis_pool.close_connection(red)
    if red then
        -- set_keepalive(idle_timeout_ms, pool_size)
        -- idle_timeout: 10 s — Redis server's default client timeout is 0
        -- (never), so the client-side timeout drives the keepalive eviction.
        local ok, err = red:set_keepalive(10000, _G.config.redis.pool_size)
        if not ok then
            ngx.log(ngx.WARN, "Failed to set keepalive: ", err)
        end
    end
end

-- ---------------------------------------------------------------------------
-- Shared dictionary initialisation
--
-- The four lua_shared_dict zones are declared in nginx.conf and are shared
-- across ALL worker processes (unlike regular Lua module variables which are
-- per-worker).  We initialise them here in the master process so that worker
-- 0's init_worker.lua does not need to re-seed on startup.
-- ---------------------------------------------------------------------------
local sessions      = ngx.shared.sessions        -- Session blob cache
local threat_intel  = ngx.shared.threat_intel    -- IP/UA reputation + health
local rate_limit    = ngx.shared.rate_limit      -- Per-IP rate counters
local honeypot_routes = ngx.shared.honeypot_routes -- Pool assignment cache

-- Seed threat_intel with static bootstrap data.
-- These entries are overwritten at runtime by:
--   - init_worker.lua: parse_suricata_logs() every 30 s
--   - pool_router.lua: health check results every 10 s
if threat_intel then
    -- Placeholder flagged IPs (real IPs accumulate from Suricata alerts).
    -- Replace or augment with a real threat-feed import for production use.
    threat_intel:set("flagged_ips", cjson.encode({
        ["1.2.3.4"] = { score = 90, reason = "known_botnet" },
        ["5.6.7.8"] = { score = 75, reason = "scanning_activity" }
    }))
    
    -- Flagged user-agent substrings checked in session_handler.lua and
    -- pattern_analyzer.lua.  Adding a string here is sufficient to make it
    -- detectable system-wide without any other code change.
    threat_intel:set("flagged_agents", cjson.encode({
        "sqlmap",    -- SQL injection automation
        "nmap",      -- Network scanner
        "masscan",   -- Mass port scanner
        "zap",       -- OWASP ZAP proxy
        "nikto",     -- Web vulnerability scanner
        "dirb",      -- Directory brute-forcer
        "gobuster"   -- Directory/DNS brute-forcer
    }))
end

-- Pre-populate the honeypot_routes dict with plugin-name → "honeypot" entries.
-- router.lua's is_vulnerable_plugin_access() function checks this dict before
-- the Redis round-trip, so plugin endpoint accesses are caught at the fastest
-- possible code path (worker-local memory, no network I/O).
if honeypot_routes then
    for _, plugin in ipairs(_G.config.vulnerability.plugins) do
        honeypot_routes:set("plugin_" .. plugin, "honeypot")
    end
end

ngx.log(ngx.INFO, "Nginx Lua initialization completed successfully")