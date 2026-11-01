-- gdpr_handler.lua - Adapter half of the consent-gated gdpr_signature identity
--
-- Does everything gdpr_rules.lua (pure) deliberately can't: loads the RSA
-- private key, RSA-OAEP-decrypts the gdpr_token cookie, cjson-decodes the
-- plaintext, SHA-256-hashes the canonical characteristics into the one-way
-- gdpr_signature, and reads/writes the honeypot-signature bindings in Redis.
-- See gdpr_rules.lua's header for the full design and privacy rationale.
--
-- Everything here fails OPEN: a missing key, an undecryptable/forged token, a
-- Redis hiccup or any crypto error must never break a normal page load, it
-- just means "no GDPR signal this request" and the SERVERID session remains
-- the only identifier. The whole subsystem also disables itself cleanly when
-- GDPR_ENABLED=false or no GDPR_PRIVATE_KEY is configured.

local cjson    = require "cjson.safe"
local sha256   = require "resty.sha256"
local str      = require "resty.string"
local gdpr_rules = require "gdpr_rules"

local _M = {}

-- Per-worker state, built lazily on first use (ensure_init). The private key
-- object, the derived public key (served to clients), and the deployment-local
-- secret the signature is salted with are all cached here so the key is parsed
-- once per worker, not per request.
local _init_done = false
local _enabled   = false
local _priv      = nil   -- resty.openssl.pkey object (private)
local _pub_b64   = nil   -- SPKI DER, base64 -- what the browser imports
local _sig_secret = nil  -- salt mixed into the signature hash (see below)
local _pkey_mod  = nil   -- resty.openssl.pkey module (lazy-required)

local function cfg()
    return _G.config and _G.config.gdpr or nil
end

-- Parse the key and derive the public key + signature salt. Guarded so a bad
-- key disables the subsystem instead of erroring on every request.
local function ensure_init()
    if _init_done then
        return
    end
    _init_done = true

    local c = cfg()
    if not c or not c.enabled or not c.private_key_b64 or c.private_key_b64 == "" then
        ngx.log(ngx.INFO, "[GDPR] Disabled (no GDPR_PRIVATE_KEY, or GDPR_ENABLED=false)")
        return
    end

    local der = ngx.decode_base64(c.private_key_b64)
    if not der then
        ngx.log(ngx.ERR, "[GDPR] GDPR_PRIVATE_KEY is not valid base64 -- GDPR disabled")
        return
    end

    local ok, pkey = pcall(require, "resty.openssl.pkey")
    if not ok then
        ngx.log(ngx.ERR, "[GDPR] lua-resty-openssl not installed -- GDPR disabled: ", tostring(pkey))
        return
    end
    _pkey_mod = pkey

    local priv, err = pkey.new(der, { format = "DER", type = "pr" })
    if not priv then
        ngx.log(ngx.ERR, "[GDPR] Failed to load RSA private key -- GDPR disabled: ", tostring(err))
        return
    end
    _priv = priv

    -- Export the matching public key as SPKI DER (exactly what the browser's
    -- WebCrypto importKey("spki", ...) expects) and base64 it for transport.
    local pub_der, perr = priv:tostring("public", "DER")
    if not pub_der then
        ngx.log(ngx.ERR, "[GDPR] Failed to derive public key -- GDPR disabled: ", tostring(perr))
        _priv = nil
        return
    end
    _pub_b64 = ngx.encode_base64(pub_der)

    -- Deployment-local salt so the one-way signature can't be precomputed from
    -- the (very low-entropy, for this demo just a screen size) characteristics
    -- with a generic rainbow table -- two deployments with different keys
    -- produce different signatures for the same browser. Derived from the
    -- private key so it needs no extra secret and is stable across restarts
    -- (as long as the key is). Never leaves the server.
    local h = sha256:new()
    h:update("gdpr-sig-salt|")
    h:update(c.private_key_b64)
    _sig_secret = str.to_hex(h:final())

    _enabled = true
    ngx.log(ngx.INFO, "[GDPR] Enabled (RSA key loaded, timestamp_window=",
        c.timestamp_window, "s, binding_ttl=", c.binding_ttl, "s)")
end

--- Is the subsystem live (key loaded, not disabled)?
function _M.is_enabled()
    ensure_init()
    return _enabled
end

--- Base64 SPKI public key for the client, or nil when disabled.
function _M.public_key_b64()
    ensure_init()
    return _pub_b64
end

--- JSON config the client bootstrap (/__gdpr/config) needs. Pure config, no
--- secrets: the public key is, by design, public.
function _M.client_config_json()
    ensure_init()
    local c = cfg() or {}
    local window = tonumber(c.timestamp_window) or 300
    return cjson.encode({
        enabled    = _enabled,
        publicKey  = _pub_b64 or "",
        cookieName = gdpr_rules.COOKIE_NAME,
        -- How long a freshly stamped token stays valid server-side; the client
        -- re-stamps well inside this so the cookie it sends is never stale.
        windowSeconds  = window,
        refreshSeconds = math.max(30, math.floor(window / 2)),
    })
end

-- Decrypt the raw cookie value to plaintext, or nil on any failure.
local function decrypt_token(cookie_val)
    if not _enabled or type(cookie_val) ~= "string" or cookie_val == "" then
        return nil
    end
    local ct = ngx.decode_base64(cookie_val)
    if not ct then
        return nil
    end
    local ok, pt = pcall(function()
        return _priv:decrypt(ct, _pkey_mod.PADDINGS.RSA_PKCS1_OAEP_PADDING,
            { oaep_md = "sha256", mgf1_md = "sha256" })
    end)
    if not ok or type(pt) ~= "string" or #pt == 0 or #pt > gdpr_rules.MAX_PLAINTEXT_LEN then
        return nil
    end
    return pt
end

-- One-way signature of the canonical characteristics, salted with the
-- deployment-local secret. SHA-256; the raw characteristics are never stored.
local function compute_signature(canonical)
    local h = sha256:new()
    h:update(_sig_secret)
    h:update("|")
    h:update(canonical)
    return str.to_hex(h:final())
end

--- Process this request's gdpr_token cookie.
--- @return table  {
---   consent   = boolean,      -- did the client send a (non-empty) token?
---   signature = string|nil,   -- one-way signature, only when valid+fresh
---   username  = string|nil,   -- logged-in WP username the token CLAIMS, if
---                             --  any. Self-reported by the client and so
---                             --  SPOOFABLE: only ever used for logging and
---                             --  to label a binding; the account COPY is
---                             --  keyed off the production-verified identity
---                             --  (X-Auth-User), never this. nil when the
---                             --  token carried no username (logged-out visit).
---   status    = string,       -- "disabled"|"no_consent"|"undecryptable"
---                             --  |"bad_json"|<gdpr_rules reason>|"ok"
--- }
function _M.process_request()
    ensure_init()
    if not _enabled then
        return { consent = false, status = "disabled" }
    end

    local cookie = ngx.var["cookie_" .. gdpr_rules.COOKIE_NAME]
    -- Empty / absent cookie == no consent (or consent revoked): nothing to do,
    -- the SERVERID session stays the only identifier. This is also exactly how
    -- a revocation reaches us -- the client simply stops sending the token.
    if not cookie or cookie == "" then
        return { consent = false, status = "no_consent" }
    end

    local pt = decrypt_token(cookie)
    if not pt then
        return { consent = true, status = "undecryptable" }
    end

    local payload = cjson.decode(pt)
    if type(payload) ~= "table" then
        return { consent = true, status = "bad_json" }
    end

    -- Pull the self-reported username out BEFORE validate()/the signature so it
    -- survives even a token the client built from stale characteristics. It is
    -- metadata, not a characteristic: gdpr_rules strips the same keys from the
    -- canonical string, so this cannot move the signature. SPOOFABLE -- see the
    -- doc on this function's return and bind_signature_to_honeypot().
    local claimed_username = gdpr_rules.extract_username(payload)

    -- Append the client's IP, as the proxy sees it, as one more identifying
    -- characteristic BEFORE the signature is derived. The browser can't know
    -- its own public address, so rather than round-trip it to the client and
    -- have it signed there, we add it here where $remote_addr is authoritative.
    -- It feeds gdpr_rules.canonical_characteristics exactly like the screen size
    -- (so the SAME browser from a DIFFERENT IP now yields a DIFFERENT signature),
    -- and because it's assigned (not merged) after the decode it also OVERRIDES
    -- any "ip" a crafted token tried to pre-seed -- the value stays server-side
    -- truth. $remote_addr is the same client notion every other subsystem uses
    -- (session_handler, pattern_analyzer, router). nil/empty-guarded so a
    -- missing var can never turn an otherwise valid token into an unsignable one.
    local client_ip = ngx.var.remote_addr
    if type(client_ip) == "string" and client_ip ~= "" then
        payload.ip = client_ip
    end

    local canonical, reason = gdpr_rules.validate(payload, ngx.time(), cfg().timestamp_window)
    if not canonical then
        -- A sent-but-invalid token (e.g. expired timestamp) is treated as a
        -- non-match, per spec: we just don't compute a signature from it.
        return { consent = true, status = reason, username = claimed_username }
    end

    return {
        consent   = true,
        signature = compute_signature(canonical),
        username  = claimed_username,
        status    = "ok",
    }
end

--- Is `signature` currently bound to a honeypot and unexpired? On a match the
--- binding's TTL is PROLONGED (so an active returning user never ages out),
--- which is the whole "expiry prolongs itself on every match" behaviour; an
--- absent key is an expired-or-never-bound signature == non-match.
--- @return boolean matched
--- @return table|nil binding  {pool, reason, bound_at} when matched.
function _M.is_signature_honeypot_bound(signature)
    if not _enabled or type(signature) ~= "string" or signature == "" then
        return false
    end
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "[GDPR] Redis unavailable for signature lookup: ", tostring(err))
        return false
    end
    local key = gdpr_rules.SIG_REDIS_PREFIX .. signature
    local val = red:get(key)
    if val and val ~= ngx.null then
        -- Prolong the binding from this match.
        red:expire(key, cfg().binding_ttl)
        _G.redis_pool.close_connection(red)
        return true, cjson.decode(val) or {}
    end
    _G.redis_pool.close_connection(red)
    return false
end

--- Bind `signature` to a honeypot (or refresh an existing binding). Called
--- whenever a request that carried a valid signature ends up routed to the
--- honeypot, for ANY reason -- that's how a known-bad browser's signature gets
--- remembered so a later cookie/localStorage wipe + re-consent lands back in
--- the honeypot. The key's TTL is the binding expiry.
---
--- `username`, when given, is the PRODUCTION-VERIFIED account this browser was
--- authenticated as at the moment it turned suspicious (lookup_auth_identity /
--- the X-Auth-User header production emits -- NEVER the spoofable token
--- username). It is stamped onto the binding so that a later wiped-and-returned
--- visit -- which is logged out and so carries no username at all -- can still
--- be reunited with, and auto-logged-into, the same account on the pool. An
--- existing binding's username is PRESERVED when this call passes none, so a
--- later anonymous re-bind never erases who the signature belonged to.
function _M.bind_signature_to_honeypot(signature, pool, reason, username)
    if not _enabled or type(signature) ~= "string" or signature == "" then
        return
    end
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "[GDPR] Redis unavailable for signature bind: ", tostring(err))
        return
    end
    local key = gdpr_rules.SIG_REDIS_PREFIX .. signature

    -- Preserve an already-recorded username when this bind doesn't supply one
    -- (e.g. a logged-out returning visit re-confirming the binding).
    if type(username) ~= "string" or username == "" then
        username = nil
        local existing = red:get(key)
        if existing and existing ~= ngx.null then
            local prev = cjson.decode(existing)
            if type(prev) == "table" and type(prev.username) == "string" and prev.username ~= "" then
                username = prev.username
            end
        end
    end

    red:setex(key, cfg().binding_ttl, cjson.encode({
        pool     = pool,
        reason   = reason or "unknown",
        bound_at = ngx.time(),
        username = username,   -- may be nil (omitted from JSON) for an anon binding
    }))
    _G.redis_pool.close_connection(red)
    ngx.log(ngx.WARN, "[GDPR] Signature bound to honeypot pool ", tostring(pool),
        " (reason=", tostring(reason), ", user=", tostring(username),
        ", ttl=", cfg().binding_ttl, "s)")
end

-- Redis key under which the edge caches, per live session, the account the
-- PRODUCTION WordPress reported this session is authenticated as. Production is
-- the only authority on who is actually logged in (it emits X-Auth-User /
-- X-Auth-Role on that user's own responses); the edge stashes it here keyed by
-- session so that when the SAME session is later diverted to a honeypot we know
-- which real account to copy -- without ever trusting the client-built token.
local AUTH_IDENTITY_PREFIX = "gdpr_auth_identity:"

-- Redis list the edge RPUSHes account-copy jobs onto; the honeypot_user_sync
-- service (replicate_user_to_honeypot.sh) BLPOPs it and copies that one user's
-- wp_users + wp_usermeta rows from production into the assigned pool's DB.
local USER_COPY_QUEUE = "honeypot_user_copy_queue"

--- Record, for this session, the production-verified logged-in identity.
--- Called from header_filter on PRODUCTION-routed responses that carried an
--- X-Auth-User header (emitted by the honeypot-auth-identity mu-plugin). Keyed
--- by session so a later diversion of the same session can look it up. TTL
--- mirrors the session idle window so a stale identity never outlives the
--- session it describes. Fails open -- a Redis hiccup just means "unknown".
--- @param session_id string|nil
--- @param user       string|nil  production-verified wp user_login
--- @param role       string|nil  production-verified primary role
function _M.record_auth_identity(session_id, user, role)
    if not _enabled
        or type(session_id) ~= "string" or session_id == ""
        or type(user) ~= "string" or user == "" then
        return
    end
    user = gdpr_rules.extract_username({ username = user })
    if not user then
        return
    end
    if type(role) ~= "string" or role == "" then
        role = "subscriber"
    end
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "[GDPR] Redis unavailable for auth-identity record: ", tostring(err))
        return
    end
    local c = cfg() or {}
    local ttl = tonumber(c.auth_identity_ttl) or 3600
    red:setex(AUTH_IDENTITY_PREFIX .. session_id, ttl,
        cjson.encode({ user = user, role = role, at = ngx.time() }))
    _G.redis_pool.close_connection(red)
end

--- The production-verified identity recorded for this session, or nil.
--- @param session_id string|nil
--- @return table|nil  { user, role, at } when known.
function _M.lookup_auth_identity(session_id)
    if not _enabled or type(session_id) ~= "string" or session_id == "" then
        return nil
    end
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "[GDPR] Redis unavailable for auth-identity lookup: ", tostring(err))
        return nil
    end
    local val = red:get(AUTH_IDENTITY_PREFIX .. session_id)
    _G.redis_pool.close_connection(red)
    if not val or val == ngx.null then
        return nil
    end
    local decoded = cjson.decode(val)
    if type(decoded) ~= "table" or type(decoded.user) ~= "string" then
        return nil
    end
    return decoded
end

--- Enqueue a job for honeypot_user_sync to copy `user`'s account (wp_users +
--- wp_usermeta, role/profile/password-hash/email) from production into pool
--- `pool`'s database. `user` MUST be a production-verified username (never the
--- spoofable token one); callers derive it from lookup_auth_identity or the
--- binding's stored username. Idempotent downstream (REPLACE INTO), so a
--- duplicate enqueue is harmless. Fails open.
--- @param user string  production-verified wp user_login
--- @param pool number|string  honeypot pool id
function _M.enqueue_user_replication(user, pool)
    if not _enabled then
        return
    end
    user = gdpr_rules.extract_username({ username = user })
    local pool_n = tonumber(pool)
    if not user or not pool_n then
        return
    end
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "[GDPR] Redis unavailable for user-copy enqueue: ", tostring(err))
        return
    end
    red:rpush(USER_COPY_QUEUE, cjson.encode({
        user = user,
        pool = pool_n,
        at   = ngx.time(),
    }))
    _G.redis_pool.close_connection(red)
    ngx.log(ngx.WARN, "[GDPR] Enqueued account copy of user '", user,
        "' into honeypot pool ", pool_n)
end

return _M
