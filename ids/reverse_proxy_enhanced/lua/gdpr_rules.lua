-- gdpr_rules.lua - Pure logic for the consent-gated "gdpr_signature" identity
--
-- PURPOSE:
--   A second, privacy-preserving identifier that runs ALONGSIDE the signed
--   SERVERID session cookie (session_handler.lua / session_identity_rules.lua),
--   never replacing it. The reverse proxy serves every page a short consent
--   banner and an RSA public key (gdpr_client.js). ONLY if the visitor agrees,
--   and immediately when they agree, the browser builds a tiny payload from
--   its own characteristics (for this demo: just the screen size) plus a
--   timestamp, RSA-OAEP-encrypts it with that public key into a "gdpr_token",
--   and sends it as a cookie on every request. The private key never leaves
--   the proxy (GDPR_PRIVATE_KEY, .env).
--
--   One more characteristic the browser cannot supply -- the client IP as the
--   proxy sees it ($remote_addr) -- is appended to the decoded payload
--   server-side, by gdpr_handler.lua, right before the signature is derived, so
--   it flows through canonical_characteristics() below like any other field.
--   The same browser from a different network therefore produces a different
--   signature; this module stays unaware of where the field came from.
--
--   The proxy decrypts the token in memory only long enough to (1) check the
--   timestamp is inside a freshness window and (2) strip the timestamp and
--   hash the REST into a one-way "gdpr_signature". The raw characteristics are
--   never stored: only the signature is, and only when that session is bound
--   to a honeypot. So a visitor who cleared their cookies AND localStorage
--   (dropping both the SERVERID session and the stored consent) can re-consent,
--   reproduce the SAME signature from the SAME browser, and be recognised and
--   re-routed to their honeypot -- yet nothing identifiable about them exists
--   server-side to erase, and declining (an empty gdpr_token) means no
--   signature can ever be computed.
--
--   Pure module, same split as pattern_rules/router_rules/session_rules: no
--   ngx.* dependency, no _G.config/_G.utils reads, no JSON or crypto. The
--   adapter half (gdpr_handler.lua) does the base64/RSA-OAEP decrypt, the
--   cjson.decode of the plaintext, the SHA-256 hashing and all Redis I/O, then
--   hands this module already-decoded Lua values. Plain-`lua`-interpreter
--   testable -- see tests/test_gdpr_rules.lua.

local _M = {}

-- Cookie the browser sends the encrypted token in (gdpr_client.js sets it).
_M.COOKIE_NAME = "gdpr_token"

-- Redis key a honeypot-bound signature is stored under. Only the signature
-- (a one-way hash) is ever the key material; the value holds the pool/reason,
-- and the key's TTL IS the binding's expiry (gdpr_handler prolongs it on every
-- match, so an unexpired binding == "still present", an expired one == gone).
_M.SIG_REDIS_PREFIX = "gdpr_honeypot_sig:"

-- Payload keys that carry the timestamp, not an identifying characteristic.
-- Stripped before the signature is computed so the signature is stable across
-- the per-request re-encryptions the browser does to keep the token fresh.
_M.TIMESTAMP_KEYS = { t = true, ts = true, timestamp = true }

-- Payload keys that carry the logged-in WordPress username (set by
-- gdpr_client.js ONLY when the visitor is logged in), which is metadata ABOUT
-- the browser's owner, not an identifying characteristic OF the browser.
-- Stripped before the signature is computed for the same reason the timestamp
-- is: the signature MUST stay identical whether or not the user is logged in.
-- If the username fed the signature, then logging out -- or clearing cookies,
-- which logs them out -- would change the signature and defeat the entire
-- recognise-the-same-browser-across-wipes purpose this module exists for. The
-- username is surfaced separately (extract_username) so the adapter can record
-- it ALONGSIDE a honeypot binding: who the signature belonged to while they
-- were logged in, carried through so a later wiped-and-returned (hence
-- logged-out) visit can still be reunited with that account -- never part of
-- the one-way signature itself.
_M.IDENTITY_KEYS = { u = true, user = true, username = true }

-- Fixed precedence when more than one identity key is present, so the chosen
-- username is deterministic regardless of JSON/table iteration order.
local IDENTITY_KEY_ORDER = { "username", "user", "u" }

-- Hard cap on the decrypted plaintext length the adapter will hand us. A
-- well-formed demo payload is ~30 bytes; with a username it is still well under
-- this -- anything far larger is malformed.
_M.MAX_PLAINTEXT_LEN = 512

-- WordPress's user_login column is 60 chars; a username longer than this could
-- not name a real account, so cap it (defence against a crafted oversized
-- token padding a binding value).
_M.MAX_USERNAME_LEN = 60

--- Whether a payload timestamp is inside the freshness window.
--- Symmetric around `now` so a little forward clock skew on the client is
--- tolerated; a token older (or newer) than `window` seconds is rejected,
--- which is what makes a captured, replayed token eventually stop matching.
---
--- @param ts      any     The payload's timestamp (epoch seconds).
--- @param now     number  Current epoch seconds (ngx.time() from the adapter).
--- @param window  number  Allowed age in seconds either side of now.
--- @return boolean
function _M.is_timestamp_fresh(ts, now, window)
    if type(ts) ~= "number" or type(now) ~= "number" or type(window) ~= "number" then
        return false
    end
    return ts >= (now - window) and ts <= (now + window)
end

--- Canonical string of the identifying characteristics in `payload`, with the
--- timestamp key(s) removed and the remaining keys sorted so the SAME browser
--- always yields the SAME string (and so the same signature) regardless of
--- JSON key order. Only string/number values are included; anything else is
--- ignored. Returns nil when nothing identifying is left (e.g. a payload that
--- was only a timestamp), which the caller treats as "cannot sign".
---
--- @param payload  table
--- @return string|nil
function _M.canonical_characteristics(payload)
    if type(payload) ~= "table" then
        return nil
    end
    local keys = {}
    for k, v in pairs(payload) do
        if not _M.TIMESTAMP_KEYS[k]
            and not _M.IDENTITY_KEYS[k]
            and (type(v) == "string" or type(v) == "number") then
            keys[#keys + 1] = k
        end
    end
    if #keys == 0 then
        return nil
    end
    table.sort(keys)
    local parts = {}
    for _, k in ipairs(keys) do
        parts[#parts + 1] = tostring(k) .. "=" .. tostring(payload[k])
    end
    return table.concat(parts, "&")
end

--- The logged-in WordPress username carried in `payload`, if any. Returns the
--- first IDENTITY_KEYS value present (in a fixed precedence) that is a
--- non-empty string, trimmed and length-capped; nil otherwise. This is pure
--- metadata extraction -- it has NO effect on canonical_characteristics (which
--- strips the same keys) and therefore none on the signature. The adapter uses
--- it to stamp a username onto a honeypot binding, never to alter the hash.
---
--- @param payload  table|nil
--- @return string|nil
function _M.extract_username(payload)
    if type(payload) ~= "table" then
        return nil
    end
    for _, k in ipairs(IDENTITY_KEY_ORDER) do
        local v = payload[k]
        if type(v) == "string" then
            v = v:gsub("^%s+", ""):gsub("%s+$", "")
            if v ~= "" then
                if #v > _M.MAX_USERNAME_LEN then
                    v = v:sub(1, _M.MAX_USERNAME_LEN)
                end
                return v
            end
        end
    end
    return nil
end

--- Validate a decoded payload and return the canonical characteristics string
--- the signature should be computed from.
---
--- @param payload  table|nil  cjson.decode of the decrypted token (nil if the
---                            decode failed).
--- @param now      number     Current epoch seconds.
--- @param window   number     Freshness window in seconds.
--- @return string|nil  canonical  Characteristics string, or nil on rejection.
--- @return string      status     "ok" | "not_table" | "no_timestamp"
---                                | "expired" | "no_characteristics"
function _M.validate(payload, now, window)
    if type(payload) ~= "table" then
        return nil, "not_table"
    end
    local ts = payload.t or payload.ts or payload.timestamp
    if type(ts) ~= "number" then
        return nil, "no_timestamp"
    end
    if not _M.is_timestamp_fresh(ts, now, window) then
        return nil, "expired"
    end
    local canonical = _M.canonical_characteristics(payload)
    if not canonical then
        return nil, "no_characteristics"
    end
    return canonical, "ok"
end

return _M
