#!/usr/bin/env lua
-- test_gdpr_rules.lua -- unit tests for the pure gdpr_signature logic
-- (lua/gdpr_rules.lua). Runs under a plain `lua` interpreter (no ngx, no
-- crypto, no Redis -- those live in gdpr_handler.lua).
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_gdpr_rules.lua

package.path = "../?.lua;" .. package.path
local r = require "gdpr_rules"

local passed, failed = 0, 0
local function check(name, cond)
    if cond then
        passed = passed + 1
        print("  [PASS] " .. name)
    else
        failed = failed + 1
        print("  [FAIL] " .. name)
    end
end

local NOW = 1700000000
local WINDOW = 300

print("== is_timestamp_fresh() ==")
check("exactly now is fresh", r.is_timestamp_fresh(NOW, NOW, WINDOW))
check("just inside past window", r.is_timestamp_fresh(NOW - WINDOW + 1, NOW, WINDOW))
check("just inside future (skew)", r.is_timestamp_fresh(NOW + WINDOW - 1, NOW, WINDOW))
check("too old is stale", not r.is_timestamp_fresh(NOW - WINDOW - 1, NOW, WINDOW))
check("too far future is stale", not r.is_timestamp_fresh(NOW + WINDOW + 1, NOW, WINDOW))
check("non-number ts is stale", not r.is_timestamp_fresh("x", NOW, WINDOW))
check("nil ts is stale", not r.is_timestamp_fresh(nil, NOW, WINDOW))

print("== canonical_characteristics() ==")
check("single screen-size field",
      r.canonical_characteristics({ s = "1920x1080", t = NOW }) == "s=1920x1080")
check("timestamp keys are all stripped",
      r.canonical_characteristics({ s = "800x600", t = 1, ts = 2, timestamp = 3 }) == "s=800x600")
check("keys are sorted for stability",
      r.canonical_characteristics({ b = "2", a = "1", t = NOW }) == "a=1&b=2")
check("key order does not change the result",
      r.canonical_characteristics({ a = "1", b = "2" })
      == r.canonical_characteristics({ b = "2", a = "1" }))
check("numeric values are kept",
      r.canonical_characteristics({ dpr = 2, t = NOW }) == "dpr=2")
-- The proxy appends the client IP (gdpr_handler.lua) as a plain field before
-- this runs; it must sort in alongside the screen size, not be special-cased.
check("server-appended client IP joins the characteristics",
      r.canonical_characteristics({ s = "1920x1080", ip = "203.0.113.7", t = NOW })
      == "ip=203.0.113.7&s=1920x1080")
check("same browser, different IP -> different canonical",
      r.canonical_characteristics({ s = "1920x1080", ip = "203.0.113.7" })
      ~= r.canonical_characteristics({ s = "1920x1080", ip = "198.51.100.4" }))
check("non-scalar values ignored", r.canonical_characteristics({ x = {}, t = NOW }) == nil)
check("only-a-timestamp yields nil", r.canonical_characteristics({ t = NOW }) == nil)
check("non-table yields nil", r.canonical_characteristics("nope") == nil)
-- The logged-in username is metadata, NOT a browser characteristic: it must be
-- stripped before hashing so the signature is identical whether or not the user
-- is logged in (logging out, or clearing cookies, must not change it).
check("username key 'u' stripped from canonical",
      r.canonical_characteristics({ s = "1920x1080", u = "alice", t = NOW }) == "s=1920x1080")
check("username key 'username' stripped from canonical",
      r.canonical_characteristics({ s = "1920x1080", username = "alice", t = NOW }) == "s=1920x1080")
check("logged-in vs logged-out yield identical characteristics",
      r.canonical_characteristics({ s = "1920x1080", u = "alice", t = NOW })
      == r.canonical_characteristics({ s = "1920x1080", t = NOW }))
check("different usernames do not change characteristics",
      r.canonical_characteristics({ s = "1920x1080", u = "alice" })
      == r.canonical_characteristics({ s = "1920x1080", u = "bob" }))

print("== extract_username() ==")
check("returns nil when no identity key present",
      r.extract_username({ s = "1920x1080", t = NOW }) == nil)
check("extracts 'u'", r.extract_username({ u = "alice" }) == "alice")
check("extracts 'user'", r.extract_username({ user = "bob" }) == "bob")
check("extracts 'username'", r.extract_username({ username = "carol" }) == "carol")
check("precedence: username > user > u",
      r.extract_username({ u = "fromU", user = "fromUser", username = "fromUsername" }) == "fromUsername")
check("precedence: user > u when no username",
      r.extract_username({ u = "fromU", user = "fromUser" }) == "fromUser")
check("surrounding whitespace is trimmed",
      r.extract_username({ u = "  alice  " }) == "alice")
check("empty / whitespace-only value is skipped",
      r.extract_username({ username = "   ", u = "alice" }) == "alice")
check("non-string value is ignored",
      r.extract_username({ u = 12345 }) == nil)
check("oversized username is capped at MAX_USERNAME_LEN",
      #r.extract_username({ u = string.rep("x", r.MAX_USERNAME_LEN + 50) }) == r.MAX_USERNAME_LEN)
check("non-table payload yields nil", r.extract_username("nope") == nil)
check("nil payload yields nil", r.extract_username(nil) == nil)

print("== determinism: same browser -> same canonical (=> same signature) ==")
local p1 = { s = "1920x1080", t = NOW }
local p2 = { s = "1920x1080", t = NOW + 120 } -- re-stamped token, same browser
check("re-stamped token has identical characteristics",
      r.canonical_characteristics(p1) == r.canonical_characteristics(p2))

print("== validate() ==")
local canon, status = r.validate({ s = "1920x1080", t = NOW }, NOW, WINDOW)
check("valid fresh payload -> canonical + ok", canon == "s=1920x1080" and status == "ok")

canon, status = r.validate({ s = "1920x1080", t = NOW - WINDOW - 5 }, NOW, WINDOW)
check("expired timestamp rejected", canon == nil and status == "expired")

canon, status = r.validate({ s = "1920x1080" }, NOW, WINDOW)
check("missing timestamp rejected", canon == nil and status == "no_timestamp")

canon, status = r.validate({ t = NOW }, NOW, WINDOW)
check("no characteristics rejected", canon == nil and status == "no_characteristics")

canon, status = r.validate("not-a-table", NOW, WINDOW)
check("non-table payload rejected", canon == nil and status == "not_table")

canon, status = r.validate(nil, NOW, WINDOW)
check("nil payload (decode failure) rejected", canon == nil and status == "not_table")

print("== constants ==")
check("cookie name is gdpr_token", r.COOKIE_NAME == "gdpr_token")
check("redis prefix present", type(r.SIG_REDIS_PREFIX) == "string" and #r.SIG_REDIS_PREFIX > 0)
check("max username len is WordPress user_login limit", r.MAX_USERNAME_LEN == 60)
check("identity keys cover u/user/username",
      r.IDENTITY_KEYS.u and r.IDENTITY_KEYS.user and r.IDENTITY_KEYS.username and true)

print(string.format("\n%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
