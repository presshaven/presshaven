-- test_trusted_callbacks.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter. Covers the trusted payment/OAuth
-- callback allowlist in pattern_rules.lua (untrusted_callback_host): a shop's
-- legitimate gateway/OAuth callbacks to known providers or its own host must
-- NOT be flagged, while an absolute URL to anyone else (the shape of an RFI /
-- open-redirect / SSRF payload) must be -- that host is then blocked OUTRIGHT
-- with a 403 in nginx.conf's access phase (NOT scored or routed, so a callback
-- link planted and sent to an innocent visitor cannot divert/mislabel them).
-- These tests also assert analyze_uri_patterns adds no callback score.
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_trusted_callbacks.lua

package.path = "../?.lua;" .. package.path
local rules = require "pattern_rules"

local passed, failed = 0, 0

local function check(name, condition)
    if condition then
        passed = passed + 1
        print("  [PASS] " .. name)
    else
        failed = failed + 1
        print("  [FAIL] " .. name)
    end
end

-- The shop's own host is added at runtime from WP_SITE_URL (see init.lua); the
-- tests supply it here the same way the config builder would.
local TRUSTED = {}
for _, d in ipairs(rules.TRUSTED_CALLBACK_DOMAINS) do TRUSTED[#TRUSTED + 1] = d end
TRUSTED[#TRUSTED + 1] = "fernhillcoffee.sk"

print("== untrusted_callback_host(): trusted callbacks are allowed ==")
check("exact provider domain is trusted",
      rules.untrusted_callback_host("/?return=https://gopay.com/pay/ok", TRUSTED) == nil)
check("subdomain of a provider is trusted",
      rules.untrusted_callback_host("/wc-api/?notify=https://gate.gpwebpay.com/pgw", TRUSTED) == nil)
check("stripe deep path is trusted",
      rules.untrusted_callback_host(
          "/checkout?success_url=https://checkout.stripe.com/c/pay/cs_test_abc", TRUSTED) == nil)
check("paypal return is trusted",
      rules.untrusted_callback_host(
          "/wc-api/WC_Gateway_Paypal?return=https://www.paypal.com/checkoutnow", TRUSTED) == nil)
check("the shop's own host (from WP_SITE_URL) is trusted",
      rules.untrusted_callback_host(
          "/oauth/cb?redirect_uri=https://fernhillcoffee.sk/account", TRUSTED) == nil)
check("relative callback (no absolute URL) is not flagged",
      rules.untrusted_callback_host("/wc-api/callback?order=42&status=ok", TRUSTED) == nil)
check("nil uri returns nil", rules.untrusted_callback_host(nil, TRUSTED) == nil)

print("== untrusted_callback_host(): untrusted / evasive callbacks are caught ==")
check("plain external host is flagged",
      rules.untrusted_callback_host("/?return=https://evil.tld/steal", TRUSTED) == "evil.tld")
check("http (not https) external host is flagged",
      rules.untrusted_callback_host("/?next=http://attacker.example/x", TRUSTED) == "attacker.example")
check("ftp wrapper to external host is flagged",
      rules.untrusted_callback_host("/?f=ftp://files.evil.tld/p", TRUSTED) == "files.evil.tld")
check("userinfo bypass (trusted@evil) is judged on the real host",
      rules.untrusted_callback_host("/?u=https://paypal.com@evil.tld/x", TRUSTED) == "evil.tld")
check("port does not hide the host",
      rules.untrusted_callback_host("/?u=http://evil.tld:8080/x", TRUSTED) == "evil.tld")
check("suffix-confusion host (paypal.com.evil.tld) is flagged",
      rules.untrusted_callback_host("/?u=https://paypal.com.evil.tld/x", TRUSTED) == "paypal.com.evil.tld")
check("lookalike (notpaypal.com) is not treated as paypal.com",
      rules.untrusted_callback_host("/?u=https://notpaypal.com/x", TRUSTED) == "notpaypal.com")
check("percent-encoded scheme/host is decoded then flagged",
      rules.untrusted_callback_host("/?u=https%3a%2f%2fevil.tld%2fx", TRUSTED) == "evil.tld")
check("169.254.169.254 metadata SSRF is flagged",
      rules.untrusted_callback_host("/?u=http://169.254.169.254/latest/meta-data/", TRUSTED)
          == "169.254.169.254")

print("== untrusted_callback_host(): first untrusted host wins ==")
check("trusted-then-untrusted returns the untrusted one",
      rules.untrusted_callback_host(
          "/?ok=https://gopay.com/a&evil=https://evil.tld/b", TRUSTED) == "evil.tld")

print("== untrusted_callback_host(): no allowlist -> no finding ==")
check("nil trusted list never flags (feature disabled)",
      rules.untrusted_callback_host("/?u=https://evil.tld/x", nil) == nil)

print("== analyze_uri_patterns(): callbacks are NOT scored (blocked at the edge instead) ==")
-- An untrusted callback is an OUTRIGHT 403 at the edge (nginx.conf), never a
-- threat score -- a planted callback link sent to an innocent visitor must not
-- divert or mislabel them. So analyze_uri_patterns must add no callback score
-- and no untrusted_external_callback signal, with or without a generic list.
local function has(list, name)
    for _, p in ipairs(list) do if p == name then return true end end
    return false
end

do
    local r = rules.analyze_uri_patterns("/?return=https://evil.tld/x", {}, 100)
    check("untrusted callback contributes no score", r.score == 0)
    check("no untrusted_external_callback signal is produced",
          not has(r.patterns, "untrusted_external_callback"))
end

print()
print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
