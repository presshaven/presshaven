/*
 * gdpr_client.js - Consent-gated browser identity for the honeypot reverse proxy.
 *
 * Injected into every HTML page by nginx (sub_filter, see nginx.conf). It is the
 * CLIENT half of the gdpr_signature system; the server half is lua/gdpr_handler.lua
 * and lua/gdpr_rules.lua (read those headers for the full design).
 *
 * What it does, and only ever with explicit consent:
 *   - Shows a consent banner with the agreement text. The decision is remembered
 *     in localStorage ("gdpr_consent").
 *   - ONLY if the visitor agrees (and immediately when they do): collects a tiny
 *     set of browser characteristics -- for this demo just the screen size --
 *     adds a fresh timestamp, and RSA-OAEP(SHA-256)-encrypts the pair with the
 *     server's PUBLIC key into a "gdpr_token" cookie that then rides along with
 *     every request. Only the browser can produce it (the plaintext is
 *     recomputed live, never stored -- storage holds only ciphertext), and it
 *     cannot be reversed without the server's private key.
 *   - If the visitor declines, or has not decided, NO token is ever sent and the
 *     cookie is cleared -- the ordinary session cookie stays the only identifier.
 *   - Lets the visitor change their mind at any time ("Privacy choices"), which
 *     is how consent is revoked: the token simply stops being sent, and because
 *     the server only ever stored a one-way hash (with a TTL), there is nothing
 *     identifiable left to erase.
 *
 * No external resources, no dependencies; CSP-safe (same-origin script, inline
 * styles only).
 */
(function () {
  "use strict";

  var CONSENT_KEY = "gdpr_consent";   // localStorage: "granted" | "denied"
  var GRANTED = "granted";
  var DENIED = "denied";
  var CONFIG_URL = "/__gdpr/config";

  var AGREEMENT_TITLE = "Your privacy choices";
  var AGREEMENT_TEXT =
    "To recognise your device across visits — even if you clear cookies and " +
    "site data — we can derive a one-way, encrypted fingerprint from basic " +
    "browser characteristics (for this demo, only your screen size) together " +
    "with a timestamp. It is encrypted in your browser with our public key and " +
    "we only ever keep a hash of it, never the underlying details. This is " +
    "entirely optional: decline and we use only an ordinary session cookie, and " +
    "you can change your decision at any time.";

  var cfg = null;      // { enabled, publicKey, cookieName, windowSeconds, refreshSeconds }
  var publicKey = null; // imported CryptoKey
  var refreshTimer = null;

  // --- small helpers --------------------------------------------------------

  function getConsent() {
    try { return window.localStorage.getItem(CONSENT_KEY); } catch (e) { return null; }
  }
  function setConsent(v) {
    try { window.localStorage.setItem(CONSENT_KEY, v); } catch (e) { /* private mode */ }
  }

  function setCookie(name, value, maxAgeSeconds) {
    var secure = location.protocol === "https:" ? "; Secure" : "";
    document.cookie = name + "=" + value +
      "; Path=/; Max-Age=" + maxAgeSeconds + "; SameSite=Lax" + secure;
  }
  function deleteCookie(name) {
    var secure = location.protocol === "https:" ? "; Secure" : "";
    document.cookie = name + "=; Path=/; Max-Age=0; SameSite=Lax" + secure;
  }

  function b64ToBytes(b64) {
    var bin = window.atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  function bytesToB64(buf) {
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return window.btoa(bin);
  }

  // The identifying characteristics. For this demo: just the screen size.
  // (Deliberately low-entropy; documented as such.) Recomputed live every time,
  // so nothing identifying is ever persisted in the browser.
  function collectCharacteristics() {
    return { s: screen.width + "x" + screen.height };
  }

  // The logged-in WordPress username, if the page says the visitor is logged
  // in. WordPress's auth cookies are HttpOnly (JS cannot read them), so the
  // honeypot-auth-identity mu-plugin publishes the current user's login name in
  // a <meta name="gdpr-user"> tag that only renders for a logged-in user. This
  // is NOT a browser characteristic and is NEVER folded into the signed screen
  // size: it rides in the token as a separate "u" key purely so the server can
  // LABEL a honeypot binding with who was logged in. The server strips it before
  // computing the signature (gdpr_rules.IDENTITY_KEYS), so the signature is
  // identical logged-in or out, and the server treats this value as spoofable --
  // the authoritative identity comes from production's own X-Auth-User header.
  function collectUsername() {
    try {
      var m = document.querySelector('meta[name="gdpr-user"]');
      if (!m) return null;
      var u = (m.getAttribute("content") || "").trim();
      return u !== "" ? u : null;
    } catch (e) {
      return null;
    }
  }

  // --- crypto ---------------------------------------------------------------

  function importPublicKey(spkiB64) {
    return window.crypto.subtle.importKey(
      "spki",
      b64ToBytes(spkiB64),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );
  }

  function buildToken() {
    if (!publicKey) return Promise.reject(new Error("no public key"));
    var payload = collectCharacteristics();
    payload.t = Math.floor(Date.now() / 1000); // fresh timestamp each time
    var u = collectUsername();                  // logged-in username, if any
    if (u) payload.u = u;                        // metadata only -- not signed
    var data = new TextEncoder().encode(JSON.stringify(payload));
    return window.crypto.subtle
      .encrypt({ name: "RSA-OAEP" }, publicKey, data)
      .then(function (cipher) { return bytesToB64(cipher); });
  }

  // Re-stamp and set the cookie. Only ever called when consent is granted.
  function refreshToken() {
    if (getConsent() !== GRANTED || !publicKey || !cfg) return Promise.resolve(false);
    return buildToken().then(function (token) {
      setCookie(cfg.cookieName, token, cfg.windowSeconds);
      return true;
    }).catch(function () { return false; });
  }

  function startRefreshLoop() {
    if (refreshTimer) return;
    var everyMs = Math.max(30, cfg.refreshSeconds) * 1000;
    refreshTimer = window.setInterval(function () { refreshToken(); }, everyMs);
    // Also re-stamp just before navigating away, so the next page's very first
    // request carries a fresh token.
    window.addEventListener("pagehide", function () { refreshToken(); });
  }

  function stopRefreshLoop() {
    if (refreshTimer) { window.clearInterval(refreshTimer); refreshTimer = null; }
  }

  // --- consent flow ---------------------------------------------------------

  function onAgree() {
    setConsent(GRANTED);
    removeBanner();
    // Generate the token NOW, then reload so the server sees it on the next
    // request and can route accordingly -- "immediately when agreed".
    refreshToken().then(function () {
      startRefreshLoop();
      location.reload();
    });
  }

  function onDecline() {
    setConsent(DENIED);
    stopRefreshLoop();
    deleteCookie(cfg.cookieName); // revoke: stop sending the token
    removeBanner();
    showManageButton();
  }

  // --- UI (inline styles only; CSP-safe) ------------------------------------

  function el(tag, styleText, text) {
    var e = document.createElement(tag);
    if (styleText) e.setAttribute("style", styleText);
    if (text != null) e.textContent = text;
    return e;
  }

  function removeBanner() {
    var b = document.getElementById("gdpr-consent-banner");
    if (b && b.parentNode) b.parentNode.removeChild(b);
  }

  function showBanner() {
    if (document.getElementById("gdpr-consent-banner")) return;

    var wrap = el("div", [
      "position:fixed", "left:0", "right:0", "bottom:0", "z-index:2147483647",
      "background:#111827", "color:#f9fafb",
      "font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif",
      "box-shadow:0 -2px 16px rgba(0,0,0,.35)", "padding:18px 20px"
    ].join(";"));
    wrap.id = "gdpr-consent-banner";
    wrap.setAttribute("role", "dialog");
    wrap.setAttribute("aria-label", AGREEMENT_TITLE);

    var inner = el("div",
      "max-width:980px;margin:0 auto;display:flex;gap:18px;align-items:center;flex-wrap:wrap;");

    var textCol = el("div", "flex:1 1 420px;min-width:260px;");
    textCol.appendChild(el("div",
      "font-weight:600;font-size:15px;margin-bottom:4px;", AGREEMENT_TITLE));
    textCol.appendChild(el("div",
      "font-size:13px;line-height:1.5;color:#d1d5db;", AGREEMENT_TEXT));

    var btnCol = el("div", "display:flex;gap:10px;flex:0 0 auto;");
    var btnBase =
      "border:0;border-radius:8px;padding:10px 18px;font-size:14px;" +
      "font-weight:600;cursor:pointer;";
    var decline = el("button", btnBase + "background:#374151;color:#f9fafb;", "Decline");
    var agree = el("button", btnBase + "background:#22c55e;color:#06260f;", "Agree");
    decline.type = "button";
    agree.type = "button";
    decline.addEventListener("click", onDecline);
    agree.addEventListener("click", onAgree);
    btnCol.appendChild(decline);
    btnCol.appendChild(agree);

    inner.appendChild(textCol);
    inner.appendChild(btnCol);
    wrap.appendChild(inner);
    document.body.appendChild(wrap);
  }

  // A small persistent control so a visitor can revisit / revoke their choice.
  function showManageButton() {
    if (document.getElementById("gdpr-manage-btn")) return;
    var btn = el("button", [
      "position:fixed", "left:14px", "bottom:14px", "z-index:2147483646",
      "background:#111827", "color:#9ca3af", "border:1px solid #374151",
      "border-radius:8px", "padding:6px 12px", "font-size:12px",
      "cursor:pointer", "font-family:system-ui,sans-serif"
    ].join(";"), "Privacy choices");
    btn.id = "gdpr-manage-btn";
    btn.type = "button";
    btn.addEventListener("click", function () {
      var m = document.getElementById("gdpr-manage-btn");
      if (m && m.parentNode) m.parentNode.removeChild(m);
      showBanner();
    });
    document.body.appendChild(btn);
  }

  // --- bootstrap ------------------------------------------------------------

  function start() {
    if (!window.crypto || !window.crypto.subtle || !window.fetch) return; // unsupported
    fetch(CONFIG_URL, { credentials: "omit" })
      .then(function (r) { return r.json(); })
      .then(function (c) {
        cfg = c;
        if (!cfg || !cfg.enabled || !cfg.publicKey) return; // subsystem off
        return importPublicKey(cfg.publicKey).then(function (key) {
          publicKey = key;
          var consent = getConsent();
          if (consent === GRANTED) {
            refreshToken();      // keep the cookie fresh on every page load
            startRefreshLoop();
            showManageButton();  // allow revocation
          } else if (consent === DENIED) {
            deleteCookie(cfg.cookieName);
            showManageButton();
          } else {
            showBanner();        // undecided -> ask, immediately
          }
        });
      })
      .catch(function () { /* fail silent: no token, session cookie only */ });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
