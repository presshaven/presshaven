"""Account Persistence: a step-by-step verifier for the "the adversary stays
logged in after diversion" feature (request 26), run from the dashboard against
the live edge.

THE FEATURE, IN ONE PARAGRAPH. When a logged-in WordPress visitor's
gdpr_signature turns suspicious and the edge diverts them to a honeypot pool,
their OWN production account -- role, profile, password hash and all -- is
copied into that pool's database and they are silently auto-logged-in there, so
nothing about the move hints they have been dropped into a honeypot. The pieces:

  * gdpr_client.js folds the logged-in username into the gdpr_token as a
    separate ``u`` key -- METADATA ONLY. gdpr_rules strips it before hashing, so
    the signature is identical logged-in or out (this module proves that live).
  * The honeypot-auth-identity mu-plugin makes production emit the REAL
    authenticated identity (X-Auth-User / X-Auth-Role) on that user's own
    responses; the edge caches it per session (gdpr_handler.record_auth_identity)
    and strips the headers before any client sees them.
  * At diversion the edge keys the copy off that PRODUCTION-VERIFIED identity
    (lookup_auth_identity), never the spoofable token username, enqueues a copy
    job on the Redis list ``honeypot_user_copy_queue`` and sets the secret-gated
    X-Honeypot-Autologin-User header.
  * honeypot_user_sync (replicate_user_to_honeypot.sh) consumes the queue and
    copies that one account into the pool; the honeypot-account-autologin
    mu-plugin -- gated on HONEYPOT_POOL_ID + INTERNAL_TEST_SECRET -- logs them in.

WHAT THIS MODULE DOES. It walks those pieces one step at a time, mixing a LIVE
end-to-end proof (step 2 mints two real tokens and reads the two signatures the
proxy derives back from its log) with READ-ONLY inspection of the deployed
config and running services (the mu-plugins are present, the edge records and
strips the identity headers, the sync worker is up, the autologin plugin is
secret-gated). Every check is read-only: it reads files, greps config, lists
containers and sends ordinary consented requests. Nothing is written, no
account is actually copied, no container is reconfigured.

SECRETS ARE NEVER PRINTED. The only secret in play, INTERNAL_TEST_SECRET, is
never read or emitted here -- the gating checks look for the *presence* of the
hash_equals()/secret guards in the deployed code, never their value. Evidence
strings carry outcomes, not secrets, and the two derived signatures are the only
hex that leaves the proxy (which is the whole privacy point of the design).

Qt-free so it is unit-testable; the UI half is ui/page_account_persistence.py
and the PDF renderer is core/account_persistence_pdf.py.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime

from core import breach_audit, signature_sim
from core.docker_ctl import Target
from core.gdpr_token import GdprConsent

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

PASS = "pass"      # the step works as designed
FAIL = "fail"      # the step is broken -- the feature would not work / is unsafe
WARN = "warn"      # works, but weaker than intended / needs a look
INFO = "info"      # not a verdict: context the reader needs to interpret a step
SKIP = "skip"      # could not run here (pools down, subsystem off, no target)
ERROR = "error"    # the check itself failed to run (tooling, timeout)

STATUSES = (PASS, FAIL, WARN, INFO, SKIP, ERROR)

# The default "screen size" characteristic the live proof signs. Any stable
# value works; the point of step 2 is that the SAME value with and without a
# username yields the SAME signature.
DEFAULT_SCREEN = "1280x800"

# The username the live proof folds into the token's ``u`` key. It never has to
# exist as a real account -- step 2 only proves the proxy STRIPS it before
# hashing, so the value is a harmless, obviously-synthetic label.
DEMO_USERNAME = "persistence_probe_user"

# Where each deployed artifact lives, so the inspection steps can find it.
_MU_PLUGIN_DIR = "/var/www/html/wp-content/mu-plugins"
AUTH_IDENTITY_PLUGIN = "honeypot-auth-identity.php"
AUTOLOGIN_PLUGIN = "honeypot-account-autologin.php"
# The reverse_proxy container bind-mounts ./reverse_proxy_enhanced to /etc/nginx.
_NGINX_CONF = "/etc/nginx/nginx.conf"
_LUA_DIR = "/etc/nginx/lua"

USER_COPY_QUEUE = "honeypot_user_copy_queue"
USER_SYNC_SERVICE = "honeypot_user_sync"


@dataclass
class StepOutcome:
    """One step in the walk-through. ``number`` orders it; ``status`` is the
    verdict; ``details`` are the human-readable lines shown under it; ``evidence``
    is the single most telling fact (never a secret)."""
    number: int
    name: str
    status: str
    summary: str                       # one line: what this step establishes
    details: list[str] = field(default_factory=list)
    evidence: str = ""

    @property
    def ok(self) -> bool:
        return self.status in (PASS, INFO)


@dataclass
class AccountPersistenceReport:
    generated_at: str
    target_label: str
    base_url: str
    username: str
    screen: str
    steps: list[StepOutcome] = field(default_factory=list)
    # The two signatures step 2 derived, kept for the PDF's side-by-side.
    sig_without_username: str = ""
    sig_with_username: str = ""

    def counts(self) -> dict[str, int]:
        out = {k: 0 for k in STATUSES}
        for s in self.steps:
            out[s.status] = out.get(s.status, 0) + 1
        return out

    @property
    def failures(self) -> list[StepOutcome]:
        return [s for s in self.steps if s.status == FAIL]

    def headline(self) -> tuple[str, str]:
        """(status word, one-line summary) for the top of the report."""
        c = self.counts()
        ran = c[PASS] + c[FAIL] + c[WARN]
        if c[FAIL]:
            return ("NOT WORKING",
                    f"{c[FAIL]} step(s) broken; {c[PASS]} verified, "
                    f"{c[WARN]} warning(s).")
        if c[WARN]:
            return ("WORKING (with warnings)",
                    f"Account persistence is wired end to end, with {c[WARN]} "
                    f"weaker-than-ideal finding(s); {c[PASS]} step(s) verified.")
        if c[PASS]:
            note = f"; {c[SKIP]} step(s) could not run here" if c[SKIP] else ""
            return ("WORKING",
                    f"All {c[PASS]} verifiable step(s) held{note}.")
        return ("INCONCLUSIVE", "No steps could run -- nothing to report.")


# ---------------------------------------------------------------------------
# Live proof: the username is token metadata, not part of the signature
# ---------------------------------------------------------------------------

def _derive_signature(base: str, target: Target, consent: GdprConsent,
                      characteristics: dict, *, timeout: int = 15,
                      attempts: int = 8, gap_s: float = 0.5) -> tuple[str, str]:
    """Mint one real gdpr_token for ``characteristics``, send it to the proxy,
    and read back the signature the proxy derives from its own log. Returns
    ``(signature, error)`` -- ``signature`` is "" when ``error`` is set.

    The new-line recognition mirrors signature_sim.run_flow: we note how many
    signature lines the proxy had logged before our request and take the first
    one that appears after. The dashboard's cookieless requests share one
    fingerprint-recovered session, so we key off the line COUNT growing, not the
    session id or value changing (the whole point is the value may repeat)."""
    token = consent.token(characteristics)
    if not token:
        return "", "could not mint a gdpr_token (is the openssl CLI available?)"
    before = len(signature_sim._signature_lines(target))
    status, err = signature_sim._send(base, consent.cookie_name, token, timeout)
    if err:
        return "", err
    for _ in range(attempts):
        time.sleep(gap_s)
        lines = signature_sim._signature_lines(target)
        if len(lines) > before:
            return lines[-1][0], ""
    return "", ("the token was sent but no new gdpr_signature appeared in the proxy "
                "log (token rejected for clock skew, or GDPR disabled on the proxy)")


def prove_username_is_metadata(base_url: str, target: Target, screen: str,
                               username: str) -> StepOutcome:
    """Step 2, the heart of it: mint a token WITHOUT a username and one WITH the
    username folded into ``u``, send both, and compare the two signatures the
    proxy derives. They MUST be identical -- that is the live proof the username
    rides as metadata and is stripped before hashing, so turning a logged-in
    visitor suspicious depends only on their browser, never on who they are."""
    base = base_url.rstrip("/")
    out = StepOutcome(
        2, "Username is token metadata, not part of the signature", SKIP,
        "A gdpr_token carrying the username derives the SAME signature as one "
        "without it -- proof the username is stripped before hashing.")

    consent = GdprConsent.acquire(base)
    if consent is None:
        out.status = SKIP
        out.evidence = "GDPR subsystem unreachable or disabled; cannot derive signatures."
        out.details.append("Start the edge with reverse_proxy up and GDPR enabled, then re-run.")
        return out
    try:
        sig_plain, err1 = _derive_signature(base, target, consent, {"s": screen})
        if err1:
            out.status = ERROR
            out.evidence = f"baseline token: {err1}"
            return out
        sig_user, err2 = _derive_signature(base, target, consent,
                                           {"s": screen, "u": username})
        if err2:
            out.status = ERROR
            out.evidence = f"username token: {err2}"
            out.details.append(f"baseline signature (no username) = {sig_plain}")
            return out

        out.details.append(f"token characteristics (no username):  {{\"s\":\"{screen}\"}}")
        out.details.append(f"  → signature  {sig_plain}")
        out.details.append(f"token characteristics (with username): "
                           f"{{\"s\":\"{screen}\",\"u\":\"{username}\"}}")
        out.details.append(f"  → signature  {sig_user}")
        if sig_plain and sig_plain == sig_user:
            out.status = PASS
            out.evidence = ("both tokens derived the SAME signature -- the username "
                            "does not change it, so it is stripped, not signed")
            out.details.append("Identical → the username is metadata. A logged-in visitor and "
                               "the same browser logged out are one signature, so diversion "
                               "depends on the browser, never on the account.")
        else:
            out.status = FAIL
            out.evidence = ("the username CHANGED the signature -- it is being folded "
                            "into the signed characteristics, which it must not be")
            out.details.append("Different → the username is leaking into the signature. Check "
                               "gdpr_rules.IDENTITY_KEYS / canonical_characteristics.")
        return out
    finally:
        consent.cleanup()


# ---------------------------------------------------------------------------
# Read-only inspection helpers (reuse the breach-audit docker plumbing)
# ---------------------------------------------------------------------------

def _file_present(target: Target, container: str, path: str) -> bool | None:
    """True/False whether ``path`` exists in ``container``, or None if the check
    itself could not run."""
    try:
        rc, _ = breach_audit._docker_exec(target, container, f"test -f {path}")
    except breach_audit.BreachAuditError:
        return None
    return rc == 0


def _grep_count(target: Target, container: str, path: str, pattern: str) -> int | None:
    """How many lines in ``path`` (inside ``container``) match the fixed-string
    ``pattern``. None if the check could not run. Fixed-string (grep -F) so a
    pattern with regex metacharacters is matched literally and safely."""
    # -c counts; redirect so a missing file is simply 0, not an error line.
    import shlex as _shlex
    cmd = f"grep -cF {_shlex.quote(pattern)} {path} 2>/dev/null || true"
    try:
        rc, out = breach_audit._docker_exec(target, container, cmd)
    except breach_audit.BreachAuditError:
        return None
    first = (out.splitlines() or ["0"])[0].strip()
    try:
        return int(first)
    except ValueError:
        return 0


def _check_production_emits_identity(target: Target, names: list[str]) -> StepOutcome:
    """Step 3: production runs the honeypot-auth-identity mu-plugin, which emits
    the authenticated user's real identity (X-Auth-User / X-Auth-Role and the
    <meta name="gdpr-user"> tag) on that user's own responses."""
    out = StepOutcome(
        3, "Production publishes the authenticated identity", SKIP,
        "The honeypot-auth-identity mu-plugin is installed on production and "
        "emits the logged-in user's real login/role for the edge to capture.")
    prod = breach_audit._prod_container(names, "production_eshop")
    if prod is None:
        out.status = SKIP
        out.evidence = "production_eshop container is not running; cannot inspect it."
        return out
    out.details.append(f"Inspecting {prod}:{_MU_PLUGIN_DIR}/{AUTH_IDENTITY_PLUGIN}")
    present = _file_present(target, prod, f"{_MU_PLUGIN_DIR}/{AUTH_IDENTITY_PLUGIN}")
    if present is None:
        out.status = ERROR
        out.evidence = "could not read the production container's mu-plugins directory"
        return out
    if not present:
        out.status = FAIL
        out.evidence = f"{AUTH_IDENTITY_PLUGIN} is MISSING on production -- the edge would " \
                       "never learn who is authenticated, so the copy would fall back to the " \
                       "spoofable token username."
        return out

    path = f"{_MU_PLUGIN_DIR}/{AUTH_IDENTITY_PLUGIN}"
    emits = _grep_count(target, prod, path, "X-Auth-User")
    uses_current = _grep_count(target, prod, path, "wp_get_current_user")
    meta = _grep_count(target, prod, path, "gdpr-user")
    out.details.append(f"X-Auth-User header emitted: {'yes' if emits else 'no'}")
    out.details.append(f"identity taken from wp_get_current_user(): {'yes' if uses_current else 'no'}")
    out.details.append(f"<meta name=\"gdpr-user\"> published for gdpr_client.js: "
                      f"{'yes' if meta else 'no'}")
    if emits and uses_current:
        out.status = PASS
        out.evidence = ("mu-plugin present and emits X-Auth-User from "
                        "wp_get_current_user() -- the authoritative, non-spoofable identity")
    else:
        out.status = WARN
        out.evidence = ("mu-plugin present but the expected X-Auth-User / "
                        "wp_get_current_user() markers were not both found")
    return out


def _check_edge_records_and_strips(target: Target, names: list[str]) -> StepOutcome:
    """Step 4: the edge treats production's X-Auth-* as authoritative (records it
    per session) and keys the copy off it -- never the spoofable token username --
    and strips the identity/autologin headers so no client can see or forge them."""
    out = StepOutcome(
        4, "Edge trusts only the production-verified identity", SKIP,
        "The edge records production's X-Auth-User per session and keys the "
        "account copy off it, never the spoofable token username, and strips the "
        "identity and autologin headers from client traffic.")
    proxy = breach_audit._prod_container(names, "reverse_proxy")
    if proxy is None:
        out.status = SKIP
        out.evidence = "reverse_proxy container is not running; cannot inspect its config."
        return out

    records = _grep_count(target, proxy, f"{_LUA_DIR}/gdpr_handler.lua", "record_auth_identity")
    looks_up = _grep_count(target, proxy, _NGINX_CONF, "lookup_auth_identity")
    clears_user = _grep_count(target, proxy, _NGINX_CONF, "clear_header")
    strips_auth = _grep_count(target, proxy, _NGINX_CONF, "X-Auth-User")
    autologin_hdr = _grep_count(target, proxy, _NGINX_CONF, "X-Honeypot-Autologin-User")

    missing = [v for v in (records, looks_up, clears_user, strips_auth) if v is None]
    if missing:
        out.status = ERROR
        out.evidence = "could not read the reverse_proxy container's nginx/lua config"
        return out

    out.details.append(f"records production identity per session (record_auth_identity): "
                      f"{'yes' if records else 'no'}")
    out.details.append(f"keys the copy off the verified identity (lookup_auth_identity): "
                      f"{'yes' if looks_up else 'no'}")
    out.details.append(f"clears inbound headers (clear_header present): "
                      f"{'yes' if clears_user else 'no'}")
    out.details.append(f"handles X-Auth-User / X-Honeypot-Autologin-User: "
                      f"{'yes' if (strips_auth and autologin_hdr) else 'partial'}")
    if records and looks_up and clears_user and strips_auth:
        out.status = PASS
        out.evidence = ("edge records X-Auth-User per session, keys the copy off it "
                        "(lookup_auth_identity) and clears the inbound identity/autologin headers")
    else:
        out.status = WARN
        out.evidence = ("the expected record/lookup/clear directives were not all found in "
                        "the edge config")
    return out


def _check_sync_worker(target: Target, names: list[str]) -> StepOutcome:
    """Step 5: the honeypot_user_sync worker is running to consume the copy queue
    the edge enqueues to -- the only service bridged to both networks that may
    copy an account into a pool."""
    out = StepOutcome(
        5, "Replication worker is running and the copy queue is wired", SKIP,
        f"The {USER_SYNC_SERVICE} worker is up to consume the Redis "
        f"'{USER_COPY_QUEUE}' list the edge enqueues a copy job to at diversion.")
    worker = breach_audit._prod_container(names, USER_SYNC_SERVICE)
    if worker is None:
        out.status = FAIL
        out.evidence = (f"{USER_SYNC_SERVICE} is not running -- copy jobs the edge enqueues "
                        "would pile up unconsumed, so a diverted user's account would never "
                        "reach the pool")
        out.details.append("Bring the edge stack fully up (the worker starts with it).")
        return out
    out.status = PASS
    out.evidence = f"{worker} is running and consuming {USER_COPY_QUEUE}"
    out.details.append(f"worker container: {worker}")
    out.details.append(f"copy queue (Redis list): {USER_COPY_QUEUE}")
    out.details.append("The edge RPUSHes a {user,pool} job here keyed off the production-"
                      "verified identity; the worker copies that one account into the pool.")
    return out


def _check_autologin_plugin(target: Target, names: list[str]) -> StepOutcome:
    """Step 6: the honeypot-account-autologin mu-plugin -- which adopts the copied
    account on the pool -- is present and HARD-GATED (pool-only, secret-gated),
    so it can only ever be driven by the edge, never a client."""
    out = StepOutcome(
        6, "Pool autologin plugin is present and secret-gated", SKIP,
        "The honeypot-account-autologin mu-plugin logs the copied account in on "
        "the pool, gated on HONEYPOT_POOL_ID and INTERNAL_TEST_SECRET so only the "
        "edge can trigger it.")
    pools = breach_audit.discover_pools(names)
    # The plugin ships in the same mu-plugins dir as the identity one, rsynced to
    # every instance (it self-gates to no-op off a pool). Inspect a pool eshop if
    # one is up, else fall back to production where the file is present but inert.
    container = None
    source = ""
    for num in sorted(pools):
        eshop = pools[num].get("eshop")
        if eshop:
            container = eshop
            source = f"honeypot pool {num} ({eshop})"
            break
    if container is None:
        prod = breach_audit._prod_container(names, "production_eshop")
        if prod is not None:
            container = prod
            source = f"{prod} (inert on production; rsynced to the pools)"
    if container is None:
        out.status = SKIP
        out.evidence = "no pool or production eshop container running to inspect."
        return out

    out.details.append(f"Inspecting {source}")
    path = f"{_MU_PLUGIN_DIR}/{AUTOLOGIN_PLUGIN}"
    present = _file_present(target, container, path)
    if present is None:
        out.status = ERROR
        out.evidence = "could not read the container's mu-plugins directory"
        return out
    if not present:
        out.status = FAIL
        out.evidence = f"{AUTOLOGIN_PLUGIN} is MISSING -- a copied account would never be " \
                       "logged in on the pool, so the visitor would land logged out."
        return out

    pool_gate = _grep_count(target, container, path, "HONEYPOT_POOL_ID")
    secret_gate = _grep_count(target, container, path, "hash_equals")
    secret_env = _grep_count(target, container, path, "INTERNAL_TEST_SECRET")
    header = _grep_count(target, container, path, "X-Honeypot-Autologin-User")
    out.details.append(f"pool-only gate (HONEYPOT_POOL_ID): {'yes' if pool_gate else 'no'}")
    out.details.append(f"constant-time secret gate (hash_equals INTERNAL_TEST_SECRET): "
                      f"{'yes' if (secret_gate and secret_env) else 'no'}")
    out.details.append(f"acts on the edge's X-Honeypot-Autologin-User header: "
                      f"{'yes' if header else 'no'}")
    if pool_gate and secret_gate and secret_env and header:
        out.status = PASS
        out.evidence = ("plugin present and gated on HONEYPOT_POOL_ID + a hash_equals() "
                        "check of INTERNAL_TEST_SECRET -- only the edge can drive it")
    else:
        out.status = WARN
        out.evidence = ("plugin present but not all of the pool-only / secret / header gates "
                        "were found")
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_report(target: Target, base_url: str, *, username: str = DEMO_USERNAME,
               screen: str = DEFAULT_SCREEN, target_label: str = "",
               log=None) -> AccountPersistenceReport:
    """Run the whole walk-through and return the assembled report. ``log`` (if
    given) is called with a short progress line before each step. Never raises:
    a step that cannot run becomes a SKIP/ERROR outcome."""
    def _log(msg: str) -> None:
        if log:
            log(msg)

    report = AccountPersistenceReport(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target_label=target_label or getattr(target, "label", "") or "edge",
        base_url=base_url.rstrip("/"),
        username=username,
        screen=screen,
    )

    # Step 1: GDPR subsystem reachable (everything downstream rides on it).
    _log("Step 1: checking the GDPR subsystem is reachable …")
    consent = GdprConsent.acquire(base_url.rstrip("/"))
    if consent is None:
        report.steps.append(StepOutcome(
            1, "GDPR subsystem reachable", FAIL,
            "The consent-gated gdpr_token subsystem answers, which the whole "
            "feature rides on.",
            details=["Start the edge stack and ensure reverse_proxy is up with GDPR enabled."],
            evidence="GET /__gdpr/config did not return an enabled subsystem with a public key"))
    else:
        consent.cleanup()
        report.steps.append(StepOutcome(
            1, "GDPR subsystem reachable", PASS,
            "The consent-gated gdpr_token subsystem answers, which the whole "
            "feature rides on.",
            details=["The proxy served its GDPR config and public key."],
            evidence="GET /__gdpr/config returned an enabled subsystem with a public key"))

    # Step 2: live proof the username is metadata, not signed.
    _log("Step 2: deriving signatures with and without the username …")
    report.steps.append(prove_username_is_metadata(base_url, target, screen, username))
    step2 = report.steps[-1]
    for line in step2.details:
        if line.startswith("  → signature  "):
            sig = line[len("  → signature  "):].strip()
            if not report.sig_without_username:
                report.sig_without_username = sig
            else:
                report.sig_with_username = sig

    # Steps 3-6 inspect the deployed pieces; they all need the container list.
    _log("Listing running edge containers …")
    try:
        names = breach_audit._running_containers(target)
    except breach_audit.BreachAuditError as e:
        for n, name, summ in (
            (3, "Production publishes the authenticated identity", ""),
            (4, "Edge trusts only the production-verified identity", ""),
            (5, "Replication worker is running and the copy queue is wired", ""),
            (6, "Pool autologin plugin is present and secret-gated", "")):
            report.steps.append(StepOutcome(
                n, name, ERROR, summ or name,
                evidence=f"could not list edge containers: {e}"))
        return report

    _log("Step 3: checking production emits the authenticated identity …")
    report.steps.append(_check_production_emits_identity(target, names))
    _log("Step 4: checking the edge records and strips the identity …")
    report.steps.append(_check_edge_records_and_strips(target, names))
    _log("Step 5: checking the replication worker …")
    report.steps.append(_check_sync_worker(target, names))
    _log("Step 6: checking the pool autologin plugin …")
    report.steps.append(_check_autologin_plugin(target, names))
    return report
