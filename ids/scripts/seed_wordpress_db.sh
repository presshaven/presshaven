#!/bin/sh
# seed_wordpress_db.sh - One-time WordPress + WooCommerce + Elementor
# bootstrap, run by production_db_seed (production_database) and
# honeypot_db_seed_1/2/3 (each honeypot pool's own database) -- see
# docker-compose.yml. Same script for all four: which WordPress instance
# it targets and how much content it seeds are entirely controlled by
# the environment variables below, not by which service runs it.
#
# PROBLEM THIS FIXES:
#   A freshly-cloned repo already ships the entire WordPress codebase --
#   core, plugins, themes, uploads -- for production (git-tracked under
#   production_eshop_files/) and, once init_setup's rsync has run, for
#   each honeypot pool too (named volumes honeypot_eshop_files[_N]) --
#   but every one of those FOUR databases starts with ZERO tables:
#   nothing had ever run `wp core install` against any of them. Every
#   request touching wp_options (nearly every request -- this is
#   WordPress core itself, not an Elementor-specific bug) errored with
#   "Table '...production_database.wp_options' doesn't exist" until a
#   human manually clicked through wp-admin/install.php in a browser --
#   including wp_install_state.lua's own 30s health-probe timer against
#   production, which is why the error recurred on a clock, AND
#   honeypot_content_sync's own periodic replication cycle against each
#   pool (its scoped DELETE/INSERT assumes the destination tables
#   already exist -- it creates content ROWS, never SCHEMA). This script
#   does the install automatically, once, idempotently, before anything
#   downstream ever sees a schemaless database -- see docker-compose.yml's
#   depends_on chains (production_eshop/honeypot_eshop_N on their
#   respective seed service; honeypot_content_sync on ALL FOUR).
#
# WHY A SCRIPT, NOT A COMMITTED SQL DUMP / git-lfs BINARY:
#   This is a few KB of plain-text, reviewable-in-a-normal-`git diff`
#   WP-CLI commands that deterministically rebuild the same demo
#   storefront from the already-git-tracked plugin/theme code, rather
#   than a large opaque binary blob that would eat GitHub's free LFS
#   quota (1GB storage / 1GB month bandwidth total across the whole
#   repo) and need regenerating and recommitting on every content change.
#   backup_service's own point-in-time dumps (ids/backups/)
#   remain the disaster-recovery mechanism for a stack that's already
#   been running -- this script is purely about first-boot bring-up.
#
# IDEMPOTENCY:
#   Safe to run on every `docker compose up` -- bails out immediately if
#   WordPress is already installed. Pass FORCE_RESEED=1 (e.g. from the
#   dashboard's Backups page "Reset demo store" button, or
#   manage_backups.sh) to wipe every WordPress table and rebuild from
#   scratch -- useful to restore a clean, known-good storefront between
#   pattern test runs, since patterns are expected to modify/corrupt
#   this database.
#
# IMPORT_SAMPLE_CONTENT (default "1"):
#   production_db_seed leaves this at its default -- production is the
#   one and only source of real content (WooCommerce sample catalog +
#   the Elementor demo pages authored by seed_elementor_pages.sh).
#   honeypot_db_seed_1/2/3 set this to "0": a honeypot pool is meant to
#   have IDENTICAL content to production, not its own independently
#   authored copy -- that's already handled by
#   scripts/replicate_content_to_honeypot.sh's own scoped-mirror logic
#   once real schema exists to mirror INTO. Authoring separate content
#   here too would just leave orphaned rows alongside whatever
#   replication brings in, with no schema/content conflict but no
#   purpose either. Schema/theme/plugin setup happens identically either
#   way -- pools need to actually LOOK like production, just not have
#   their own independently-sourced data.
#
# RESILIENCE:
#   `wp core install` itself is the one step allowed to fail loudly and
#   abort (set -e) -- without it nothing downstream makes sense, and the
#   dependent eshop container's depends_on (service_completed_successfully)
#   means the whole stack correctly stays down rather than serving a
#   broken site. Everything past that (product catalog import needs a
#   one-time wordpress.org plugin download; the Elementor pages are
#   cosmetic) is best-effort: a transient network hiccup on first boot
#   degrades to a working-but-emptier storefront instead of blocking
#   startup entirely.
set -eu

: "${WORDPRESS_DB_HOST:?WORDPRESS_DB_HOST environment variable is required}"
: "${WORDPRESS_DB_NAME:?WORDPRESS_DB_NAME environment variable is required}"
: "${WORDPRESS_DB_USER:?WORDPRESS_DB_USER environment variable is required}"
: "${WORDPRESS_DB_PASSWORD:?WORDPRESS_DB_PASSWORD environment variable is required}"
: "${WP_ADMIN_USER:?WP_ADMIN_USER environment variable is required}"
: "${WP_ADMIN_PASSWORD:?WP_ADMIN_PASSWORD environment variable is required}"
: "${WP_ADMIN_EMAIL:?WP_ADMIN_EMAIL environment variable is required}"
: "${WP_SITE_URL:?WP_SITE_URL environment variable is required}"
: "${WP_SITE_TITLE:?WP_SITE_TITLE environment variable is required}"

cd /var/www/html

# --allow-root: this container runs wp-cli as root (matches production_eshop's
# own container, which the official wordpress:apache image also runs as root
# by default) -- wp-cli refuses by default as a safety rail meant for
# multi-user shared hosting, irrelevant here.
WP="wp --allow-root --path=/var/www/html"

# `wp rewrite ... --hard` only writes mod_rewrite rules into .htaccess if
# WP-CLI is told Apache has mod_rewrite -- from the CLI there is no Apache
# to ask, so without this WordPress's got_mod_rewrite() is false and the
# .htaccess keeps an EMPTY "# BEGIN WordPress ... # END WordPress" block.
# Confirmed live: that's exactly why /shop/, /product/<slug>/ and every
# other pretty permalink 404'd from Apache on all four instances while
# ?post_type=product worked fine. Kept out of the web root (not a
# wp-cli.yml in /var/www/html) so it is never served to a client.
WP_CLI_CONFIG_PATH=/tmp/wp-cli-seed.yml
export WP_CLI_CONFIG_PATH
printf 'apache_modules:\n  - mod_rewrite\n' > "$WP_CLI_CONFIG_PATH"

now_iso() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { echo "[SEED] $(now_iso) $*"; }

# depends_on: service_healthy only proves mysqld itself is accepting
# connections -- for a MySQL container, that's a mysqladmin ping using
# WHATEVER credentials that healthcheck happens to use, which isn't
# necessarily WORDPRESS_DB_USER/PASSWORD as seen from THIS container
# (confirmed live: honeypot_database_2/3 start out cloned from
# production's own data directory and keep production's password until
# honeypot_db_migration's own ALTER USER step rotates it -- a real race
# against this container if that dependency were ever missing or
# insufficient).
#
# A PHP mysqli connect with the real WORDPRESS_DB_* credentials, not
# `wp db check`/`mysql -e` -- confirmed live those fail here with
# "TLS/SSL error: Certificate verification failure", unrelated to
# credentials: this image's bundled mysql CLI client (MariaDB 15.2)
# defaults to verifying certs and rejects the self-signed one a
# mysql server presents, the same class of issue backup.sh already
# works around for mysqldump with --skip-ssl. `wp core install` itself,
# just below, does NOT go through that CLI binary at all --
# WordPress/wpdb connects via PHP's mysqli extension directly, which
# doesn't hit this -- so a CLI-based pre-flight check was actively
# wrong here, not just unnecessary: it could fail (and block startup)
# on a perfectly healthy database that `wp core install` would have
# connected to just fine. Probing through the same mysqli extension
# with the same credentials wp-config.php will use is the one check
# that proves exactly what `wp core install` needs.
#
# Not a raw TCP connect (fsockopen) either, as this used to be:
# confirmed live that connecting and closing without a MySQL handshake
# makes mysqld log '[Note] Got an error reading communication packets'
# for every probe -- one per seed container per boot. A completed
# handshake with valid credentials logs nothing. Only a connect-level
# failure (mysqli errno 2002/2003 "Can't connect", 2006 "gone away")
# keeps waiting -- that's the genuine "container just started, not
# accepting connections yet" race this loop exists for. Anything else
# (e.g. 1045 access denied) means the server IS up but these
# credentials won't work, and waiting wouldn't change that: fail
# immediately with the server's own message rather than looping 60s
# and then having `wp core install` fail with the same error anyway.
db_host="${WORDPRESS_DB_HOST%%:*}"
db_port="${WORDPRESS_DB_HOST##*:}"
[ "$db_port" = "$WORDPRESS_DB_HOST" ] && db_port=3306  # no ":port" suffix present

# Exit 0: connected. Exit 1: not accepting connections yet (retry).
# Exit 2: server answered but rejected the connection (fatal); the
# reason is printed on stdout.
db_probe() {
    DB_HOST="$db_host" DB_PORT="$db_port" php -r '
        mysqli_report(MYSQLI_REPORT_OFF);
        $m = mysqli_init();
        $m->options(MYSQLI_OPT_CONNECT_TIMEOUT, 2);
        if (@$m->real_connect(getenv("DB_HOST"), getenv("WORDPRESS_DB_USER"),
                getenv("WORDPRESS_DB_PASSWORD"), getenv("WORDPRESS_DB_NAME"),
                (int) getenv("DB_PORT"))) {
            $m->close();
            exit(0);
        }
        if (in_array($m->connect_errno, [2002, 2003, 2006], true)) {
            exit(1);
        }
        echo $m->connect_errno, ": ", $m->connect_error, "\n";
        exit(2);
    '
}

log "Waiting for ${db_host}:${db_port} to accept connections..."
attempt=0
max_attempts=30
while :; do
    probe_out=$(db_probe) && break
    probe_rc=$?
    if [ "$probe_rc" -eq 2 ]; then
        log "ERROR: ${db_host}:${db_port} rejected the connection: ${probe_out} -- giving up."
        exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$max_attempts" ]; then
        log "ERROR: ${db_host}:${db_port} still not accepting connections after ${max_attempts} attempts (60s) -- giving up."
        exit 1
    fi
    sleep 2
done
log "${db_host}:${db_port} reachable."

# ---------------------------------------------------------------------------
# configure_storefront -- everything a visitor needs to actually browse and
# BUY: pretty permalinks written to .htaccess, a shipping method, and
# payment gateways. Idempotent and cheap (a handful of option writes), so
# it runs on EVERY boot, including the "already installed" no-op path
# below -- these live in wp_options, which honeypot_content_sync
# deliberately never replicates (it mirrors content rows only), so each
# of the four instances has to get them from its own seed run, and an
# instance seeded before this step existed picks it up on its next boot
# without a FORCE_RESEED.
#
# Payment:
#   * Stripe (woocommerce-gateway-stripe, already shipped under
#     wp-content/plugins) in TEST MODE, when STRIPE_TEST_PUBLISHABLE_KEY /
#     STRIPE_TEST_SECRET_KEY are set in .env -- Stripe's own sandbox, card
#     4242 4242 4242 4242 with any future expiry/CVC completes an order.
#     The keys come from a free Stripe account's "Test mode" dashboard;
#     Stripe refuses to enable the gateway on made-up keys, so there is no
#     built-in default. Not activated at all when the keys are absent, so
#     an offline stack never tries to reach api.stripe.com.
#   * "Cash on delivery" and "Direct bank transfer" (WooCommerce core's
#     offline gateways) are always enabled as the "something similar"
#     fallback: checkout completes end-to-end with no external service,
#     so an order can be placed on every instance regardless of Stripe.
# Shipping: one "Free shipping" method on the default (rest of the world)
#   zone -- without ANY shipping method WooCommerce blocks checkout with
#   "no shipping options were found" for every physical product, which was
#   the case on all four instances.
# ---------------------------------------------------------------------------
#
# Startup cost: every $WP call boots all of WordPress + WooCommerce +
# Elementor (~0.6s+ each), and this runs on every boot of all four seed
# containers, so the warm path is kept to ONE boot (the eval-file below).
# The Stripe activation happens inside it (activate_plugin() is exactly
# what `wp plugin activate` calls), and the permalink step -- two more
# boots, since `wp rewrite structure --hard` itself re-launches `wp
# rewrite flush --hard` -- only runs when the eval-file reports the
# structure/.htaccess/rewrite_rules aren't already in place.
# ---------------------------------------------------------------------------
configure_storefront() {
    log "Configuring storefront (permalinks, shipping, payment gateways)..."

    needs_rewrite_flag=/tmp/seed-needs-rewrite
    rm -f "$needs_rewrite_flag"

    NEEDS_REWRITE_FLAG="$needs_rewrite_flag" $WP eval-file - <<'PHP'
<?php
// Permalinks: only flag for a (costly) `wp rewrite structure` run if
// something is actually missing. A pool's .htaccess is re-synced from
// production's by init_setup on every boot, so it already carries the
// rules once production has been seeded.
$htaccess = ABSPATH . '.htaccess';
if ( get_option( 'permalink_structure' ) !== '/%postname%/'
    || ! get_option( 'rewrite_rules' )
    || ! is_readable( $htaccess )
    || strpos( (string) file_get_contents( $htaccess ), 'RewriteRule . /index.php' ) === false ) {
    touch( getenv( 'NEEDS_REWRITE_FLAG' ) );
}

// Activate Stripe before writing its settings so the plugin's own
// activation defaults never overwrite them.
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$stripe_plugin = 'woocommerce-gateway-stripe/woocommerce-gateway-stripe.php';
if ( getenv( 'STRIPE_TEST_PUBLISHABLE_KEY' ) && getenv( 'STRIPE_TEST_SECRET_KEY' )
    && ! is_plugin_active( $stripe_plugin ) ) {
    $result = activate_plugin( $stripe_plugin );
    if ( is_wp_error( $result ) ) {
        WP_CLI::error( 'Could not activate woocommerce-gateway-stripe: ' . $result->get_error_message() );
    }
    WP_CLI::log( '  Activated woocommerce-gateway-stripe' );
}

// Shipping on the default zone, once: standard $5.95, free over $45 (the
// storefront advertises exactly this -- see the Shipping & Returns page).
$zone = WC_Shipping_Zones::get_zone( 0 );
if ( empty( $zone->get_shipping_methods() ) ) {
    $free = $zone->add_shipping_method( 'free_shipping' );
    $flat = $zone->add_shipping_method( 'flat_rate' );
    update_option( 'woocommerce_free_shipping_' . $free . '_settings', [
        'title' => 'Free shipping', 'requires' => 'min_amount', 'min_amount' => '45', 'ignore_discounts' => 'no',
    ] );
    update_option( 'woocommerce_flat_rate_' . $flat . '_settings', [
        'title' => 'Standard shipping', 'tax_status' => 'none', 'cost' => '5.95',
    ] );
    WP_CLI::log( '  Added Standard ($5.95) and Free-over-$45 shipping to the default shipping zone' );
}

// Offline gateways (always on).
$merge = function ( $option, array $values ) {
    $current = get_option( $option );
    if ( ! is_array( $current ) ) {
        $current = [];
    }
    update_option( $option, array_merge( $current, $values ) );
};
$merge( 'woocommerce_cod_settings', [
    'enabled'            => 'yes',
    'title'              => 'Cash on delivery',
    'description'        => 'Pay with cash upon delivery.',
    'instructions'       => 'Pay with cash upon delivery.',
    'enable_for_methods' => [],
    'enable_for_virtual' => 'yes',
] );
$merge( 'woocommerce_bacs_settings', [
    'enabled'      => 'yes',
    'title'        => 'Direct bank transfer',
    'description'  => 'Make your payment directly into our bank account. Your order will not be shipped until the funds have cleared.',
    'instructions' => 'Make your payment directly into our bank account. Please use your Order ID as the payment reference.',
] );
WP_CLI::log( '  Enabled Cash on delivery + Direct bank transfer' );

// Stripe test mode, only with real sandbox keys.
$pk = getenv( 'STRIPE_TEST_PUBLISHABLE_KEY' );
$sk = getenv( 'STRIPE_TEST_SECRET_KEY' );
if ( $pk && $sk ) {
    $merge( 'woocommerce_stripe_settings', [
        'enabled'                         => 'yes',
        'title'                           => 'Credit / debit card',
        'description'                     => 'Pay securely with your card via Stripe.',
        'testmode'                        => 'yes',
        'test_publishable_key'            => $pk,
        'test_secret_key'                 => $sk,
        'capture'                         => 'yes',
        'payment_request'                 => 'no',
        'upe_checkout_experience_enabled' => 'yes',
        'logging'                         => 'no',
    ] );
    WP_CLI::log( '  Configured Stripe gateway (test mode)' );
} else {
    WP_CLI::log( '  STRIPE_TEST_PUBLISHABLE_KEY/STRIPE_TEST_SECRET_KEY not set -- Stripe gateway left off' );
}
PHP

    if [ -f "$needs_rewrite_flag" ]; then
        # --hard: regenerate .htaccess (see WP_CLI_CONFIG_PATH above). This
        # already runs `wp rewrite flush --hard` itself -- no separate flush.
        $WP rewrite structure '/%postname%/' --hard
        rm -f "$needs_rewrite_flag"
    else
        log "  Permalinks + .htaccess already in place -- skipping rewrite flush."
    fi
}

# Authors the Fernhill Coffee Roasters catalog, pages and journal (production
# only: IMPORT_SAMPLE_CONTENT=1). Version-gated and idempotent -- the PHP bails
# out in one WordPress boot when the stored catalog version is current -- so it
# is safe on every boot and upgrades an older install to the current catalog.
author_storefront_content() {
    [ "${IMPORT_SAMPLE_CONTENT:-1}" = "1" ] || return 0
    [ -f /seed_storefront_content.php ] && [ -f /eshop_seed/catalog.json ] || return 0
    $WP eval-file /seed_storefront_content.php || log "  WARNING: storefront content authoring failed -- continuing."
}

# ---------------------------------------------------------------------------
# Main admin account: make WP_ADMIN_USER exist as an administrator with
# WP_ADMIN_PASSWORD / WP_ADMIN_EMAIL from .env. `wp core install` only sets
# it once, so without this an edited .env never reached an installed site,
# and a pool cloned from production + scrubbed (honeypot migrations replace
# wp_users with placeholder accounts) kept a password nobody knew. Runs on
# every boot in one wp-cli call. The password is only rewritten when it
# differs, because wp_set_password() also ends every session of that user
# (the dashboard's WordPress Studio would be logged out on each restart).
#
# Honeypot seeds pass HONEYPOT_WP_ADMIN_PASSWORD here instead (see
# docker-compose.yml), so decoys share the user name but never the password.
# ---------------------------------------------------------------------------
ensure_admin_account() {
    $WP eval-file - <<'PHP' || log "  WARNING: could not apply the admin account from .env -- continuing."
<?php
$login = getenv( 'WP_ADMIN_USER' );
$pass  = getenv( 'WP_ADMIN_PASSWORD' );
$email = getenv( 'WP_ADMIN_EMAIL' );
$user  = get_user_by( 'login', $login );
if ( ! $user ) {
    $id = wp_insert_user( [
        'user_login' => $login,
        'user_pass'  => $pass,
        'user_email' => $email,
        'role'       => 'administrator',
    ] );
    if ( is_wp_error( $id ) ) {
        WP_CLI::error( 'admin account: ' . $id->get_error_message() );
    }
    WP_CLI::log( "  Admin account '$login' created" );
    return;
}
$changed = [];
if ( ! wp_check_password( $pass, $user->user_pass, $user->ID ) ) {
    wp_set_password( $pass, $user->ID );
    $changed[] = 'password';
}
if ( $email && strcasecmp( $user->user_email, $email ) !== 0 ) {
    $res = wp_update_user( [ 'ID' => $user->ID, 'user_email' => $email ] );
    if ( is_wp_error( $res ) ) {
        WP_CLI::warning( 'admin e-mail not changed: ' . $res->get_error_message() );
    } else {
        $changed[] = 'e-mail';
    }
}
if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
    $user->set_role( 'administrator' );
    $changed[] = 'role';
}
WP_CLI::log( $changed
    ? "  Admin account '$login' updated: " . implode( ', ', $changed )
    : "  Admin account '$login' already matches .env" );
PHP
}

# WP_SITE_URL is only consumed by `wp core install`, so a database seeded
# earlier (e.g. while .env still said http://localhost) keeps that siteurl/home
# forever and WordPress 301-redirects every request for the real domain to it.
# Re-sync on every boot: update both options and rewrite the old URL inside
# stored content (serialized-safe via wp search-replace; guid is left alone).
ensure_site_url() {
    want="${WP_SITE_URL%/}"
    have="$($WP option get siteurl 2>/dev/null || true)"
    have="${have%/}"
    if [ -z "$have" ] || [ "$have" = "$want" ]; then
        log "  Site URL already matches WP_SITE_URL"
        return 0
    fi
    log "  Site URL differs from WP_SITE_URL -- updating ($have -> $want)"
    $WP option update siteurl "$want" >/dev/null
    $WP option update home "$want" >/dev/null
    $WP search-replace "$have" "$want" --all-tables --skip-columns=guid --quiet || \
        log "  search-replace of stored URLs failed (options were still updated)"
}

# ADMIN_ONLY=1: only apply the admin account (the db-proxy layer's
# honeypot_admin_seed, whose database is a scrubbed clone that must not be
# re-seeded or re-configured from here).
if [ "${ADMIN_ONLY:-0}" = "1" ]; then
    if $WP core is-installed 2>/dev/null; then
        ensure_admin_account
    else
        log "ADMIN_ONLY=1 but WordPress is not installed in this database -- nothing to do."
    fi
    exit 0
fi

if $WP core is-installed 2>/dev/null; then
    if [ "${FORCE_RESEED:-0}" != "1" ]; then
        log "WordPress already installed -- skipping install (set FORCE_RESEED=1 to wipe and rebuild)."
        ensure_admin_account
        ensure_site_url
        # SKIP_STOREFRONT_CONFIG=1: the database was cloned from an already-
        # configured source (pool_manager cloning production for a runtime
        # pool), so permalinks, shipping and the enabled payment gateways are
        # already present and identical -- re-running configure_storefront only
        # repeats work. Each wp-cli call boots WordPress, so those ~10-15 calls
        # are the bulk of a runtime pool's "WordPress seed" time. Skipping them
        # when the source was already configured cuts that to the is-installed
        # check alone. Leave unset (default) to always refresh, which is what
        # pools 1-3 and a from-scratch seed need.
        if [ "${SKIP_STOREFRONT_CONFIG:-0}" = "1" ]; then
            log "SKIP_STOREFRONT_CONFIG=1 -- storefront inherited from the cloned source, not refreshed."
            exit 0
        fi
        configure_storefront
        author_storefront_content
        log "Storefront configuration refreshed."
        exit 0
    fi
    log "FORCE_RESEED=1 -- dropping and recreating all WordPress tables..."
    $WP db reset --yes
fi

log "Installing WordPress core..."
$WP core install \
    --url="$WP_SITE_URL" \
    --title="$WP_SITE_TITLE" \
    --admin_user="$WP_ADMIN_USER" \
    --admin_password="$WP_ADMIN_PASSWORD" \
    --admin_email="$WP_ADMIN_EMAIL" \
    --skip-email

log "Activating theme (Omega Storefront)..."
if $WP theme is-installed omega-storefront 2>/dev/null; then
    $WP theme activate omega-storefront
else
    log "  omega-storefront not found, leaving default theme active"
fi

# Only the two plugins the storefront actually needs to function are
# activated here. Everything else under wp-content/plugins/ (akismet,
# jetpack, wordfence, mailpoet, the various WooCommerce payment gateways,
# ...) is deliberately left installed-but-inactive: their PHP files are
# still reachable at their normal paths (which is what most classic
# pre-auth plugin CVEs actually target -- WordPress "active" status in
# wp_options is irrelevant to that), but activating them for real risks
# unpredictable side effects with no upside here -- e.g. Wordfence
# actively firewalling/blocking the exact traffic this honeypot exists
# to let through, or Jetpack hanging startup on an external
# WordPress.com connection attempt that will never succeed offline.
log "Activating WooCommerce and Elementor..."
$WP plugin activate woocommerce
$WP plugin activate elementor

log "Configuring WooCommerce base settings..."
# The storefront mu-plugin (fernhill-storefront.php) pins the store address
# with pre_option_ filters, which makes `option update` fail for these keys on
# a fresh install ("Could not update option"). The shop shows the mu-plugin's
# values either way, so a refused update is not an error.
$WP option update woocommerce_store_address "60 29th Street" || true
$WP option update woocommerce_store_city "San Francisco" || true
$WP option update woocommerce_default_country "US:CA" || true
$WP option update woocommerce_store_postcode "94110" || true
$WP option update woocommerce_currency "USD"
$WP option update woocommerce_price_thousand_sep ","
$WP option update woocommerce_price_decimal_sep "."
$WP option update woocommerce_allow_tracking "no"
# Marks WooCommerce's setup wizard as already completed so a real visit
# to wp-admin doesn't immediately redirect into it -- {"skipped":true} is
# the same shape WooCommerce itself writes when a human clicks "Skip
# setup" on that wizard.
$WP option update woocommerce_onboarding_profile '{"skipped":true}' --format=json
# WooCommerce's own activation hook (triggered by `plugin activate` above)
# already creates the Shop/Cart/Checkout/My Account pages and their
# associated wc_get_page_id() option entries -- no separate step needed.

configure_storefront

if [ "${IMPORT_SAMPLE_CONTENT:-1}" != "1" ]; then
    log "IMPORT_SAMPLE_CONTENT=0 -- schema/theme/plugins ready, skipping content"
    log "  authoring (honeypot_content_sync will mirror production's real"
    log "  content into this database instead)."
    log "Seed complete (schema only)."
    exit 0
fi

# Best-effort from here: a working (if emptier) storefront on failure,
# not a blocked startup -- see the file header's RESILIENCE note.
if [ -f /seed_storefront_content.php ] && [ -f /eshop_seed/catalog.json ]; then
    log "Authoring the Fernhill Coffee Roasters catalog, pages and journal..."
    author_storefront_content
    log "Demo storefront ready."
    exit 0
fi

log "Importing WooCommerce's official sample product catalog..."
if $WP plugin install wordpress-importer --activate 2>/var/log/wp_seed_importer_install.log; then
    if $WP import wp-content/plugins/woocommerce/sample-data/sample_products.xml \
            --authors=create 2>/var/log/wp_seed_import.log; then
        log "  Sample product catalog imported."
    else
        log "  WARNING: product import failed -- see /var/log/wp_seed_import.log inside this container. Continuing with an empty catalog."
    fi
    $WP plugin deactivate wordpress-importer || true
    $WP plugin uninstall wordpress-importer || true
else
    log "  WARNING: could not install the wordpress-importer plugin (offline first boot?) -- skipping sample product import."
fi

log "Authoring Elementor demo pages..."
if [ -x /seed_elementor_pages.sh ]; then
    /seed_elementor_pages.sh || log "  WARNING: Elementor page authoring failed -- continuing without it."
else
    log "  WARNING: seed_elementor_pages.sh not found -- skipping."
fi

log "Demo storefront ready."
