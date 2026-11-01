<?php
/**
 * Plugin Name: Honeypot Account Autologin
 * Description: Adopts a named account on a honeypot pool when the reverse proxy
 *              (edge) diverts a suspicious-but-authenticated visitor there, so
 *              the adversary stays logged in exactly as they were on production
 *              and nothing hints they have been moved into a honeypot ("account
 *              persistence", request 26).
 *
 *              The edge, having copied that one user's wp_users/wp_usermeta rows
 *              from production into THIS pool's database (honeypot_user_sync /
 *              replicate_user_to_honeypot.sh), replays the diverted request with
 *              an internal header naming the account. This plugin logs that
 *              account in for the request.
 *
 *              HARD-GATED so it can only ever be driven by the edge, never a
 *              client:
 *                - runs ONLY on a honeypot pool (HONEYPOT_POOL_ID env present --
 *                  absent on production, so this is inert there);
 *                - requires the internal secret (X-Internal-Test-Auth) to
 *                  hash_equals() INTERNAL_TEST_SECRET, the same secret the edge
 *                  holds; a blank secret disables the feature (fails safe);
 *                - acts only on X-Honeypot-Autologin-User, a header the edge
 *                  STRIPS from inbound client requests before it ever sets its
 *                  own, so a visitor cannot supply it.
 *
 *              Idempotent: if the named account has not been copied into this
 *              pool yet (content-sync still in flight) get_user_by() returns
 *              false and the request proceeds anonymously; the next request
 *              after the copy lands logs them in. If the user is already the
 *              current user it does nothing.
 *
 *              Lives in mu-plugins/ so it is always loaded. It self-gates on
 *              HONEYPOT_POOL_ID, so although it is rsynced to every instance it
 *              is a no-op on production.
 *
 * Version:     1.0.0
 * Author:      Honeynet Research System
 *
 * SECURITY MODEL:
 *   - The copied account is, by design (request 26), only ever the adversary's
 *     OWN production-authenticated account -- the edge keys the copy off
 *     production's X-Auth-User, never the spoofable token username -- so the
 *     real password hash + email that land in this isolated honeypot DB are the
 *     adversary's own. This plugin does not widen that: it only logs in whatever
 *     account the edge (secret-authenticated) named.
 *   - Pool WordPress uses its own auto-generated auth salts (it does not share
 *     production's WORDPRESS_AUTH_KEY), so the auth cookie minted here is valid
 *     only on this pool and never on production.
 */

// Guard: only run inside a proper WordPress request.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Is this instance a honeypot pool? Pools set HONEYPOT_POOL_ID; production does
 * not. Keeps the whole feature inert on production.
 *
 * @return bool
 */
function honeypot_autologin_is_pool() {
    $pool = getenv( 'HONEYPOT_POOL_ID' );
    return is_string( $pool ) && $pool !== '';
}

/**
 * Does the request carry the edge's internal secret, matching INTERNAL_TEST_SECRET?
 * Constant-time compare; a blank configured secret disables the feature.
 *
 * @return bool
 */
function honeypot_autologin_secret_ok() {
    $expected = getenv( 'INTERNAL_TEST_SECRET' );
    if ( ! is_string( $expected ) || $expected === '' ) {
        return false; // not configured -> feature off (fail safe)
    }
    $presented = isset( $_SERVER['HTTP_X_INTERNAL_TEST_AUTH'] )
        ? (string) $_SERVER['HTTP_X_INTERNAL_TEST_AUTH']
        : '';
    if ( $presented === '' ) {
        return false;
    }
    return hash_equals( $expected, $presented );
}

/**
 * Perform the auto-login if all gates pass. Hooked on init (after pluggable
 * functions are available). No-op unless: on a pool, secret matches, the header
 * names an account, that account exists in THIS pool's DB, and it is not already
 * the current user.
 */
function honeypot_autologin_maybe_login() {
    if ( ! honeypot_autologin_is_pool() ) {
        return;
    }
    $login = isset( $_SERVER['HTTP_X_HONEYPOT_AUTOLOGIN_USER'] )
        ? trim( (string) $_SERVER['HTTP_X_HONEYPOT_AUTOLOGIN_USER'] )
        : '';
    if ( $login === '' ) {
        return;
    }
    if ( ! honeypot_autologin_secret_ok() ) {
        return;
    }

    $user = get_user_by( 'login', $login );
    if ( ! $user ) {
        // Account not copied into this pool yet (content-sync still in flight).
        // Proceed anonymously; a later request logs them in once it lands.
        return;
    }

    // Already logged in as this account? Nothing to do.
    if ( is_user_logged_in() && get_current_user_id() === (int) $user->ID ) {
        return;
    }

    if ( headers_sent() ) {
        // Can still set the current user for this request even if we cannot
        // mint the persistent cookie.
        wp_set_current_user( $user->ID );
        return;
    }

    wp_set_current_user( $user->ID );
    wp_set_auth_cookie( $user->ID, true );
}
add_action( 'init', 'honeypot_autologin_maybe_login', 1 );
