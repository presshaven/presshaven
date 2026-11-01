<?php
/**
 * Plugin Name: Honeypot Auth Identity
 * Description: Publishes the CURRENTLY logged-in user's identity so the reverse
 *              proxy (edge) can, later, carry that same account into a honeypot
 *              pool when this visitor turns suspicious ("account persistence",
 *              request 26). Two outputs, both only ever for a logged-in user:
 *
 *                1. Response headers X-Auth-User / X-Auth-Role on this user's
 *                   OWN responses. Production WordPress is the only authority on
 *                   who is actually authenticated; the edge caches this
 *                   per-session and treats it as the AUTHORITATIVE identity --
 *                   the one the account copy is keyed off -- and strips both
 *                   headers before the client ever sees them (see nginx.conf
 *                   header_filter and gdpr_handler.record_auth_identity).
 *
 *                2. A <meta name="gdpr-user"> tag in <head>. WordPress auth
 *                   cookies are HttpOnly, so gdpr_client.js cannot read the
 *                   username itself; this tag lets it fold the username into the
 *                   gdpr_token as metadata (never into the signed characteristics
 *                   -- see gdpr_rules.IDENTITY_KEYS). That token username is
 *                   SPOOFABLE and used only for labelling, NOT for the copy.
 *
 *              Lives in mu-plugins/ so it is always loaded and cannot be
 *              disabled from wp-admin. Unlike production-hardening.php this file
 *              is NOT removed from the honeypot pools: it is harmless there (the
 *              edge only records identities seen on a PRODUCTION-routed response
 *              and strips the headers on every route), and leaving it in place
 *              keeps a pool's auto-logged-in user emitting the same meta tag, so
 *              nothing about the response shape hints at diversion.
 *
 * Version:     1.0.0
 * Author:      Honeynet Research System
 *
 * SECURITY MODEL:
 *   - Emits ONLY the account the request is genuinely authenticated as
 *     (wp_get_current_user()); it never reads or trusts any client-supplied
 *     identity header. This is what makes it the authoritative source the edge
 *     keys the account copy off, closing the arbitrary-account exfiltration
 *     oracle that trusting the self-built gdpr_token username would open.
 *   - CR/LF stripped and length capped on the header values (defence against
 *     header injection via a crafted display/login name); the meta content is
 *     esc_attr()'d.
 *   - No secrets are emitted -- only a username and a role name.
 */

// Guard: only run inside a proper WordPress request.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// WordPress user_login column is 60 chars; mirror gdpr_rules.MAX_USERNAME_LEN
// so the edge and WordPress agree on the cap.
if ( ! defined( 'HONEYPOT_AUTH_MAX_USERNAME_LEN' ) ) {
    define( 'HONEYPOT_AUTH_MAX_USERNAME_LEN', 60 );
}

/**
 * Sanitise a value destined for an HTTP response header: strip anything that
 * could break out of the header (CR/LF/NUL and other control chars) and cap the
 * length. Returns '' for a non-string or empty result.
 *
 * @param mixed $value
 * @return string
 */
function honeypot_auth_identity_header_safe( $value ) {
    if ( ! is_string( $value ) || $value === '' ) {
        return '';
    }
    // Remove CR, LF, NUL and other C0 control characters.
    $value = preg_replace( '/[\x00-\x1F\x7F]/', '', $value );
    $value = trim( $value );
    if ( strlen( $value ) > HONEYPOT_AUTH_MAX_USERNAME_LEN ) {
        $value = substr( $value, 0, HONEYPOT_AUTH_MAX_USERNAME_LEN );
    }
    return $value;
}

/**
 * The logged-in user's login name and primary role, or null when not logged in.
 *
 * @return array|null { 'login' => string, 'role' => string }
 */
function honeypot_auth_identity_current() {
    if ( ! function_exists( 'is_user_logged_in' ) || ! is_user_logged_in() ) {
        return null;
    }
    $user = wp_get_current_user();
    if ( ! $user || empty( $user->user_login ) ) {
        return null;
    }
    $role = '';
    if ( ! empty( $user->roles ) && is_array( $user->roles ) ) {
        // The first assigned role is WordPress's own notion of the primary one.
        $role = (string) reset( $user->roles );
    }
    return array(
        'login' => (string) $user->user_login,
        'role'  => $role,
    );
}

/**
 * Emit X-Auth-User / X-Auth-Role response headers for the logged-in user. Hooked
 * to both send_headers (front-end) and admin_init (wp-admin) so an authenticated
 * session is announced wherever the user actually browses. No-op if headers are
 * already sent or the visitor is anonymous.
 */
function honeypot_auth_identity_emit_headers() {
    if ( headers_sent() ) {
        return;
    }
    $id = honeypot_auth_identity_current();
    if ( $id === null ) {
        return;
    }
    $login = honeypot_auth_identity_header_safe( $id['login'] );
    if ( $login === '' ) {
        return;
    }
    header( 'X-Auth-User: ' . $login );
    $role = honeypot_auth_identity_header_safe( $id['role'] );
    if ( $role !== '' ) {
        header( 'X-Auth-Role: ' . $role );
    }
}
add_action( 'send_headers', 'honeypot_auth_identity_emit_headers' );
add_action( 'admin_init', 'honeypot_auth_identity_emit_headers' );

/**
 * Print <meta name="gdpr-user"> into <head> for the logged-in user so
 * gdpr_client.js can read the username (the auth cookie it would otherwise come
 * from is HttpOnly). Front-end only; esc_attr()'d.
 */
function honeypot_auth_identity_emit_meta() {
    $id = honeypot_auth_identity_current();
    if ( $id === null || $id['login'] === '' ) {
        return;
    }
    echo '<meta name="gdpr-user" content="' . esc_attr( $id['login'] ) . '">' . "\n";
}
add_action( 'wp_head', 'honeypot_auth_identity_emit_meta' );
