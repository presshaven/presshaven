#!/usr/local/bin/php
<?php
/**
 * container-firewall: the iptables ruleset of one WordPress container's network
 * namespace. It runs in its own small container that OWNS that namespace --
 * the WordPress container joins it (compose: network_mode service:<this>), so
 * the rules filter every packet WordPress sends or receives while nothing in
 * the WordPress container can see or change them: it holds no NET_ADMIN, has
 * no iptables binary, and cannot see this container's processes or files.
 * (A firewall inside the WordPress container itself could not hold against
 * root there: root could replace a binary the privileged watcher runs next.)
 *
 * Only NEW connections are filtered -- loopback and ESTABLISHED / RELATED
 * traffic always pass -- so a connection is allowed when it opens only if a
 * rule names its peer and port. Everything else is dropped (inbound) or
 * rejected (outbound: fails fast instead of hanging PHP).
 *
 *   container-firewall run            the container's command: apply the
 *                                     ruleset (retrying until it is), then
 *                                     re-check every 5 s: re-resolve peers (the
 *                                     edge's IP changes whenever it is
 *                                     recreated), re-read the ruleset file (the
 *                                     dashboard may have changed it), re-apply
 *                                     on any change
 *   container-firewall apply --b64 X  validate, apply and save a ruleset
 *   container-firewall status         JSON: ruleset, resolved peers, counters
 *   container-firewall health         exit 0 once the ruleset is enforced
 *   container-firewall default        print the image's default ruleset
 *
 * $FIREWALL_PROFILE picks the ruleset: "production" (production_eshop),
 * "honeypot" (every honeypot pool's WordPress, compose and runtime) or
 * "honeypot_database" (every honeypot database). One file per profile
 * in RULES_DIR (a volume every firewall container shares), so a change the
 * dashboard applies through one honeypot pool's firewall reaches the others
 * within WATCH_INTERVAL. No file = the image default for the profile.
 *
 * Own chains only (FW_IN, FW_OUT, FW_INET, FW_FWD in the filter table), hooked
 * first into INPUT, OUTPUT and FORWARD, replaced atomically with
 * iptables-restore --noflush. FW_FWD drops everything, always: no container
 * here routes, so a namespace on two networks (production_eshop_net in the
 * db-proxy layer) can never be used as a router between them.
 *
 * The honeypot profiles are LOCKED (validate_locked()): an attacker can get
 * into those containers, so no ruleset -- not the dashboard's, not a hand-
 * written file -- may switch the firewall off or open a way out past the
 * pool's own database, and IPv6 must be enforced too (fails closed).
 * The nat table is never touched: Docker's embedded DNS (127.0.0.11) lives
 * there, and is reached over loopback.
 *
 * Ruleset document (version 1), validated identically by the dashboard
 * (dashboard/core/container_firewall.py):
 *   {version, enabled, inbound: [rule], outbound: [rule]}
 *   rule = {id, enabled, peer, proto, ports, label, layer?}
 *   peer  : a container / service name (resolved on every check), an IPv4
 *           address or CIDR, "any", "local-subnets" (every subnet this
 *           container is attached to), "db-host" (this container's own
 *           database, $FIREWALL_DB_HOST) or, outbound only, "internet"
 *           (anything outside the private / reserved ranges)
 *   proto : tcp | udp | tcp/udp
 *   ports : "80", "465,587", "8000-8100" (at most 15 ports, a range counts 2)
 *   layer : "default" | "db-proxy" -- the rule applies only in that honeypot
 *           layer ($FIREWALL_LAYER); absent = every layer
 */

const RULES_DIR = '/var/lib/container-firewall';
const DEFAULTS_DIR = '/usr/local/share/container-firewall';
const RUNTIME_FILE = '/run/container-firewall.json';
const PROFILES = ['production', 'honeypot', 'honeypot_database'];
// Locked profiles => the outbound peers they may have: a pool's WordPress only
// its own database, a honeypot database nothing at all (it answers, never calls).
const LOCKED_OUTBOUND = ['honeypot' => ['db-host'], 'honeypot_database' => []];
const WATCH_INTERVAL = 5;
const MAX_RULES = 64;
const MAX_PORTS = 15;
const PEER_KEYWORDS = ['any', 'internet', 'local-subnets', 'db-host'];
const LAYERS = ['default', 'db-proxy'];
// Not "internet": RFC 1918, loopback, link-local, CGNAT, "this network",
// multicast and reserved.
const NON_INTERNET = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
	'172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4'];

function fail( string $msg, int $code = 1 ): void {
	fwrite( STDERR, "container-firewall: $msg\n" );
	exit( $code );
}

function layer(): string {
	$l = getenv( 'FIREWALL_LAYER' );
	return in_array( $l, LAYERS, true ) ? $l : 'default';
}

/** No fallback: the wrong profile would open production's egress on a honeypot. */
function profile(): string {
	$p = getenv( 'FIREWALL_PROFILE' );
	if ( ! in_array( $p, PROFILES, true ) ) {
		fail( 'FIREWALL_PROFILE must be one of ' . implode( ', ', PROFILES ), 2 );
	}
	return $p;
}

function rules_file(): string {
	return RULES_DIR . '/' . profile() . '.json';
}

/** Runs argv (no shell); returns [exit code, stdout, stderr]. */
function run( array $argv, ?string $stdin = null ): array {
	$p = proc_open( $argv, [ 0 => [ 'pipe', 'r' ], 1 => [ 'pipe', 'w' ], 2 => [ 'pipe', 'w' ] ], $pipes );
	if ( ! is_resource( $p ) ) {
		return [ 127, '', "cannot run {$argv[0]}" ];
	}
	if ( $stdin !== null ) {
		fwrite( $pipes[0], $stdin );
	}
	fclose( $pipes[0] );
	$out = stream_get_contents( $pipes[1] );
	$err = stream_get_contents( $pipes[2] );
	fclose( $pipes[1] );
	fclose( $pipes[2] );
	return [ proc_close( $p ), $out, $err ];
}

// -- validation ---------------------------------------------------------------

function valid_cidr( string $s ): bool {
	if ( ! preg_match( '#^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$#', $s, $m ) ) {
		return false;
	}
	return filter_var( $m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) !== false
		&& ( ! isset( $m[2] ) || (int) $m[2] <= 32 );
}

/** Canonical port list ("80,443", "8000:8100") or an error string prefixed "!". */
function parse_ports( $ports ): string {
	if ( ! is_string( $ports ) || trim( $ports ) === '' ) {
		return '!ports are required';
	}
	$out = [];
	$weight = 0;
	foreach ( explode( ',', str_replace( ' ', '', $ports ) ) as $part ) {
		if ( ! preg_match( '/^(\d{1,5})(?:-(\d{1,5}))?$/', $part, $m ) ) {
			return "!bad port \"$part\"";
		}
		$lo = (int) $m[1];
		$hi = isset( $m[2] ) ? (int) $m[2] : $lo;
		if ( $lo < 1 || $hi > 65535 || $lo > $hi ) {
			return "!bad port \"$part\"";
		}
		$out[] = $lo === $hi ? (string) $lo : "$lo:$hi";
		$weight += $lo === $hi ? 1 : 2;
	}
	if ( $weight > MAX_PORTS ) {
		return '!at most ' . MAX_PORTS . ' ports per rule (a range counts as two)';
	}
	return implode( ',', $out );
}

/** Returns a list of error strings; empty = valid. A locked profile's
 * ruleset must also pass validate_locked(). */
function validate( $doc, ?string $profile = null ): array {
	if ( ! is_array( $doc ) ) {
		return [ 'ruleset must be a JSON object' ];
	}
	$errors = [];
	if ( ( $doc['version'] ?? null ) !== 1 ) {
		$errors[] = 'version must be 1';
	}
	if ( ! is_bool( $doc['enabled'] ?? null ) ) {
		$errors[] = 'enabled must be true or false';
	}
	foreach ( [ 'inbound', 'outbound' ] as $dir ) {
		$rules = $doc[ $dir ] ?? null;
		if ( ! is_array( $rules ) || ( $rules && array_keys( $rules ) !== range( 0, count( $rules ) - 1 ) ) ) {
			$errors[] = "$dir must be a list";
			continue;
		}
		if ( count( $rules ) > MAX_RULES ) {
			$errors[] = "$dir: at most " . MAX_RULES . ' rules';
		}
		$seen = [];
		foreach ( $rules as $i => $r ) {
			$where = "{$dir}[$i]";
			if ( ! is_array( $r ) ) {
				$errors[] = "$where: must be an object";
				continue;
			}
			$id = $r['id'] ?? '';
			if ( ! is_string( $id ) || ! preg_match( '/^[a-z0-9][a-z0-9-]{0,47}$/', $id ) ) {
				$errors[] = "$where: id must be 1-48 of a-z 0-9 -";
			} elseif ( isset( $seen[ $id ] ) ) {
				$errors[] = "$where: duplicate id $id";
			} else {
				$seen[ $id ] = true;
				$where = "$dir/$id";
			}
			if ( ! is_bool( $r['enabled'] ?? null ) ) {
				$errors[] = "$where: enabled must be true or false";
			}
			$peer = $r['peer'] ?? '';
			if ( ! is_string( $peer ) || ! ( in_array( $peer, PEER_KEYWORDS, true ) || valid_cidr( $peer )
					|| ( preg_match( '/^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/', $peer ) && ! preg_match( '#^[\d./]+$#', $peer ) ) ) ) {
				$errors[] = "$where: peer must be a container name, an IPv4 address/CIDR, any, local-subnets, db-host or internet";
			} elseif ( $peer === 'internet' && $dir === 'inbound' ) {
				$errors[] = "$where: internet is outbound only (inbound traffic always comes through the edge)";
			}
			if ( ! in_array( $r['proto'] ?? '', [ 'tcp', 'udp', 'tcp/udp' ], true ) ) {
				$errors[] = "$where: proto must be tcp, udp or tcp/udp";
			}
			$ports = parse_ports( $r['ports'] ?? null );
			if ( $ports[0] === '!' ) {
				$errors[] = "$where: " . substr( $ports, 1 );
			}
			if ( ! is_string( $r['label'] ?? '' ) || strlen( $r['label'] ?? '' ) > 200 ) {
				$errors[] = "$where: label must be text of at most 200 characters";
			}
			if ( isset( $r['layer'] ) && ! in_array( $r['layer'], LAYERS, true ) ) {
				$errors[] = "$where: layer must be default or db-proxy";
			}
		}
	}
	if ( ! $errors && $profile !== null && isset( LOCKED_OUTBOUND[ $profile ] ) ) {
		$errors = validate_locked( $doc, $profile );
	}
	return $errors;
}

/** The shape that keeps a hijacked honeypot container a dead end. Disabled
 * rules count too: switching one on must not be the way out. */
function validate_locked( array $doc, string $profile ): array {
	$errors = [];
	if ( ! $doc['enabled'] ) {
		$errors[] = "the $profile firewall cannot be switched off (attackers get into these containers)";
	}
	$allowed = LOCKED_OUTBOUND[ $profile ];
	foreach ( $doc['outbound'] as $r ) {
		if ( ! $allowed ) {
			$errors[] = "outbound/{$r['id']}: a $profile container opens no connections at all";
		} elseif ( ! in_array( $r['peer'], $allowed, true ) || $r['proto'] !== 'tcp' ) {
			$errors[] = "outbound/{$r['id']}: a $profile container may only open tcp to " . implode( ', ', $allowed );
		}
	}
	return $errors;
}

// -- ruleset --------------------------------------------------------------------

function load_default(): array {
	$file = DEFAULTS_DIR . '/' . profile() . '.json';
	$doc = json_decode( (string) @file_get_contents( $file ), true );
	if ( validate( $doc, profile() ) ) {
		fail( "the image default ruleset $file is invalid" );
	}
	if ( profile() === 'production' ) {
		$doc = production_egress_overlay( $doc );
	}
	return $doc;
}

/** Interpret an .env flag the way compose / the dashboard do. */
function env_truthy( string $name ): bool {
	$v = strtolower( trim( (string) getenv( $name ) ) );
	return in_array( $v, [ '1', 'true', 'yes', 'on' ], true );
}

/** Split PRODUCTION_TRUSTED_EGRESS_DOMAINS into clean, de-duplicated domains. */
function trusted_egress_domains(): array {
	$out = [];
	foreach ( preg_split( '/[\s,]+/', (string) getenv( 'PRODUCTION_TRUSTED_EGRESS_DOMAINS' ) ) as $d ) {
		$d = rtrim( strtolower( trim( $d ) ), '.' );
		if ( $d !== '' && preg_match( '/^[a-z0-9][a-z0-9.-]{0,62}$/', $d ) && strpos( $d, '.' ) !== false
				&& ! in_array( $d, $out, true ) ) {
			$out[] = $d;
		}
		if ( count( $out ) >= 20 ) {
			break;  // a sane ceiling; the rest of MAX_RULES stays for operators
		}
	}
	return $out;
}

/** Seed production's internet egress from .env on a fresh deploy (no saved
 * ruleset yet): the broad-internet TEMPORARY bypass toggle
 * (PRODUCTION_INTERNET_EGRESS) and the persistent per-domain allow-list
 * (PRODUCTION_TRUSTED_EGRESS_DOMAINS, outbound HTTPS to each named host). The
 * dashboard's Studio page is what flips these on the fly after deploy; this
 * only decides the starting point so the allow-list survives `down -v`. */
function production_egress_overlay( array $doc ): array {
	$allow_internet = env_truthy( 'PRODUCTION_INTERNET_EGRESS' );
	foreach ( $doc['outbound'] as &$r ) {
		if ( $r['id'] === 'internet-https' ) {
			$r['enabled'] = $allow_internet;
		}
	}
	unset( $r );
	$seen = [];
	foreach ( $doc['outbound'] as $r ) {
		$seen[ $r['id'] ] = true;
	}
	foreach ( trusted_egress_domains() as $d ) {
		$id = substr( 'trusted-' . preg_replace( '/[^a-z0-9-]/', '-', $d ), 0, 48 );
		if ( isset( $seen[ $id ] ) ) {
			continue;  // two domains slugified to the same id, or already present
		}
		$seen[ $id ] = true;
		$doc['outbound'][] = [
			'id' => $id,
			'enabled' => true,
			'peer' => $d,
			'proto' => 'tcp',
			'ports' => '443',
			'label' => "Trusted egress domain (PRODUCTION_TRUSTED_EGRESS_DOMAINS): $d",
		];
	}
	return $doc;
}

/** The saved ruleset, or the image default when there is none (or it is broken). */
function load_saved( ?string &$source = null ): array {
	$raw = @file_get_contents( rules_file() );
	if ( $raw !== false ) {
		$doc = json_decode( $raw, true );
		if ( ! validate( $doc, profile() ) ) {
			$source = 'saved';
			return $doc;
		}
		fwrite( STDERR, 'container-firewall: ' . rules_file() . " is invalid, using the default\n" );
	}
	$source = 'default';
	return load_default();
}

function save( array $doc ): void {
	$tmp = rules_file() . '.tmp';
	if ( file_put_contents( $tmp, json_encode( $doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" ) === false
			|| ! rename( $tmp, rules_file() ) ) {
		fail( 'cannot write ' . rules_file() );
	}
}

/** Directly attached IPv4 subnets (from the routing table, minus the default route). */
function local_subnets(): array {
	$out = [];
	foreach ( array_slice( (array) @file( '/proc/net/route', FILE_IGNORE_NEW_LINES ), 1 ) as $line ) {
		$f = preg_split( '/\s+/', trim( $line ) );
		if ( count( $f ) < 8 || $f[0] === 'lo' || $f[1] === '00000000' || $f[2] !== '00000000' ) {
			continue;
		}
		$net = long2ip( unpack( 'V', pack( 'H*', $f[1] ) )[1] );
		$bits = substr_count( decbin( unpack( 'V', pack( 'H*', $f[7] ) )[1] ), '1' );
		$out[] = "$net/$bits";
	}
	sort( $out );
	return array_values( array_unique( $out ) );
}

/** Names of the Docker networks this container is on: Docker's DNS answers a
 * PTR query for each of our addresses with "<container>.<network>". */
function networks(): array {
	static $nets = null;
	if ( $nets !== null ) {
		return $nets;
	}
	$nets = [];
	$ips = [];
	foreach ( net_get_interfaces() ?: [] as $name => $if ) {
		foreach ( $name === 'lo' ? [] : ( $if['unicast'] ?? [] ) as $u ) {
			if ( filter_var( $u['address'] ?? '', FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				$ips[] = $u['address'];
			}
		}
	}
	foreach ( $ips as $ip ) {
		$ptr = implode( '.', array_reverse( explode( '.', $ip ) ) ) . '.in-addr.arpa';
		foreach ( @dns_get_record( $ptr, DNS_PTR ) ?: [] as $rec ) {
			$dot = strpos( $rec['target'] ?? '', '.' );
			if ( $dot !== false ) {
				$nets[] = substr( $rec['target'], $dot + 1 );
			}
		}
	}
	return $nets = array_values( array_unique( $nets ) );
}

/** Every IPv4 address of a container name. A plain lookup answers with its
 * address on ONE shared network only, while it may connect from any of them
 * (db-proxy layer: the edge and production share three), so the name is also
 * asked per network as "<name>.<network>". */
function resolve_name( string $name ): array {
	$ips = gethostbynamel( $name ) ?: [];
	if ( strpos( $name, '.' ) === false ) {
		foreach ( networks() as $net ) {
			$ips = array_merge( $ips, gethostbynamel( "$name.$net" ) ?: [] );
		}
	}
	$ips = array_values( array_unique( $ips ) );
	sort( $ips );
	return $ips;
}

/** Peer => list of source/destination specs ([] = unresolved; ['*'] = anywhere). */
function resolve( array $doc ): array {
	$out = [];
	foreach ( [ 'inbound', 'outbound' ] as $dir ) {
		foreach ( $doc[ $dir ] as $r ) {
			$peer = $r['peer'];
			if ( isset( $out[ $peer ] ) ) {
				continue;
			}
			if ( $peer === 'any' || $peer === 'internet' ) {
				$out[ $peer ] = [ '*' ];
			} elseif ( $peer === 'local-subnets' ) {
				$out[ $peer ] = local_subnets();
			} elseif ( $peer === 'db-host' ) {
				$host = preg_replace( '/:\d+$/', '', (string) getenv( 'FIREWALL_DB_HOST' ) );
				$out[ $peer ] = $host === '' ? [] : ( valid_cidr( $host ) ? [ $host ] : resolve_name( $host ) );
			} elseif ( valid_cidr( $peer ) ) {
				$out[ $peer ] = [ $peer ];
			} else {
				$out[ $peer ] = resolve_name( $peer );
			}
		}
	}
	ksort( $out );
	return $out;
}

function active( array $r ): bool {
	return $r['enabled'] && ( ! isset( $r['layer'] ) || $r['layer'] === layer() );
}

/** The iptables-restore input for the filter table. */
function render( array $doc, array $resolved ): string {
	$l = [ '*filter', ':FW_IN - [0:0]', ':FW_OUT - [0:0]', ':FW_INET - [0:0]', ':FW_FWD - [0:0]',
		'-F FW_IN', '-F FW_OUT', '-F FW_INET', '-F FW_FWD', '-A FW_FWD -m comment --comment fw:fwd:default -j DROP' ];
	if ( ! $doc['enabled'] ) {
		$l[] = '-A FW_IN -m comment --comment fw:disabled -j ACCEPT';
		$l[] = '-A FW_OUT -m comment --comment fw:disabled -j ACCEPT';
		$l[] = 'COMMIT';
		return implode( "\n", $l ) . "\n";
	}
	foreach ( NON_INTERNET as $net ) {
		$l[] = "-A FW_INET -d $net -j RETURN";
	}
	$l[] = '-A FW_INET -j ACCEPT';
	foreach ( [ 'in' => 'FW_IN', 'out' => 'FW_OUT' ] as $dir => $chain ) {
		$l[] = "-A $chain " . ( $dir === 'in' ? '-i' : '-o' ) . ' lo -j ACCEPT';
		$l[] = "-A $chain -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT";
		$l[] = "-A $chain -m conntrack --ctstate INVALID -j DROP";
		foreach ( $doc[ $dir === 'in' ? 'inbound' : 'outbound' ] as $r ) {
			if ( ! active( $r ) ) {
				continue;
			}
			$ports = parse_ports( $r['ports'] );
			$protos = $r['proto'] === 'tcp/udp' ? [ 'tcp', 'udp' ] : [ $r['proto'] ];
			$target = $r['peer'] === 'internet' ? 'FW_INET' : 'ACCEPT';
			foreach ( $resolved[ $r['peer'] ] ?? [] as $addr ) {
				$match = $addr === '*' ? '' : ( $dir === 'in' ? " -s $addr" : " -d $addr" );
				foreach ( $protos as $p ) {
					$l[] = "-A $chain$match -p $p -m multiport --dports $ports -m conntrack --ctstate NEW"
						. " -m comment --comment fw:$dir:{$r['id']} -j $target";
				}
			}
		}
		if ( $dir === 'in' ) {
			$l[] = '-A FW_IN -m comment --comment fw:in:default -j DROP';
		} else {
			$l[] = '-A FW_OUT -p tcp -m comment --comment fw:out:default -j REJECT --reject-with tcp-reset';
			$l[] = '-A FW_OUT -m comment --comment fw:out:default -j REJECT --reject-with icmp-port-unreachable';
		}
	}
	$l[] = 'COMMIT';
	return implode( "\n", $l ) . "\n";
}

/** Same idea for IPv6: the stack networks are IPv4, so only loopback and
 * established traffic pass when the firewall is on. Required for the locked
 * profiles (see enforce()), best effort for production. */
function render6( bool $enabled ): string {
	$l = [ '*filter', ':FW_IN - [0:0]', ':FW_OUT - [0:0]', ':FW_FWD - [0:0]', '-F FW_IN', '-F FW_OUT', '-F FW_FWD',
		'-A FW_FWD -j DROP' ];
	if ( $enabled ) {
		$l[] = '-A FW_IN -i lo -j ACCEPT';
		$l[] = '-A FW_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT';
		$l[] = '-A FW_IN -j DROP';
		$l[] = '-A FW_OUT -o lo -j ACCEPT';
		$l[] = '-A FW_OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT';
		$l[] = '-A FW_OUT -j REJECT';
	} else {
		$l[] = '-A FW_IN -j ACCEPT';
		$l[] = '-A FW_OUT -j ACCEPT';
	}
	$l[] = 'COMMIT';
	return implode( "\n", $l ) . "\n";
}

function hook( string $bin ): bool {
	foreach ( [ 'INPUT' => 'FW_IN', 'OUTPUT' => 'FW_OUT', 'FORWARD' => 'FW_FWD' ] as $builtin => $chain ) {
		if ( run( [ $bin, '-w', '5', '-C', $builtin, '-j', $chain ] )[0] !== 0
				&& run( [ $bin, '-w', '5', '-I', $builtin, '1', '-j', $chain ] )[0] !== 0 ) {
			return false;
		}
	}
	return true;
}

/** Loads the chains, then hooks them; throws RuntimeException on failure (never the other way round: a hook into
 * an empty chain would be a no-op, a half-loaded chain could lock us out). */
function enforce( array $doc ): array {
	$resolved = resolve( $doc );
	[ $code, , $err ] = run( [ 'iptables-restore', '-w', '5', '--noflush' ], render( $doc, $resolved ) );
	if ( $code !== 0 ) {
		throw new RuntimeException( 'iptables-restore failed: ' . trim( $err ) );
	}
	if ( ! hook( 'iptables' ) ) {
		throw new RuntimeException( 'cannot hook FW_IN / FW_OUT / FW_FWD into INPUT / OUTPUT / FORWARD' );
	}
	$v6 = run( [ 'ip6tables-restore', '-w', '5', '--noflush' ], render6( $doc['enabled'] ) )[0] === 0
		&& hook( 'ip6tables' );
	// A kernel without IPv6 has nothing to filter; anywhere else a locked
	// profile does not report healthy (and its container never starts) without it.
	if ( ! $v6 && isset( LOCKED_OUTBOUND[ profile() ] ) && file_exists( '/proc/net/if_inet6' ) ) {
		throw new RuntimeException( 'ip6tables rules failed to load; the ' . profile() . ' profile requires them' );
	}
	$runtime = [ 'applied_at' => gmdate( 'c' ), 'profile' => profile(), 'layer' => layer(), 'resolved' => $resolved,
		'fingerprint' => fingerprint( $doc ), 'ipv6' => $v6 ];
	@file_put_contents( RUNTIME_FILE, json_encode( $runtime, JSON_UNESCAPED_SLASHES ) . "\n" );
	return $runtime;
}

/** sha256 of the canonical document -- the dashboard computes the same to
 * tell whether what it has is what is enforced. */
function fingerprint( array $doc ): string {
	return hash( 'sha256', json_encode( canonical( $doc ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
}

function canonical( $v ) {
	if ( is_array( $v ) ) {
		if ( $v && array_keys( $v ) !== range( 0, count( $v ) - 1 ) ) {
			ksort( $v );
		}
		return array_map( 'canonical', $v );
	}
	return $v;
}

/** Packet counters per rule id from the live chains. */
function counters(): array {
	[ $code, $out ] = run( [ 'iptables-save', '-c', '-t', 'filter' ] );
	$hooked = [ 'in' => false, 'out' => false, 'fwd' => false ];
	$hits = [ 'in' => [], 'out' => [] ];
	if ( $code !== 0 ) {
		return [ null, $hits ];
	}
	foreach ( explode( "\n", $out ) as $line ) {
		if ( preg_match( '/^\[\d+:\d+\] -A (INPUT|OUTPUT|FORWARD) -j FW_(IN|OUT|FWD)$/', $line, $m ) ) {
			$hooked[ strtolower( $m[2] ) ] = true;
		} elseif ( preg_match( '/^\[(\d+):(\d+)\] -A FW_(?:IN|OUT) .*--comment "?fw:(in|out):([a-z0-9-]+)"?/', $line, $m ) ) {
			$hits[ $m[3] ][ $m[4] ]['packets'] = ( $hits[ $m[3] ][ $m[4] ]['packets'] ?? 0 ) + (int) $m[1];
			$hits[ $m[3] ][ $m[4] ]['bytes'] = ( $hits[ $m[3] ][ $m[4] ]['bytes'] ?? 0 ) + (int) $m[2];
		}
	}
	return [ $hooked['in'] && $hooked['out'] && $hooked['fwd'], $hits ];
}

// -- commands -------------------------------------------------------------------

/** Applies when the ruleset file, the resolved peers or the hooks differ from what is enforced; true if it applied. */
function reconcile( bool $force = false ): bool {
	$doc = load_saved( $source );
	$rt = json_decode( (string) @file_get_contents( RUNTIME_FILE ), true ) ?: [];
	if ( ! $force && fingerprint( $doc ) === ( $rt['fingerprint'] ?? null )
			&& resolve( $doc ) == ( $rt['resolved'] ?? null ) && counters()[0] ) {
		return false;
	}
	$rt = enforce( $doc );
	$missing = array_keys( array_filter( $rt['resolved'], fn( $ips ) => ! $ips ) );
	echo 'container-firewall: ' . profile() . " $source ruleset applied at {$rt['applied_at']} ("
		. ( $doc['enabled'] ? 'enforcing' : 'disabled' ) . ')'
		. ( $missing ? '; unresolved: ' . implode( ', ', $missing ) : '' ) . "\n";
	return true;
}

$cmd = $argv[1] ?? '';
try {
switch ( $cmd ) {
	case 'run':
		profile();
		@unlink( RUNTIME_FILE );
		$force = true;
		while ( true ) {
			try {
				reconcile( $force );
				$force = false;
			} catch ( RuntimeException $e ) {
				fwrite( STDERR, 'container-firewall: apply failed, retrying: ' . $e->getMessage() . "\n" );
			}
			sleep( WATCH_INTERVAL );
		}

	case 'apply':
		if ( ( $argv[2] ?? '' ) !== '--b64' || ! isset( $argv[3] ) ) {
			fail( 'usage: container-firewall apply --b64 <base64 JSON>', 2 );
		}
		$doc = json_decode( (string) base64_decode( $argv[3], true ), true );
		$errors = validate( $doc, profile() );
		if ( $errors ) {
			fail( "invalid ruleset:\n  " . implode( "\n  ", $errors ) );
		}
		enforce( $doc );
		save( $doc );
		echo "applied\n";
		break;

	case 'status':
		$doc = load_saved( $source );
		[ $hooked, $hits ] = counters();
		$rt = json_decode( (string) @file_get_contents( RUNTIME_FILE ), true ) ?: [];
		echo json_encode( [
			'source' => $source,
			'profile' => profile(),
			'layer' => layer(),
			'hooked' => $hooked,
			'document' => $doc,
			'fingerprint' => fingerprint( $doc ),
			'enforced_fingerprint' => $rt['fingerprint'] ?? null,
			'applied_at' => $rt['applied_at'] ?? null,
			'resolved' => $rt['resolved'] ?? (object) [],
			'ipv6' => $rt['ipv6'] ?? null,
			'counters' => $hits,
		], JSON_UNESCAPED_SLASHES ) . "\n";
		break;

	case 'health':
		profile();
		exit( is_file( RUNTIME_FILE ) && counters()[0] ? 0 : 1 );

	case 'default':
		echo json_encode( load_default(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";
		break;

	default:
		fail( 'usage: container-firewall run|apply --b64 <doc>|status|health|default', 2 );
}
} catch ( RuntimeException $e ) {
	fail( $e->getMessage() );
}
