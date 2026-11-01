"""Teaching content for the Knowledge Base page and the dashboard's in-app hints.

The dashboard's audience includes cybersecurity students who have never run
a honeypot or a SIEM before. Everything here is plain data (no Qt), so it is
unit-testable and reusable by any page:

  - GLOSSARY: the terms a student meets on the pages, each with a plain
    definition and what it means in THIS project.
  - PAGE_GUIDES: one per sidebar page -- what it is for, what to try, what
    to notice. Drives sidebar tooltips, F1 help and the Knowledge Base page's tour.
  - PATTERN_LESSONS: one per core/patterns.PATTERN_PRESETS entry, keyed by
    its ``cve`` -- attack class, OWASP Top 10 (2021) category, MITRE ATT&CK
    technique, how the attack works and how to defend against it. The test
    suite checks every preset has one, so a new preset can't ship without.
  - LABS: short guided exercises that walk through the pages in order, with
    per-step progress persisted in AppState.learn_completed_steps.
  - explain_event(): a plain-language explanation for a pattern-analyzer
    event (core/pattern_log_parser.PatternEvent label), for card tooltips.
"""
from __future__ import annotations

from dataclasses import dataclass


# ---- glossary ----

@dataclass(frozen=True)
class GlossaryTerm:
    term: str
    definition: str
    in_this_project: str
    page: str = ""  # sidebar page id where the concept is visible, if any


GLOSSARY: list[GlossaryTerm] = [
    GlossaryTerm(
        "Honeypot",
        "A decoy system that looks like a real target but exists only to be attacked. "
        "Nobody legitimate should use it, so any activity on it is suspicious by "
        "definition, and users' tools and techniques can be studied safely.",
        "The honeypot is a decoy copy of the WordPress/WooCommerce eshop with its own "
        "decoy database. Suspicious visitors are silently routed to it instead of the "
        "real shop, so they keep attacking without reaching real data.",
        "patterns",
    ),
    GlossaryTerm(
        "IDS (Intrusion Detection System)",
        "Software that watches traffic or hosts for signs of attack and raises alerts. "
        "An IDS only detects; an IPS (Intrusion Prevention System) also blocks.",
        "Two layers detect attacks here: the Lua pattern analyzer in the reverse proxy "
        "(application layer, per HTTP request) and Suricata (network layer). Instead of "
        "blocking, the project deceives: detected users are diverted to the honeypot.",
        "patterns",
    ),
    GlossaryTerm(
        "Reverse proxy",
        "A server that sits in front of web applications, receives every client request "
        "and forwards it to a backend. It is a natural place to inspect, log and route "
        "traffic.",
        "OpenResty (nginx + Lua) is the only entry point. It scores every request and "
        "decides whether it goes to production or to a honeypot pool.",
        "health",
    ),
    GlossaryTerm(
        "Risk score",
        "A number summarising how suspicious a request or session looks, built by adding "
        "up points for individual signals (bad patterns, suspicious headers, known "
        "patterns, bad IP reputation, automation tools and so on).",
        "Scores run from 0 to 100. A session whose score reaches the honeypot threshold "
        "(80 by default) is routed to the honeypot. The Attack Simulation page shows each signal "
        "with the points it added.",
        "patterns",
    ),
    GlossaryTerm(
        "Risk score decay",
        "Letting old evidence count for less over time, so a single mistake by a normal "
        "user doesn't keep them flagged forever.",
        "A session's peak score halves every SCORE_DECAY_HALF_LIFE_SECONDS (300 s by "
        "default); repeat offenders decay more slowly. Setting THREAT_DECAY_ENABLED=false "
        "in the edge .env turns decay off so scores persist. Kibana's Threat Decisions & "
        "Decay dashboard plots each request's own score against what it carried over.",
        "settings",
    ),
    GlossaryTerm(
        "Sticky session",
        "Keeping a client on the same backend for the rest of its session, usually via a "
        "cookie.",
        "Once a session is sent to a honeypot it stays bound there, so a user never "
        "notices the switch by suddenly landing back on the real shop.",
        "patterns",
    ),
    GlossaryTerm(
        "CVE",
        "Common Vulnerabilities and Exposures: a public ID (like CVE-2024-27956) for one "
        "specific, disclosed vulnerability in one product.",
        "The proxy knows the request patterns of a set of real WordPress plugin CVEs. A "
        "matching request goes to the honeypot immediately. Each attack-simulation preset fires one "
        "of them (the GENERIC-WP-* ones are common WordPress attacks without a CVE).",
        "patterns",
    ),
    GlossaryTerm(
        "Severity (CVSS)",
        "How bad a vulnerability is, usually rated with the Common Vulnerability Scoring "
        "System (0-10) and grouped as LOW, MEDIUM, HIGH or CRITICAL.",
        "Each pattern preset carries a severity label. CRITICAL ones typically allow "
        "remote code execution or full database access without logging in.",
        "patterns",
    ),
    GlossaryTerm(
        "SQL injection (SQLi)",
        "Smuggling SQL syntax into a parameter that the application pastes into a "
        "database query, so the user's SQL runs with the application's privileges.",
        "Several presets send a UNION SELECT payload that would dump WordPress user "
        "hashes on a vulnerable plugin. The proxy recognises the pattern and diverts it.",
        "patterns",
    ),
    GlossaryTerm(
        "Path traversal",
        "Using ../ sequences in a file path parameter to escape the intended directory "
        "and read or write arbitrary files, such as /etc/passwd.",
        "Two presets try to read /etc/passwd through a plugin's file[path] parameter.",
        "patterns",
    ),
    GlossaryTerm(
        "Remote code execution (RCE)",
        "The worst class of bug: the user can make the server run commands or code "
        "of their choice.",
        "The Bricks Builder and file-upload presets demonstrate RCE attempts; on the "
        "honeypot they execute nothing real.",
        "patterns",
    ),
    GlossaryTerm(
        "Web shell",
        "A small script (for example shell.php) uploaded to a web server that gives the "
        "user a command prompt through HTTP requests.",
        "The upload-bypass presets try to upload shell.php; the proxy's upload analysis "
        "scores that as suspicious.",
        "patterns",
    ),
    GlossaryTerm(
        "Honeytoken",
        "Fake data (a credential, an API key, a user record) planted where only an "
        "intruder would find it. Any use of it is a high-confidence alert.",
        "Honeytokens are planted in the decoy content; a request that carries one is "
        "logged as a security event and shows under Honeytoken Hits on Kibana's Attack "
        "Patterns dashboard.",
        "kibana",
    ),
    GlossaryTerm(
        "IP reputation",
        "A score for how likely an IP address is to be flagged, from past behaviour or "
        "threat-intelligence feeds such as AbuseIPDB.",
        "Suricata alerts and past honeypot hits raise an IP's reputation score (stored "
        "in Redis). A bad reputation alone can send a request to the honeypot.",
        "redis",
    ),
    GlossaryTerm(
        "Suricata",
        "An open-source network IDS that inspects packets against signature rules.",
        "Runs next to the proxy, and its alerts feed both the SIEM and the IP reputation "
        "signal.",
        "health",
    ),
    GlossaryTerm(
        "SIEM",
        "Security Information and Event Management: a system that collects logs from "
        "everywhere, stores them centrally, and lets analysts search, correlate and "
        "visualise them.",
        "The siem project: Vector ships logs into Elasticsearch, Kibana visualises them. "
        "Open it from the SIEM Analytics page.",
        "kibana",
    ),
    GlossaryTerm(
        "Elasticsearch / Kibana / Vector",
        "Elasticsearch is a search engine used as a log store, Kibana is its web UI for "
        "dashboards and searching, and Vector is a log shipper that collects and "
        "transforms logs before storing them.",
        "Together they form the SIEM stack in siem/. The SIEM Analytics page embeds its "
        "dashboards and logs you in automatically.",
        "kibana",
    ),
    GlossaryTerm(
        "Session store (Redis)",
        "Redis is a fast in-memory key-value database, often used for sessions and "
        "counters.",
        "Holds sessions, their scores and pool assignments, and IP reputation. The Redis "
        "page lets you look inside.",
        "redis",
    ),
    GlossaryTerm(
        "Automation / bot detection",
        "Recognising scripted clients (scanners, curl, sqlmap, headless browsers) by "
        "their User-Agent, headers and request rate.",
        "Sending a pattern with curl adds an automation signal on top of the pattern "
        "itself, which is why curl runs often score higher than the same path in the "
        "browser.",
        "patterns",
    ),
    GlossaryTerm(
        "User sophistication",
        "Classifying users by skill: from scripted mass scanners up to careful, "
        "manual, targeted users.",
        "The proxy's sophistication analyzer classifies each session; Kibana's Session "
        "Analysis dashboard charts the results.",
        "kibana",
    ),
    GlossaryTerm(
        "False positive / false negative",
        "A false positive flags a legitimate user; a false negative lets "
        "a hostile user through unflagged. Every detection threshold trades one for the "
        "other.",
        "The honeypot threshold (honeypot_threshold in the proxy's init.lua) was raised "
        "from 50 to 80 to cut false positives. Try the Manual request tab to see which "
        "harmless-looking requests still score.",
        "patterns",
    ),
    GlossaryTerm(
        "MITRE ATT&CK",
        "A public knowledge base of real-world adversary tactics and techniques, each with "
        "an ID like T1190 (Exploit Public-Facing Application).",
        "Each pattern lesson on the Knowledge Base page names the ATT&CK technique it belongs to.",
        "learn",
    ),
    GlossaryTerm(
        "OWASP Top 10",
        "The Open Worldwide Application Security Project's list of the ten most critical "
        "web application risk categories (the 2021 edition is used here).",
        "Each pattern lesson names its OWASP Top 10 category, such as A03 Injection.",
        "learn",
    ),
    GlossaryTerm(
        "TLS certificate",
        "Proves a server's identity and enables HTTPS encryption. Self-signed "
        "certificates encrypt but aren't trusted by browsers by default.",
        "The PKI & Certificates page generates the self-signed certificates the proxy and SIEM "
        "use, which is why curl runs with -k.",
        "certificates",
    ),
    GlossaryTerm(
        "Honeypot pool",
        "One isolated set of decoy containers (a decoy eshop plus its decoy database) that "
        "diverted sessions are routed to. Keeping users on separate pools stops one user from "
        "seeing another's activity and keeps the real shop untouched.",
        "Pools 1-3 are declared in docker-compose.yml and always present; the pool manager "
        "creates further pools at runtime and reuses the numbers of ones it destroyed. Each "
        "diverted session is handed its own pool until the resource budget runs out. The Pool "
        "Scaling page shows every pool, who is on it and why.",
        "pool_scaling",
    ),
    GlossaryTerm(
        "Per-session segmentation",
        "Telling visitors apart by their session (cookie plus browser fingerprint) rather than "
        "by IP address, so several people behind one address -- or one user clearing cookies -- "
        "are isolated from each other.",
        "Every diverted session is bound to its own honeypot pool, not shared by address. The "
        "Segmentation Validation page runs several independent sessions from one machine and "
        "shows each landing on a pool of its own.",
        "pool_test",
    ),
    GlossaryTerm(
        "Pool autoscaling",
        "Starting and stopping decoy capacity on demand, within a fixed resource budget, so "
        "there is always a free pool for the next user without wasting a running pool per idle one.",
        "The pool manager builds one pool per waiting session plus a few spares, bounded by "
        "POOL_MAX (pool count), POOL_MAX_MEMORY_MB and POOL_MAX_CPUS -- each WordPress-layer pool "
        "reserves about 1536 MB and 1.5 CPUs. Idle pools are scaled down after "
        "POOL_IDLE_TIMEOUT_SECONDS. Once the budget is reached, new sessions share existing pools; "
        "the Pool Scaling page names whichever limit stopped scaling.",
        "pool_scaling",
    ),
    GlossaryTerm(
        "Honeypot layer",
        "Which layer of the stack the deception happens at. Deceiving higher up (the whole "
        "backend) catches more attack types; deceiving lower down (just the data) is lighter but "
        "narrower.",
        "Pick it from the Services page's Honeypot layer dropdown. Reverse-proxy level "
        "(docker-compose.yml, default) routes suspicious sessions to separate honeypot WordPress "
        "containers (pools). Database level (docker-compose.db-proxy.yml) keeps one eshop and lets "
        "wp-content/db.php switch between the production and honeypot database per request, so it "
        "isolates database-layer attacks only -- file-upload or code-execution attacks have no "
        "separate backend to land in.",
        "services",
    ),
    GlossaryTerm(
        "Device signature (GDPR signature)",
        "A stable, privacy-preserving identifier derived from a browser's own characteristics, so "
        "a returning visitor can be recognised even after they clear cookies and local storage.",
        "Consent-gated and one-way. After the visitor agrees, the browser encrypts its screen size "
        "plus a timestamp with the proxy's public key (the gdpr_token cookie). Per request the "
        "proxy decrypts it in memory, appends the client IP it actually sees, and hashes the result "
        "with a deployment salt into the gdpr_signature. Only that hash is stored (no personal "
        "data), only for honeypot-bound sessions, and only with a TTL. The Signature Simulation "
        "page shows the whole flow live.",
        "signature_sim",
    ),
    GlossaryTerm(
        "Pattern catalogue",
        "A single machine-readable list of every detection pattern the system knows, so tools and "
        "docs share one source of truth instead of each keeping their own copy.",
        "Generated into patterns/patterns.json: one record per CVE, generic signature, upload or "
        "header rule, scanner-tool fingerprint and Suricata SID, each with a stable ID and its "
        "provenance. The Pattern Database page and the documentation site both read it, so the two "
        "can never drift apart.",
        "pattern_database",
    ),
]


def search_glossary(query: str) -> list[GlossaryTerm]:
    """Terms whose name or text contains every word of ``query`` (case-
    insensitive), term-name matches first. An empty query returns all."""
    words = query.lower().split()
    if not words:
        return list(GLOSSARY)
    hits = [t for t in GLOSSARY
            if all(w in f"{t.term} {t.definition} {t.in_this_project}".lower() for w in words)]
    return sorted(hits, key=lambda t: not all(w in t.term.lower() for w in words))


# ---- page guides ----

@dataclass(frozen=True)
class PageGuide:
    summary: str        # one line: what the page is for (sidebar tooltip)
    try_this: str       # a first thing to do there
    notice: str         # what a student should look for / learn from it


PAGE_GUIDES: dict[str, PageGuide] = {
    "overview": PageGuide(
        "Operations landing page: current risk score, both stacks' health, and a live feed of notable security events.",
        "Leave it open and run a pattern on the Attack Simulation page -- watch the score and events update here live.",
        "A SOC console opens on a summary. The current score and recent diversions tell you at a glance whether "
        "anything is happening right now, before you drill into any single page.",
    ),
    "live_events": PageGuide(
        "Real-time stream of the proxy's detection decisions, filterable and exportable, without needing the SIEM.",
        "Run a pattern, then filter to 'Honeypot diversions' and watch the request that tipped the score.",
        "Each row is one decision or scoring signal. Severity follows the points added; the stream keeps working "
        "even when Kibana or the SIEM stack is down.",
    ),
    "pipeline": PageGuide(
        "Is the edge shipper really delivering logs to the SIEM? Shipping config, shipper, log errors and aggregator in one check.",
        "Open it with both stacks up; then stop the SIEM's vector_inbound and watch the verdict turn to failing.",
        "A green container is not a working pipeline: the mTLS channel can be broken while everything shows up. "
        "Delivery errors in the shipper's own log are the earliest sign that telemetry is being lost.",
    ),
    "sessions": PageGuide(
        "Per-session drill-down: who each visitor is, how their risk score climbed, and where they were diverted.",
        "Run a pattern, open this page, and select your session to read its timeline.",
        "An attack is a story, not a number: the timeline shows which requests added points and when the "
        "session crossed the honeypot threshold.",
    ),
    "suricata": PageGuide(
        "Network IDS view: recent Suricata alerts, top signatures and sources, and the rule set with per-rule switches.",
        "Run a scanner-style pattern, then look for its signature on the Alerts tab.",
        "Suricata watches packets, the Lua analyzer watches requests. Switching a rule off and re-running the "
        "same attack shows which layer actually caught it.",
    ),
    "detection": PageGuide(
        "Tune how evidence builds and fades: score decay, IP-reputation weight and shared-address handling.",
        "Lengthen the decay half-life, save and restart the proxy, then re-run the same pattern.",
        "Detection is configuration. The summary under the form turns the half-life into seconds so you can "
        "see how long an adversary stays flagged after they stop.",
    ),
    "whitelist": PageGuide(
        "The inventory of legitimate shop URLs. A path that is not on the enabled whitelist adds the "
        "unlisted-path score to the request.",
        "Apply the policy to the edge, then request /.env and /shop/ and compare their scores in Adversary Sessions.",
        "An allow-list turns 'unknown' into evidence without trusting 'known': a payload on a whitelisted "
        "path is still scored like any other request.",
    ),
    "honeypot_targets": PageGuide(
        "The CVE trap URLs and vulnerable plugin paths that exist only on the honeypots, with what a hit does.",
        "Switch to score-first mode, apply it, run a CVE preset on Attack Simulation and watch the score "
        "rather than an instant diversion.",
        "Auto-send traps an attacker on first contact. Score-first trades that for fewer false diversions "
        "when a target URL is also reachable by legitimate traffic.",
    ),
    "container_firewall": PageGuide(
        "The firewalls around the WordPress containers -- production and every honeypot pool: who may open a "
        "connection to them, and where they may open connections themselves.",
        "Apply the production defaults, Check, then load the shop once and watch the edge-http and database "
        "packet counters rise. Switch to Honeypot pools: the only outbound rule is the pool's own database.",
        "Filtering only NEW connections keeps every reply flowing while a compromised plugin can no longer reach "
        "anything the shop does not need. An attacker who takes over a honeypot pool is meant to get in, but "
        "not out: no internet, no edge, no production, no other pool. The rules sit in a sidecar container "
        "whose network namespace WordPress joins, so even root inside WordPress cannot change them.",
    ),
    "pool_scaling": PageGuide(
        "Standing view of the honeypot pools: count, resource budget, who is on which pool, and why scaling stops.",
        "Open it, then run Attack from all on Segmentation Validation and watch pools being built and handed over.",
        "Pools are built per session until a memory, CPU or pool-count budget is hit; after that sessions share "
        "pools. The event log shows each build, hand-off and scale-down as it happens.",
    ),
    "services": PageGuide(
        "Workload inventory and lifecycle control for the IDS edge and SIEM stacks, with live container logs.",
        "Press Start on the ids project, then on siem, and watch the logs scroll.",
        "Every container is a separate service: proxy, eshops, databases, Suricata, "
        "Redis. The combined log is what a sysadmin reads first when something breaks. "
        "The Honeypot layer dropdown picks where the deception happens: at the reverse "
        "proxy (separate honeypot eshops) or at the database (one eshop that switches "
        "databases per request, which cannot contain file or code-execution attacks).",
    ),
    "health": PageGuide(
        "Topology map of every workload with live health, enforcement path and honeypot pool status.",
        "Stop one container from a terminal and watch its node change colour.",
        "The diagram is the system's architecture: traffic enters at the proxy, fans "
        "out to production or honeypot eshops, and everything reports to the SIEM.",
    ),
    "resources": PageGuide(
        "Per-workload CPU, memory and network telemetry, annotated with attack-simulation markers.",
        "Run a pattern on the Attack Simulation page and look for its marker on the graphs.",
        "Attacks cost resources. Scanners and brute force show up as load spikes, which "
        "is also how denial-of-service is noticed.",
    ),
    "certificates": PageGuide(
        "Issue and rotate the TLS certificates securing the edge proxy and SIEM endpoints.",
        "Generate certificates once before the first start.",
        "The certificates are self-signed, so browsers and curl need to be told to "
        "trust them (curl -k).",
    ),
    "redis": PageGuide(
        "Inspect the proxy's live state store: sessions, risk scores, IP reputation and pool bindings.",
        "Run a pattern, then refresh here and find your session and its score.",
        "The proxy's memory is data you can inspect: a score is just a number in a key, "
        "and a sticky honeypot binding is just a stored pool name.",
    ),
    "backups": PageGuide(
        "Snapshot and restore workload data volumes for incident recovery.",
        "Take a backup before experimenting so you can roll back.",
        "Backups are part of incident response: being able to restore a known-good "
        "state matters as much as detecting the attack.",
    ),
    "kibana": PageGuide(
        "SIEM dashboards for flows, alerts and security events, correlated across both stacks.",
        "Open Attack Patterns after running a few patterns and find your CVEs, then open "
        "Threat Decisions & Decay to see why each request was diverted.",
        "This is the analyst's view. The same attack you fired appears here as "
        "structured events you can filter, count and correlate.",
    ),
    "patterns": PageGuide(
        "Replay real WordPress CVE patterns against the edge and observe detection, scoring and diversion.",
        "Pick a preset, press 'What is this?' to read about it, then Run pattern (curl).",
        "Each card on the Pattern analyzer tab is one signal that added points. Watch the "
        "score cross the threshold and the route flip to HONEYPOT.",
    ),
    "pattern_database": PageGuide(
        "Browse every detection pattern in one place: CVEs, generic signatures, upload and header rules, "
        "scanner tools and Suricata SIDs, with provenance and an attack lesson for each.",
        "Search for 'sql', 'upload' or a CVE ID, then select a row and read its detection path and sources.",
        "The same generated catalogue feeds the docs site. Stable IDs and export are the contract for the "
        "upcoming pattern-plugin workflow: add, edit, remove and enable without two lists drifting apart.",
    ),
    "signature_sim": PageGuide(
        "Watch one browser characteristic become the proxy's consent-gated one-way gdpr_signature, end to end.",
        "Resize the visitor browser window, press 'Agree & derive signature', then resize and run again.",
        "The browser signs its screen size plus a timestamp; the proxy appends the client IP it sees and "
        "hashes it. Only the signature leaves the proxy, and the same browser from the same size reproduces "
        "the same signature — that is how a returning visitor is re-recognised without storing anything about them.",
    ),
    "account_persistence": PageGuide(
        "Step-by-step proof that a logged-in adversary keeps their own account — role, profile, the lot — when the edge diverts them to a honeypot pool, with a PDF export.",
        "Press 'Run step-by-step test' with the edge up; watch step 2 derive the same signature with and without the username, then read steps 3–6.",
        "Diversion must not tip the adversary off. The username rides the gdpr_token as metadata only (step 2 proves live it never changes the signature), while the account copy is keyed off production's own X-Auth-User — the authoritative, non-spoofable identity — so a client cannot name someone else's account to have it copied into a honeypot it controls. A worker copies that one account into the pool and a secret-gated plugin logs them straight back in, exactly as they were.",
    ),
    "log_search": PageGuide(
        "Forensic search across raw logs from every workload.",
        "Search for the CVE ID of a pattern you just ran.",
        "Raw logs are the ground truth behind every dashboard. Being able to grep them "
        "is a core analyst skill.",
    ),
    "pool_test": PageGuide(
        "Validate per-session segmentation: several isolated user sessions, each diverted to its own honeypot pool.",
        "Press Open shop in all, then Attack from all, then Refresh pool state.",
        "Users are told apart by session, not by address: each frame has its own cookie "
        "and browser fingerprint, so each is diverted to a honeypot pool of its own.",
    ),
    "breach_audit": PageGuide(
        "Attacker's-eye hardening audit: assume a honeypot is already owned and try to break the containment, then export a PDF.",
        "Leave all categories ticked, press Run breach validation, and read the table top-down -- failures first.",
        "Diversion and isolation are only half the story: the other half is that a compromised honeypot "
        "stays a dead end. These read-only probes try to pivot out of a honeypot to production, the other "
        "pools, the Docker daemon and the internet, and to smuggle a honeypot target past the edge whitelist "
        "onto production. Every blocked attempt is a PASS.",
    ),
    "extras": PageGuide(
        "Report generation: implementation chapter, architecture overview and pattern / CVE matrix.",
        "Export the Pattern / CVE matrix as a study sheet.",
        "The matrix lists every preset with its CVE and severity in one table.",
    ),
    "wp_studio": PageGuide(
        "Edit the real WordPress + WooCommerce shop in wp-admin, then push pages, posts, products and safe settings to every honeypot pool at once.",
        "Change a product price or the store address, save, then press “Propagate to honeypot pools” and watch the progress bar fan it out.",
        "Deception only holds if the decoys match production: an adversary who spots a stale catalog or a different price knows they have been moved. "
        "The sync copies content and presentational settings but never user accounts, orders, or secrets (API keys, passwords, payment config) -- "
        "those stay in production so a compromised honeypot leaks nothing of value.",
    ),
    "wp_update": PageGuide(
        "Check for newer WordPress core and WooCommerce releases and apply them to production and every honeypot pool behind a maintenance page.",
        "Press “Check for updates”; if a newer version is offered, press “Update all instances” and watch the staged progress bar.",
        "An update takes the whole site offline for a few minutes: the edge serves a maintenance page while production is upgraded, the new files "
        "are re-synced to the pools, and each database is migrated. The maintenance flag is TTL-guarded in Redis, so the site comes back on its own "
        "even if the update is interrupted -- and keeping the decoys on the same version as production keeps their fingerprints believable.",
    ),
    "targeted_access": PageGuide(
        "Open the real wp-admin panel on production or on any one honeypot pool, on demand.",
        "Propagate a change in WordPress Studio, then open the same pool here and confirm it landed.",
        "Pinned the same way WordPress Studio pins to production: the chosen target is forced "
        "with a secret-gated header, so scoring and session routing are skipped entirely -- the "
        "check can't be diverted off its target, and it never poisons the operator's own IP "
        "reputation, whichever pool is opened.",
    ),
    "settings": PageGuide(
        "Target connectors (local or SSH), stack configuration, detection policy values and console preferences.",
        "Open the edge .env and find SCORE_DECAY_HALF_LIFE_SECONDS and THREAT_DECAY_ENABLED.",
        "Detection is configuration: changing how fast evidence fades changes who still "
        "gets flagged. Change it and re-run the same pattern.",
    ),
    "learn": PageGuide(
        "Glossary, guided labs and a threat brief for every attack-simulation preset.",
        "Start with Lab 1 on the Guided labs tab.",
        "Everything on the other pages is explained here in plain language.",
    ),
}


# ---- pattern lessons ----

@dataclass(frozen=True)
class PatternLesson:
    attack_class: str
    owasp: str       # OWASP Top 10 (2021) category
    attack: str      # MITRE ATT&CK technique, "Txxxx Name"
    how_it_works: str
    defence: str


_T1190 = "T1190 Exploit Public-Facing Application"
_SQLI_HOW = ("The plugin copies the parameter straight into an SQL query. The payload closes "
             "the original string with an apostrophe and appends UNION SELECT user_login, "
             "user_pass FROM wp_users, so the page would print usernames and password hashes.")
_SQLI_DEFENCE = ("Use prepared statements ($wpdb->prepare), validate the parameter's type "
                 "(an ID should be an integer), and update the plugin.")

PATTERN_LESSONS: dict[str, PatternLesson] = {
    "CVE-2023-28121": PatternLesson(
        "Authentication bypass", "A07 Identification and Authentication Failures", _T1190,
        "WooCommerce Payments trusted a request header to say which user was logged in. "
        "Sending X-WCPAY-PLATFORM-CHECKOUT-USER: 1 makes the site treat the request as "
        "user 1, normally the administrator.",
        "Never derive identity from a client-controlled header; update the plugin "
        "(fixed in 5.6.2)."),
    "CVE-2023-2986": PatternLesson(
        "Hard-coded cryptographic key", "A02 Cryptographic Failures", _T1190,
        "Abandoned Cart Lite signs its checkout links with a key that is the same on every "
        "install, so anyone can forge a link that logs them in as a customer.",
        "Generate secrets per install, verify signatures server-side, update the plugin."),
    "CVE-2025-4403": PatternLesson(
        "Unrestricted file upload", "A04 Insecure Design", "T1505.003 Web Shell",
        "The upload handler checks the file type loosely, so a PHP file (shell.php) can be "
        "uploaded and then requested to run commands on the server.",
        "Allow-list extensions and MIME types, store uploads outside the web root, and "
        "never let the web server execute files in upload folders."),
    "CVE-2025-2266": PatternLesson(
        "Missing authorization", "A01 Broken Access Control", _T1190,
        "An AJAX action updates WordPress options without checking who is asking. Setting "
        "default_role=administrator makes every new registration an admin.",
        "Check capabilities (current_user_can) and nonces on every state-changing action."),
    "CVE-2025-47577": PatternLesson(
        "Unrestricted file upload leading to RCE", "A04 Insecure Design", "T1505.003 Web Shell",
        "The gift voucher preview handler accepts an unauthenticated attachment upload, so "
        "a PHP file can be dropped on the server and executed.",
        "Require authentication, allow-list file types, disable PHP execution in uploads."),
    "CVE-2024-2387": PatternLesson(
        "SQL injection", "A03 Injection", _T1190, _SQLI_HOW, _SQLI_DEFENCE),
    "CVE-2025-10142": PatternLesson(
        "Path traversal", "A01 Broken Access Control", "T1083 File and Directory Discovery",
        "The callback builds a file path from file[path]. ../../../../etc/passwd walks up "
        "out of the uploads folder to read a system file.",
        "Resolve the real path and reject anything outside the allowed directory; never "
        "build file paths from raw user input."),
    "CVE-2024-50508": PatternLesson(
        "Path traversal", "A01 Broken Access Control", "T1083 File and Directory Discovery",
        "Same idea as the PagSeguro bug: ../ sequences in file[path] escape the intended "
        "upload directory, allowing arbitrary file reads or writes.",
        "Canonicalise paths and compare against an allowed base directory; update the plugin."),
    "GENERIC-WP-001": PatternLesson(
        "Sensitive file disclosure", "A05 Security Misconfiguration",
        "T1552.001 Credentials In Files",
        "wp-config.php holds the database password and secret keys. If the server ever "
        "serves it as text (a misconfiguration or a backup copy like wp-config.php.bak), "
        "the user owns the database.",
        "Make sure PHP files are never served as plain text, keep backups out of the web "
        "root, and deny direct access to wp-config.php."),
    "GENERIC-WP-002": PatternLesson(
        "Exposed installer", "A05 Security Misconfiguration", _T1190,
        "install.php is only meant for first setup. On a half-installed site a user "
        "can finish the installation with their own admin account and database.",
        "Finish installation immediately and block installer scripts once done."),
    "GENERIC-WP-003": PatternLesson(
        "User enumeration", "A01 Broken Access Control",
        "T1589.003 Gather Victim Identity Information: Employee Names",
        "/?author=1 redirects to /author/<username>/, revealing a valid login name. Walking "
        "1, 2, 3... lists every user, halving the work of a password-guessing attack.",
        "Block ?author= redirects for anonymous users and use login names that differ "
        "from display names."),
    "GENERIC-WP-004": PatternLesson(
        "Brute-force amplification", "A07 Identification and Authentication Failures",
        "T1110 Brute Force",
        "xmlrpc.php's system.multicall lets one HTTP request try hundreds of passwords, "
        "slipping past login rate limits. system.listMethods (this preset) is the usual "
        "first probe.",
        "Disable XML-RPC if unused, or rate-limit it and block system.multicall."),
    "CVE-2017-1001000": PatternLesson(
        "Content injection (defacement)", "A01 Broken Access Control", _T1190,
        "WordPress 4.7.0 and 4.7.1 checked permissions against the post id before casting it "
        "to an integer, so posts/1?id=1abc passed the check as a different, unprotected id "
        "while still editing post 1. Anyone could rewrite pages and posts.",
        "Update WordPress (fixed in 4.7.2) and monitor for unexpected content changes."),
    "GENERIC-XSS-001": PatternLesson(
        "Cross-site scripting (script tag)", "A03 Injection", "T1189 Drive-by Compromise",
        "A <script> tag sent in the search parameter. If the page prints the search term "
        "without escaping it, the script runs in every visitor's browser who opens the link.",
        "Escape output (esc_html, esc_attr), set a Content-Security-Policy, and filter or "
        "block script tags in requests."),
    "GENERIC-XSS-002": PatternLesson(
        "Cross-site scripting (event handler)", "A03 Injection", "T1189 Drive-by Compromise",
        "XSS without a script tag: an <img> with a broken src whose onerror handler runs "
        "JavaScript. Filters that only look for <script> miss it.",
        "Escape output by context, use a strict Content-Security-Policy, and match on "
        "handlers such as onerror= and onload=, not only on <script>."),
    "GENERIC-SQLI-001": PatternLesson(
        "SQL injection (boolean)", "A03 Injection", _T1190,
        "A quote and OR '1'='1 in a form field. If the value is pasted into an SQL query, "
        "the condition is always true and the query returns rows it should not.",
        "Use prepared statements ($wpdb->prepare) and validate input types."),
    "GENERIC-SQLI-002": PatternLesson(
        "SQL injection (time-based blind)", "A03 Injection", _T1190,
        "No data is returned, so the user asks the database to SLEEP and measures how "
        "long the response takes. A delay proves the query ran, and bits of data can then "
        "be read one at a time.",
        "Use prepared statements, and alert on SLEEP/BENCHMARK in requests and on slow queries."),
    "GENERIC-SQLI-003": PatternLesson(
        "SQL injection (form body)", "A03 Injection", _T1190,
        "The payload is in the POST body of a form, not the URL. Filters that only inspect "
        "the URL and headers never see it, so this tests whether a body-borne attack is "
        "detected at all.",
        "Inspect request bodies too (a WAF), and use prepared statements so injection "
        "fails regardless of detection."),
    "GENERIC-ENUM-001": PatternLesson(
        "Content discovery (wordlist scan)", "A05 Security Misconfiguration",
        "T1595.003 Active Scanning: Wordlist Scanning",
        "A tool tries a long list of common paths (/admin, /.env, /backup.zip, ...) and "
        "notes which exist. Each single request looks harmless, so the signal is the "
        "pattern across requests.",
        "Remove backups and config files from the web root, rate-limit 404 bursts, and "
        "flag clients that probe many sensitive paths."),
    "GENERIC-ENUM-002": PatternLesson(
        "Plugin and theme discovery", "A06 Vulnerable and Outdated Components",
        "T1595.002 Active Scanning: Vulnerability Scanning",
        "Requesting each plugin's readme.txt and each theme's style.css reveals which are "
        "installed and their versions, which the user then matches against known CVEs.",
        "Block direct access to readme files, keep components updated, and hide version "
        "strings."),
    "GENERIC-IDOR-001": PatternLesson(
        "Insecure direct object reference (users)", "A01 Broken Access Control",
        "T1087 Account Discovery",
        "Changing the id in /wp-json/wp/v2/users/<id> lists accounts one by one. The server "
        "answers without checking whether the requester may see them.",
        "Require authentication for user listings and check ownership on every object access."),
    "GENERIC-IDOR-002": PatternLesson(
        "Insecure direct object reference (orders)", "A01 Broken Access Control",
        "T1213 Data from Information Repositories",
        "Walking order ids in the WooCommerce REST API reads other customers' orders if "
        "the endpoint does not verify who owns each one.",
        "Check ownership on every object, use authenticated API keys, and avoid guessable "
        "sequential ids where possible."),
    "GENERIC-TOOL-001": PatternLesson(
        "Automated SQL injection tool", "A03 Injection",
        "T1595.002 Active Scanning: Vulnerability Scanning",
        "sqlmap announces itself in its User-Agent. Detecting the tool by name is easy to "
        "evade (users change the header) but catches careless automation.",
        "Do not rely on User-Agent alone: also detect the payloads and request rates."),
    "GENERIC-TOOL-002": PatternLesson(
        "Automated web scanner (Nikto)", "A05 Security Misconfiguration",
        "T1595.002 Active Scanning: Vulnerability Scanning",
        "Nikto sends thousands of requests for known-bad files and identifies itself in the "
        "User-Agent unless told otherwise.",
        "Detect scanner bursts by behaviour (many 404s, known-bad paths), not just by name."),
    "GENERIC-TOOL-003": PatternLesson(
        "Exploitation framework (Metasploit)", "A06 Vulnerable and Outdated Components",
        "T1595.002 Active Scanning: Vulnerability Scanning",
        "Metasploit modules normally send a browser-like User-Agent, so a name match is a "
        "weak signal. This preset sends an honest agent to show that name-based detection "
        "works only for the unevasive case.",
        "Detect the pattern payloads and post-exploitation behaviour, not the framework name."),
    "GENERIC-TOOL-004": PatternLesson(
        "Directory brute-forcer (Gobuster)", "A05 Security Misconfiguration",
        "T1595.003 Active Scanning: Wordlist Scanning",
        "Gobuster requests every entry of a wordlist and keeps the paths that exist. Its "
        "default User-Agent is gobuster/<version>.",
        "Rate-limit and flag clients with many 404s in a short time."),
    "GENERIC-TOOL-005": PatternLesson(
        "WordPress scanner (WPScan)", "A06 Vulnerable and Outdated Components",
        "T1595.002 Active Scanning: Vulnerability Scanning",
        "WPScan enumerates WordPress version, plugins, themes and users, and matches them "
        "against a vulnerability database. Its default User-Agent names it.",
        "Hide version information, restrict user enumeration, and flag WPScan-style probing."),
    "CVE-2024-25600": PatternLesson(
        "Remote code execution (code injection)", "A03 Injection", _T1190,
        "Bricks Builder's render_element endpoint passes user-supplied PHP to eval() "
        "without logging in. The payload runs system('id') to prove command execution.",
        "Never eval() user input; require authentication and nonces; update Bricks "
        "(fixed in 1.9.6.1)."),
    "CVE-2024-27956": PatternLesson(
        "SQL injection", "A03 Injection", _T1190,
        "WP Automatic's csv.php runs a query built from the q parameter without "
        "authentication. It was mass-exploited to create rogue admin accounts. " + _SQLI_HOW,
        _SQLI_DEFENCE),
    "CVE-2024-1071": PatternLesson(
        "SQL injection", "A03 Injection", _T1190,
        "Ultimate Member's um_get_members AJAX action puts directory_id into a query "
        "unescaped. " + _SQLI_HOW, _SQLI_DEFENCE),
    "CVE-2022-0739": PatternLesson(
        "SQL injection", "A03 Injection", _T1190,
        "BookingPress passes total_service into a query unescaped. " + _SQLI_HOW,
        _SQLI_DEFENCE),
    "CVE-2024-2879": PatternLesson(
        "SQL injection", "A03 Injection", _T1190,
        "LayerSlider's ls_get_popup_markup action puts id into a query unescaped. " + _SQLI_HOW,
        _SQLI_DEFENCE),
}


# CVE aliases that share an Attack Simulation preset's lesson. Keeping these
# out of PATTERN_LESSONS itself preserves "every lesson key has a preset" --
# CVE-2024-8425 is the same Gift Voucher handler as CVE-2025-47577 but has no
# separate preset of its own.
PATTERN_LESSON_ALIASES = {
    "CVE-2024-8425": "CVE-2025-47577",
}


def lesson_for(cve: str) -> PatternLesson | None:
    return PATTERN_LESSONS.get(PATTERN_LESSON_ALIASES.get(cve, cve))


# ---- pattern-analyzer event explanations ----

# (substring of the event label, lower-case) -> explanation. Checked in order,
# first match wins, so more specific phrases come first. Labels come from
# core/pattern_log_parser (which mirrors pattern_analyzer.lua / router.lua).
_EVENT_EXPLANATIONS: list[tuple[str, str]] = [
    ("cve", "The request matched the known pattern of a published vulnerability (CVE). "
            "A CVE match alone is enough to divert the session to the honeypot."),
    ("uri pattern", "The URL contains patterns typical of attacks or probing, such as "
                    "../, SQL keywords or requests for sensitive files."),
    ("suspicious header", "A request header looks forged or tool-generated, for example an "
                          "pattern-specific header or a missing/odd User-Agent."),
    ("bad ip reputation", "This IP address has a bad reputation from earlier alerts "
                          "(Suricata, previous honeypot hits or threat-intel feeds)."),
    ("known threat ip", "This IP address is already on the known-threat list, so its "
                        "requests start with extra suspicion."),
    ("whitelisted", "This IP address is trusted, so its score is lowered."),
    ("request method", "An unusual HTTP method (such as PUT, DELETE or TRACE) for a "
                       "public shop."),
    ("automation", "The client looks like a script or scanner (curl, sqlmap, a headless "
                   "browser) rather than a person in a browser."),
    ("upload", "The request uploads a file that looks dangerous, such as a .php web shell "
               "or a mismatched MIME type."),
    ("prompt-injection", "The request contains text crafted to manipulate an AI system "
                         "(prompt injection)."),
    ("below threshold", "This session was sent to the honeypot earlier, but its score has "
                        "decayed below the threshold, so it is allowed back to production."),
    ("staying on production", "Something looked a little suspicious and was logged, but not "
                              "enough to divert the session."),
    ("session bound", "This session was already sent to the honeypot earlier, so it stays "
                      "there (sticky session) whatever this request scores."),
    ("high risk score", "The accumulated score crossed the honeypot threshold, so the "
                          "session was diverted."),
    ("vulnerable plugin", "Direct access to a file of a plugin with a known vulnerability."),
    ("admin attempt", "Repeated attempts to reach the WordPress admin area, typical of "
                      "password guessing."),
    ("accumulated suspicious", "Many individually small suspicious actions added up to "
                               "enough evidence to divert the session."),
    ("rapid automation", "Requests are arriving too fast for a human."),
    ("final decision: honeypot", "The request was sent to the decoy shop. The user "
                                 "sees a normal-looking site and doesn't know."),
    ("final decision: production", "The request was judged safe and sent to the real shop."),
    ("routed to honeypot", "The request was sent to the decoy shop."),
    ("routed to production", "The request was judged safe and sent to the real shop."),
    ("final score", "The total of all signal points for this request, out of 100. The "
                    "session goes to the honeypot at the threshold (80 by default)."),
    ("clean request", "No suspicious signals at all."),
    ("low threat", "A few weak signals, but below the threshold, so it stays on production."),
    ("missing required dependency", "A tool the dashboard needs is not installed; see the "
                                    "banner at the top of the window."),
]


def explain_event(label: str) -> str:
    """Plain-language explanation of a pattern-analyzer event label, or ""."""
    low = label.lower()
    for needle, text in _EVENT_EXPLANATIONS:
        if needle in low:
            return text
    return ""


# ---- guided labs ----

@dataclass(frozen=True)
class LabStep:
    id: str
    text: str
    page: str = ""  # page to open for this step ("" = none)


@dataclass(frozen=True)
class Lab:
    id: str
    title: str
    goal: str
    steps: tuple[LabStep, ...]


LABS: list[Lab] = [
    Lab("lab1", "Lab 1: Bring the system up",
        "Start both stacks and understand what each container does.",
        (
            LabStep("lab1.certs", "Generate TLS certificates (only needed once).", "certificates"),
            LabStep("lab1.start", "Start the ids project, then the siem project.", "services"),
            LabStep("lab1.health", "Wait until every node on the Global Visualization map is green. "
                    "Find the reverse proxy, both eshops and Suricata.", "health"),
            LabStep("lab1.glossary", "Read the glossary entries for Honeypot, Reverse proxy "
                    "and SIEM.", "learn"),
        )),
    Lab("lab2", "Lab 2: Watch a normal visitor",
        "See what a clean request looks like before attacking anything.",
        (
            LabStep("lab2.reset", "On Attack Simulation, press 'Reset local score + cookies'.", "patterns"),
            LabStep("lab2.browse", "Browse the shop in the embedded browser for a minute.", "patterns"),
            LabStep("lab2.cards", "On the Pattern analyzer tab, confirm the requests route to "
                    "PRODUCTION with a low score.", "patterns"),
        )),
    Lab("lab3", "Lab 3: Fire an SQL injection",
        "Trigger detection and follow one attack from request to routing decision.",
        (
            LabStep("lab3.read", "Select CVE-2024-27956 (WP Automatic SQLi) and press "
                    "'What is this?' to read how it works.", "patterns"),
            LabStep("lab3.run", "Press 'Run pattern (curl)'.", "patterns"),
            LabStep("lab3.signals", "On the Pattern analyzer tab, find each signal and its points. "
                    "Hover a card for an explanation.", "patterns"),
            LabStep("lab3.route", "Confirm the final decision is HONEYPOT and note the score.",
                    "patterns"),
            LabStep("lab3.redis", "Find your session and its stored score in the Pool State Store.", "redis"),
        )),
    Lab("lab4", "Lab 4: Investigate in the SIEM",
        "Find the same attack as an analyst would, in Kibana and the raw logs.",
        (
            LabStep("lab4.kibana", "Open Attack Patterns and find the CVE under Top CVEs "
                    "Detected.", "kibana"),
            LabStep("lab4.discover", "Open Discover and filter to your IP address.", "kibana"),
            LabStep("lab4.logs", "Search the raw logs for the CVE ID.", "log_search"),
        )),
    Lab("lab5", "Lab 5: Tune the detector",
        "See how configuration changes who gets flagged.",
        (
            LabStep("lab5.unpoison", "Press 'Unpoison host IP' to start clean.", "patterns"),
            LabStep("lab5.run", "Select CVE-2024-27956, press 'Run pattern (browser)' and "
                    "confirm the browser's session is routed to HONEYPOT.", "patterns"),
            LabStep("lab5.decay", "Wait five minutes (one half-life: 100 decays to 50, under the "
                    "threshold), browse the shop again and watch the route.", "patterns"),
            LabStep("lab5.nodecay", "Set THREAT_DECAY_ENABLED=false in the edge .env, restart ids "
                    "and repeat. What changed, and why does never forgiving raise false "
                    "positives?", "settings"),
            LabStep("lab5.restore", "Put the setting back and restart ids.", "settings"),
        )),
    Lab("lab6", "Lab 6: Divert sessions and watch the pools",
        "See per-session segmentation and pool autoscaling: each adversary gets a decoy of its own.",
        (
            LabStep("lab6.state", "Open Pool Scaling and note how many pools exist now and the "
                    "memory, CPU and pool-count budget.", "pool_scaling"),
            LabStep("lab6.open", "On Segmentation Validation, press 'Open shop in all' so each "
                    "frame starts its own session.", "pool_test"),
            LabStep("lab6.attack", "Press 'Attack from all', then 'Refresh pool state', and confirm "
                    "each session is diverted to a different pool number.", "pool_test"),
            LabStep("lab6.scale", "Back on Pool Scaling, read the event log: find a pool being built "
                    "and handed over, and note which limit stops scaling once the budget is hit.",
                    "pool_scaling"),
            LabStep("lab6.glossary", "Read the glossary entries for Honeypot pool, Per-session "
                    "segmentation and Pool autoscaling.", "learn"),
        )),
    Lab("lab7", "Lab 7: Switch the honeypot layer",
        "Compare deceiving the whole backend with deceiving only the database.",
        (
            LabStep("lab7.note", "On Services, note the current Honeypot layer (WordPress proxy "
                    "level by default).", "services"),
            LabStep("lab7.base", "Run CVE-2024-27956 on Attack Simulation and confirm the session "
                    "is diverted to a separate honeypot eshop pool.", "patterns"),
            LabStep("lab7.switch", "Set the Honeypot layer to Database proxy level and restart the "
                    "ids project.", "services"),
            LabStep("lab7.compare", "Re-run the same pattern. There are no honeypot eshop pools now: "
                    "one eshop serves everyone and only the database is switched. Which attack "
                    "types can this layer still isolate, and which can it not?", "patterns"),
            LabStep("lab7.restore", "Set the Honeypot layer back to WordPress proxy level and "
                    "restart ids.", "services"),
        )),
    Lab("lab8", "Lab 8: Derive a device signature",
        "Watch a browser characteristic become a consent-gated, one-way signature that re-recognises "
        "a returning visitor without storing anything about them.",
        (
            LabStep("lab8.open", "Open Signature Simulation and read what each half of the flow "
                    "does.", "signature_sim"),
            LabStep("lab8.derive", "Resize the visitor window, press 'Agree & derive signature', and "
                    "note the hex signature the proxy logged.", "signature_sim"),
            LabStep("lab8.change", "Resize to a clearly different size and derive again -- the "
                    "signature changes.", "signature_sim"),
            LabStep("lab8.return", "Resize back to the first size and derive once more: the original "
                    "signature returns. That is how a visitor is re-recognised after clearing "
                    "cookies.", "signature_sim"),
            LabStep("lab8.glossary", "Read the glossary entry for Device signature (GDPR signature) "
                    "and note why only a one-way hash is ever stored.", "learn"),
        )),
]


def all_step_ids() -> list[str]:
    return [s.id for lab in LABS for s in lab.steps]


def lab_progress(lab: Lab, completed: set[str] | list[str]) -> tuple[int, int]:
    """(done, total) for one lab given the completed step ids."""
    done_ids = set(completed)
    return sum(1 for s in lab.steps if s.id in done_ids), len(lab.steps)
