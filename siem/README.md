# elk-dockerized
Repository contains ELK secure installation in docker environment

**This is one half of a two-host system.** The other half is `ids/` (the honeypot itself) at the repository root — see `../ARCHITECTURE.md` for why they're split across two hosts, the full data-flow diagram, and how to run both together on a single host for testing. See `../docs/MANUAL.md` §6 for how the shipped log data is structured once it lands here (index naming, what's in each log type).

## Usage
1. Run `./gen_elk_certs.sh` in `certs/root-ca/` — creates a CA, signs certs for `es01`/`kibana`/`vector`/`vector-agent`, and copies them into each service's own `certs/` directory. The `vector-agent` client certificate (under `vector/certs/vector-agent/`) needs to be copied to the *other* host's `ids/vector/certs/` directory before its Vector shipper can connect — see `../ARCHITECTURE.md` for the exact steps, both for a real two-host deployment and for single-host testing.
2. Run `docker compose up -d` (from `docker/`). First boot pulls the Elasticsearch and Kibana images, which are large — expect several minutes.
3. Enjoy or Cry&Debug

## Known-fixed issues (see `../ARCHITECTURE.md` for full detail)
- The `vector` service's Docker healthcheck used to always report `unhealthy` regardless of whether Vector itself was actually fine — it invoked `wget`, which isn't in the `timberio/vector:*-debian` image. Fixed to use `bash`'s `/dev/tcp` instead.
- The `vector` service's TLS certificate used to only validate for a client connecting via the literal hostname `vector` — which broke both single-host testing (`host.docker.internal`) and the real two-host deployment's own default `VECTOR_HOST` (a raw IP). Fixed by adding a proper Subject Alternative Name list to `certs/root-ca/gen_elk_certs.sh`'s `vector` cert generation.
- The Elasticsearch sink's index name (`vector/vector.yaml`) used to be the literal placeholder `hello-world-index` — every log type and every day landed in one single index. Fixed to `honeypot-{log_type}-%Y.%m.%d`, using the `log_type` field the edge shipper already tags every event with.
- `nginx_security` log lines (the ones carrying `route`/`risk_score`/`suspicious` — the actually interesting fields) were shipped as one opaque raw-text `message` string, unqueryable in Kibana. Added a VRL parse step to `vector/vector.yaml`'s `enrich` transform to extract real, correctly-typed fields.

## Dashboards
Six Kibana dashboards, each answering a different question, plus the `honeypot-*` data view (time field `timestamp`) they're built on, are committed as a Saved Objects export at `kibana/saved_objects/honeypot-dashboards.ndjson` and re-imported by the `kibana_dashboards_setup` service on every `docker compose up` (`overwrite=true`, so it's idempotent and self-healing). Kibana's default landing page is set to the Web Traffic dashboard by that same service.

- **IDS Alerts (Suricata)**: what the network IDS saw: severity over time, categories, protocols, targeted ports, top signatures and source IPs.
- **Web Traffic & Threat Overview**: what was requested and how it was answered; the Top URIs table marks every URI `attack_pattern` or `safe`.
- **Threat Decisions & Decay**: why each request went where it went: its own score vs. the score carried over from the session after decay, against the honeypot threshold; decay states (decaying / permaflagged), offenses and routing reasons.
- **Session Analysis**: per-session volume, duration, peak score, offenses and sophistication class.
- **Attack Patterns**: which attack patterns and CVEs requests matched, the URIs behind them, security events, CVEs, honeytokens and top attacking IPs.
- **Threat Intelligence**: the same events as threat intel — per-IP IOC list, MITRE ATT&CK techniques and kill-chain stage reached, attack tools fingerprinted, CVEs targeted, and an exportable flagged-event feed.

The decision fields (`request_score`, `decayed_score`, `carried_score`, `offenses`, `decay_state`, `uri_class`, `patterns`, `route_reason`) come from the reverse proxy's `security` access log (`log_format security` in nginx.conf, filled by `router_rules.decision_trace()`) and are parsed in `vector/vector.yaml`. To change a panel, edit `kibana/build_dashboards.py` and run `python3 kibana/build_dashboards.py --ndjson` to rewrite the committed NDJSON (no Kibana needed), or run it without `--ndjson` to push the objects to a live Kibana.

## Alerts
Six **active Kibana alerting rules** fire when the honeypot sees something notable, so a diversion or a hit shows up in Kibana's own Rules/Alerts UI (and is queryable), not only on a dashboard you have to be looking at. They are committed one JSON body per rule under `kibana/saved_objects/alert_rules/` and seeded by the `kibana_alerts_setup` service on every `docker compose up` (delete-then-create by stable id, so the committed definition always wins — the same self-healing idempotence the dashboards' `overwrite=true` import has). The dashboard app's SIEM Analytics page links straight to the Rules list ("Alerts (Rules)" button).

- **session diverted to the decoy** — `log_type:nginx_security AND route:honeypot`
- **high-severity Suricata IDS alert** — `log_type:suricata AND event_type:alert AND alert.severity <= 2`
- **planted honeytoken was used** — `security_event_type:honeytoken_used`
- **session compromise detected** — `security_event_type:session_compromised`
- **CVE exploitation attempt** — a request tagged with a `vulnerability.id`
- **offensive scanning tool detected** — `client_tool_class:offensive_scanner`

Each is a built-in **Elasticsearch-query rule** (`.es-query`) over `honeypot-*`, available on the Basic (free) license and needing no connector: it runs on a 1-minute schedule and raises an alert whenever its query matches within the look-back window. The rules ship with no actions (firing is visible in Kibana without an external notifier — the dashboard app's OS notifications in `dashboard/ui/main_window.py` cover operator alerting); add email/webhook/Slack actions to a rule in Kibana if you want delivery. To change a rule, edit `kibana/build_alert_rules.py` and run `python3 kibana/build_alert_rules.py --json` to rewrite the committed files (no Kibana needed), or run it without `--json` to create-or-replace them in a live Kibana.

## Known pre-existing issues, not fixed
- **Cert/key files in `certs/`, `elasticsearch/certs/`, `kibana/certs/`, `vector/certs/` (including the CA's own private key, `certs/root-ca/certs/rootCA.key`) are tracked in git.** Discovered while regenerating them this session — not introduced by this session's changes, but worth deciding whether to `.gitignore` them and scrub git history.
- **`.env`'s `ELASTIC_PASSWORD`/`KIBANA_PASSWORD`/`VECTOR_PASSWORD` are checked-in placeholder values** (`changemepls` etc.), same category of issue as above.
- **`honeypot-docker-*` index silently fails to ingest anything**: Elasticsearch rejects every `docker_logs`-sourced document with `illegal_argument_exception: can't merge a non object mapping [label.com.docker.compose.project] with an object mapping` — a field-mapping conflict from Docker container labels, present since before this session (the index always showed 0 documents). Not investigated further; out of scope for the nginx/Suricata dashboard work this pass covered.
