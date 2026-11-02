# Architecture: two hosts, two independent `docker compose` projects

This repository contains **two separate systems**, each with its own `docker-compose.yml`, meant to run on **two separate hosts**:

| | Directory | Role | Compose project |
|---|---|---|---|
| **Edge host** | `ids/` | The honeypot itself: reverse proxy, WordPress (production + 3 honeypot pools), Redis, Suricata, a local Vector log shipper | `honeypot-ids-system-v1` |
| **SIEM host** | `siem/` | Log storage/analysis: Elasticsearch, Kibana, a Vector aggregator that receives the edge host's logs | (directory-named, no explicit project name) |

This isn't an accident of two people building unrelated things — it's a deliberate security boundary. The edge host is the one an adversary can realistically get code execution on (that's the whole point of a honeypot); the SIEM host holds the actual telemetry about what adversaries did. Merging them into one `docker-compose.yml` on one host would mean a honeypot compromise is one Docker-socket-mount or network-hop away from the incident data describing that same compromise. Keeping them on separate hosts, connected by one narrow, authenticated, outbound-only channel (the edge Vector shipper pushing to the SIEM Vector aggregator over mTLS on port 6000), is what makes the boundary real rather than nominal.

**Until this file existed**, nothing explained this relationship anywhere except two lines in `docs/MANUAL.md`'s Run section — a reader landing in either directory alone (which is exactly how you *would* land in one of them, since they're separate compose projects with no shared files) had no way to discover the other half existed. `architecture.canvas`'s `n24-callout` node flagged this explicitly as an undocumented cross-project relationship; this file is that fix.

## Data flow

```
┌─────────────────────────── Edge host (ids/) ───────────────────────────┐
│                                                                                      │
│  user/customer → reverse_proxy (nginx+Lua) → production_eshop / honeypot pools  │
│                            │                              │                         │
│                     nginx access/error/security logs      │                         │
│                            │                        Suricata (IDS) → eve.json/fast.log
│                            │                              │                         │
│                            ▼                              ▼                         │
│                     ┌──────────────────────────────────────────┐                    │
│                     │  vector_outbound (shipper, profile: elk)  │                   │
│                     │  tails: docker logs, nginx logs,          │                   │
│                     │  suricata eve.json/fast.log, redis logs   │                   │
│                     └──────────────────┬─────────────────────┘                      │
└────────────────────────────────────────┼────────────────────────────────────────────┘
                                          │ mTLS, port 6000
                                          │ (client cert: vector-agent.crt/key)
                                          ▼
┌────────────────────── SIEM host (siem/) ─────────────┐
│                     ┌──────────────────────────────────────────┐                    │
│                     │  vector_inbound (aggregator)               │                   │
│                     │  verifies client cert, tags/enriches,     │                   │
│                     │  writes to honeypot-{log_type}-%Y.%m.%d   │                   │
│                     └──────────────────┬─────────────────────┘                      │
│                                        ▼                                            │
│                                 Elasticsearch (es01)                                │
│                                        │                                            │
│                                        ▼                                            │
│                                    Kibana                                           │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

Every log event picked up by the edge shipper is tagged with `log_type` (`docker`, `nginx_access`, `nginx_error`, `nginx_security`, `suricata`, `suricata_fast`, `redis`) before it ever leaves the edge host; the aggregator's Elasticsearch sink uses that field to route each event into its own daily index (`honeypot-nginx_access-2026.08.05`, `honeypot-suricata-2026.08.05`, etc.) — fixed this session; it used to write everything into a single literal `hello-world-index` placeholder that was never replaced with real index logic.

Beyond those logs, the shipper also carries the **metrics pillar** into the same Elasticsearch: Vector's own `internal_metrics` (pipeline health — events in/out, discarded/errored counts, buffer fill, send failures) from both the edge shipper and the SIEM aggregator land in `honeypot-vector_metrics-*` (told apart by `vector_role`), and the edge host's `host_metrics` (CPU/memory/disk/network, read from the host's `/proc`/`/sys` bind-mounted read-only into `vector_outbound`) land in `honeypot-host_metrics-*`. Both are flattened from metric events to log events with `metric_to_log` so the log-only Elasticsearch sink accepts them, and `log_type`-tagged like everything else so the existing `honeypot-*` data view picks them up with no extra config. (The request-level **trace pillar** — the proxy's per-request score/decay/route/pattern decision trace — is already carried on `honeypot-nginx_security-*`/`honeypot-nginx_error-*`.)

## Edge URL policy (whitelist + honeypot targets)

The dashboard has two pages for the edge's URL policy: **URL Whitelist**
and **Honeypot Targets**.

- **URL Whitelist** lists the legitimate shop paths. A path that is not on
  it adds an `unlisted_endpoint` score. It never subtracts.
- **Honeypot Targets** lists the CVE patterns and vulnerable plugin paths,
  each one enabled or disabled. A target hit either diverts at once with
  scoring bypassed, or adds a score and lets the threshold decide.

Both pages push one JSON document to the edge's Redis
(`honeypot_edge_policy`). `init_worker.lua` mirrors it into a shared dict,
and the router and pattern analyzer read it from there (`lua/edge_policy.lua`).
If no document exists, the edge keeps its built-in behaviour. See
`patterns/README.md`, "Edge policy".

## Honeypot pool assignment (WordPress proxy level)

Each user IP gets a honeypot pool (`honeypot_eshop_N` + `honeypot_database_N`) to itself:

1. `pool_router.lua` asks Redis for a **free ready pool** with one atomic `EVAL`; the pool is removed from `honeypot_pool:free` and the IP recorded as its owner, so two users can't be handed the same pool. The IP keeps that pool for 24 h (`honeypot_pool_ip:<IP>`).
2. Every assignment also queues a wake-up on `honeypot_pool:provision`. The `pool_manager` service keeps `POOL_SPARES` unowned pools ready, building more pairs (pool 4, 5, …, each an eshop container plus its own database seeded from production) through the Docker API. Before a new pool is registered as ready, production's current pages, posts and products are mirrored into its database (`replicate_content_to_honeypot.sh --once N`), so it never serves the install-time snapshot's catalog and a diverted visitor's cart (rebuilt from product IDs) is not lost. Pools 1-3 come from `docker-compose.yml`; `pool_manager` only adopts them. A pool left half-built by a `pool_manager` restart is removed when it starts again.
3. **Scaling with the sessions.** If no pool is free while growth is still allowed, the new session **borrows a ready pool round-robin** and joins `honeypot_pool:waiting`. `pool_manager` builds one pool per waiting session (`POOL_PARALLEL_BUILDS` at a time) and, as each becomes healthy, atomically moves the longest-waiting session onto it. The router caches a waiting session's pool for only a few seconds, so the move takes effect on its next requests; the cart follows in its cookie. In the **database layer** a build no longer dumps production each time (~44 s): `pool_manager` clones + scrubs one honeypot database into a **template** data directory once (pre-built at start-up, rebuilt when older than `POOL_TEMPLATE_TTL_SECONDS`, `0` = never), shuts its MySQL down cleanly, and each new pool is built by copying that directory and starting MySQL on it — ready in roughly MySQL's start time. `POOL_TEMPLATE=0` restores the per-pool clone; while the template is still (re)building, pools clone from production directly. The **WordPress layer** uses the same **template** mechanism for its heavier build: the files + database volume pair is seeded once — production files, a database clone, migrations and the one-time WordPress install (`wp-cli`, ~50 s) — keeping production's baseline DB password; each new pool then copies both volumes, rotates the DB password to its own, and syncs the current catalog, so the slow `wp-cli` install is skipped per pool. `POOL_TEMPLATE=0`, or a template still (re)building, falls back to the full from-scratch build.
4. **Resource limit.** Scaling stops once the next pool would exceed the budget for all pools together (`POOL_MAX_MEMORY_MB` / `POOL_MAX_CPUS`, counted from the containers' limits: 1536 MB / 1.5 CPUs per WordPress pool, 512 MB / 0.5 CPUs per database-layer pool, pools 1-3 included) or `POOL_MAX`. `pool_manager` then sets `honeypot_pool:capped`, the sessions still waiting keep the pool they borrowed, and every further session **reuses a ready pool round-robin**. This is the only case where two users keep sharing a pool.

5. **Scale-down.** `pool_router.lua` stamps each pool's last request in `honeypot_pool:last_seen`. A bound session's requests always follow its Redis assignment, so the moves `pool_manager` makes take effect; the copy kept in the session only records it. Once no request has reached a pool for `POOL_IDLE_TIMEOUT_SECONDS` (default 1800, 0 = never, at least 600 because nginx caches a session's pool for 300 s), `pool_manager` drops its users' assignments. A returning user is assigned afresh. Then it removes runtime pools, used ones first, until only `POOL_SPARES` unowned pools are left, which frees their memory, CPU and volumes. Pools 1-3 are only freed. A client can force this right away for named sessions (`honeypot_pool:release` + `honeypot_pool:scaledown_now`); the dashboard's pool test does that at the end of its report. A forced scale-down that finds a pool still being built waits for it (starting no new spares meanwhile) and removes it too if it is not needed, before it reports `scaledown_done`.

**Measuring it.** `pool_manager` logs every build (with per-phase timings), every hand-over (with how long the session waited) and every resource-limit change to `honeypot_pool:events`. The dashboard's Pool test page runs 3–10 browser windows. Of those, the last *N* (the "wait for pools" counter) attack only after the test has asked for that many pools in advance (`honeypot_pool:reserve`) and they are ready, so these windows never borrow a pool. Its PDF report draws the run as a timeline. It also covers each pool's build time by phase, how long each window borrowed a pool, page-load latency on production, own, borrowed and shared pools, and both round-robin cases (not scaled up yet / resource limit reached). The run ends with a forced scale-down: the report shows the pools removed and how long each took, plus memory, CPU and container counts before and after, all on a resource-use chart sampled from `docker stats` over the whole run.

**Low host resources.** On top of the budget, `pool_manager` builds only while the host has room: free memory above `POOL_MIN_FREE_MEM_MB`, load per CPU below `POOL_MAX_LOAD_PER_CPU`, and disk above `POOL_MIN_FREE_DISK_GB`. Otherwise it sets `honeypot_pool:capped` the same way and new users reuse existing pools round-robin (reuse is exclusive when a pool has gone idle, shared otherwise). When a pool's users have all expired, `pool_manager` destroys it and builds a clean spare if the host has room (`POOL_RECYCLE_IDLE`), or hands it to the next user as it is.

Before this change the router did `INCR counter % 3`, so the 4th user already shared pool 1. `lua/tests/test_pool_assignment.lua` runs the real assignment script against an in-memory Redis and checks the exclusive, pending (scale-up) and capped reuse paths; `images/pool_manager/test_manager_reconcile.py` runs the hand-off against a real Redis. `pool_manager` mounts the Docker socket, so it sits only on `session_network` and publishes no ports.

## Running for real (two hosts)

1. **SIEM host**: `cd siem/certs/root-ca && ./gen_elk_certs.sh` (generates a CA + certs for `es01`/`kibana`/`vector` (the cert identity issued to the `vector_inbound` container), and a `vector-agent` client cert bundle under `../../vector/certs/vector-agent/`), then `cd ../../docker && docker compose up -d`.
2. Copy `siem/vector/certs/vector-agent/{ca.crt,vector-agent.crt,vector-agent.key}` to the **edge host**'s `ids/vector/certs/` (this is a manual step by design — the client cert should never live in the same place as the CA's private key, and the two hosts don't share a filesystem).
3. **Edge host**: set `VECTOR_HOST` to the SIEM host's real address (defaults to a placeholder IP, `147.175.151.193`, in `ids/vector/vector.yaml` — override it via `.env` or the environment) and bring the `elk` profile up: `docker compose --profile elk up -d vector_outbound`.
4. If the SIEM host's real address differs from what's in `VECTOR_SAN` in `gen_elk_certs.sh` (currently `vector_inbound`, `localhost`, `host.docker.internal`, `127.0.0.1`, `147.175.151.193`), add it there and re-run the script — the aggregator's server certificate needs the address the edge shipper actually connects through as a Subject Alternative Name, or TLS hostname verification will fail (this bit single-host testing below until the SAN list was added — see that section for the exact error).

## Running both on one host (testing / development)

The two compose projects don't need to be merged to test them together — they already don't conflict on ports (`80`/`443` for the edge stack vs. `9200`/`5601`/`6000` for the SIEM stack), container names, or networks (each project gets its own bridge network; nothing is shared by default). The only thing standing between "two independent stacks happen to be running on the same machine" and "the edge shipper is actually delivering logs to the SIEM stack" is that they're on different Docker networks with no way to resolve each other by container name. Verified working this session:

1. Bring up the SIEM stack: `cd siem/certs/root-ca && ./gen_elk_certs.sh && cd ../../docker && docker compose up -d`. Wait for `es01`, `kibana`, and `vector_inbound` to all report healthy (`docker ps` — first boot pulls the Elasticsearch and Kibana images, which are large; expect several minutes).
2. Copy the `vector-agent` client cert bundle to the edge host's cert directory (same as production step 2 above — on one host this is just a local `cp`, not a cross-host transfer):
   ```
   cp siem/vector/certs/vector-agent/{ca.crt,vector-agent.crt,vector-agent.key} ids/vector/certs/
   ```
3. Bring up the edge stack as normal (`cd ids && docker compose up -d`), then start the Vector shipper pointed at the SIEM stack via the host's own network stack instead of a remote IP:
   ```
   VECTOR_HOST=host.docker.internal VECTOR_PORT=6000 docker compose --profile elk up -d vector_outbound
   ```
   `ids/docker-compose.yml`'s `vector_outbound` service has `extra_hosts: ["host.docker.internal:host-gateway"]` specifically for this — it's what lets the edge shipper container reach a port the SIEM stack published on the same physical/VM host, without joining the two compose projects onto a shared Docker network (which would be a bigger, more invasive change purely for a dev/test convenience). This has zero effect on the real two-host deployment above: `host.docker.internal` is just an unused DNS alias there.
4. Confirm data is flowing: `docker compose logs vector_outbound` on the edge side should show `Healthcheck passed.` (not "Retrying after error" / TLS failures); on the SIEM side, `docker exec es01 curl -s --cacert /usr/share/elasticsearch/config/certs/ca/ca.crt -u elastic:<password> "https://es01:9200/_cat/indices?v"` should show real, growing `honeypot-*` indices with non-zero `docs.count`.

### Two real bugs found getting this far, both fixed

- **Vector aggregator's own healthcheck was permanently broken** (`docker ps` always showed `unhealthy` even though Vector itself was fine): the healthcheck used `wget`, which doesn't exist in the `timberio/vector:*-debian` image (confirmed via `docker inspect`'s health log: `exec: "wget": executable file not found in $PATH`). Fixed by using `bash`'s `/dev/tcp` instead (confirmed present in the image; confirmed `/bin/sh` in this image is `dash`, which does *not* support `/dev/tcp`, so the fix explicitly invokes `bash -c`, not `CMD-SHELL`, which runs via `/bin/sh`).
- **TLS hostname verification failure when the edge shipper connects via anything other than the literal string `"vector"`**: the aggregator's server certificate only had a bare CN, no Subject Alternative Names, so it only validated for a client connecting via the exact hostname `vector` — which neither `host.docker.internal` (single-host testing) nor the real deployment's default IP address `147.175.151.193` (two-host production — this was silently broken there too, not just in the testing path) ever matched. Fixed by adding a proper SAN list to the `vector` aggregator's certificate (`DNS:vector, DNS:localhost, DNS:host.docker.internal, IP:127.0.0.1, IP:147.175.151.193`) in `gen_elk_certs.sh`, rather than disabling hostname verification — this is a private CA minted specifically for this one shipper↔aggregator pairing, so CA-chain trust is already the real security boundary, and there was no reason to give up hostname checking too when just listing the legitimate hostnames fixes it properly.
- **The Elasticsearch sink's index name was the literal placeholder `hello-world-index`** (`vector/vector.yaml`) — every log type from every day landed in one single, non-rotating, untyped index. Fixed to `honeypot-{{ log_type }}-%Y.%m.%d`, using the `log_type` field the edge shipper already tags every event with but which the aggregator was never actually using.

## Dashboards

`nginx_security` log lines (see `ids/reverse_proxy_enhanced/nginx.conf`'s `log_format security`) carry the most operationally interesting fields for a honeypot — `route` (production vs. honeypot), `risk_score`, `suspicious` — but the aggregator used to ship the whole line as one opaque `message` string, making none of it queryable. Fixed by adding a VRL regex parse step to `vector/vector.yaml`'s `enrich` transform (splits the shared nginx combined-log-format prefix from the `security`-specific suffix, and type-casts `status`/`body_bytes_sent`/`risk_score` to numbers and `suspicious` to a boolean rather than leaving them as strings).

Two Kibana dashboards were built on top of this (via the Saved Objects API — `POST /api/saved_objects/visualization` and `.../dashboard`, classic visualization type for schema stability across versions, referencing the single `honeypot-*` data view with a per-panel `log_type:` query filter rather than separate per-index data views):

- **"Honeypot: IDS Alerts (Suricata)"**: total alert count, alerts over time, alerts by category, alerts by severity, top signatures, top source IPs.
- **"Honeypot: Web Traffic & Threat Overview"**: total requests, requests over time split by route, production-vs-honeypot routing pie, risk-score histogram, top URIs, top User-Agents, top IPs flagged suspicious.

Both verified against real data generated by exercising the edge stack (mixed clean/scanner/SQLi-shaped traffic), not just checked for successful object creation — the underlying Elasticsearch aggregations were queried directly and confirmed to return real, non-empty, correctly-bucketed results before being wired into panels.

**Bug caught during that verification**: the `honeypot-*` data view spans every shipped log type by wildcard (docker, suricata, nginx_access, nginx_security, nginx_error, redis each land in their own `honeypot-<log_type>-YYYY.MM.DD` index, but one data view covers all of them). A panel with no explicit filter doesn't implicitly scope itself to "the index this dashboard is about" — "Total Requests" with no query counted 21,207 docs across every log type where only 166 were real nginx_security requests, and `event_type:"alert"` alone (no `log_type` filter) picked up 44 cross-type matches vs. 41 real Suricata alerts (a docker-sourced log line's message text free-text-matched "alert" too, since `event_type` is a `text` field, not a `keyword`-only one). Fixed by giving every one of the 13 panels an explicit `log_type:"..."` term in its query — see `siem/kibana/build_dashboards.py`'s `_IDS_Q`/`_WEB_Q`.

**Persistence**: both dashboards, their data view, and all 13 panel visualizations are committed as a Saved Objects NDJSON export (`siem/kibana/saved_objects/honeypot-dashboards.ndjson`) and re-imported automatically (`overwrite=true`, idempotent) by the `kibana_dashboards_setup` compose service on every `docker compose up` — a `down -v` purge no longer loses them. That service also sets Kibana's default landing page (`defaultRoute`) to the Web Traffic dashboard; that setting is applied via a direct API call rather than shipped in the NDJSON, since Kibana stores it as a `config` saved object keyed by the exact running version string, so an exported copy would silently stop applying the moment `STACK_VERSION` changes. To change a panel, edit it live in Kibana then re-run `siem/kibana/build_dashboards.py` (rebuilds all 16 objects from source) and re-export, or hand-edit the NDJSON directly for a small change.

**Not built**: session-analysis and attack-pattern dashboards (grouping by session, sophistication classification, user dwell time) — that data currently lives only in Redis (`session:*`, see `docs/MANUAL.md` §3.5), not Elasticsearch. Shipping it would need either a new Vector source reading from Redis, or the Lua pipeline itself emitting session-summary events somewhere Vector can tail — neither exists yet.

## See also

- `docs/MANUAL.md` §1 (Architecture Overview) and §6 (SIEM/ELK Integration) for the edge host's full detail.
- `siem/README.md` for the SIEM project's own (minimal) setup notes.
- `architecture.canvas` (open the repo root as an Obsidian vault) — `g-edge`/`g-siem` groups and the nodes around them for the component-level diagram this file's data-flow section summarizes in prose.
