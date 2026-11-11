# Check kinds and the assertion grammar

Reference for writing catalogue checks. Every check names a `kind` (which observes) and a
list of assertions (which judge). The assertion grammar is the same for every kind; see
the docstring of `src/tgx_monitor/assertions.py` for the operators:

`eq ne gt gte lt lte in not_in has lacks matches not_matches contains not_contains
len_eq len_gte len_lte exists absent eq_path within_pct_of_path max_age max_drop_pct monotonic`,
each with optional `warn: true` (amber, never fails) and `label`.

The two kinds written first, `http` and `sparql`, are documented in their module docstrings
(`src/tgx_monitor/kinds/web.py`, `src/tgx_monitor/kinds/sparql.py`).


---

# Network: tls, dns

## kind `tls` (src/tgx_monitor/kinds/net.py, `TlsKind`)

via: `public | tgx1 | tgx2`. For tgx1/tgx2 it connects to `http.NODES[via]`. For public it uses public DNS. SNI and hostname verification always use `host`.

**request**
- `host` (required)
- `port` (default 443)

Timeout: the check's `timeout`. Each blocking handshake runs in `asyncio.to_thread`, with the socket timeout set to `timeout_s` and an outer `wait_for(timeout_s+2)`.

**Flow**
1. It first tries a verifying handshake using the system trust store, through `_verifying_context()`.
2. If that fails on an `ssl.SSLError` (bad certificate or another TLS problem), it runs a second handshake with CERT_NONE to get the leaf certificate.
3. The leaf certificate (DER) is parsed with `cryptography.x509`, so issuer and expiry are still reported when the certificate is invalid.

**Errors and unknowns**
- These give `Observation.error`: connection refused, timeout, a DNS failure, or a handshake that fails even without verification.
- A certificate that cannot be parsed gives `unknown`.
- Calls: `Call(method="TLS" | "TLS (no verify)", url="tls://host:port", via)`.
- `metrics={"days_left": ...}`.
- On a verify failure, `evidence` holds the verify error, issuer, SAN and not_after.

**values**
- `verified` (bool), `verify_error` (str, e.g. "certificate: self-signed certificate")
- `issuer_cn`, `issuer_o`, `subject_cn`
- `san` (list of DNS names and IP SANs)
- `covers_host` (a SAN matches host, with RFC 6125 wildcards)
- `not_before`, `not_after` (ISO UTC), `days_left` (float, from `ctx.now()`, negative once expired)
- `is_traefik_default` ("TRAEFIK DEFAULT CERT" appears in the issuer CN)
- `fingerprint_sha256` (hex), so a compare kind can check that both nodes serve the same certificate
- `chain` (subject CNs of the presented chain; leaf first)
- `tls_version`, `cipher`, `peer_ip` (the IP actually connected to; for public, this is where DNS sent us)
- `latency_ms` (time of the first handshake)

Live-verified on 2026-11-11:
- aopwiki.rdf: verified, issuer YR2/Let's Encrypt, days_left about 32.5, same fingerprint on tgx1 and tgx2.
- www.nsdra.org on tgx1: verified=false, is_traefik_default=true.

```yaml
- id: tls-aopwiki
  kind: tls
  every: 1d
  via: [tgx1, tgx2]
  describe: Both nodes serve a trusted Let's Encrypt certificate for the name, not Traefik's default, with time to spare.
  request: {host: aopwiki.rdf.bigcat-bioinformatics.org}
  assert:
    - {that: verified, eq: true}
    - {that: is_traefik_default, eq: false}
    - {that: san, contains: aopwiki-rdf.vhp4safety.nl}
    - {that: days_left, gte: 21, warn: true}
    - {that: days_left, gte: 10}
```

## kind `dns` (`DnsKind`)

via: `public` only. It uses the dnspython async resolver. The query sets RD|AD so validating resolvers report the AD bit.

**request**
- `name` (required)
- `type`: `A` (default) | `AAAA` | `CNAME` | `NS` | `TXT` | `MX`
- `resolvers`: list of IPs (default: the system resolver, keyed `system`)
- `wildcard_probe`: `false` (default) | `true` (probe a random label `zz-tgxmon-probe-<hex>` under the parent of `name`) | `"<zone>"` (probe under that zone, e.g. for `name: vhp4safety.nl`)

`validate_request` also checks that `type` is in the allowed set and that each resolver is an IP.

**values**
- `answers` (sorted strings, trailing dots stripped):
  - A/AAAA: the addresses
  - CNAME/NS: the targets
  - MX: `"10 mail.x"`
  - TXT: the joined strings
- `first` (or null)
- `rcode` (`NOERROR` | `NXDOMAIN`), `nxdomain` (bool), `ad` (bool)
- `per_resolver` `{ip|system: answers or null}`, `resolver_errors` `{ip: reason}`
- `consistent`: all resolvers that answered agree on answers and NXDOMAIN
- `cname_chain` (CNAME targets in order), `canonical_name`
- `node`: only for type A. It is `tgx1` | `tgx2` | `other` | `none` for the first answer.
- With a wildcard probe: `wildcard_zone`, `wildcard_answers`, `wildcard` (bool, or null with `wildcard_error` if the probe got no answer)

**Which resolver supplies the values:** `answers`, `first`, `rcode` and the rest come from the first resolver that answered.

**NXDOMAIN, timeout and SERVFAIL**
- NXDOMAIN is a value (`nxdomain=true`), not an error.
- A resolver timeout or SERVFAIL (NoNameservers) counts against that resolver only.
- If no resolver answers, the observation is `unknown`.
- Calls: `Call(method="DNS A", url="dns://1.1.1.1/<name>", via="public", note=rcode or reason)`.

Live-verified on 2026-11-11:
- aopwiki.rdf gives node=tgx1, consistent via 1.1.1.1 and 9.9.9.9, wildcard=false under rdf.bigcat-bioinformatics.org.
- A probe under vhp4safety.nl gives wildcard=true (GitHub Pages, 185.199.109.153).
- www.r-odaf.nl gives cname_chain [r-odaf.nl].
- vhp4safety.nl via 1.1.1.1 gives ad=true.

```yaml
- id: dns-aopwiki
  kind: dns
  every: 1h
  describe: The name resolves to tgx1 through two public resolvers, and they agree.
  request: {name: aopwiki.rdf.bigcat-bioinformatics.org, resolvers: [1.1.1.1, 9.9.9.9]}
  assert:
    - {that: node, eq: tgx1}
    - {that: consistent, eq: true}
- id: dns-ns-vhp4safety
  kind: dns
  every: 1d
  request: {name: vhp4safety.nl, type: NS, resolvers: [1.1.1.1]}
  assert: [{that: answers, eq_path: answers, label: placeholder}, {that: answers, len_eq: 2}]
- id: dns-wildcard-vhp4safety
  kind: dns
  every: 1d
  request: {name: vhp4safety.nl, resolvers: [1.1.1.1], wildcard_probe: vhp4safety.nl}
  assert:
    - {that: wildcard, eq: true, label: "the GitHub Pages wildcard is still there (ACME trap)"}
- id: dns-dnssec-vhp4safety
  kind: dns
  every: 6h
  request: {name: vhp4safety.nl, resolvers: [1.1.1.1]}
  assert: [{that: ad, eq: true}]
```

**Other public names in net.py**
- `parse_cert(der, host, now) -> dict`: reusable, for example by a cert-file kind.
- `node_of(ip) -> "tgx1"|"tgx2"|"other"|"none"`
- `DNS_TYPES`, `PROBE_PREFIX`

**Test seams:** `_verifying_context()` and `_resolver(ip, timeout)`.

**Wiring:** none needed beyond the existing `kinds/__init__.py` import of `net`. Both kinds register on import: KINDS now holds dns, http, sparql, tls, and IMPORT_ERRORS is empty.

---

# Data and files: invariant, compare, roundtrip, shiny, browser_artifact, file_age, sqlite_backup, restore_marker

## kinds/data.py

The module adds eight kinds: `invariant`, `compare`, `roundtrip`, `shiny`, `browser_artifact`, `file_age`, `sqlite_backup` and `restore_marker`. It also has one shared source resolver. Nothing raises across the kind boundary.
- `Observation.error` (shown as failed) means the target or the roundtrip broke.
- `Observation.unknown` means a 429, a missing mount, an upstream source marked `on_error: unknown`, or a filesystem error.
- Everything else is a value that assertions judge.

### Source resolver (shared)
`async def resolve_source(spec, ctx, via, timeout=30.0) -> (value, calls: list[Call], error: str|None)`

`spec` has exactly one of these keys:
- `sparql: {endpoint, select|ask|file, value: <column>, method: GET|POST}` gives the first row's column (typed the way the sparql kind types it), or the boolean for ASK. When there is a single column, `value` can be left out.
- `http_json: {url, path}` gives a dotted path into the JSON body (`a.b.0.c`).
- `http_regex: {url, re}` gives group 1 of the first match, or group 0 if the regex has no group (multiline mode).
- `http_list: {url, re, pick: newest|previous|all}` collects every match, removes duplicates and sorts them in natural order. `newest` is the last one, `previous` the second last, `all` the whole list.
- `http_header: {url, header, method: HEAD}` gives the value of a response header.
- `const: <value>`

Keys any source can take:
- `extract: <regex>`: post-processing, group 1 applied to the value (for example `(\d{8})` pulls the release out of a dataset IRI).
- `via`: overrides the vantage point for that source only.
- `on_error: unknown`: for an upstream we do not own. If it cannot be read the check is unknown, not failed.
- The http sources also take `headers`, `params` and `method`.

How vantage points map:
- `core` and `agent:*` make their HTTP calls through public DNS.
- `tgx1`/`tgx2` pin the request to that node.

Short forms, through `normalise_source(raw, request)`:
- A bare string `q/x.rq` is a SPARQL query file run against the request-level `endpoint`.
- `{sparql: q/x.rq}` works the same way.
- A `sparql` source without its own endpoint inherits `endpoint` from the request.

Also public: `validate_source(spec, where)`, `relation(a, b)`, `as_date(v)` (ISO, yyyymmdd, or a dotted 2026.11.07; a count is never read as a date) and `derive(spec, rows)`.

### invariant
- **request:** `left`, `right` (sources), optional `endpoint`.
- **values:** `left`, `right`, `equal`. Also `diff` (right - left) when both are numbers, and `<side>_error` when a source fails.
```yaml
- id: aopwiki-dsubj-void
  kind: invariant
  every: 1d
  request:
    endpoint: https://aopwiki.rdf.bigcat-bioinformatics.org/sparql
    left: q/distinct-subjects.rq
    right: {sparql: {file: q/void-distinct-subjects.rq, value: n}}
  assert: [{that: equal, eq: true, label: "distinct subjects == VoID void:distinctSubjects"}]
```

### compare
- **request:** `left`, `right`, optional `sources: {name: <source>}`, optional `endpoint`.
- **values:**
  - `left`, `right` and each named source.
  - `equal`.
  - `relation`: one of equal | left_newer | right_newer | incomparable. It compares by date, then number, then natural string order.
  - For every value that reads as a date: `<name>_date` (ISO, so `max_age` can use it) and `<name>_age_days`.
  - `<name>_error` when a source fails.
```yaml
- id: aopwiki-version-master
  kind: compare
  every: 1h
  request:
    endpoint: https://aopwiki.rdf.bigcat-bioinformatics.org/sparql
    left: {sparql: {file: q/pav-version.rq, value: v}}
    right: {http_regex: {url: https://raw.githubusercontent.com/marvinm2/AOPWikiRDF/master/data/AOPWikiRDF-Void.ttl, re: 'pav:version\s+"([^"]+)"'}, via: public, on_error: unknown}
  assert:
    - {that: left, eq_path: right}
    - {that: left_date, max_age: {warn: 8d, crit: 15d}}
- id: wp-standby-prev
  kind: compare
  every: 6h
  via: [core]
  request:
    left: {sparql: {endpoint: "http://wikipathways_wikipathways-ep2:8890/sparql", file: q/wp-release.rq}, extract: '(\d{8})'}
    right: {http_list: {url: https://data.wikipathways.org/, re: 'href="(\d{8})/?"', pick: previous}}
    sources: {upstream: {http_list: {url: https://data.wikipathways.org/, re: 'href="(\d{8})/?"', pick: newest}}}
  assert: [{that: equal, eq: true}, {that: upstream_age_days, lt: 33, warn: true}]
```

### roundtrip
- **request:**
  - `base`: optional. Relative step URLs are appended to it.
  - `steps`: a list. Each step takes:
    - `method` (default GET).
    - `url`: `{name}` placeholders are filled from earlier captures. Placeholders are also filled in `headers`, `params` and inline `data`.
    - `headers`, `params`.
    - One of `data`, `json` or `payload`. A `payload` is a file under `catalogue/payloads/`. It is path-safe, capped at 8 MiB and sent verbatim.
    - `follow`.
    - `capture: {name: {regex: ..} | {json_path: ..} | {header: ..}}`.
  - `derive: {name: <op>}`: computed from the last step's TSV. Columns are 0-based, as in `last.tsv.0.2`. The ops:
    - `tsv_nonempty_col: N, of_rows: all|<int>`: the share of rows whose column N is filled. `N/A`, `NA`, `-`, `null` and blanks count as empty. An int `of_rows` is the number of inputs sent, for services that drop unmapped rows.
    - `tsv_distinct: N`: the sorted distinct values of column N.
    - `tsv_col: N`: column N in row order.
    - `tsv_by_key: {key, value}`: a mapping from the key column to the value column.
    - `tsv_count_by_key: {key, value, sep: ","}`: the number of items in the value column, per key.
    - `tsv_distinct_sets: {col, sep}`: how many different item sets the column holds. A batch call that unions its inputs gives 1.
- **values:**
  - `steps`: a list of `{status, latency_ms, content_type, body (first 2000 characters), json}`.
  - `captures`.
  - `last`: `{status, latency_ms, body, headers, size, lines (non-empty lines), first_line, tsv, tsv_cols, json (only when the body looks like JSON)}`.
  - `status`: the last step's status.
  - `derived`.
  - `completed`.
- **Failure handling:** a transport failure or an unfillable placeholder sets error `step i: ...`. A 429 makes the check unknown.
```yaml
- id: bridgedb-wire-format
  kind: roundtrip
  every: 15m
  request: {steps: [{url: https://webservice.bridgedb.org/Human/xrefs/H/TP53}]}
  assert:
    - {that: last.headers.content-type, contains: text/plain}
    - {that: last.first_line, matches: '^[^\t{\[]+\t[^\t]+$', label: TSV, not JSON}
    - {that: last.body, not_matches: '(^|\s)(ncbigene|hgnc\.symbol|chebi|ensembl):'}
- id: bridgedb-batch-union
  kind: roundtrip
  every: 15m
  request:
    steps: [{method: POST, url: https://webservice.bridgedb.org/Human/xrefsBatch/H, data: "TP53\nBRCA1\nEGFR\n", headers: {Content-Type: text/plain}}]
    derive: {keys: {tsv_distinct: 0}, systems: {tsv_distinct: 1}, sets: {tsv_distinct_sets: {col: 2}}, n: {tsv_count_by_key: {key: 0, value: 2}}}
  assert:
    - {that: last.lines, eq: 3}
    - {that: derived.keys, eq: [BRCA1, EGFR, TP53]}
    - {that: derived.systems, eq: [HGNC]}
    - {that: derived.sets, eq: 3, label: each input has its own mapping set}
    - {that: derived.n.TP53, within_pct_of_path: {path: derived.n.TP53, pct: 5}, warn: true}
- id: bridgedb-batch-ratio
  kind: roundtrip
  every: 1d
  timeout: 2m
  request:
    base: https://webservice.bridgedb.org
    steps: [{method: POST, url: /Human/xrefsBatch/L, payload: batch-3133.tsv, headers: {Content-Type: text/plain}}]
    derive: {mapped_ratio: {tsv_nonempty_col: 2, of_rows: 3133}}
  assert: [{that: derived.mapped_ratio, gte: 0.975}]
```

### shiny (vias: public, tgx1, tgx2)
- **request:**
  - `url`.
  - `ws_wait` (seconds, default 10).
  - `robust` (default false): adds the shiny-server `n=<18>` reconnect id.
  - `session` (default true; false skips the websocket).
- **What it does:**
  1. GETs the page.
  2. GETs `<base>__sockjs__/info`.
  3. If `websocket` is true, opens `ws(s)://<base>__sockjs__/<3 digits>/<8 chars>/websocket` with `websockets` (pinned to the node IP with the real SNI and Host when via is tgx1/tgx2), waits for the `o` frame, and closes at once.
- **values:** `page_status`, `page_has_shiny`, `sockjs` (the parsed info), `sockjs_status`, `websocket`, `ws_open`, `ws_ms`, `ws_note`, plus the standard `status`, `headers`, `final_url`, `redirects` for the page. The body is dropped.
```yaml
- {id: rodaf-session, kind: shiny, every: 15m, request: {url: "https://r-odaf.nl/"}, assert: [{that: page_has_shiny, eq: true}, {that: websocket, eq: true}, {that: ws_open, eq: true}, {that: ws_ms, lt: 10000}]}
```

### browser_artifact (vias: public, core; always fetched publicly)
- **request:** `url` (raw JSON) and `page` (id).
- **artifact shape:** `{generated_at, pages: {id: {...}}}` or `{generated_at, pages: [{id, ...}]}`.
- **values:** `generated_at`, `age_h`, `page` (that page's dict, `{}` if absent), `page_found`, `pages` (ids present).
```yaml
- {id: oppbk-browser, kind: browser_artifact, every: 1h, via: [core], request: {url: "https://raw.githubusercontent.com/TGX-UM/tgx-monitor/history/browser.json", page: oppbk}, assert: [{that: age_h, lt: 13}, {that: page.ok, eq: true}, {that: page.console_errors, len_eq: 0}]}
```

### file_age (via: core only)
- **request:**
  - `mount`: an alias in `ctx.mounts`.
  - `glob` (default `*`; may cross directories, e.g. `*/postgres_toxtempass.sql.gz`).
  - `recursive` (default false).
  - `type`: `file` | `dir`.
  - `small_bytes` (default 1): files below it are counted in `small_count`.
  - `verify_gzip` (default true).
  - `scan: {grep: <regex>, tail: <n>}`: run over the decompressed newest .gz.
  - `max_bytes` (default 4 GiB decompression cap).
- **values:**
  - `exists`, `count`.
  - `newest_name`, `newest_mtime` (ISO), `newest_age_h`, `newest_size`.
  - `prev_size`, `size_change_pct`, `total_size`.
  - `small_count`, `names` (the newest 5).
  - When the newest file is a .gz: `gzip_ok`, `gzip_bytes`, plus `grep_count`, `tail` and `gzip_note` when relevant.
- **Edge cases:**
  - A missing mount gives unknown "mount not available: <alias>".
  - No match gives `count: 0`.
  - Globs that are absolute or contain `..` give unknown. Symlinks that resolve outside the mount are skipped.
```yaml
- {id: bk-molaop-builder, kind: file_age, every: 1h, via: [core], timeout: 2m, request: {mount: molaop-builder-backups, glob: "ke_wp_mapping_*.db"}, assert: [{that: count, gte: 1, label: a backup exists}, {that: newest_age_h, lt: 26}, {that: size_change_pct, gte: -20}, {that: small_count, eq: 0}]}
- {id: bk-toxtemp-dump, kind: file_age, every: 1h, via: [core], timeout: 2m, request: {mount: toxtemp-backups, glob: "*/postgres_toxtempass.sql.gz", small_bytes: 1000, scan: {grep: "^CREATE TABLE", tail: 3}}, assert: [{that: gzip_ok, eq: true}, {that: grep_count, gte: 40}, {that: newest_size, gt: 1000000}]}
```

### sqlite_backup (via: core only)
- **request:** `mount`, `glob`, `tables: [names]`, `quick` (default false: use quick_check), `max_bytes` (default 2 GiB copy cap).
- **What it does:** copies the newest match into a temp dir (under `ctx.env["TGXMON_TMP"]` if set), decompressing .gz on the way. It opens the copy read-only and runs `PRAGMA integrity_check`. Table names are checked against `sqlite_master` and an identifier regex before they are counted.
- **values:** `integrity` ("ok", the first problems, "copy failed: ...", "no backup", or "not checked: larger than ..."), `tables.<name>` (None if absent), `missing_tables`, `copied_bytes`, plus every file_age value.
```yaml
- {id: bk-molaop-builder-integrity, kind: sqlite_backup, every: 1d, via: [core], timeout: 5m, request: {mount: molaop-builder-backups, glob: "ke_wp_mapping_*.db", tables: [mappings]}, assert: [{that: integrity, eq: ok}, {that: tables.mappings, gte: 440}]}
```

### restore_marker (via: core only)
- **request:** `mount`, `file` (a path or glob; the newest match is read, capped at 1 MiB), `format`: `json` | `kv` | `text`.
  - `kv` reads `key=value` or `key: value` lines, with integers converted.
  - `text` gives `text` and `fields` (split on whitespace).
- **values:** the marker's keys, plus `exists`, `marker_name`, `marker_size` and `mtime_age_h`. `age_h` comes from the marker's own `verified_at`, `finished_at`, `timestamp` or `generated_at` if one parses, otherwise from the mtime. A missing file gives `{exists: false}`; a parse error gives `parse_error`.
```yaml
- {id: bk-dashboard-manifest, kind: restore_marker, every: 6h, via: [core], request: {mount: hidrive-dashboard, file: "virtuoso-*.manifest", format: kv}, assert: [{that: graphs, gte: 38}, {that: age_h, lt: 26}]}
```

### Wiring for the service
- `Context.mounts`: populate it with alias -> read-only bind path for every backup location (for example `molaop-builder-backups`, `toxtemp-backups`, `hidrive-dashboard`). Only the alias appears in the catalogue.
- `Context.env["TGXMON_TMP"]`: optional; where SQLite copies go. Give core a scratch volume or tmpfs at least as large as the biggest DB (molaop-analyser is 131 MB).
- `ctx.catalogue.root/payloads/`: holds roundtrip payload files.
- No other wiring is needed. The kinds register on import of `tgx_monitor.kinds`.

---

# Swarm: swarm, job_run, digest_drift, docs_drift

## tgx_monitor.docker (non-kind)

`DockerAPI(base_urls=None, timeout=15.0, *, api_version=API_VERSION, transport=None, endpoint_ttl=60.0)` is an async client that only sends GET requests. `base_urls` can be a list of proxy base URLs, a sync or async callable that returns one, or None. With None it resolves `TGXMON_DOCKER_PROXY` (default `tasks.docker-proxy`) on port 2375 through the container resolver. `transport` lets you pass `httpx.MockTransport` in tests, or `httpx.AsyncHTTPTransport(uds=...)` for local development with `base_urls=["http://docker"]`. The API prefix comes from `TGXMON_DOCKER_API` (default `v1.47`).

Every method accepts `calls: list[Call] | None`. Each request appends a `Call(via="docker", url="docker://<alias>/v1.47/<path>")`. Every JSON answer goes through `redact_spec`, and every log line goes through `redact_text`. Errors raise `DockerError(message, status)` and nothing else.

- `endpoints(calls=None, refresh=False) -> dict[alias, Endpoint(base_url, alias, hostname, node_id)]`: sends GET /info to each proxy and maps the hostname prefix h3068544 to tgx1 and h2973005 to tgx2. The result is cached for 60 s.
- Swarm-wide calls try tgx1 first and fall over to tgx2 on a connection error or 5xx. A 4xx is final.
  - `services(filters=None)` uses `?status=true`, so `ServiceStatus` is included.
  - `tasks(service=None, desired_state=None)`
  - `nodes()` lifts `Description.Hostname` into top-level `NodeHostname` and `Alias` before redaction, because redact_spec drops every `Hostname` key.
  - `info(node=None)`
  - `task_logs(task_id, tail=200) -> list[str]` decodes multiplexed 8-byte framing and also handles raw TTY output. It rejects ids that do not match `[a-z0-9]+` before sending any request.
- Node-local calls:
  - `images(node)`
  - `containers(node, all=False)`
  - `info(node)`
  - `events(since, until, filters=None, node=None)` covers one node, or all nodes with each event tagged `_node`. `until` is required, the body is capped at 4 MB and the list at 5000 events.
- Helpers and constants:
  - `ALLOWED_PATHS` (the proxy's `-allowGET` regex, without anchors)
  - `TERMINAL_STATES`, `NODE_ALIASES`, `node_alias()`, `parse_ts()` (handles nanosecond timestamps; `0001-` returns None), `demux()`, `resolve_proxy()`
  - `aclose()`

**Wiring:** core builds one `DockerAPI()` at startup and passes it as `Context(docker=...)`. Close it with `await docker.aclose()` on shutdown. The `public` service and the agent never get one.

## Recorders in tgx_monitor.kinds.infra (non-kind)

- `async def record_job_runs(store, docker) -> int`: for every service with `swarm.cronjob.enable=true`, it reads that service's tasks. Each task in a terminal state that is not yet in `job_runs` is inserted with these fields:
  - job, task_id
  - scheduled_at: the cron slot if the task started within 5 min of it, otherwise NULL for a manual run
  - started_at (task CreatedAt), finished_at (Status.Timestamp)
  - node alias, state, exit_code
  - markers: JSON from lines matching `^TGXMON-MARKER key=value`
  - log_tail: the last 200 lines, redacted
  - source='swarm'

  It is idempotent, and logs are fetched only for new tasks. **Wiring:** the scheduler (or a core background task) should call it every 2 min, because logs disappear when the 5-task history rotates. It returns the number of rows inserted.
- `def ingest_push(store, job, payload) -> int`: stores a run that a cron script POSTed, with source='push'. The payload keys are `exit_code`, `started_at`, `finished_at` (ISO), `state`, `node`, `log` (text; last 200 lines kept, redacted, markers extracted), `markers` (mapping) and `run_id` (dedupe key, default `push-<started_at>`). It returns the row id, which is the same id on a duplicate. It raises ValueError on a bad job name or payload; the `/api/push/<job>` handler should answer 400.
- Other public helpers: `cron_prev(expr, at)` gives the latest fire time at or before `at` (UTC, 5 fields, a leading seconds field is dropped; supports `*`, lists, ranges, steps, MON/JAN names, @daily and similar, and the Vixie rule that a restricted day-of-month and day-of-week match on either). Also `parse_cron`, `split_image`, `is_local_build`, `parse_registry`, `extract_markers`.

## Kinds (all `vias = ("core",)`, so checks must say `via: [core]`)

### `swarm`
Request keys: `check` (required; one of replicas, crash_loops, placement, local_images, nodes, restart_policy), `services` (glob list, default all) and `ignore` (glob list).

What each check reports:
- **replicas:** `by.<svc>.{running,desired,mode}`, `not_converged` (list of "svc 0/1"), `not_converged_count`, `checked` and `cron_resting`. Cron jobs at 0/0 or 0/1 are left out, and so are Replicated or Global jobs.
- **crash_loops:** extra keys `window` (default 1h) and `threshold` (default 3). Reports `failures` {svc: n}, `failed_task_count`, `crash_looping` (list), `crash_looping_count`, and `killed` / `killed_count` for exit 137 or 139.
- **placement:** `pinned` ("robot -> tgx1"), `pinned_services`, `pinned_count`, `pins`, and `pinned_on_unavailable_node`.
- **local_images:** optional `nodes` (default [tgx1, tgx2]). Reports `by.<svc>` (list of nodes that have the image), `single_node_images`, `single_node_count`, `local_only`, `local_only_services`, `local_only_count`, `missing_everywhere` and `missing_count`. The result is unknown if either node's proxy is unreachable.
- **nodes:** `nodes.<alias>.{id,state,availability,role,reachability,leader}`, `leader` (alias or null), `leader_count`, `node_count`, `manager_count`, `not_ready` and `unreachable_managers`. A 503 "no leader" makes the check **failed**. Any other Docker error makes a swarm check unknown.
- **restart_policy:** `on_failure`, `none`, `not_any` and `not_any_count`, with cron jobs left out.

```yaml
- id: swarm-replicas
  kind: swarm
  every: 5m
  via: [core]
  request: {check: replicas, ignore: [toxtempass_minio_init]}
  assert: [{that: not_converged_count, eq: 0}]
  alert_after: 5m
- id: swarm-local-images
  kind: swarm
  every: 1d
  via: [core]
  request: {check: local_images}
  assert: [{that: local_only_services, eq: [biodatafuse_biodatafuse-backend, biodatafuse_biodatafuse-vue, robot, xploreaop]}]
- id: swarm-nodes
  kind: swarm
  every: 2m
  via: [core]
  request: {check: nodes}
  assert: [{that: leader, eq: tgx1}, {that: not_ready, len_eq: 0}]
```

### `job_run`
Request keys:
- `service` (required, e.g. cronjobs_aopwiki-snorql-reload)
- `grace` (default 20m)
- `marker_re` (regex; group 1 is exposed)
- `after_success_of` (another job service)
- `schedule` (overrides the swarm label, so a push-only job needs no Docker)

It reads the schedule from the `swarm.cronjob.schedule` label. It judges the latest slot whose grace has elapsed; while the newest slot is still inside grace, it judges the previous one and sets `pending: true`. It then looks in `job_runs` for a run that started in [slot − 1 min, slot + grace].

Values:
- `schedule`, `last_scheduled_at`, `checked_slot`, `pending`
- `ran` (bool)
- `run` and `last_run`, each {task_id, state, exit_code, scheduled_at, started_at, finished_at, node, source, markers, ok}; `run` is {} if nothing ran in the window
- `last_run_age_h`
- `marker_found`, `marker`
- `dependency_run`, and `ran_after_dependency` (true when the dependency's latest run before this one succeeded and started after this job's previous slot)

The result is unknown when there is no store, or when the slot predates the service's creation ("not yet due", as for wikipathways-switch until 2026-11-12). It is failed when the service is not in the swarm or has no enabled schedule.

```yaml
- id: cron-wp-switch
  kind: job_run
  every: 15m
  via: [core]
  request: {service: cronjobs_wikipathways-switch, after_success_of: cronjobs_wikipathways-reload, grace: 30m}
  assert: [{that: ran, eq: true}, {that: run.exit_code, eq: 0}, {that: ran_after_dependency, eq: true}]
- id: cron-mbb-backup
  kind: job_run
  every: 1h
  via: [core]
  request: {service: cronjobs_molaop-builder-backup, marker_re: 'integrity ok, (\d+) mappings'}
  assert: [{that: ran, eq: true}, {that: run.exit_code, eq: 0}, {that: marker_found, eq: true}]
```

### `digest_drift` (informational)
Request keys: `services` and `ignore` (globs). For each running container on each node it reads the ImageID and the service's spec image without its digest. The previous observation is kept in store meta under `digest_drift:<check id>`.

Values:
- `changed`: ImageID changed while the spec tag stayed the same, e.g. "aopsuite@tgx1: aaaa… -> dddd… (ghcr.io/vhp4safety/aopsuite:latest)"
- `changed_count`
- `redeployed`: the spec itself changed
- `node_mismatch`: one service runs different ImageIDs on the two nodes
- `services`, `first_run`

```yaml
- id: digest-drift
  kind: digest_drift
  every: 1h
  via: [core]
  severity: low
  assert: [{that: changed_count, eq: 0, warn: true}]
```

### `docs_drift` (weekly, never pages)
Request keys:
- `mount` (required; key into ctx.mounts)
- `path` (default services/service-registry.md)
- `aliases` {doc name: live prefix}, e.g. {toxtempassistant: toxtempass}
- `ignore` (globs over live stacks)

It parses the first `| Service | Image |` table. Struck-through and "Removed" rows are skipped. A row matches live services by exact name, by `<name>_` prefix, or by stack namespace.

Values:
- `rows`
- `missing_live`, `missing_in_docs`, `image_mismatch` (e.g. "arrayanalysis: docs …:0.1.4, live 0.1.5"), and a `_count` for each
- `unknown_owner_labels` / `unknown_owner_count`: `tgx.service.owner` labels that are not handles in owners.yaml. E-mail addresses are masked, so none ever reaches values.

```yaml
- id: docs-registry-drift
  kind: docs_drift
  every: 7d
  via: [core]
  severity: low
  request: {mount: docs, aliases: {toxtempassistant: toxtempass}, ignore: [cronjobs, tgx-monitor*]}
  assert: [{that: image_mismatch_count, eq: 0, warn: true}, {that: missing_live_count, eq: 0, warn: true}]
```

Live run on 2026-11-11 against both engines (GET only, through SSH socket forwards that are now closed):
- replicas: 0 not converged once toxtempass_minio_init is ignored; 11 cron jobs resting.
- crash_loops (24h): ontoportal_redis exit 137.
- placement: robot and xploreaop pinned to tgx1.
- local_only: exactly biodatafuse-backend, biodatafuse-vue, robot and xploreaop (58 images are on one node only but can be pulled from a registry).
- nodes: tgx1 is leader, both nodes Ready.
- record_job_runs: 44 runs inserted, 0 on the second pass.
- job_run for snorql-reload, molaop-builder-backup and refresh-corpora: ran=true. wikipathways-switch: "not yet due".
- docs_drift found real drift: arrayanalysis 0.1.4 vs 0.1.5 and the ontoportal virtuoso tag.

---

# Host, pipelines, security, self: host, gha, registry, security, self

# Kinds in `kinds/pipeline.py`

General rule for all five kinds: nothing raises. When a source is absent, rate-limited or has no credential, the kind returns `unknown`. A real break returns `error` or produces a value that fails an assertion.

## host (via `agent:tgx1` | `agent:tgx2`)
- **Request:** `{signal: mdstat|disk|memory|load|boot|peer|root_status|hidrive|agent}`.
- **Data source:** `ctx.agents.signals()`.
- **When it is `unknown`:**
  - the agent did not answer;
  - the snapshot is older than 180 s;
  - the agent could not read that signal;
  - `ctx.agents` is None.
- **Values per signal:**
  - **mdstat:** `arrays.<md>.{state,level,devices,failed_devices,total,active,status,degraded,progress}`, `degraded_arrays` (list), `degraded_count`, `array_count`.
  - **disk:** `disk.<name>.{total_gb,free_gb,used_pct,inodes_used_pct,fstype,mounted}`. `<name>` comes from TGXMON_AGENT_PATHS, e.g. rootfs, brick, hidrive. `disk.hidrive.fstype == cifs` means HiDrive is mounted.
  - **memory:** `mem.{total_gb,available_gb,available_pct,swap_total_gb,swap_used_gb,swap_free_pct}`.
  - **load:** `load.{load1,load5,load15,cpus,per_cpu1,per_cpu15}`.
  - **boot:** `boot.{btime,boot_at,uptime_h,previous_btime,changed}`.
    - `changed` compares against the stored metric `boot.btime` (30-day window). It is true only on the first observation after a reboot.
    - For a reboot alert that lasts, assert `uptime_h gt 1`.
  - **peer:** `peer.{node,ip,ports.<2377|7946|24007|443>.{ok,ms,error},all_ok,failed,checked_at}`.
  - **root_status:** `present`, `age_s`, `age_h` (taken from the file mtime at observe time), plus every top-level key of the status.json written by the cron:
    - `gluster.{heal_pending,split_brain,bricks_down,peers_connected,peers_total,volumes.<vol>.*}`;
    - `md.<dev>.{state,degraded,active_devices,...}`, `md_degraded`;
    - `smart.<dev>.{health,passed}`, `smart_available`;
    - `inodes.{root,brick}.used_pct`, `ntp.synchronized`, `reboot_required`, `units.{docker,glusterd,containerd}`, `dockerd`, `systemd.{state,responsive}`, `errors`.
  - **hidrive:** `hidrive.<dir>.{count,truncated,newest_name,newest_size,newest_age_h,total_size,entries[<=50]}`.
  - **agent:** `reachable` (false instead of unknown when the agent is down), `snapshot_age_s`, `heartbeats.{core,<peer>}` (age in s), `errors`, `error_count`, `hc`.
- **Example:**
```yaml
- id: tgx1-raid
  kind: host
  every: 5m
  via: [agent:tgx1]
  request: {signal: mdstat}
  assert: [{that: degraded_arrays, len_eq: 0}]
- id: tgx1-root-status
  kind: host
  every: 5m
  via: [agent:tgx1]
  request: {signal: root_status}
  assert:
    - {that: present, eq: true}
    - {that: age_h, lt: 0.25}
    - {that: gluster.split_brain, eq: 0}
    - {that: gluster.heal_pending, eq: 0}
    - {that: md_degraded, len_eq: 0}
- id: tgx1-disk
  kind: host
  every: 5m
  via: [agent:tgx1]
  request: {signal: disk}
  assert:
    - {that: disk.rootfs.used_pct, lt: 80, warn: true}
    - {that: disk.rootfs.used_pct, lt: 90}
    - {that: disk.hidrive.fstype, eq: cifs}
```

## gha (via `public` | `core`)
- **Request:** `{repo, workflow?, branch?, event?}`. `workflow` is a file name or a numeric id.
- **Calls:** `GET /repos/{repo}/actions/workflows/{wf}` and `/runs?per_page=5[&branch][&event]`.
- **Auth:** the token comes from secret `tgxmon_gh_token`. With no token the requests are anonymous. If the token gets a 401, the kind retries anonymously.
- **ETag cache:** in-process; a 304 reuses the cached body.
- **Errors:**
  - 403 rate limit or 429 → `unknown`;
  - other 401/403 → `unknown`;
  - 404 → `error`;
  - 5xx → `unknown`.
- **Values with a workflow:**
  - `state` (active | disabled_inactivity | ...), `workflow_name`, `workflow_id`, `workflow_path`, `run_count`;
  - `last_status`, `last_conclusion`, `last_run_at`, `last_run_age_h`, `last_event`, `last_branch`, `last_head_sha`, `html_url`;
  - `completed_conclusion`, `completed_at`, `completed_age_h` (the newest completed run, so an in-progress run does not mask the last result);
  - `last_success_at`, `last_success_age_h`, `auth` (token|anonymous).
- **Values without a workflow** (repo-wide check): `states` {file: state}, `inactive` (list of disabled_inactivity), `disabled` (any non-active), `count`.
- **Example:**
```yaml
- id: gha-aopwikirdf-generation
  kind: gha
  every: 15m
  request: {repo: marvinm2/AOPWikiRDF, workflow: rdfgeneration.yml}
  assert:
    - {that: state, eq: active}
    - {that: completed_conclusion, eq: success}
    - {that: last_run_at, max_age: {crit: 8d}}
- id: gha-bridgedb-docker-states
  kind: gha
  every: 1d
  request: {repo: bridgedb/docker}
  assert: [{that: inactive, len_eq: 0}]
```

## registry (via `public` | `core`)
- **Request:** `{image}`, e.g. `ghcr.io/vhp4safety/oppbk:latest`, `vhp4safety/virtual-human-platform:1.0-6` or `postgres:17`. A digest reference (`@sha256:`) also works.
- **Flow:**
  1. Manifest HEAD with OCI and Docker index/manifest Accept headers.
  2. On 401, follow the WWW-Authenticate challenge and fetch an anonymous token. This covers Docker Hub (auth.docker.io) and GHCR.
  3. For ghcr.io, if the request is still denied, retry with Basic `tgx-monitor:<tgxmon_ghcr_read_pat>` against the token endpoint.
  4. No GitHub App tokens are tried.
- **Credential cases:**
  - private package and no PAT → `unknown`;
  - PAT rejected → `unknown` ("expired or lacks read:packages");
  - 429 → `unknown`.
- **Values:** `registry`, `repository`, `reference`, `auth` (none|anonymous|pat), `status`, `reachable` (status == 200), `digest` (docker-content-digest), `media_type`.
- **Values when `ctx.docker` is set:** the kind calls `DockerAPI.images(node, calls)` for each node in http.NODES and adds:
  - `present_on_nodes`, `missing_on_nodes`;
  - `nodes_unknown` (that node's proxy failed);
  - `node_digest_match` {node: the registry digest is in RepoDigests}.
- **Example:**
```yaml
- id: oppbk-image
  kind: registry
  every: 1d
  request: {image: "ghcr.io/vhp4safety/oppbk:latest"}
  assert:
    - {that: reachable, eq: true}
    - {that: missing_on_nodes, len_eq: 0}
```
- **Live-verified 2026-11-11:**
  - ghcr.io/tgx-um/r-odaf:latest and Docker Hub vhp4safety/virtual-human-platform:1.0-6 return 200 with a digest anonymously;
  - oppbk and qaop on GHCR are denied anonymously, so they give `unknown` until the PAT secret exists.

## security (via `public` | `tgx1` | `tgx2`)
- **Request:** `{url, method: GET|HEAD (default GET), expect_status: [..], absent_markers: [..], headers?, follow? (default false), verify?}`.
- **Method guard:** `validate_request` rejects any other method, and `observe` refuses it again.
- **`{node_ip}` placeholder:** replaced by the via node's IP and fetched with via public. It needs a via of tgx1/tgx2.
- **Connection outcomes:**
  - connect or TLS error → `reachable: false`, `exposed: false`, no error (a closed port is the goal);
  - 429 → `unknown`.
- **Values:** `reachable`, `status`, `expected_status`, `markers_found` (case-insensitive), `exposed` (= a marker was found, or the status is not in expect_status), `server`, `final_url`.
- **Evidence:** only "HTTP <status>…; markers found: …". The body is never kept.
- **Example:**
```yaml
- id: traefik-dashboard-closed
  kind: security
  every: 1h
  via: [tgx1, tgx2]
  request: {url: "http://{node_ip}:8080/dashboard/", expect_status: [401]}
  assert: [{that: exposed, eq: false}]
- id: multirdf-conductor-closed
  kind: security
  every: 1h
  request:
    url: "https://aopwiki-multirdf.vhp4safety.nl/conductor/"
    expect_status: [403, 404]
    absent_markers: ["Virtuoso Conductor"]
  assert: [{that: exposed, eq: false}]
```
- Live-verified: multirdf /conductor gives 403 and `exposed=false`.

## self (via `core`)
- **Request:** `{signal: tick|outbox|vantage|selftest|token, secret?}`.
- **tick:** store meta `last_tick` → `last_tick`, `tick_age_s`. `unknown` if the meta is missing.
- **outbox:** `pending` (sent_at NULL, dead=0, dry_run=0), `oldest_pending_age_min` (0 when none), `dead_letters`.
- **vantage:** TCP connect to 1.1.1.1:53 plus `GET https://api.github.com/zen` (with the token if present; any HTTP answer counts as reachable). Values: `dns_tcp_ok`, `github_ok`, `github_status`, `vantage_ok`.
- **selftest:** `broken` = (meta `selftest_broken` == "1").
- **token:**
  - Call: `GET https://api.github.com/rate_limit` with the secret; this call does not count against the rate limit.
  - `secret` defaults to tgxmon_gh_token. Pass `tgxmon_ghcr_read_pat` to watch the PAT.
  - Values: `valid`, `expires_at`, `days_left` (36500 with `no_expiry: true` when GitHub sends no expiration header), `rate_remaining`.
  - A 401 gives `valid: false, days_left: 0`. A missing secret gives `unknown`.
- **Example:**
```yaml
- id: self-outbox
  kind: self
  every: 5m
  via: [core]
  request: {signal: outbox}
  assert:
    - {that: oldest_pending_age_min, lt: 30}
    - {that: dead_letters, eq: 0}
- id: self-ghcr-pat-expiry
  kind: self
  every: 1d
  via: [core]
  request: {signal: token, secret: tgxmon_ghcr_read_pat}
  assert:
    - {that: days_left, gte: 30, warn: true}
    - {that: days_left, gte: 7}
```

# `agent.py`

## Running it
- **CLI:** `tgx-monitor agent [--port N] [--once]`, registered by `add_commands(sub)`. `--once` collects one snapshot, prints it as JSON and forces dry-run.
- **Stack service:** global mode, non-root, `cap_drop: ALL`, network `tgxmon_int` only, no Traefik labels. Port 8001 is not published.

## Environment
- `TGXMON_NODE={{.Node.Hostname}}` → mapped to tgx1/tgx2 via `docker.NODE_ALIASES` (override with `TGXMON_NODE_ALIASES="h3068544=tgx1,h2973005=tgx2"`).
- `TGXMON_AGENT_PATHS="rootfs=/hostfs/rootfs-probe,brick=/hostfs/gluster-brick,hidrive=/hostfs/hidrive"` (statvfs targets).
- `TGXMON_AGENT_HIDRIVE="aopwiki-dashboard=/hostfs/hidrive/docker/aopwiki-dashboard/virtuoso,..."` (directories to list).
- `TGXMON_AGENT_STATUS` (default `/hostfs/root-status/{host}.json`).
- `TGXMON_AGENT_HB_DIR` (rw Gluster dir, e.g. `/mnt/gluster/docker/tgx-monitor/agent-hb` mounted at `/hb`).
- `TGXMON_AGENT_PROC` (default /proc), `TGXMON_AGENT_PORT` (8001), `TGXMON_AGENT_INTERVAL` (30), `TGXMON_DRY_RUN=1`.
- **Secret:** `tgxmon_hc_urls` (JSON `{"agent-tgx1": url, "agent-tgx2": url, ...}`).

## Binds (all ro except hb)
- `/etc/os-release` → `/hostfs/rootfs-probe` (statvfs of /) and `/mnt/gluster/docker/tgx-monitor/root-status` → `/hostfs/root-status`
- `/mnt/gluster-brick` → `/hostfs/gluster-brick`
- `/mnt/hidrive` → `/hostfs/hidrive`
- the hb dir (rw)

## Collection cadence
- Every 30 s: `/proc` mdstat, meminfo, loadavg and stat btime; statvfs and fstype (from /proc/self/mountinfo); status.json age and content (capped at 256 KB).
- Every 60 s: peer TCP 2377/7946/24007/443.
- Every 300 s: HiDrive listings (max 200 entries, newest first).
- Each blocking read runs in a thread with a 10 s timeout. A read that is still stuck is not started again.

## Endpoints
- `GET /signals`: the latest snapshot. Keys: `node`, `hostname`, `collected_at`, `collected_epoch`, `interval_s`, `errors{signal: msg}`, `mdstat`, `disk`, `memory`, `load`, `boot`, `peer`, `root_status`, `hidrive`, `heartbeats`, `hc`. Returns 503 before the first collection.
- `GET /livez`: 200 while the last collection is younger than 4 intervals.

## Dead-man switch
- Each cycle writes `<hb_dir>/<node>.json` (`{"node","ts","hostname"}`) atomically, then reads `core.json` and `<peer>.json`. Ages are computed from their `ts`.
- **Core must write `core.json` in the same dir at least once a minute:** `from tgx_monitor.agent import write_heartbeat; write_heartbeat(hb_dir, "core", {"last_tick": ...})`.
- The agent POSTs to the `agent-<node>` healthchecks URL (body = reason): success, or `/fail` when any heartbeat is missing or older than 300 s.
- Pings go out once a minute, or immediately when the reason changes.
- No `/fail` is sent during the first 300 s after start, so a deploy does not page.
- `TGXMON_DRY_RUN=1` records the would-be ping in `/signals.hc` instead of sending it.

## Public helpers
- Parsers: `parse_mdstat`, `parse_meminfo`, `parse_loadavg`, `parse_btime`, `mount_fstype`.
- Readers: `disk_usage`, `read_root_status`, `list_dir`, `read_heartbeat`, `write_heartbeat`.
- Probes: `tcp_probe(host, port, timeout)` (also used by `self:vantage`).
- Naming: `node_alias`, `peer_of`.
- Classes: `AgentConfig.from_env()`, `Agent(cfg).cycle()/run_forever()/app()`, `serve(cfg)`.

## AgentClient (for core)
- **Constructor:** `AgentClient(base_dns="tasks.agent", port=8001, timeout=5, ttl=20, transport=None, resolve=None)`.
- **`await signals()`** returns `{"tgx1": snapshot | {"error": ...}, "tgx2": ...}`:
  - it resolves every task IP, GETs `/signals` from each, and keys the answers by the node each agent reports;
  - a node with no answer gets an error naming the IPs tried;
  - results are cached for 20 s, so one cycle of host checks costs one request per agent.
- **Wiring:** `Context(agents=AgentClient(os.environ.get("TGXMON_AGENT_DNS", "tasks.agent")))`. Use the DNS name that resolves on `tgxmon_int` in the deployed stack (`tasks.agent` or `tasks.tgx-monitor_agent`).

# host/tgx-monitor-status.sh (root cron, for Egon)
- **Install:** `install -m 0755 host/tgx-monitor-status.sh /usr/local/sbin/tgx-monitor-status; echo '*/5 * * * * root /usr/local/sbin/tgx-monitor-status' > /etc/cron.d/tgx-monitor-status`.
- **Optional ping:** `/root/.tgx-monitor-hc` (0600) holds the healthchecks URL for root-status-tgxN.
- **Behaviour:**
  - Read-only probes, each under `timeout 20`, with a flock so runs do not overlap.
  - JSON is built with `python3 -I -S` (stdlib only) and written atomically (tmp + mv) to `/mnt/gluster/docker/tgx-monitor/root-status/<host>.json` with mode 0644.
  - Pings `<url>` on success or `<url>/fail` if the JSON could not be written. Uses curl, or python urllib if curl is missing.
- **Testing:**
  - `STATUS_OUT=/tmp/x.json` writes elsewhere and disables the ping.
  - Test-only env: `STATUS_TEST_BIN`, `MDSTAT`, `PROBE_TIMEOUT`, `LOCK_FILE`, `HC_FILE`, `NO_PING`.
  - Shellcheck is clean.
- The JSON shape is in host/README.md.
