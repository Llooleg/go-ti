# Wazuh Integration — Implementation Plan

> **Status:** REVISED — review round 1 decisions incorporated (see §11). Nothing
> in the codebase has been changed yet.
> **Assumptions:** Wazuh 4.8+ only; single-manager setup for development; existing
> go-ti architecture (domain / usecase / repository / delivery) is kept as-is.

---

## 1. Goals

Turn go-ti from a "one IOC at a time" lookup tool into a small **threat-intelligence
enrichment service and batch scanner** that interoperates with Wazuh:

1. **Push direction (primary):** Wazuh fires an alert → go-ti automatically extracts
   IOCs (URLs, domains, IPs, file hashes) from the alert → looks them up on VirusTotal /
   AbuseIPDB → returns an enriched alert back to the caller.
2. **Pull direction (secondary):** go-ti queries the Wazuh Manager REST API
   (agents, FIM/syscheck file hashes, vulnerability data) and batch-scans them.
3. **Write-back (optional, last):** push enrichment verdicts into the Wazuh
   indexer so they become searchable next to the original alerts.

### Non-goals (for now)

- Replacing the Wazuh indexer/dashboard or storing alerts in go-ti.
- Active response / blocking. Read-only enrichment only.
- Persistent storage (no DB); caches are in-memory.
- Supporting Wazuh versions older than 4.8.

---

## 2. Integration surface — why these three patterns

Wazuh offers three realistic hooks for an external tool:

| # | Pattern | Mechanism | Effort | Value |
|---|---------|-----------|--------|-------|
| 1 | **Alert enrichment (webhook-style)** | Wazuh `integrator` module runs a custom script per matching alert; script POSTs the alert JSON to go-ti's `/api/enrich` | M | High — automatic, real-time |
| 2 | **Pull from Manager API** | Wazuh Manager REST API (port 55000, JWT auth): `/agents`, `/syscheck/{id}`, `/vulnerability_detection` | M | Medium — batch audits |
| 3 | **Write to indexer** | example integration script ships go-ti's enriched response to the Wazuh indexer REST (port 9200, `_bulk` into `goti-enrichment-*` index) | L | Medium — searchable history |

Phase order: **1 → 2 → 3**. Phase 1 alone already delivers the "useful stuff".

---

## 3. Phase 1 — Alert enrichment endpoint (MVP)

### 3.1 Flow

```
Wazuh manager                        go-ti
─────────────                        ─────
rule fires (level ≥ N, groups X)
  └─ integrator module
       └─ runs /var/ossec/integrations/custom-goti
            └─ HTTP POST /api/enrich  ──────►  extract IOCs
                                              dedupe + cache check
                                              rate-limited VT / AbuseIPDB lookups
            ◄── enriched alert JSON ─────────  respond 200
       (script may forward result to
        the Wazuh indexer — Phase 3)
```

### 3.2 Domain model (new `internal/domain/ioc.go`)

```go
type IOCType string

const (
    IOCTypeURL      IOCType = "url"
    IOCTypeDomain   IOCType = "domain"    // bare hostname from DNS logs etc.
    IOCTypeIP       IOCType = "ip"
    IOCTypeFileHash IOCType = "file_hash" // md5 | sha1 | sha256
)

type IOC struct {
    Type  IOCType `json:"type"`
    Value string  `json:"value"` // hash value, URL, or IP literal
    Algo  string  `json:"algo,omitempty"` // md5|sha1|sha256, for file_hash
}

type EnrichmentVerdict string

const (
    VerdictMalicious EnrichmentVerdict = "malicious"
    VerdictSuspicious EnrichmentVerdict = "suspicious"
    VerdictClean     EnrichmentVerdict = "clean"
    VerdictUnknown   EnrichmentVerdict = "unknown"   // no data / lookup failed
)

type EnrichmentResult struct {
    IOC     IOC            `json:"ioc"`
    Verdict EnrichmentVerdict `json:"verdict"`
    Stats   *AnalysisStats `json:"stats,omitempty"` // VirusTotal (url/hash/ip?)
    Abuse   *AbuseReport   `json:"abuse,omitempty"` // AbuseIPDB (ip only)
    Cached  bool           `json:"cached"`
    Error   string         `json:"error,omitempty"`
}
```

Verdict rule (documented, tested): `malicious ≥ 1` VT malicious → `malicious`;
else `suspicious ≥ 1` or AbuseIPDB confidence ≥ 50 → `suspicious`; else stats
present → `clean`; else `unknown`.

Domain IOCs are analyzed by resolving the hostname to an IPv4 address (existing
`dnsresolver` adapter, reused by the enrichment service) and running the
AbuseIPDB check against the resolved IP; VirusTotal is only queried when the
extracted value is a full URL. Resolution failures yield `verdict: "unknown"`
with the error attached — never a failed request.

### 3.3 IOC extraction rules (`internal/usecase/ioc_extract.go`)

Input: the Wazuh alert JSON as `map[string]any` (tolerant — alerts vary by source).

| Alert field (examples)                              | IOC type | Notes |
|-----------------------------------------------------|----------|-------|
| `data.syscheck.sha256_after` / `_md5` / `_sha1`      | file_hash| FIM "added/modified" events |
| `data.win.eventdata.hashes` (`"SHA256=A..,MD5=B.."`)| file_hash| Sysmon EventID 1/6/7 etc.; needs string parsing |
| `data.url`, `data.data.url`                          | url      | Suricata `event_type:url`, web rules |
| `data.dns.queries[*].name`, `data.dns.rrname`        | domain   | Suricata/Snort DNS events |
| `data.win.eventdata.queryName`                       | domain   | Sysmon EventID 22 (DNS query) |
| `data.srcip`, `data.dstip`, `srcip`, `dstip`         | ip       | skip RFC1918/loopback/multicast by default |
| `data.alert...` unknown                              | —        | extraction is table-driven + unit-tested; unknown layouts simply yield fewer IOCs, never errors |

Guardrails: dedupe; skip private/reserved IPs; validate domain syntax and skip
infrastructure suffixes (`.arpa`, `.local`, `.internal` — configurable);
**max IOCs per alert** (default 10, env-tunable) so one noisy alert cannot burn
the VT daily quota.

### 3.4 API contract — `POST /api/enrich`

Request: full Wazuh alert (or integration wrapper) as-is:

```json
{
  "agent": {"id": "001", "name": "web-01"},
  "rule": {"level": 7, "groups": ["syscheck"]},
  "data": {"syscheck": {"path": "/tmp/warez.exe", "sha256_after": "ab12..."}}
}
```

Response:

```json
{
  "enrichments": [
    {
      "ioc": {"type": "file_hash", "value": "ab12...", "algo": "sha256"},
      "verdict": "malicious",
      "stats": {"malicious": 41, "harmless": 12, "...": 0},
      "cached": false
    },
    {
      "ioc": {"type": "domain", "value": "malicious-cdn.example"},
      "verdict": "suspicious",
      "abuse": {"ipAddress": "203.0.113.9", "abuseConfidenceScore": 75, "...": 0},
      "cached": false
    }
  ],
  "summary": {"iocs_found": 2, "looked_up": 2, "malicious": 1, "suspicious": 1, "failures": 0}
}
```

- `200` always when the payload parses (partial failures are per-IOC `error` fields);
- `400` malformed JSON / body > 1 MiB; `401` missing/wrong bearer token (when
  `GOTI_WEB_TOKEN` is set); `405` wrong method.
- Existing `/api/analyze` stays untouched (human-facing, accepts a single input string).

### 3.5 Caching & rate limiting (critical — VT free tier is 4 req/min, 500/day)

- `pkg/ratelimit` — hand-rolled token-bucket limiter (no new dependencies),
  default 4 req/min for VirusTotal, env-tunable `VT_RATE_PER_MIN`.
- `internal/usecase` IOC cache: in-memory, mutex-guarded, TTL 24 h, keyed by
  `type:value`; `Cached: true` marks hits in the response. AbuseIPDB quota
  (1,000/day free) shares the same cache pattern, separate bucket (`ABUSE_RATE_PER_MIN`, default 60).
- When the limiter delays a lookup beyond the request budget (`ENRICH_TIMEOUT`,
  default 15 s), the IOC is answered with `verdict: "unknown", error: "rate limited"`,
  HTTP stays 200 — Wazuh must never see spurious failures.

### 3.6 Config additions (`internal/config`)

All optional — the tool keeps working without them:

| Variable | Default | Purpose |
|----------|---------|---------|
| `VT_RATE_PER_MIN` | `4` | VT requests/min budget |
| `ABUSE_RATE_PER_MIN` | `60` | AbuseIPDB requests/min budget |
| `IOC_CACHE_TTL` | `24h` | verdict cache TTL |
| `MAX_IOCS_PER_ALERT` | `10` | extraction cap |
| `DOMAIN_SKIP_SUFFIXES` | `.arpa,.local,.internal` | domain IOCs with these suffixes are ignored |
| `GOTI_WEB_TOKEN` | *(empty)* | if set, `/api/*` requires `Authorization: Bearer …` |

`GOTI_WEB_TOKEN` is included in Phase 1 (decided): it hardens deployments where
go-ti is not on localhost (recommended default binding stays `127.0.0.1`).

### 3.7 Wazuh-side setup (docs + example script, no Go changes)

`examples/wazuh/ossec.conf.snippet`:

```xml
<ossec_config>
  <integration>
    <name>custom-goti</name>
    <hook_url>http://127.0.0.1:8080/api/enrich</hook_url>
    <level>7</level>
    <alert_format>json</alert_format>
    <group>syscheck,rootcheck,</group>
  </integration>
</ossec_config>
```

`examples/wazuh/custom-goti` (Python 3, executable, owner `wazuh:wazuh`):
reads the alert file path from argv (Wazuh convention), POSTs it to `hook_url`
(with the bearer token, when configured), prints/logs the enriched result, and —
from Phase 3 — forwards the enriched alert to the Wazuh indexer (credentials via
`WAZUH_INDEXER_*` env vars, see §5). `examples/wazuh/README.md` explains
installation paths (`/var/ossec/integrations/`), permissions and env vars.

### 3.8 Files touched in Phase 1

| File | Change |
|------|--------|
| `internal/domain/ioc.go` | **new** — IOC, verdicts, EnrichmentResult |
| `internal/usecase/enrich.go` | **new** — EnrichmentService (orchestration, cache, verdicts) |
| `internal/usecase/ioc_extract.go` | **new** — alert → []IOC extractor (URLs, IPs, domains, hashes) |
| `pkg/ratelimit/ratelimit.go` | **new** — token bucket |
| `internal/delivery/web/enrich.go` | **new** — POST /api/enrich handler |
| `internal/repository/virustotal/client.go` | extend: `HashStats(ctx, algo, hash)` (VT `/files/{id}` accepts md5/sha1/sha256) |
| `internal/usecase/analysis.go` | extend `VirusTotal` interface accordingly |
| `internal/config/config.go` | new optional vars (no fatal if unset) |
| `internal/delivery/web/*_test.go`, `internal/usecase/*_test.go`, `pkg/ratelimit/*_test.go` | **new** tests (see §8) |
| `examples/wazuh/*`, `README.MD` | **new** docs |

---

## 4. Phase 2 — Pull from the Wazuh Manager API

### 4.1 Repository client (`internal/repository/wazuh/`)

- Base URL: `WAZUH_API_URL` (default `https://127.0.0.1:55000`).
- Auth: basic credentials `WAZUH_API_USER` / `WAZUH_API_PASSWORD` →
  `POST /security/user/authenticate` → JWT; cached and transparently refreshed
  on 401. (`run_as` auth-context supported for TLP-scoped users via `WAZUH_RUN_AS`.)
- TLS: self-signed manager certs are the norm → `WAZUH_CA_CERT` (path to CA) or
  explicit opt-in `WAZUH_TLS_INSECURE=true` (documented risk, default false).
- Endpoints (all read-only):
  - `GET /agents` — inventory, status;
  - `GET /syscheck/{agent_id}` — FIM files incl. sha256 → batch VT scan;
  - `GET /vulnerability_detection/last_scan` + report endpoints — overview
    (enrichment optional: hash lookups for vulnerable packages' files).
- Conventions identical to existing adapters: constructor + functional options
  (`WithBaseURL`, `WithHTTPClient`) so tests use `httptest`.

### 4.2 New CLI surface — subcommand

```
go-ti wazuh agents                       # list agents
go-ti wazuh fim --agent 001 --limit 50   # batch-scan FIM hashes; --limit defaults to 50
go-ti wazuh vulns --agent 001            # vulnerability summary
```

Implementation: `flag.NewFlagSet` per subcommand in `cmd/go-ti` (stdlib pattern,
no new deps). Existing behavior (console/web) unchanged — `wazuh` only triggers
when `args[0] == "wazuh"`.

### 4.3 Files

`internal/domain/wazuh.go` (Agent, SyscheckFile, Vulnerability models) ·
`internal/repository/wazuh/{client,auth}.go` + tests · `internal/usecase/wazuh_scan.go` + tests ·
`cmd/go-ti/main.go` subcommand wiring · README.

---

## 5. Phase 3 — Write-back & end-to-end environment (optional)

- **Indexer write-back (decided: script-side):** the example integration script
  forwards go-ti's enriched response to the Wazuh indexer via `_bulk` into
  `goti-enrichment-%{date}` (plain JSON docs, no fancy mappings in v1) →
  searchable in the Wazuh dashboard next to the original alerts. go-ti itself
  stays indexer-free and needs no indexer credentials; the script reads
  `WAZUH_INDEXER_URL` / `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` from a
  protected env file (`/var/ossec/etc/goti-indexer.env`, mode 0640, owner
  `wazuh:wazuh`) — documented in `examples/wazuh/README.md`.
- **Local e2e lab:** `examples/wazuh/docker-compose.yml` — single-node Wazuh
  (manager + indexer + dashboard) + go-ti container; documented happy-path test.
- **Web UI:** small "Enrichments" tab fed from an in-memory ring buffer of the
  last N enrichments (no persistence).

---

## 6. Security considerations

- API keys and Wazuh credentials only via environment (existing `internal/config`); never logged.
- Alert payloads may contain sensitive data → request logging stays at
  method/path/status level (already the case); bodies are never logged.
- go-ti keeps binding to `127.0.0.1` by default; remote Wazuh managers should
  use an SSH tunnel / reverse proxy with TLS, or the `GOTI_WEB_TOKEN` bearer auth.
- `WAZUH_TLS_INSECURE` is opt-in and loudly documented; CA-cert path preferred.
- Outbound lookups carry only the IOC value — never the full alert — to VT/AbuseIPDB.

## 7. Dependency policy

Zero new third-party dependencies: limiter, cache, JWT handling (if any) are
hand-rolled against stdlib, consistent with the current `go.mod`.

## 8. Testing strategy

- **Unit:** IOC extractor table tests with real-shaped alert samples (syscheck,
  Sysmon incl. EventID 22, Suricata DNS/URL events); domain syntax validation and
  suffix skipping; verdict computation; cache TTL/eviction; token-bucket timing;
  VT hash-lookup adapter via `httptest`; domain IOC path (resolver stub → abuse check).
- **Handler:** `/api/enrich` — happy path, rate-limited path (still 200 + unknown
  verdicts), malformed payload 400, 405, bearer-token enforcement.
- **Wazuh client (Phase 2):** `httptest` servers covering auth flow, token
  refresh on 401, self-signed TLS via generated cert.
- **Manual e2e (Phase 3):** docker-compose lab, scripted alert injection.

## 9. Rough effort

| Phase | Scope | Estimate |
|-------|-------|----------|
| 1 | Enrichment endpoint + extraction + cache/limiter + example script + tests | ~1–2 focused sessions |
| 2 | Wazuh API client + CLI subcommands + tests | ~1 session |
| 3 | Indexer write-back + docker lab + UI tab | ~1–2 sessions |

## 10. Suggested commit sequence (Phase 1)

1. `feat(domain): IOC and enrichment verdict models`
2. `feat(pkg): token-bucket rate limiter`
3. `feat(usecase): IOC extraction from Wazuh alerts (URLs, IPs, domains, hashes)`
4. `feat(usecase): enrichment service with verdict cache and domain resolution`
5. `feat(virustotal): hash lookups by algorithm`
6. `feat(web): POST /api/enrich endpoint`
7. `feat(examples): Wazuh integration script and docs`

## 11. Decisions (resolved in review round 1)

1. **Wazuh version:** 4.8+ only.
2. **Write-back transport:** the example integration script forwards enriched
   alerts to the indexer itself; go-ti grows no `/api/forward` endpoint.
3. **Bearer token:** `GOTI_WEB_TOKEN` is part of Phase 1.
4. **FIM batch scan limit:** `--limit` defaults to 50 per run.
5. **Extra IOC source:** bare domains from DNS logs (Suricata/Snort DNS events,
   Sysmon EventID 22) are extracted and analyzed via resolve → AbuseIPDB
   (see §3.2–3.3).
