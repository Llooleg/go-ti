# go-ti

Simple CLI-only threat intelligence tool: it checks links and files against
[VirusTotal](https://www.virustotal.com) and resolved IPs against
[AbuseIPDB](https://www.abuseipdb.com). Made for Go learning mainly, not serious.

## Usage

Console mode (default):

```sh
make run
# or
go run ./cmd/go-ti https://example.com
```

Web GUI (optional mode):

```sh
make run-web
# or
go run ./cmd/go-ti -web            # GUI on http://127.0.0.1:8080
go run ./cmd/go-ti -addr :8080     # -addr implies -web
```

Pass a target as an argument, or run without arguments and answer the prompt.
`http`/`https` URLs are analyzed as links; anything else is treated as a file
path (hashed with SHA-256 and looked up on VirusTotal).

The web GUI serves a browser frontend plus a JSON API:

| Endpoint          | Method | Description                          |
| ----------------- | ------ | ------------------------------------ |
| `/`               | GET    | embedded single-page GUI             |
| `/api/analyze`    | POST   | body `{"input": "..."}` → report JSON |
| `/api/enrich`     | POST   | Wazuh alert JSON → per-IOC verdicts  |
| `/api/health`     | GET    | liveness check                       |

```sh
curl -s localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"input": "https://example.com"}' | jq
```

By default the server binds to `127.0.0.1` so your API-key-backed lookups
are not exposed to the network; override with `-addr`.

### Wazuh alert enrichment

The web server also exposes `POST /api/enrich`: it accepts a Wazuh alert JSON,
extracts IOCs (URLs, domains, IPs, file hashes), and returns per-IOC verdicts
from VirusTotal / AbuseIPDB — with rate limiting and caching. See
[`examples/wazuh/README.md`](examples/wazuh/README.md) for the Wazuh-side
integration script and [`WazuhAPI.md`](WazuhAPI.md) for the full design.

## Configuration

API keys are read from the process environment — the app never reads `.env`
files:

| Variable    | Purpose              |
| ----------- | -------------------- |
| `VTKEY`     | VirusTotal API key   |
| `IPABUSEKEY`| AbuseIPDB API key    |

For local development you can export your `.env` into the shell:

```sh
set -a; source .env; set +a
```

## Project layout

```
cmd/go-ti/            application entrypoint
internal/config/      environment-based configuration
internal/domain/      domain models (no external dependencies)
internal/usecase/     business logic and orchestration
internal/repository/  data access adapters (VirusTotal, AbuseIPDB, DNS)
internal/delivery/    transport layers: console CLI and web GUI
pkg/                  utilities safe to reuse (checksum, inputparse)
Makefile              automation entrypoint
```

## Development

```sh
make install-tools   # golangci-lint, mockgen
make build           # compile the binary
make lint            # golangci-lint run ./...
make test            # go test -v -race -cover ./...
```
