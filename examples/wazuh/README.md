# Wazuh ↔ go-ti integration

Automatically enrich Wazuh alerts with VirusTotal / AbuseIPDB verdicts by
routing them through go-ti's `POST /api/enrich` endpoint.

## How it works

```
Wazuh rule fires (level ≥ 7, groups: syscheck, rootcheck, ...)
  └─ integrator module runs custom-goti
       └─ POST alert JSON → http://127.0.0.1:8080/api/enrich
       ←─ enriched verdicts per IOC (url / domain / ip / file_hash)
```

go-ti extracts IOCs from the alert (FIM hashes, Sysmon hash strings and DNS
queries, Suricata URLs, source/destination IPs), looks them up with per-API
rate limiting and a verdict cache, and answers with a summary.

## Installation (on the Wazuh manager)

1. Start go-ti on the same host (or adjust the hook URL):

   ```sh
   set -a; source /path/to/.env; set +a   # VTKEY, IPABUSEKEY
   ./go-ti -web -addr 127.0.0.1:8080
   ```

2. Install the integration script:

   ```sh
   cp custom-goti /var/ossec/integrations/custom-goti
   chmod 750 /var/ossec/integrations/custom-goti
   chown root:wazuh /var/ossec/integrations/custom-goti
   ```

3. Add the `<integration>` block from `ossec.conf.snippet` to
   `/var/ossec/etc/ossec.conf` (inside `<ossec_config>`), adjust
   `<group>` to the rule groups you want enriched, then restart the manager:

   ```sh
   systemctl restart wazuh-manager
   ```

4. (Optional) If go-ti runs with `GOTI_WEB_TOKEN` set, export the same value
   for the manager before restart — the script sends it as a bearer token.

## Testing

Generate an alert (e.g. touch a FIM-monitored file) and check:

```sh
tail -f /var/ossec/logs/ossec.log                                   # integration errors
cat /var/ossec/logs/integrations/goti-*.json                        # enriched output
curl -s localhost:8080/api/health
```

Direct API check:

```sh
curl -s localhost:8080/api/enrich \
  -H 'Content-Type: application/json' \
  -d '{"data":{"syscheck":{"sha256_after":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}}'
```

## Response format

```json
{
  "enrichments": [
    {
      "ioc": {"type": "file_hash", "value": "ba78...", "algo": "sha256"},
      "verdict": "clean",
      "stats": {"harmless": 70, "malicious": 0, "...": 0},
      "cached": false
    }
  ],
  "summary": {"iocs_found": 1, "looked_up": 1, "malicious": 0, "suspicious": 0, "failures": 0}
}
```

Verdicts: `malicious` (≥1 VT engine), `suspicious` (VT suspicious ≥1 or
AbuseIPDB confidence ≥50), `clean` (data found, nothing fired), `unknown`
(lookup failed / rate limited — never a failed HTTP request).

## Tuning (go-ti side)

| Env var | Default | Purpose |
| ------- | ------- | ------- |
| `VT_RATE_PER_MIN` | `4` | VirusTotal requests/min (public quota) |
| `ABUSE_RATE_PER_MIN` | `60` | AbuseIPDB requests/min |
| `IOC_CACHE_TTL` | `24h` | verdict cache TTL |
| `MAX_IOCS_PER_ALERT` | `10` | extraction cap per alert |
| `DOMAIN_SKIP_SUFFIXES` | `.arpa,.local,.internal` | ignored domain suffixes |
| `ENRICH_TIMEOUT` | `15s` | overall budget per alert |
| `GOTI_WEB_TOKEN` | *(empty)* | bearer token for `/api/*` |

Full design: see `WazuhAPI.md` in the repository root.
