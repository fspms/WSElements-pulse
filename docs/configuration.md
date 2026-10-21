# Configuration reference

Sources, highest priority first:

1. Environment variables (`PULSE_*`, plus `ELEMENTS_CLIENT_ID`, `ELEMENTS_CLIENT_SECRET`,
   `DATABASE_URL`, and their `*_FILE` variants).
2. The YAML file named by `PULSE_CONFIG_FILE` (or `--config`).
3. Built-in defaults.

Nested settings map to env variables with the `PULSE_` prefix and `__` between levels:
`collectors.security_events.engine_groups` → `PULSE_COLLECTORS__SECURITY_EVENTS__ENGINE_GROUPS`.
List values can be comma-separated in env variables (`epp,edr`).

## Secrets

| Variable | File variant | Purpose |
|---|---|---|
| `ELEMENTS_CLIENT_ID` | `ELEMENTS_CLIENT_ID_FILE` | API client ID |
| `ELEMENTS_CLIENT_SECRET` | `ELEMENTS_CLIENT_SECRET_FILE` | API client secret |
| `DATABASE_URL` | `DATABASE_URL_FILE` | PostgreSQL connection string |

These are **refused in the YAML file**.

### Docker secrets

```yaml
# docker-compose.override.yml
services:
  collector:
    environment:
      ELEMENTS_CLIENT_ID_FILE: /run/secrets/elements_client_id
      ELEMENTS_CLIENT_SECRET_FILE: /run/secrets/elements_client_secret
    secrets: [elements_client_id, elements_client_secret]
secrets:
  elements_client_id:
    file: ./secrets/elements_client_id       # git-ignored
  elements_client_secret:
    file: ./secrets/elements_client_secret
```

Leave `ELEMENTS_CLIENT_ID` / `ELEMENTS_CLIENT_SECRET` empty in `.env` when you use files.

## All settings

| YAML key | Default | Description |
|---|---|---|
| `log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `log_format` | `json` | `json` or `console` |
| `auto_migrate` | `true` | apply DB migrations when `run`/`backfill` start |
| `api.base_url` | `https://api.connect.withsecure.com` | API host |
| `api.timeout_seconds` | `30` | per-request timeout |
| `api.request_delay_seconds` | `0.25` | minimum delay between two requests, shared by all collectors |
| `api.max_retries` | `5` | retries on 429, 5xx and network errors |
| `api.backoff_base_seconds` / `api.backoff_max_seconds` | `1` / `60` | exponential backoff (with jitter) |
| `api.max_retry_after_seconds` | `300` | upper bound for a server `Retry-After` |
| `api.user_agent` | `WSElements-pulse/<version> ...` | sent on every request (required by the API) |
| `organizations.ids` | `[]` | organizations to poll; empty = client's default organization |
| `organizations.discover` | `false` | poll every company under `ids` (or the default org) instead |
| `organizations.discovery_interval_minutes` | `60` | how often discovery runs again |
| `collectors.incidents.enabled` / `interval_minutes` / `backfill_days` / `overlap_minutes` | `true` / `5` / `30` / `10` | |
| `collectors.detections.enabled` / `interval_minutes` / `max_incidents_per_run` | `true` / `5` / `50` | |
| `collectors.security_events.enabled` / `interval_minutes` / `backfill_days` / `overlap_minutes` | `true` / `5` / `7` / `10` | |
| `collectors.security_events.engine_groups` | `[epp, edr]` | also `ecp` (Collaboration Protection), `xm` (Exposure Management) |
| `collectors.devices.enabled` / `interval_minutes` / `states` | `true` / `15` / `[active, blocked, inactive]` | |
| `collectors.audit_logs.enabled` / `interval_minutes` / `backfill_days` / `overlap_minutes` | `true` / `15` / `7` / `10` | |
| `retention.api_requests_days` / `retention.collector_runs_days` | `14` / `30` | purge of health metrics (data tables are never purged) |
| `health.host` / `health.port` | `0.0.0.0` / `8080` | `/healthz` listener inside the container |

## MSP / multi-organization setups

- **Explicit list**: `PULSE_ORGANIZATIONS__IDS=uuid1,uuid2`. Each organization gets its own
  cursors, runs and health rows.
- **Discovery**: `PULSE_ORGANIZATIONS__DISCOVER=true` with a partner-level API client. The
  collector lists companies through `/organizations/v1/organizations` (`type=company`) and polls
  each one. New companies are picked up at the next discovery interval.

Each record's `organization_id` comes from the record itself when the API provides it (security
events, devices, audit logs, incidents). Data stays correctly attributed even if a partner-level
query returns child companies.

API cost per cycle grows with the number of organizations. For many companies, raise the
intervals or the request delay.

## Grafana

- Admin credentials: `GRAFANA_ADMIN_USER`, `GRAFANA_ADMIN_PASSWORD`.
- Port: `GRAFANA_PORT` (bound to `127.0.0.1`). Put a reverse proxy with HTTPS in front if it needs
  to be reachable from other machines.
- Datasource user: `grafana_reader` with `GRAFANA_DB_PASSWORD`. The role is created by
  `docker/postgres/init` when the database volume is first initialized. To change the password
  later, run `ALTER ROLE grafana_reader PASSWORD '...'` and update `.env`.
