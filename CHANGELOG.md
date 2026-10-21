# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-21

### Added

- Collector (Python 3.12) with a read-only Elements API client: OAuth2 client credentials with
  the `connect.api.read` scope only, token caching and refresh, one re-authentication on 401,
  exponential backoff with jitter on 429/5xx/network errors, `Retry-After` support, a
  configurable request delay, and an allowlist that blocks any non-read request.
- Collectors: incidents (BCDs), incident detections, security events (one cursor per engine
  group: EPP and EDR by default, ECP and XM optional), devices (full snapshot with removal
  detection) and audit logs.
- Incremental sync with per-collector, per-organization cursors (`sync_state`), overlap
  re-reads, idempotent upserts, 30-day query windows, and normalized columns plus raw JSONB.
- Multi-organization support: configured organization list or discovery of child companies.
- CLI: `run`, `check`, `backfill`, `health`, `migrate`, `seed`.
- `/healthz` endpoint, structured JSON logs, graceful shutdown.
- PostgreSQL schema with SQL migrations, dashboard views, and a read-only Grafana role.
- Grafana provisioning: datasource, six dashboards (Overview, Incidents, Security events,
  Devices, Audit logs, Collector health) and two alert rules (new critical incident, stale
  collector).
- `seed` command generating fictional demo data.
- Docker image, `docker-compose.yml`, documentation and GitHub Actions CI.
