# Security policy

WSElements-pulse is an unofficial community project. **Vulnerabilities in WithSecure products
or in the Elements API itself must be reported to WithSecure**, not here.

## Reporting a vulnerability in this project

Please do **not** open a public issue. Use GitHub's private vulnerability reporting
(*Security → Report a vulnerability*) on this repository. Include a description, affected
version, reproduction steps (with fictional data only) and impact. Maintainers will acknowledge
the report as soon as they can. This is a volunteer project, so there is no guaranteed response
time.

Supported versions: the latest release only.

## Design principles

- **Read-only access to Elements.** Only the `connect.api.read` scope is requested. The HTTP
  client refuses any request outside a fixed allowlist of read endpoints, before sending it.
  Use an API client created as read-only in Elements.
- **Secrets only from the environment.** Client credentials and the database URL come from
  environment variables or Docker secrets (`*_FILE`). They are rejected in the YAML config,
  never logged, and kept out of the image and the repository (`.env` is git-ignored).
- **Least privilege for Grafana.** Grafana connects with `grafana_reader`, a role limited to
  `SELECT` with read-only transactions and a statement timeout.
- **No exposed database.** PostgreSQL isn't published on the host by default. Grafana is bound
  to `127.0.0.1` by default.
- The collector container runs as a non-root user.

## Operating it safely

The database contains sensitive security data: device names, usernames and email addresses,
detection details including **process command lines**, file paths and hashes, audit log
descriptions, and the full raw API payloads. Command lines can contain secrets typed by users or
attackers. Therefore:

- Use strong, unique passwords in `.env` and restrict access to the host.
- Put Grafana behind HTTPS and your SSO if you expose it beyond localhost, and keep sign-up
  disabled.
- Restrict Grafana users and folders. Every Grafana viewer can see all collected data.
- Back up and delete data following your retention and privacy obligations. For example, delete
  old rows with `DELETE FROM security_events WHERE persistence_ts < now() - interval '180 days'`.
- Rotate the Elements API client secret if you think it has leaked, and delete unused API clients
  in Elements.
- Before sharing logs, screenshots or database dumps, make sure they contain no real tenant or
  customer data.
