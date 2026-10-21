## What and why

<!-- Short description of the change. -->

## Checklist

- [ ] No real credentials, tenant/organization names, device names, usernames or customer data
      anywhere (code, tests, fixtures, screenshots, this PR).
- [ ] Still read-only: no write endpoint, no `connect.api.write`.
- [ ] Only documented API endpoints are used.
- [ ] Tests added/updated; `ruff check .`, `ruff format --check .` and `pytest` pass.
- [ ] Dashboards regenerated with `python scripts/build_dashboards.py` (if changed).
- [ ] `CHANGELOG.md` updated under *Unreleased*.
