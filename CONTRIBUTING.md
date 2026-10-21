# Contributing

Thanks for helping. This is a community project: it is not affiliated with or supported by
WithSecure.

## Ground rules

1. **No real data, ever.** No real credentials, tenant or organization names, device names,
   usernames, email addresses, IPs or customer data in code, tests, fixtures, dashboards,
   screenshots, issues or commit history. Use `example.com`, `DEMO-*` hosts, "Demo Org ..."
   names and placeholder UUIDs such as `00000000-0000-4000-8000-0000000000a1`. When sharing an
   API response in an issue, anonymize it first.
2. **Read-only.** The collector must never modify anything in Elements. New endpoints go into
   `READ_ONLY_ALLOWLIST` in `src/elements_pulse/api/client.py`, and only if they are read
   operations available with the `connect.api.read` scope. PRs that request `connect.api.write`
   or call write endpoints will not be merged.
3. **No guessed endpoints.** Only implement API paths documented in the official Elements API
   reference. If something is unclear, open an issue or leave a clear `TODO`.
4. **No WithSecure logos or branding**, and nothing that implies official status.

## Development setup

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check . && ruff format --check .
pytest                     # unit tests (HTTP mocked with respx)
```

Database integration tests need PostgreSQL:

```bash
docker run --rm -d --name pulse-testdb -p 127.0.0.1:55432:5432 \
  -e POSTGRES_PASSWORD=test postgres:16-alpine
TEST_DATABASE_URL=postgresql://postgres:test@127.0.0.1:55432/postgres pytest -m db
```

## Typical changes

- **New collector**: add a module in `src/elements_pulse/collectors/`, with a pure
  `normalize_*` function plus a `Collector` subclass. Add a migration (a new numbered SQL file,
  never edit an applied one), settings in `config.py`, registration in `collectors/__init__.py`,
  tests with fictional fixtures, seed data in `seed.py`, and docs.
- **Dashboards**: edit `scripts/build_dashboards.py`, run it, and commit both the script and the
  generated JSON. Check the result with `seed` data. Keep the conventions: severity colors
  only for severity/state and always with their label, fixed series colors, no dual axes.
- **Schema**: add `src/elements_pulse/migrations/NNNN_description.sql`.

## Pull requests

- Keep PRs focused, with tests and a `CHANGELOG.md` entry under *Unreleased*.
- CI (ruff, pytest with PostgreSQL, dashboard generation check, Docker build) must pass.
- Write code, comments and docs in English.
- By contributing you agree that your contribution is licensed under the MIT license.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).
