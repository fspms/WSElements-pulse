"""Command line interface: ``elements-pulse <command>``."""

from __future__ import annotations

import asyncio
import contextlib
import signal
import sys
from datetime import timedelta
from typing import Annotated, Any
from uuid import UUID

import typer

from elements_pulse import __version__
from elements_pulse.api.errors import ElementsApiError
from elements_pulse.collectors import COLLECTOR_NAMES, build_collectors, run_once
from elements_pulse.collectors.organizations import resolve_organizations, whoami
from elements_pulse.config import READ_SCOPE, ConfigError, Settings, load_settings
from elements_pulse.db import create_pool, migrate
from elements_pulse.health import start_health_server
from elements_pulse.logs import configure_logging, get_logger
from elements_pulse.runtime import open_client, open_repository
from elements_pulse.scheduler import Scheduler
from elements_pulse.timeutil import fmt_ts, utcnow

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Unofficial collector for WithSecure Elements API data (read-only).",
)
log = get_logger("elements_pulse.cli")

ConfigOption = Annotated[
    str | None,
    typer.Option("--config", "-c", help="YAML config file (or set PULSE_CONFIG_FILE)."),
]


def _settings(config: str | None) -> Settings:
    try:
        settings = load_settings(config)
    except (ConfigError, ValueError) as exc:
        typer.secho(f"Configuration error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    configure_logging(settings.log_level, settings.log_format)
    return settings


def _fail(message: str, code: int = 1) -> typer.Exit:
    typer.secho(message, fg=typer.colors.RED, err=True)
    return typer.Exit(code)


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


@app.command("migrate")
def migrate_cmd(config: ConfigOption = None) -> None:
    """Apply database migrations."""
    settings = _settings(config)

    async def _run() -> list[str]:
        pool = create_pool(settings.database_url.get_secret_value())
        await pool.open(wait=True, timeout=60)
        try:
            return await migrate(pool)
        finally:
            await pool.close()

    applied = asyncio.run(_run())
    typer.echo(f"Applied {len(applied)} migration(s): {', '.join(applied) or 'none'}")


@app.command()
def run(config: ConfigOption = None) -> None:
    """Run the collectors continuously (until SIGINT/SIGTERM)."""
    settings = _settings(config)
    try:
        asyncio.run(_run_forever(settings))
    except ConfigError as exc:
        raise _fail(str(exc), 2) from exc


async def _run_forever(settings: Settings) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # pragma: no cover - Windows
            loop.add_signal_handler(sig, stop.set)

    async with open_repository(settings) as repo, open_client(settings, repo) as client:
        scheduler = Scheduler(client, repo, settings)

        async def probe() -> tuple[bool, dict[str, Any]]:
            db_ok = True
            collectors: list[dict[str, Any]] = []
            try:
                collectors = await repo.collector_health()
            except Exception:
                db_ok = False
            stale = [f"{c['collector']}:{c['organization_id']}" for c in collectors if c["stale"]]
            return db_ok and scheduler.started, {
                "database": db_ok,
                "scheduler_started": scheduler.started,
                "stale_collectors": stale,
            }

        server = await start_health_server(settings.health.host, settings.health.port, probe)
        try:
            await scheduler.run(stop)
        finally:
            server.close()
            await server.wait_closed()


@app.command()
def backfill(
    days: Annotated[int, typer.Option(min=1, max=3650, help="How many days back to fetch.")],
    collector: Annotated[
        list[str] | None,
        typer.Option("--collector", help=f"Limit to collector(s): {', '.join(COLLECTOR_NAMES)}"),
    ] = None,
    org: Annotated[
        list[str] | None, typer.Option("--org", help="Limit to organization UUID(s).")
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Fetch history once (ignores cursors, never moves them backwards), then exit."""
    settings = _settings(config)
    only = set(collector) if collector else None
    if only and not only <= set(COLLECTOR_NAMES):
        raise _fail(f"Unknown collector(s): {', '.join(sorted(only - set(COLLECTOR_NAMES)))}", 2)
    try:
        orgs_filter = [UUID(o) for o in org] if org else None
    except ValueError as exc:
        raise _fail(f"Invalid organization UUID: {exc}", 2) from exc

    async def _run() -> int:
        failures = 0
        since = utcnow() - timedelta(days=days)
        async with open_repository(settings) as repo, open_client(settings, repo) as client:
            orgs = orgs_filter or await resolve_organizations(client, repo, settings)
            collectors = build_collectors(client, repo, settings, only=only)
            # Devices and detections have no time window; they just run once.
            for org_id in orgs:
                for c in collectors:
                    status, stats = await run_once(c, org_id, since=since)
                    failures += status != "ok"
                    typer.echo(
                        f"{c.key:<24} {org_id}  {status:<6} fetched={stats.fetched} "
                        f"upserted={stats.upserted} api_calls={stats.api_calls}"
                    )
        return failures

    try:
        failures = asyncio.run(_run())
    except ConfigError as exc:
        raise _fail(str(exc), 2) from exc
    raise typer.Exit(1 if failures else 0)


@app.command()
def check(
    config: ConfigOption = None,
    skip_db: Annotated[bool, typer.Option("--skip-db", help="Do not test the database.")] = False,
) -> None:
    """Validate credentials, the read scope and access to each enabled endpoint."""
    settings = _settings(config)
    results: list[tuple[str, bool, str]] = []

    async def _run() -> None:
        async with open_client(settings) as client:
            try:
                await client.access_token()
                results.append(("token", True, f"obtained with scope '{READ_SCOPE}' only"))
                me = await whoami(client)
                results.append(
                    ("whoami", True, f"client={me.get('clientId')} org={me.get('organizationId')}")
                )
                orgs = await resolve_organizations(client, None, settings)
                results.append(("organizations", True, ", ".join(str(o) for o in orgs)))
            except ElementsApiError as exc:
                results.append(("authentication", False, str(exc)))
                return
            await _probe_endpoints(client, settings, orgs[0], results)

        if not skip_db:
            try:
                async with open_repository(settings, run_migrations=False) as repo:
                    await repo.ping()
                results.append(("database", True, "reachable"))
            except Exception as exc:
                results.append(("database", False, str(exc)))

    try:
        asyncio.run(_run())
    except ConfigError as exc:
        raise _fail(str(exc), 2) from exc

    for name, ok, detail in results:
        mark = (
            typer.style("OK  ", fg=typer.colors.GREEN)
            if ok
            else typer.style("FAIL", fg=typer.colors.RED)
        )
        typer.echo(f"[{mark}] {name:<28} {detail}")
    typer.echo(
        "\nNote: only the read scope is ever requested. Whether the API client itself also has "
        "write permission cannot be checked from the API; use a read-only API client."
    )
    raise typer.Exit(0 if all(ok for _, ok, _ in results) else 1)


async def _probe_endpoints(
    client: Any, settings: Settings, org_id: UUID, results: list[tuple[str, bool, str]]
) -> None:
    cfg = settings.collectors
    day_ago = fmt_ts(utcnow() - timedelta(days=1))
    probes: list[tuple[str, bool, Any]] = [
        (
            "incidents",
            cfg.incidents.enabled,
            lambda: client.get(
                "/incidents/v1/incidents", {"organizationId": org_id, "limit": 1}, org_id=org_id
            ),
        ),
        (
            "devices",
            cfg.devices.enabled,
            lambda: client.get(
                "/devices/v1/devices", {"organizationId": org_id, "limit": 1}, org_id=org_id
            ),
        ),
        (
            "audit_logs",
            cfg.audit_logs.enabled,
            lambda: client.get(
                "/audit-logs/v1/audit-logs",
                {"organizationId": org_id, "serverTimestampStart": day_ago, "limit": 1},
                org_id=org_id,
            ),
        ),
    ]
    for group in cfg.security_events.engine_groups if cfg.security_events.enabled else []:
        probes.append(
            (
                f"security_events:{group}",
                True,
                lambda group=group: client.post_form(
                    "/security-events/v1/security-events",
                    {
                        "organizationId": str(org_id),
                        "engineGroup": [group],
                        "persistenceTimestampStart": day_ago,
                        "limit": 1,
                    },
                    headers={"Accept": "application/json"},
                    org_id=org_id,
                ),
            )
        )
    for name, enabled, call in probes:
        if not enabled:
            results.append((name, True, "disabled"))
            continue
        try:
            payload = await call()
            results.append((name, True, f"reachable ({len(payload.get('items') or [])} item)"))
        except ElementsApiError as exc:
            results.append((name, False, str(exc)))


@app.command()
def health(config: ConfigOption = None) -> None:
    """Print collector status from the database; exit 1 if a collector is stale or failing."""
    settings = _settings(config)

    async def _run() -> list[dict[str, Any]]:
        async with open_repository(settings, run_migrations=False) as repo:
            return await repo.collector_health()

    rows = asyncio.run(_run())
    if not rows:
        typer.echo("No collector has run yet.")
        raise typer.Exit(1)
    unhealthy = False
    for r in rows:
        bad = r["stale"] or r["consecutive_failures"] > 0
        unhealthy |= bool(r["stale"])
        mark = typer.style(
            "STALE" if r["stale"] else ("WARN " if bad else "OK   "),
            fg=typer.colors.RED
            if r["stale"]
            else (typer.colors.YELLOW if bad else typer.colors.GREEN),
        )
        typer.echo(
            f"[{mark}] {r['collector']:<24} {r['organization_name'] or r['organization_id']}"
            f"  last_success={r['last_success_at']}  failures={r['consecutive_failures']}"
            + (f"  error={r['last_error'][:120]}" if r["last_error"] and bad else "")
        )
    raise typer.Exit(1 if unhealthy else 0)


@app.command()
def seed(
    days: Annotated[int, typer.Option(min=1, max=365, help="Days of fake history.")] = 30,
    organizations: Annotated[int, typer.Option(min=1, max=20)] = 3,
    reset: Annotated[bool, typer.Option("--reset", help="Delete ALL existing data first.")] = False,
    random_seed: Annotated[int, typer.Option(help="Seed for reproducible data.")] = 42,
    config: ConfigOption = None,
) -> None:
    """Fill the database with FICTIONAL demo data (no API access needed)."""
    from elements_pulse.seed import seed_database

    settings = _settings(config)

    async def _run() -> dict[str, int]:
        async with open_repository(settings, run_migrations=True) as repo:
            return await seed_database(
                repo, days=days, org_count=organizations, reset=reset, random_seed=random_seed
            )

    counts = asyncio.run(_run())
    for table, n in counts.items():
        typer.echo(f"{table:<24} {n}")


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:  # pragma: no cover
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
