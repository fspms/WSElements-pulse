"""Database connection pool and migrations runner."""

from __future__ import annotations

from importlib import resources

from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

from elements_pulse.logs import get_logger

log = get_logger(__name__)

# Arbitrary constant used as a PostgreSQL advisory lock so two collectors never migrate at once.
_MIGRATION_LOCK_ID = 727_421_001


async def _configure(conn: AsyncConnection) -> None:
    await conn.execute("SET TIME ZONE 'UTC'")


def create_pool(database_url: str, *, max_size: int = 8) -> AsyncConnectionPool:
    return AsyncConnectionPool(
        conninfo=database_url,
        min_size=1,
        max_size=max_size,
        open=False,
        kwargs={"autocommit": True},
        configure=_configure,
    )


def _migration_files() -> list[tuple[str, str]]:
    package = resources.files("elements_pulse.migrations")
    files = sorted(
        (entry.name, entry.read_text(encoding="utf-8"))
        for entry in package.iterdir()
        if entry.name.endswith(".sql")
    )
    return files


async def migrate(pool: AsyncConnectionPool) -> list[str]:
    """Apply pending SQL migrations in order. Returns the list of applied versions."""
    applied: list[str] = []
    async with pool.connection() as conn:
        await conn.execute("SELECT pg_advisory_lock(%s)", (_MIGRATION_LOCK_ID,))
        try:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                " version text PRIMARY KEY,"
                " applied_at timestamptz NOT NULL DEFAULT now())"
            )
            cur = await conn.execute("SELECT version FROM schema_migrations")
            done = {row[0] for row in await cur.fetchall()}
            for name, sql_text in _migration_files():
                if name in done:
                    continue
                log.info("applying_migration", version=name)
                async with conn.transaction():
                    await conn.execute(sql_text)  # type: ignore[arg-type]
                    await conn.execute(
                        "INSERT INTO schema_migrations (version) VALUES (%s)", (name,)
                    )
                applied.append(name)
        finally:
            await conn.execute("SELECT pg_advisory_unlock(%s)", (_MIGRATION_LOCK_ID,))
    return applied
