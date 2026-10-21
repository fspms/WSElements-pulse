"""Wiring shared by the CLI commands."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from psycopg_pool import AsyncConnectionPool

from elements_pulse.api.client import Credentials, ElementsClient
from elements_pulse.config import ConfigError, Settings
from elements_pulse.db import create_pool, migrate
from elements_pulse.repository import Repository


def credentials_from(settings: Settings) -> Credentials:
    if not settings.has_credentials:
        raise ConfigError(
            "Missing API credentials: set ELEMENTS_CLIENT_ID and ELEMENTS_CLIENT_SECRET "
            "(or ELEMENTS_CLIENT_ID_FILE / ELEMENTS_CLIENT_SECRET_FILE)."
        )
    assert settings.client_id is not None and settings.client_secret is not None
    return Credentials(
        settings.client_id.get_secret_value(), settings.client_secret.get_secret_value()
    )


@asynccontextmanager
async def open_repository(
    settings: Settings, *, run_migrations: bool | None = None
) -> AsyncIterator[Repository]:
    pool: AsyncConnectionPool = create_pool(settings.database_url.get_secret_value())
    await pool.open(wait=True, timeout=60)
    try:
        if settings.auto_migrate if run_migrations is None else run_migrations:
            await migrate(pool)
        yield Repository(pool)
    finally:
        await pool.close()


@asynccontextmanager
async def open_client(
    settings: Settings, repo: Repository | None = None
) -> AsyncIterator[ElementsClient]:
    hook = repo.insert_api_request if repo is not None else None
    async with ElementsClient(settings.api, credentials_from(settings), on_request=hook) as client:
        yield client
