"""Integration tests against a real PostgreSQL. Skipped unless TEST_DATABASE_URL is set.

docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=test postgres:16-alpine
TEST_DATABASE_URL=postgresql://postgres:test@localhost:55432/postgres pytest -m db
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

from elements_pulse.collectors.incidents import normalize_incident
from elements_pulse.collectors.security_events import normalize_security_event
from elements_pulse.db import create_pool, migrate
from elements_pulse.repository import Repository, RunStats
from elements_pulse.seed import DATA_TABLES, seed_database

from .conftest import ORG_ID, load_fixture

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="TEST_DATABASE_URL unset"),
]


@pytest.fixture
async def db_repo():
    pool = create_pool(os.environ["TEST_DATABASE_URL"])
    await pool.open(wait=True)
    await migrate(pool)
    async with pool.connection() as conn:
        await conn.execute("TRUNCATE " + ", ".join(DATA_TABLES))
    try:
        yield Repository(pool)
    finally:
        await pool.close()


async def _count(repo: Repository, table: str) -> int:
    async with repo.pool.connection() as conn:
        cur = await conn.execute(f"SELECT count(*) FROM {table}")
        row = await cur.fetchone()
    return int(row[0])


async def test_migrations_are_idempotent(db_repo):
    assert await migrate(db_repo.pool) == []


async def test_upserts_never_duplicate(db_repo):
    items = (
        load_fixture("incidents_page1.json")["items"]
        + load_fixture("incidents_page2.json")["items"]
    )
    rows = [normalize_incident(i, ORG_ID) for i in items]
    await db_repo.upsert_incidents(rows)
    rows[0]["status"] = "closed"
    await db_repo.upsert_incidents(rows)
    assert await _count(db_repo, "incidents") == 2
    async with db_repo.pool.connection() as conn:
        cur = await conn.execute(
            "SELECT status, raw->>'incidentPublicId' FROM incidents"
            " WHERE public_id = '1000-DEMO0001'"
        )
        assert await cur.fetchone() == ("closed", "1000-DEMO0001")

    events = [
        normalize_security_event(i, "epp", ORG_ID)
        for i in load_fixture("security_events.json")["items"]
    ]
    for _ in range(3):
        await db_repo.upsert_security_events(events)
    assert await _count(db_repo, "security_events") == 2


async def test_cursor_never_moves_backwards(db_repo):
    t1 = datetime(2026, 1, 10, tzinfo=UTC)
    await db_repo.advance_cursor("incidents", ORG_ID, t1)
    await db_repo.advance_cursor("incidents", ORG_ID, t1 - timedelta(days=5))
    assert await db_repo.get_cursor("incidents", ORG_ID) == t1
    await db_repo.advance_cursor("incidents", ORG_ID, t1 + timedelta(hours=1))
    assert await db_repo.get_cursor("incidents", ORG_ID) == t1 + timedelta(hours=1)


async def test_run_bookkeeping_and_health_view(db_repo):
    run_id = await db_repo.start_run("incidents", ORG_ID, 300)
    await db_repo.finish_run(run_id, "incidents", ORG_ID, "error", RunStats(), error="boom")
    run_id = await db_repo.start_run("incidents", ORG_ID, 300)
    await db_repo.finish_run(run_id, "incidents", ORG_ID, "ok", RunStats(fetched=3))
    health = await db_repo.collector_health()
    assert health[0]["consecutive_failures"] == 0
    assert health[0]["stale"] is False


async def test_seed_and_dashboard_views(db_repo):
    counts = await seed_database(db_repo, days=5, org_count=2)
    assert counts["organizations"] == 2
    assert counts["security_events"] > 0 and counts["incidents"] > 0
    async with db_repo.pool.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*), count(*) FILTER (WHERE outdated) FROM v_device_agent_status"
        )
        total, _outdated = await cur.fetchone()
        assert total == counts["devices"]
        cur = await conn.execute("SELECT count(*) FROM v_collector_health")
        assert (await cur.fetchone())[0] == 12
    # Seeding again with the same seed is idempotent for data tables.
    await seed_database(db_repo, days=5, org_count=2)
    assert await _count(db_repo, "incidents") == counts["incidents"]


async def test_devices_removed_after_snapshot(db_repo):
    from elements_pulse.collectors.devices import normalize_device

    dev = normalize_device(load_fixture("devices.json")["items"][0], ORG_ID)
    await db_repo.upsert_devices([dev])
    snapshot = datetime.now(UTC) + timedelta(seconds=1)
    assert await db_repo.mark_devices_removed(ORG_ID, snapshot) == 1
    await db_repo.upsert_devices([dev])  # seen again -> back
    async with db_repo.pool.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM v_devices_current")
        assert (await cur.fetchone())[0] == 1
