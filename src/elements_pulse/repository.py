"""All SQL reads/writes. Writes are idempotent upserts (INSERT ... ON CONFLICT)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg import sql
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from elements_pulse.api.client import RequestRecord


@dataclass
class RunStats:
    fetched: int = 0
    upserted: int = 0
    api_calls: int = 0


INCIDENT_COLUMNS = (
    "incident_id",
    "organization_id",
    "public_id",
    "name",
    "status",
    "severity",
    "risk_level",
    "risk_score",
    "resolution",
    "categories",
    "sources",
    "created_at",
    "updated_at",
    "initial_received_at",
    "raw",
)
DETECTION_COLUMNS = (
    "detection_id",
    "incident_id",
    "organization_id",
    "device_id",
    "name",
    "detection_class",
    "severity",
    "risk_level",
    "exe_name",
    "exe_path",
    "exe_hash",
    "cmdl",
    "username",
    "mitre",
    "created_at",
    "raw",
)
SECURITY_EVENT_COLUMNS = (
    "event_id",
    "organization_id",
    "engine",
    "engine_group",
    "severity",
    "action",
    "alert_type",
    "infection_name",
    "persistence_ts",
    "server_ts",
    "client_ts",
    "device_id",
    "device_name",
    "target_id",
    "target_name",
    "user_name",
    "acknowledged",
    "message",
    "description",
    "raw",
)
DEVICE_COLUMNS = (
    "device_id",
    "organization_id",
    "polled_organization_id",
    "name",
    "type",
    "state",
    "os_name",
    "os_version",
    "os_end_of_life",
    "client_version",
    "protection_status",
    "protection_status_overview",
    "malware_state",
    "firewall_state",
    "patch_overall_state",
    "online",
    "last_user",
    "product_variant",
    "status_update_at",
    "registered_at",
    "raw",
)
AUDIT_LOG_COLUMNS = (
    "id",
    "organization_id",
    "server_ts",
    "namespace",
    "action",
    "username",
    "target_id",
    "target_name",
    "description",
    "raw",
)


def _upsert_sql(
    table: str, columns: Sequence[str], key: Sequence[str], *, touch: bool = True
) -> sql.Composed:
    updates = [
        sql.SQL("{c} = EXCLUDED.{c}").format(c=sql.Identifier(c)) for c in columns if c not in key
    ]
    if touch:
        updates.append(sql.SQL("last_collected_at = now()"))
    return sql.SQL(
        "INSERT INTO {table} ({cols}) VALUES ({vals}) ON CONFLICT ({key}) DO UPDATE SET {upd}"
    ).format(
        table=sql.Identifier(table),
        cols=sql.SQL(", ").join(map(sql.Identifier, columns)),
        vals=sql.SQL(", ").join(sql.Placeholder() * len(columns)),
        key=sql.SQL(", ").join(map(sql.Identifier, key)),
        upd=sql.SQL(", ").join(updates),
    )


def _row(record: dict[str, Any], columns: Sequence[str]) -> tuple[Any, ...]:
    return tuple(Jsonb(record[c]) if c == "raw" else record.get(c) for c in columns)


class Repository:
    def __init__(self, pool: AsyncConnectionPool):
        self.pool = pool

    async def ping(self) -> bool:
        async with self.pool.connection() as conn:
            await conn.execute("SELECT 1")
        return True

    # ------------------------------------------------------------ generic

    async def _upsert_many(
        self,
        table: str,
        columns: Sequence[str],
        key: Sequence[str],
        records: Iterable[dict[str, Any]],
    ) -> int:
        rows = [_row(r, columns) for r in records]
        if not rows:
            return 0
        query = _upsert_sql(table, columns, key)
        async with self.pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            await cur.executemany(query, rows)
        return len(rows)

    # ------------------------------------------------------- organizations

    async def upsert_organizations(
        self, orgs: Iterable[tuple[UUID, str | None, str | None]], source: str
    ) -> None:
        rows = [(org_id, name, org_type, source) for org_id, name, org_type in orgs]
        if not rows:
            return
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.executemany(
                "INSERT INTO organizations (id, name, type, source) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET "
                " name = COALESCE(EXCLUDED.name, organizations.name),"
                " type = COALESCE(EXCLUDED.type, organizations.type),"
                " source = CASE WHEN organizations.source = 'observed' THEN EXCLUDED.source"
                "               ELSE organizations.source END,"
                " updated_at = now()",
                rows,
            )

    async def observe_organizations(self, orgs: dict[UUID, str | None]) -> None:
        """Record organizations seen inside API records (names for the Grafana variable)."""
        if not orgs:
            return
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.executemany(
                "INSERT INTO organizations (id, name, source) VALUES (%s, %s, 'observed') "
                "ON CONFLICT (id) DO UPDATE SET"
                " name = COALESCE(EXCLUDED.name, organizations.name), updated_at = now()"
                " WHERE organizations.name IS DISTINCT FROM COALESCE(EXCLUDED.name,"
                " organizations.name)",
                list(orgs.items()),
            )

    # ---------------------------------------------------------- sync state

    async def get_cursor(self, collector: str, org_id: UUID) -> datetime | None:
        async with self.pool.connection() as conn:
            cur = await conn.execute(
                "SELECT cursor_ts FROM sync_state WHERE collector = %s AND organization_id = %s",
                (collector, org_id),
            )
            row = await cur.fetchone()
        return row[0] if row else None

    async def advance_cursor(self, collector: str, org_id: UUID, ts: datetime) -> None:
        """Move the cursor forward only (never backwards)."""
        async with self.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO sync_state (collector, organization_id, cursor_ts) "
                "VALUES (%s, %s, %s) ON CONFLICT (collector, organization_id) DO UPDATE SET "
                "cursor_ts = GREATEST(COALESCE(sync_state.cursor_ts, EXCLUDED.cursor_ts),"
                " EXCLUDED.cursor_ts)",
                (collector, org_id, ts),
            )

    async def start_run(self, collector: str, org_id: UUID, interval_seconds: int) -> int:
        async with self.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO sync_state (collector, organization_id, last_run_started_at,"
                " interval_seconds) VALUES (%s, %s, now(), %s) "
                "ON CONFLICT (collector, organization_id) DO UPDATE SET"
                " last_run_started_at = now(), interval_seconds = EXCLUDED.interval_seconds",
                (collector, org_id, interval_seconds),
            )
            cur = await conn.execute(
                "INSERT INTO collector_runs (collector, organization_id) VALUES (%s, %s)"
                " RETURNING id",
                (collector, org_id),
            )
            row = await cur.fetchone()
        assert row is not None
        return int(row[0])

    async def finish_run(
        self,
        run_id: int,
        collector: str,
        org_id: UUID,
        status: str,
        stats: RunStats,
        error: str | None = None,
    ) -> None:
        async with self.pool.connection() as conn, conn.transaction():
            await conn.execute(
                "UPDATE collector_runs SET finished_at = now(), status = %s, items_fetched = %s,"
                " items_upserted = %s, api_calls = %s, error = %s WHERE id = %s",
                (status, stats.fetched, stats.upserted, stats.api_calls, error, run_id),
            )
            if status == "ok":
                await conn.execute(
                    "UPDATE sync_state SET last_success_at = now(), consecutive_failures = 0"
                    " WHERE collector = %s AND organization_id = %s",
                    (collector, org_id),
                )
            elif status == "error":
                await conn.execute(
                    "UPDATE sync_state SET last_error = %s, last_error_at = now(),"
                    " consecutive_failures = consecutive_failures + 1"
                    " WHERE collector = %s AND organization_id = %s",
                    ((error or "")[:2000], collector, org_id),
                )

    async def collector_health(self) -> list[dict[str, Any]]:
        async with self.pool.connection() as conn:
            cur = await conn.execute(
                "SELECT collector, organization_id, organization_name, last_success_at,"
                " last_error, consecutive_failures, interval_seconds, stale"
                " FROM v_collector_health ORDER BY collector, organization_id"
            )
            cols = [d.name for d in cur.description or []]
            return [dict(zip(cols, row, strict=True)) for row in await cur.fetchall()]

    # -------------------------------------------------------------- metrics

    async def insert_api_request(self, rec: RequestRecord) -> None:
        async with self.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO api_requests (ts, organization_id, method, endpoint, status,"
                " duration_ms, attempt) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    rec.ts,
                    rec.organization_id,
                    rec.method,
                    rec.endpoint,
                    rec.status,
                    rec.duration_ms,
                    rec.attempt,
                ),
            )

    async def purge(self, api_requests_days: int, collector_runs_days: int) -> None:
        async with self.pool.connection() as conn:
            await conn.execute(
                "DELETE FROM api_requests WHERE ts < now() - make_interval(days => %s)",
                (api_requests_days,),
            )
            await conn.execute(
                "DELETE FROM collector_runs WHERE started_at < now() - make_interval(days => %s)",
                (collector_runs_days,),
            )

    # ------------------------------------------------------------ incidents

    async def upsert_incidents(self, records: Iterable[dict[str, Any]]) -> int:
        return await self._upsert_many("incidents", INCIDENT_COLUMNS, ("incident_id",), records)

    async def incidents_needing_detections(self, org_id: UUID, limit: int) -> list[UUID]:
        """Incidents whose detections were never fetched or changed since the last fetch."""
        async with self.pool.connection() as conn:
            cur = await conn.execute(
                "SELECT incident_id FROM incidents WHERE organization_id = %s"
                " AND (detections_synced_at IS NULL OR detections_synced_at < updated_at)"
                " ORDER BY updated_at DESC NULLS LAST LIMIT %s",
                (org_id, limit),
            )
            return [row[0] for row in await cur.fetchall()]

    async def upsert_detections(self, records: Iterable[dict[str, Any]]) -> int:
        return await self._upsert_many(
            "incident_detections", DETECTION_COLUMNS, ("detection_id",), records
        )

    async def mark_detections_synced(self, incident_id: UUID, synced_at: datetime) -> None:
        async with self.pool.connection() as conn:
            await conn.execute(
                "UPDATE incidents SET detections_synced_at = %s WHERE incident_id = %s",
                (synced_at, incident_id),
            )

    # ------------------------------------------------------ security events

    async def upsert_security_events(self, records: Iterable[dict[str, Any]]) -> int:
        return await self._upsert_many(
            "security_events", SECURITY_EVENT_COLUMNS, ("event_id",), records
        )

    # -------------------------------------------------------------- devices

    async def upsert_devices(self, records: Iterable[dict[str, Any]]) -> int:
        recs = [{**r, "removed_at": None} for r in records]
        return await self._upsert_many(
            "devices", (*DEVICE_COLUMNS, "removed_at"), ("device_id",), recs
        )

    async def mark_devices_removed(self, org_id: UUID, snapshot_started: datetime) -> int:
        """Devices of this org not returned by a complete snapshot are flagged as removed."""
        async with self.pool.connection() as conn:
            cur = await conn.execute(
                "UPDATE devices SET removed_at = now() WHERE polled_organization_id = %s"
                " AND removed_at IS NULL AND last_collected_at < %s",
                (org_id, snapshot_started),
            )
            return cur.rowcount

    async def refresh_device_status_daily(self, org_id: UUID) -> None:
        async with self.pool.connection() as conn, conn.transaction():
            await conn.execute(
                "DELETE FROM device_status_daily WHERE day = CURRENT_DATE AND organization_id IN"
                " (SELECT DISTINCT organization_id FROM devices WHERE polled_organization_id = %s)",
                (org_id,),
            )
            await conn.execute(
                "INSERT INTO device_status_daily (day, organization_id,"
                " protection_status_overview, count)"
                " SELECT CURRENT_DATE, organization_id,"
                " COALESCE(protection_status_overview, 'unknown'), count(*)"
                " FROM devices WHERE polled_organization_id = %s AND removed_at IS NULL"
                " AND state = 'active' GROUP BY 1, 2, 3",
                (org_id,),
            )

    # ----------------------------------------------------------- audit logs

    async def upsert_audit_logs(self, records: Iterable[dict[str, Any]]) -> int:
        return await self._upsert_many("audit_logs", AUDIT_LOG_COLUMNS, ("id",), records)
