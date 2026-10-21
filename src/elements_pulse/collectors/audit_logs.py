"""Audit logs (actions performed in Elements)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from elements_pulse.collectors.base import IncrementalCollector, as_uuid
from elements_pulse.repository import RunStats
from elements_pulse.timeutil import fmt_ts, parse_ts, time_windows, utcnow

AUDIT_LOGS_PATH = "/audit-logs/v1/audit-logs"
PAGE_SIZE = 200  # API maximum
MAX_WINDOW = timedelta(days=30)  # API caps queries at 31 days


def normalize_audit_log(item: dict[str, Any], fallback_org: UUID) -> dict[str, Any] | None:
    entry_id = item.get("id")
    server_ts = parse_ts(item.get("serverTimestamp"))
    if not entry_id or server_ts is None:
        return None
    org = item.get("organization") or {}
    target = item.get("target") or {}
    return {
        "id": str(entry_id),
        "organization_id": as_uuid(org.get("id")) or fallback_org,
        "server_ts": server_ts,
        "namespace": item.get("namespace"),
        "action": item.get("action"),
        "username": item.get("username"),
        "target_id": target.get("id"),
        "target_name": target.get("name"),
        "description": item.get("description"),
        "raw": item,
    }


class AuditLogsCollector(IncrementalCollector):
    name = "audit_logs"

    @property
    def _cfg(self):
        return self.settings.collectors.audit_logs

    @property
    def interval(self) -> timedelta:
        return timedelta(minutes=self._cfg.interval_minutes)

    @property
    def backfill(self) -> timedelta:
        return timedelta(days=self._cfg.backfill_days)

    @property
    def overlap(self) -> timedelta:
        return timedelta(minutes=self._cfg.overlap_minutes)

    async def collect(
        self, org_id: UUID, stats: RunStats, *, since: datetime | None = None
    ) -> None:
        start = await self.start_from(org_id, since)
        end = utcnow()
        for window_start, window_end in time_windows(start, end, MAX_WINDOW):
            params = {
                "organizationId": org_id,
                "serverTimestampStart": fmt_ts(window_start),
                "serverTimestampEnd": fmt_ts(window_end),
                "order": "asc",
                "language": "en",
                "limit": PAGE_SIZE,
            }
            observed: dict[UUID, str | None] = {}
            async for items in self.client.paginate(
                "GET", AUDIT_LOGS_PATH, params=params, org_id=org_id
            ):
                stats.fetched += len(items)
                rows = [r for r in (normalize_audit_log(i, org_id) for i in items) if r]
                for item in items:
                    org = item.get("organization") or {}
                    org_uuid = as_uuid(org.get("id"))
                    if org_uuid:
                        observed[org_uuid] = org.get("name")
                stats.upserted += await self.repo.upsert_audit_logs(rows)
                newest = max((r["server_ts"] for r in rows), default=None)
                if newest:
                    await self.repo.advance_cursor(self.key, org_id, newest)
            await self.repo.observe_organizations(observed)
            await self.repo.advance_cursor(self.key, org_id, window_end)
