"""Security events (EPP, EDR and optionally Collaboration Protection / Exposure Management)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from elements_pulse.collectors.base import IncrementalCollector, as_uuid
from elements_pulse.config import Settings
from elements_pulse.repository import Repository, RunStats
from elements_pulse.timeutil import fmt_ts, parse_ts, time_windows, utcnow

SECURITY_EVENTS_PATH = "/security-events/v1/security-events"
PAGE_SIZE = 200  # API maximum
# The API rejects ranges longer than 31 days; stay a bit below.
MAX_WINDOW = timedelta(days=30)


def normalize_security_event(
    item: dict[str, Any], engine_group: str, fallback_org: UUID
) -> dict[str, Any] | None:
    event_id = item.get("id")
    persistence_ts = parse_ts(item.get("persistenceTimestamp"))
    if not event_id or persistence_ts is None:
        return None
    details = item.get("details") or {}
    device = item.get("device") or {}
    target = item.get("target") or {}
    org = item.get("organization") or {}
    return {
        "event_id": str(event_id),
        "organization_id": as_uuid(org.get("id")) or fallback_org,
        "engine": item.get("engine"),
        "engine_group": engine_group,
        "severity": item.get("severity"),
        "action": item.get("action"),
        "alert_type": details.get("alertType"),
        "infection_name": details.get("infectionName") or details.get("name"),
        "persistence_ts": persistence_ts,
        "server_ts": parse_ts(item.get("serverTimestamp")),
        "client_ts": parse_ts(item.get("clientTimestamp")),
        "device_id": device.get("id"),
        "device_name": device.get("name"),
        "target_id": target.get("id"),
        "target_name": target.get("name"),
        "user_name": item.get("userName"),
        "acknowledged": item.get("acknowledged"),
        "message": item.get("message"),
        "description": item.get("description"),
        "raw": item,
    }


class SecurityEventsCollector(IncrementalCollector):
    """One instance per engine group, each with its own cursor (``security_events:<group>``).

    Uses ``persistenceTimestamp`` (time the event was stored), which is stable for polling.
    Ranges are split into windows of at most 30 days because the API caps queries at 31 days.
    """

    name = "security_events"

    def __init__(
        self, client: Any, repo: Repository, settings: Settings, engine_group: str
    ) -> None:
        super().__init__(client, repo, settings)
        self.engine_group = engine_group

    @property
    def key(self) -> str:
        return f"{self.name}:{self.engine_group}"

    @property
    def _cfg(self):
        return self.settings.collectors.security_events

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
            await self._collect_window(org_id, window_start, window_end, stats)
            # Window fully read: the cursor can move to its end even if it was empty.
            await self.repo.advance_cursor(self.key, org_id, window_end)

    async def _collect_window(
        self, org_id: UUID, start: datetime, end: datetime, stats: RunStats
    ) -> None:
        data = {
            "organizationId": str(org_id),
            "engineGroup": [self.engine_group],
            "persistenceTimestampStart": fmt_ts(start),
            "persistenceTimestampEnd": fmt_ts(end),
            "order": "asc",
            "limit": PAGE_SIZE,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        observed: dict[UUID, str | None] = {}
        async for items in self.client.paginate(
            "POST", SECURITY_EVENTS_PATH, data=data, headers=headers, org_id=org_id
        ):
            stats.fetched += len(items)
            rows = [
                r
                for r in (normalize_security_event(i, self.engine_group, org_id) for i in items)
                if r
            ]
            for item in items:
                org = item.get("organization") or {}
                org_uuid = as_uuid(org.get("id"))
                if org_uuid:
                    observed[org_uuid] = org.get("name")
            stats.upserted += await self.repo.upsert_security_events(rows)
            newest = max((r["persistence_ts"] for r in rows), default=None)
            if newest:
                await self.repo.advance_cursor(self.key, org_id, newest)
        await self.repo.observe_organizations(observed)
