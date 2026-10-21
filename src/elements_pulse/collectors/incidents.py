"""Broad Context Detections (incidents) and their detections."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from elements_pulse.collectors.base import Collector, IncrementalCollector, as_uuid
from elements_pulse.logs import get_logger
from elements_pulse.repository import RunStats
from elements_pulse.timeutil import fmt_ts, parse_ts, utcnow

log = get_logger(__name__)

INCIDENTS_PATH = "/incidents/v1/incidents"
DETECTIONS_PATH = "/incidents/v1/detections"
INCIDENTS_PAGE_SIZE = 50  # API maximum
DETECTIONS_PAGE_SIZE = 100  # API maximum


def normalize_incident(item: dict[str, Any], fallback_org: UUID) -> dict[str, Any] | None:
    incident_id = as_uuid(item.get("incidentId"))
    if incident_id is None:
        return None
    score = item.get("riskScore")
    return {
        "incident_id": incident_id,
        "organization_id": as_uuid(item.get("organizationId")) or fallback_org,
        "public_id": item.get("incidentPublicId"),
        "name": item.get("name"),
        "status": item.get("status"),
        "severity": item.get("severity"),
        "risk_level": item.get("riskLevel"),
        "risk_score": float(score) if isinstance(score, int | float) else None,
        "resolution": item.get("resolution"),
        "categories": [str(c) for c in item.get("categories") or []],
        "sources": [str(s) for s in item.get("sources") or []],
        "created_at": parse_ts(item.get("createdTimestamp")),
        "updated_at": parse_ts(item.get("updatedTimestamp")),
        "initial_received_at": parse_ts(item.get("initialReceivedTimestamp")),
        "raw": item,
    }


def normalize_detection(
    item: dict[str, Any], incident_id: UUID, org_id: UUID
) -> dict[str, Any] | None:
    detection_id = item.get("detectionId")
    if not detection_id:
        return None
    return {
        "detection_id": str(detection_id),
        "incident_id": as_uuid(item.get("incidentId")) or incident_id,
        "organization_id": org_id,
        "device_id": item.get("deviceId"),
        "name": item.get("name"),
        "detection_class": item.get("detectionClass"),
        "severity": item.get("severity"),
        "risk_level": item.get("riskLevel"),
        "exe_name": item.get("exeName"),
        "exe_path": item.get("exePath"),
        "exe_hash": item.get("exeHash"),
        "cmdl": item.get("cmdl"),
        "username": item.get("username"),
        "mitre": [str(m) for m in item.get("mitre") or []],
        "created_at": parse_ts(item.get("createdTimestamp")),
        "raw": item,
    }


class IncidentsCollector(IncrementalCollector):
    """Incremental sync on ``updatedTimestamp`` (incidents evolve after creation)."""

    name = "incidents"

    @property
    def _cfg(self):
        return self.settings.collectors.incidents

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
        params = {
            "organizationId": org_id,
            "updatedTimestampStart": fmt_ts(start),
            "order": "asc",
            "limit": INCIDENTS_PAGE_SIZE,
        }
        async for items in self.client.paginate(
            "GET", INCIDENTS_PATH, params=params, org_id=org_id
        ):
            stats.fetched += len(items)
            rows = [r for r in (normalize_incident(i, org_id) for i in items) if r]
            stats.upserted += await self.repo.upsert_incidents(rows)
            newest = max((r["updated_at"] for r in rows if r["updated_at"]), default=None)
            if newest:
                # Ascending order: everything up to `newest` on this page is stored.
                await self.repo.advance_cursor(self.key, org_id, newest)


class DetectionsCollector(Collector):
    """Fetches detections for incidents that are new or changed since the last fetch.

    Costs at least one API call per incident, so it is capped per run
    (``collectors.detections.max_incidents_per_run``); the backlog drains over several runs.
    """

    name = "detections"

    @property
    def interval(self) -> timedelta:
        return timedelta(minutes=self.settings.collectors.detections.interval_minutes)

    async def collect(
        self, org_id: UUID, stats: RunStats, *, since: datetime | None = None
    ) -> None:
        limit = self.settings.collectors.detections.max_incidents_per_run
        incident_ids = await self.repo.incidents_needing_detections(org_id, limit)
        for incident_id in incident_ids:
            synced_at = utcnow()
            params = {
                "organizationId": org_id,
                "incidentId": incident_id,
                "limit": DETECTIONS_PAGE_SIZE,
            }
            async for items in self.client.paginate(
                "GET", DETECTIONS_PATH, params=params, org_id=org_id
            ):
                stats.fetched += len(items)
                rows = [
                    r for r in (normalize_detection(i, incident_id, org_id) for i in items) if r
                ]
                stats.upserted += await self.repo.upsert_detections(rows)
            await self.repo.mark_detections_synced(incident_id, synced_at)
