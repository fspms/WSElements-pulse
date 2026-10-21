"""Devices: full snapshot on every run (the API has no 'changed since' filter)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from elements_pulse.collectors.base import Collector, as_uuid
from elements_pulse.logs import get_logger
from elements_pulse.repository import RunStats
from elements_pulse.timeutil import parse_ts, utcnow

log = get_logger(__name__)

DEVICES_PATH = "/devices/v1/devices"
PAGE_SIZE = 200  # API maximum


def normalize_device(item: dict[str, Any], polled_org: UUID) -> dict[str, Any] | None:
    device_id = item.get("id")
    if not device_id:
        return None
    company = item.get("company") or {}
    os_info = item.get("os") or {}
    subscription = item.get("subscription") or {}
    return {
        "device_id": str(device_id),
        "organization_id": as_uuid(company.get("id")) or polled_org,
        "polled_organization_id": polled_org,
        "name": item.get("name"),
        "type": item.get("type"),
        "state": item.get("state"),
        "os_name": os_info.get("name"),
        "os_version": os_info.get("version"),
        "os_end_of_life": os_info.get("endOfLife"),
        "client_version": item.get("clientVersion"),
        "protection_status": item.get("protectionStatus"),
        "protection_status_overview": item.get("protectionStatusOverview"),
        "malware_state": item.get("malwareState"),
        "firewall_state": item.get("firewallState"),
        "patch_overall_state": item.get("patchOverallState"),
        "online": item.get("online"),
        "last_user": item.get("lastUser"),
        "product_variant": subscription.get("productVariant"),
        "status_update_at": parse_ts(item.get("statusUpdateTimestamp")),
        "registered_at": parse_ts(item.get("registrationTimestamp")),
        "raw": item,
    }


class DevicesCollector(Collector):
    name = "devices"

    @property
    def interval(self) -> timedelta:
        return timedelta(minutes=self.settings.collectors.devices.interval_minutes)

    async def collect(
        self, org_id: UUID, stats: RunStats, *, since: datetime | None = None
    ) -> None:
        snapshot_started = utcnow()
        observed: dict[UUID, str | None] = {}
        # Without a `state` filter the API only returns active devices.
        for state in self.settings.collectors.devices.states:
            params = {"organizationId": org_id, "state": state, "limit": PAGE_SIZE}
            async for items in self.client.paginate(
                "GET",
                DEVICES_PATH,
                params=params,
                headers={"Accept": "application/json"},
                org_id=org_id,
            ):
                stats.fetched += len(items)
                rows = [r for r in (normalize_device(i, org_id) for i in items) if r]
                for item in items:
                    company = item.get("company") or {}
                    company_id = as_uuid(company.get("id"))
                    if company_id:
                        observed[company_id] = company.get("name")
                stats.upserted += await self.repo.upsert_devices(rows)
        # Only reached when every state was read completely, so the snapshot is trustworthy.
        removed = await self.repo.mark_devices_removed(org_id, snapshot_started)
        if removed:
            log.info("devices_marked_removed", organization_id=str(org_id), count=removed)
        await self.repo.observe_organizations(observed)
        await self.repo.refresh_device_status_daily(org_id)
