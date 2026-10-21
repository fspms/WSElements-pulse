"""Collectors and the factory that builds the enabled ones from settings."""

from __future__ import annotations

from elements_pulse.api.client import ElementsClient
from elements_pulse.collectors.audit_logs import AuditLogsCollector
from elements_pulse.collectors.base import Collector, IncrementalCollector, run_once
from elements_pulse.collectors.devices import DevicesCollector
from elements_pulse.collectors.incidents import DetectionsCollector, IncidentsCollector
from elements_pulse.collectors.security_events import SecurityEventsCollector
from elements_pulse.config import Settings
from elements_pulse.repository import Repository

COLLECTOR_NAMES = ("incidents", "detections", "security_events", "devices", "audit_logs")


def build_collectors(
    client: ElementsClient,
    repo: Repository,
    settings: Settings,
    only: set[str] | None = None,
) -> list[Collector]:
    cfg = settings.collectors

    def wanted(name: str, enabled: bool) -> bool:
        return name in only if only else enabled

    collectors: list[Collector] = []
    if wanted("incidents", cfg.incidents.enabled):
        collectors.append(IncidentsCollector(client, repo, settings))
    if wanted("detections", cfg.detections.enabled):
        collectors.append(DetectionsCollector(client, repo, settings))
    if wanted("security_events", cfg.security_events.enabled):
        for group in dict.fromkeys(cfg.security_events.engine_groups):
            collectors.append(SecurityEventsCollector(client, repo, settings, group))
    if wanted("devices", cfg.devices.enabled):
        collectors.append(DevicesCollector(client, repo, settings))
    if wanted("audit_logs", cfg.audit_logs.enabled):
        collectors.append(AuditLogsCollector(client, repo, settings))
    return collectors


__all__ = [
    "COLLECTOR_NAMES",
    "AuditLogsCollector",
    "Collector",
    "DetectionsCollector",
    "DevicesCollector",
    "IncidentsCollector",
    "IncrementalCollector",
    "SecurityEventsCollector",
    "build_collectors",
    "run_once",
]
