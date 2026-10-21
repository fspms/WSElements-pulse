"""Long-running scheduler: one loop per (collector, organization)."""

from __future__ import annotations

import asyncio
import random
from uuid import UUID

from elements_pulse.api.client import ElementsClient
from elements_pulse.collectors import Collector, build_collectors, run_once
from elements_pulse.collectors.organizations import resolve_organizations
from elements_pulse.config import Settings
from elements_pulse.logs import get_logger
from elements_pulse.repository import Repository

log = get_logger(__name__)

SHUTDOWN_GRACE_SECONDS = 20
MAINTENANCE_INTERVAL_SECONDS = 3600


async def _wait(stop: asyncio.Event, seconds: float) -> bool:
    """Sleep up to ``seconds``; return True if stop was requested."""
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return False
    return True


class Scheduler:
    def __init__(self, client: ElementsClient, repo: Repository, settings: Settings):
        self.client = client
        self.repo = repo
        self.settings = settings
        self.collectors: list[Collector] = build_collectors(client, repo, settings)
        self._tasks: dict[tuple[str, UUID], asyncio.Task[None]] = {}
        self._aux: list[asyncio.Task[None]] = []
        self.started = False

    async def _loop(self, collector: Collector, org_id: UUID, stop: asyncio.Event) -> None:
        # Stagger start-up so all collectors do not hit the API at the same second.
        if await _wait(stop, random.uniform(0, 10)):
            return
        interval = collector.interval.total_seconds()
        while not stop.is_set():
            try:
                await run_once(collector, org_id)
            except Exception as exc:  # e.g. database unavailable: keep the loop alive
                log.error(
                    "collector_loop_error",
                    collector=collector.key,
                    organization_id=str(org_id),
                    error=str(exc),
                )
            if await _wait(stop, interval):
                return

    def _ensure_tasks(self, orgs: list[UUID], stop: asyncio.Event) -> None:
        for org_id in orgs:
            for collector in self.collectors:
                key = (collector.key, org_id)
                if key in self._tasks and not self._tasks[key].done():
                    continue
                self._tasks[key] = asyncio.create_task(
                    self._loop(collector, org_id, stop), name=f"{collector.key}:{org_id}"
                )

    async def _discovery_loop(self, stop: asyncio.Event) -> None:
        interval = self.settings.organizations.discovery_interval_minutes * 60
        while not await _wait(stop, interval):
            try:
                orgs = await resolve_organizations(self.client, self.repo, self.settings)
            except Exception as exc:
                log.error("organization_discovery_failed", error=str(exc))
                continue
            self._ensure_tasks(orgs, stop)

    async def _maintenance_loop(self, stop: asyncio.Event) -> None:
        retention = self.settings.retention
        while True:
            try:
                await self.repo.purge(retention.api_requests_days, retention.collector_runs_days)
            except Exception as exc:
                log.warning("maintenance_failed", error=str(exc))
            if await _wait(stop, MAINTENANCE_INTERVAL_SECONDS):
                return

    async def run(self, stop: asyncio.Event) -> None:
        if not self.collectors:
            log.warning("no_collector_enabled")
        orgs = await resolve_organizations(self.client, self.repo, self.settings)
        log.info(
            "scheduler_started",
            organizations=[str(o) for o in orgs],
            collectors=[c.key for c in self.collectors],
        )
        self._ensure_tasks(orgs, stop)
        self._aux.append(asyncio.create_task(self._maintenance_loop(stop)))
        if self.settings.organizations.discover:
            self._aux.append(asyncio.create_task(self._discovery_loop(stop)))
        self.started = True

        await stop.wait()
        log.info("scheduler_stopping", grace_seconds=SHUTDOWN_GRACE_SECONDS)
        tasks = [*self._tasks.values(), *self._aux]
        _, pending = await asyncio.wait(tasks, timeout=SHUTDOWN_GRACE_SECONDS)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        log.info("scheduler_stopped")
