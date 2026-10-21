"""Collector base class and the run bookkeeping wrapper."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, ClassVar
from uuid import UUID

from elements_pulse.api.client import CallCounter, ElementsClient, current_call_counter
from elements_pulse.config import Settings
from elements_pulse.logs import get_logger
from elements_pulse.repository import Repository, RunStats
from elements_pulse.timeutil import utcnow

log = get_logger(__name__)


def as_uuid(value: Any) -> UUID | None:
    if value is None or value == "":
        return None
    try:
        return UUID(str(value))
    except ValueError:
        return None


class Collector(ABC):
    #: Logical collector key, stored in sync_state / collector_runs.
    name: ClassVar[str]

    def __init__(self, client: ElementsClient, repo: Repository, settings: Settings):
        self.client = client
        self.repo = repo
        self.settings = settings

    @property
    def key(self) -> str:
        """Key used for sync_state; subclasses may add a suffix (e.g. engine group)."""
        return self.name

    @property
    @abstractmethod
    def interval(self) -> timedelta: ...

    @abstractmethod
    async def collect(
        self, org_id: UUID, stats: RunStats, *, since: datetime | None = None
    ) -> None:
        """Fetch and store data for one organization.

        ``since`` forces the lower bound (used by ``backfill``); otherwise the stored cursor
        (minus the configured overlap) or the initial backfill window is used.
        """


class IncrementalCollector(Collector):
    """Collector driven by a timestamp cursor stored in sync_state."""

    @property
    @abstractmethod
    def backfill(self) -> timedelta: ...

    @property
    @abstractmethod
    def overlap(self) -> timedelta: ...

    async def start_from(self, org_id: UUID, since: datetime | None) -> datetime:
        if since is not None:
            return since
        cursor = await self.repo.get_cursor(self.key, org_id)
        if cursor is None:
            return utcnow() - self.backfill
        return cursor - self.overlap


async def run_once(
    collector: Collector, org_id: UUID, *, since: datetime | None = None
) -> tuple[str, RunStats]:
    """Run a collector for one org with sync_state / collector_runs bookkeeping.

    Never raises for collection errors (they are logged and recorded); re-raises cancellation.
    """
    repo = collector.repo
    stats = RunStats()
    counter = CallCounter()
    token = current_call_counter.set(counter)
    bound = log.bind(collector=collector.key, organization_id=str(org_id))
    run_id = await repo.start_run(collector.key, org_id, int(collector.interval.total_seconds()))
    started = utcnow()
    try:
        await collector.collect(org_id, stats, since=since)
    except asyncio.CancelledError:
        stats.api_calls = counter.calls
        await asyncio.shield(repo.finish_run(run_id, collector.key, org_id, "cancelled", stats))
        bound.info("collector_run_cancelled")
        raise
    except Exception as exc:
        stats.api_calls = counter.calls
        bound.error("collector_run_failed", error=str(exc), exc_info=True)
        await repo.finish_run(run_id, collector.key, org_id, "error", stats, error=str(exc))
        return "error", stats
    finally:
        current_call_counter.reset(token)
    stats.api_calls = counter.calls
    await repo.finish_run(run_id, collector.key, org_id, "ok", stats)
    bound.info(
        "collector_run_ok",
        fetched=stats.fetched,
        upserted=stats.upserted,
        api_calls=stats.api_calls,
        duration_s=round((utcnow() - started).total_seconds(), 2),
    )
    return "ok", stats
