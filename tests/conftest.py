"""Shared fixtures. All identifiers and names below are fictional."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import respx

from elements_pulse.api.client import Credentials, ElementsClient, RequestRecord
from elements_pulse.config import ApiSettings, Settings
from elements_pulse.repository import RunStats

BASE_URL = "https://api.example.test"
ORG_ID = UUID("00000000-0000-4000-8000-0000000000a1")
CHILD_ORG_ID = UUID("00000000-0000-4000-8000-0000000000b2")
FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeRepository:
    """In-memory stand-in for Repository, recording what collectors write."""

    def __init__(self) -> None:
        self.cursors: dict[tuple[str, UUID], datetime] = {}
        self.incidents: dict[UUID, dict[str, Any]] = {}
        self.detections: dict[str, dict[str, Any]] = {}
        self.events: dict[str, dict[str, Any]] = {}
        self.devices: dict[str, dict[str, Any]] = {}
        self.audit_logs: dict[str, dict[str, Any]] = {}
        self.observed: dict[UUID, str | None] = {}
        self.orgs: dict[UUID, tuple[str | None, str]] = {}
        self.detections_synced: set[UUID] = set()
        self.removed_calls: list[UUID] = []
        self.runs: list[tuple[str, UUID, str]] = []
        self.requests: list[RequestRecord] = []
        self.pending_detection_incidents: list[UUID] = []

    async def get_cursor(self, collector: str, org_id: UUID) -> datetime | None:
        return self.cursors.get((collector, org_id))

    async def advance_cursor(self, collector: str, org_id: UUID, ts: datetime) -> None:
        current = self.cursors.get((collector, org_id))
        self.cursors[(collector, org_id)] = max(current, ts) if current else ts

    async def start_run(self, collector: str, org_id: UUID, interval_seconds: int) -> int:
        self.runs.append((collector, org_id, "running"))
        return len(self.runs)

    async def finish_run(
        self,
        run_id: int,
        collector: str,
        org_id: UUID,
        status: str,
        stats: RunStats,
        error: str | None = None,
    ) -> None:
        self.runs[run_id - 1] = (collector, org_id, status)

    async def upsert_organizations(self, orgs: Any, source: str) -> None:
        for org_id, name, _type in orgs:
            self.orgs[org_id] = (name, source)

    async def observe_organizations(self, orgs: dict[UUID, str | None]) -> None:
        self.observed.update(orgs)

    async def upsert_incidents(self, rows: list[dict[str, Any]]) -> int:
        for r in rows:
            self.incidents[r["incident_id"]] = r
        return len(rows)

    async def incidents_needing_detections(self, org_id: UUID, limit: int) -> list[UUID]:
        return self.pending_detection_incidents[:limit]

    async def upsert_detections(self, rows: list[dict[str, Any]]) -> int:
        for r in rows:
            self.detections[r["detection_id"]] = r
        return len(rows)

    async def mark_detections_synced(self, incident_id: UUID, synced_at: datetime) -> None:
        self.detections_synced.add(incident_id)

    async def upsert_security_events(self, rows: list[dict[str, Any]]) -> int:
        for r in rows:
            self.events[r["event_id"]] = r
        return len(rows)

    async def upsert_devices(self, rows: list[dict[str, Any]]) -> int:
        for r in rows:
            self.devices[r["device_id"]] = r
        return len(rows)

    async def mark_devices_removed(self, org_id: UUID, snapshot_started: datetime) -> int:
        self.removed_calls.append(org_id)
        return 0

    async def refresh_device_status_daily(self, org_id: UUID) -> None:
        return None

    async def upsert_audit_logs(self, rows: list[dict[str, Any]]) -> int:
        for r in rows:
            self.audit_logs[r["id"]] = r
        return len(rows)

    async def insert_api_request(self, rec: RequestRecord) -> None:
        self.requests.append(rec)


class SleepRecorder:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


@pytest.fixture
def api_settings() -> ApiSettings:
    return ApiSettings(base_url=BASE_URL, request_delay_seconds=0, max_retries=3)


@pytest.fixture
def settings(api_settings: ApiSettings) -> Settings:
    return Settings(api=api_settings, client_id="demo-client", client_secret="demo-secret")


@pytest.fixture
def sleeps() -> SleepRecorder:
    return SleepRecorder()


@pytest.fixture
def repo() -> FakeRepository:
    return FakeRepository()


@pytest.fixture
def mock_api():
    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        router.post("/as/token.oauth2").respond(
            200, json={"access_token": "fake-token-1", "token_type": "Bearer", "expires_in": 1799}
        )
        yield router


@pytest.fixture
async def client(api_settings: ApiSettings, sleeps: SleepRecorder, repo: FakeRepository):
    async with ElementsClient(
        api_settings,
        Credentials("demo-client", "demo-secret"),
        sleep=sleeps,
        rng=lambda: 0.5,
        on_request=repo.insert_api_request,
    ) as c:
        yield c
