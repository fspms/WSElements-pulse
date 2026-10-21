"""Collectors against a mocked API and an in-memory repository."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs
from uuid import UUID

import httpx

from elements_pulse.collectors import (
    AuditLogsCollector,
    DetectionsCollector,
    DevicesCollector,
    IncidentsCollector,
    SecurityEventsCollector,
    build_collectors,
    run_once,
)
from elements_pulse.collectors.incidents import normalize_incident
from elements_pulse.repository import RunStats

from .conftest import CHILD_ORG_ID, ORG_ID, load_fixture


# ------------------------------------------------------------------------- incidents
async def test_incidents_paginates_and_upserts(mock_api, client, repo, settings):
    route = mock_api.get("/incidents/v1/incidents")
    route.side_effect = [
        httpx.Response(200, json=load_fixture("incidents_page1.json")),
        httpx.Response(200, json=load_fixture("incidents_page2.json")),
    ]
    collector = IncidentsCollector(client, repo, settings)
    stats = RunStats()
    await collector.collect(ORG_ID, stats)

    first, second = (c.request.url.params for c in route.calls)
    assert first["organizationId"] == str(ORG_ID)
    assert first["order"] == "asc"
    assert first["limit"] == "50"
    assert "updatedTimestampStart" in first
    assert "anchor" not in first
    assert second["anchor"] == "demo-anchor-2"
    assert second["updatedTimestampStart"] == first["updatedTimestampStart"]

    assert stats.fetched == 2 and stats.upserted == 2
    inc = repo.incidents[UUID("22222222-2222-4222-8222-222222222222")]
    assert inc["risk_level"] == "severe"
    assert inc["categories"] == ["CREDENTIAL_THEFT", "LATERAL_MOVEMENT"]
    assert inc["raw"]["incidentPublicId"] == "1000-DEMO0002"
    assert repo.cursors[("incidents", ORG_ID)] == datetime(2026, 1, 12, 12, 30, tzinfo=UTC)


async def test_incidents_resume_from_cursor_minus_overlap(mock_api, client, repo, settings):
    route = mock_api.get("/incidents/v1/incidents").respond(200, json={"items": []})
    repo.cursors[("incidents", ORG_ID)] = datetime(2026, 1, 12, 12, 30, tzinfo=UTC)
    await IncidentsCollector(client, repo, settings).collect(ORG_ID, RunStats())
    assert route.calls[0].request.url.params["updatedTimestampStart"] == "2026-01-12T12:20:00.000Z"


async def test_incidents_initial_backfill_window(mock_api, client, repo, settings):
    route = mock_api.get("/incidents/v1/incidents").respond(200, json={"items": []})
    await IncidentsCollector(client, repo, settings).collect(ORG_ID, RunStats())
    start = datetime.fromisoformat(route.calls[0].request.url.params["updatedTimestampStart"])
    expected = datetime.now(UTC) - timedelta(days=settings.collectors.incidents.backfill_days)
    assert abs((start - expected).total_seconds()) < 60


def test_normalize_incident_skips_invalid_ids():
    assert normalize_incident({"incidentId": "not-a-uuid"}, ORG_ID) is None


async def test_detections_for_pending_incidents(mock_api, client, repo, settings):
    incident = UUID("11111111-1111-4111-8111-111111111111")
    repo.pending_detection_incidents = [incident]
    route = mock_api.get("/incidents/v1/detections").respond(
        200,
        json={
            "items": [
                {
                    "detectionId": "det-1",
                    "incidentId": str(incident),
                    "deviceId": "dev-1",
                    "name": "suspiciousPowershellCommand",
                    "detectionClass": "PROCESS",
                    "severity": "medium",
                    "riskLevel": "medium",
                    "cmdl": "demo.exe --arg",
                    "createdTimestamp": "2026-01-10T08:00:00Z",
                    "mitre": ["TA0002", "T1059"],
                }
            ]
        },
    )
    await DetectionsCollector(client, repo, settings).collect(ORG_ID, RunStats())
    params = route.calls[0].request.url.params
    assert params["incidentId"] == str(incident)
    assert params["limit"] == "100"
    assert repo.detections["det-1"]["mitre"] == ["TA0002", "T1059"]
    assert repo.detections["det-1"]["cmdl"] == "demo.exe --arg"
    assert incident in repo.detections_synced


# ------------------------------------------------------------------ security events
async def test_security_events_form_body_and_org_from_record(mock_api, client, repo, settings):
    route = mock_api.post("/security-events/v1/security-events").respond(
        200, json=load_fixture("security_events.json")
    )
    repo.cursors[("security_events:epp", ORG_ID)] = datetime.now(UTC) - timedelta(hours=1)
    collector = SecurityEventsCollector(client, repo, settings, "epp")
    stats = RunStats()
    await collector.collect(ORG_ID, stats)

    request = route.calls[0].request
    assert request.headers["Accept"] == "application/json"
    assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"
    body = parse_qs(request.content.decode())
    assert body["engineGroup"] == ["epp"]
    assert body["order"] == ["asc"]
    assert body["limit"] == ["200"]
    assert body["organizationId"] == [str(ORG_ID)]
    assert "persistenceTimestampStart" in body and "persistenceTimestampEnd" in body

    ev = repo.events["aaaaaaaa-0000-4000-8000-000000000001_0"]
    assert ev["organization_id"] == CHILD_ORG_ID  # from the record, not the polled org
    assert ev["engine_group"] == "epp"
    assert ev["alert_type"] == "process.behavior.blocked"
    assert ev["infection_name"] == "Trojan.Demo.Generic"
    assert repo.observed[CHILD_ORG_ID] == "Demo Child Org"
    assert stats.upserted == 2


async def test_security_events_splits_long_ranges(mock_api, client, repo, settings):
    route = mock_api.post("/security-events/v1/security-events").respond(200, json={"items": []})
    collector = SecurityEventsCollector(client, repo, settings, "edr")
    since = datetime.now(UTC) - timedelta(days=75)
    await collector.collect(ORG_ID, RunStats(), since=since)

    assert route.call_count == 3  # 30 + 30 + 15 days
    for call in route.calls:
        body = parse_qs(call.request.content.decode())
        start = datetime.fromisoformat(body["persistenceTimestampStart"][0])
        end = datetime.fromisoformat(body["persistenceTimestampEnd"][0])
        assert timedelta(0) < end - start <= timedelta(days=31)
    # cursor moved to the end of the last window even without events
    assert repo.cursors[("security_events:edr", ORG_ID)] > datetime.now(UTC) - timedelta(minutes=1)


async def test_security_events_pagination_sends_anchor_in_body(mock_api, client, repo, settings):
    route = mock_api.post("/security-events/v1/security-events")
    route.side_effect = [
        httpx.Response(200, json={"items": [], "nextAnchor": "demo-next"}),
        httpx.Response(200, json={"items": []}),
    ]
    repo.cursors[("security_events:epp", ORG_ID)] = datetime.now(UTC) - timedelta(minutes=5)
    await SecurityEventsCollector(client, repo, settings, "epp").collect(ORG_ID, RunStats())
    assert parse_qs(route.calls[1].request.content.decode())["anchor"] == ["demo-next"]


# ------------------------------------------------------------------------- devices
async def test_devices_queries_each_state(mock_api, client, repo, settings):
    route = mock_api.get("/devices/v1/devices")
    route.side_effect = [
        httpx.Response(200, json=load_fixture("devices.json")),
        httpx.Response(200, json={"items": []}),
        httpx.Response(200, json={"items": []}),
    ]
    await DevicesCollector(client, repo, settings).collect(ORG_ID, RunStats())
    states = [c.request.url.params["state"] for c in route.calls]
    assert states == ["active", "blocked", "inactive"]
    dev = repo.devices["dddddddd-0000-4000-8000-000000000001"]
    assert dev["client_version"] == "25.4"
    assert dev["os_name"] == "Windows 11 Pro"
    assert dev["product_variant"] == "computerprotection_premium_edr"
    assert dev["polled_organization_id"] == ORG_ID
    assert repo.removed_calls == [ORG_ID]


async def test_devices_failure_does_not_mark_removed(mock_api, client, repo, settings):
    mock_api.get("/devices/v1/devices").respond(400, json={"message": "bad", "code": 400000})
    status, _ = await run_once(DevicesCollector(client, repo, settings), ORG_ID)
    assert status == "error"
    assert repo.removed_calls == []
    assert repo.runs[-1] == ("devices", ORG_ID, "error")


# ----------------------------------------------------------------------- audit logs
async def test_audit_logs(mock_api, client, repo, settings):
    route = mock_api.get("/audit-logs/v1/audit-logs").respond(
        200, json=load_fixture("audit_logs.json")
    )
    await AuditLogsCollector(client, repo, settings).collect(ORG_ID, RunStats())
    params = route.calls[0].request.url.params
    assert params["order"] == "asc" and params["language"] == "en"
    assert "serverTimestampStart" in params and "serverTimestampEnd" in params
    entry = repo.audit_logs["demo-audit-1"]
    assert entry["action"] == "login" and entry["username"] == "admin@example.com"


# --------------------------------------------------------------------------- misc
async def test_run_once_records_success_and_api_calls(mock_api, client, repo, settings):
    mock_api.get("/incidents/v1/incidents").respond(200, json={"items": []})
    status, stats = await run_once(IncidentsCollector(client, repo, settings), ORG_ID)
    assert status == "ok"
    assert stats.api_calls == 2  # token + one page
    assert repo.runs[-1] == ("incidents", ORG_ID, "ok")


def test_build_collectors_respects_settings(client, repo, settings):
    settings.collectors.audit_logs.enabled = False
    settings.collectors.security_events.engine_groups = ["epp", "edr", "epp"]
    keys = [c.key for c in build_collectors(client, repo, settings)]
    assert keys == [
        "incidents",
        "detections",
        "security_events:epp",
        "security_events:edr",
        "devices",
    ]
    only = [c.key for c in build_collectors(client, repo, settings, only={"audit_logs"})]
    assert only == ["audit_logs"]
