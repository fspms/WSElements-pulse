"""Generate FICTIONAL demo data so the dashboards can be explored without an API key.

All names use reserved/example values (example.com, DEMO-* hosts, "Demo Org ..."). The fake
records are shaped like real API payloads and go through the same normalizers as live data.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid5

from elements_pulse.collectors.audit_logs import normalize_audit_log
from elements_pulse.collectors.devices import normalize_device
from elements_pulse.collectors.incidents import normalize_detection, normalize_incident
from elements_pulse.collectors.security_events import normalize_security_event
from elements_pulse.repository import Repository
from elements_pulse.timeutil import fmt_ts, utcnow

SEED_NAMESPACE = UUID("6f1c7d2e-0000-4000-8000-00000000d3e0")  # arbitrary, demo only
ORG_NAMES = [
    "Demo Org Alpha",
    "Demo Org Bravo",
    "Demo Org Charlie",
    "Demo Org Delta",
    "Demo Org Echo",
    "Demo Org Foxtrot",
    "Demo Org Golf",
    "Demo Org Hotel",
    "Demo Org India",
    "Demo Org Juliett",
]

DATA_TABLES = (
    "incident_detections",
    "incidents",
    "security_events",
    "devices",
    "device_status_daily",
    "audit_logs",
    "api_requests",
    "collector_runs",
    "sync_state",
    "organizations",
)

OS_CHOICES = [
    ("computer", "Windows 11 Pro", "10.0.22631", ["25.4", "25.3", "25.2"]),
    ("computer", "Windows 10 Pro", "10.0.19045", ["25.4", "25.3", "24.6"]),
    ("computer", "Windows Server 2022", "10.0.20348", ["25.4", "25.2"]),
    ("computer", "macOS 14", "14.6", ["25.3.1", "25.2.0"]),
    ("computer", "Ubuntu 22.04", "22.04", ["24.5", "24.4"]),
    ("mobile", "Android", "14", ["24.1"]),
    ("connector", "Windows Server 2019", "10.0.17763", ["25.1"]),
]
EPP_ENGINES = [
    ("deepGuard", 18),
    ("realtimeScanning", 30),
    ("browsingProtection", 22),
    ("webTrafficScanning", 10),
    ("firewall", 6),
    ("deviceControl", 5),
    ("applicationControl", 4),
    ("dataGuard", 2),
    ("AMSI", 3),
]
INFECTIONS = [
    "Trojan.Demo.Generic",
    "PUA.Demo.Toolbar",
    "Exploit.Demo.CVE",
    "Ransom.Demo.Sample",
    "Backdoor.Demo.Agent",
    "Heuristic.Demo.Suspicious",
]
ALERT_TYPES = [
    "file.scan.infection",
    "web.access.blocked",
    "process.behavior.blocked",
    "device.access.blocked",
    "product.path.excluded",
]
CATEGORIES = [
    "MALWARE",
    "CREDENTIAL_THEFT",
    "LATERAL_MOVEMENT",
    "PERSISTENCE",
    "SCRIPTING_ABUSE",
    "PRIVILEGE_ESCALATION",
    "RECON_ACTIVITIES",
    "PUP",
]
DETECTION_NAMES = [
    "suspiciousPowershellCommand",
    "credentialDumpingTool",
    "unusualParentProcess",
    "scheduledTaskPersistence",
    "remoteServiceExecution",
    "encodedCommandLine",
    "suspiciousRegistryRunKey",
    "knownHackToolExecution",
]
MITRE = {
    "suspiciousPowershellCommand": ["TA0002", "T1059", "T1059.001"],
    "credentialDumpingTool": ["TA0006", "T1003"],
    "unusualParentProcess": ["TA0005", "T1036"],
    "scheduledTaskPersistence": ["TA0003", "T1053", "T1053.005"],
    "remoteServiceExecution": ["TA0008", "T1021"],
    "encodedCommandLine": ["TA0005", "T1027"],
    "suspiciousRegistryRunKey": ["TA0003", "T1547", "T1547.001"],
    "knownHackToolExecution": ["TA0002", "T1204"],
}
AUDIT_ACTIONS = [
    ("elements-core", "login", 40),
    ("epp", "assignProfile", 8),
    ("epp", "profileUpdated", 6),
    ("epp", "isolateFromNetwork", 1),
    ("epp", "scanForMalware", 6),
    ("elements-core", "incidentStatusChanged", 10),
    ("epp", "acknowledgeSecurityEvent", 12),
    ("epp", "installSoftwareUpdates", 4),
    ("elements-core", "credentialCreated", 1),
]


def _weighted(rng: random.Random, pairs: list[tuple[Any, int]]) -> Any:
    return rng.choices([p[0] for p in pairs], weights=[p[1] for p in pairs])[0]


def _rand_ts(rng: random.Random, start: datetime, end: datetime) -> datetime:
    span = (end - start).total_seconds()
    return start + timedelta(seconds=rng.random() * span)


def _uuid(*parts: object) -> UUID:
    return uuid5(SEED_NAMESPACE, "/".join(str(p) for p in parts))


async def seed_database(
    repo: Repository,
    *,
    days: int = 30,
    org_count: int = 3,
    reset: bool = False,
    random_seed: int = 42,
) -> dict[str, int]:
    rng = random.Random(random_seed)
    now = utcnow()
    start = now - timedelta(days=days)
    counts: dict[str, int] = {}

    if reset:
        async with repo.pool.connection() as conn:
            await conn.execute("TRUNCATE " + ", ".join(DATA_TABLES))

    orgs = [(_uuid("org", i), ORG_NAMES[i % len(ORG_NAMES)]) for i in range(org_count)]
    await repo.upsert_organizations(((o, n, "company") for o, n in orgs), "seed")
    counts["organizations"] = len(orgs)

    devices_n = incidents_n = detections_n = events_n = audits_n = 0
    for org_index, (org_id, org_name) in enumerate(orgs):
        org_ref = {"id": str(org_id), "name": org_name}

        # ---------------------------------------------------------------- devices
        devices: list[dict[str, Any]] = []
        for d in range(rng.randint(25, 60)):
            dtype, os_name, os_version, versions = rng.choice(OS_CHOICES)
            prefix = {"computer": "WS", "mobile": "MOB", "connector": "CON"}[dtype]
            if "Server" in os_name:
                prefix = "SRV"
            overview = _weighted(
                rng,
                [("allOk", 80), ("warning", 10), ("critical", 4), ("inactive", 5), ("isolated", 1)],
            )
            status = {
                "allOk": "protected",
                "warning": "malwareIssue",
                "critical": "firewallIssue",
                "inactive": "notConnected",
                "isolated": "isolated",
            }[overview]
            last_status = now - timedelta(
                minutes=rng.randint(1, 600) if overview != "inactive" else rng.randint(2000, 40000)
            )
            item = {
                "id": str(_uuid("device", org_index, d)),
                "name": f"DEMO-{prefix}-{org_index + 1}{d + 1:03d}",
                "type": dtype,
                "state": _weighted(rng, [("active", 95), ("inactive", 4), ("blocked", 1)]),
                "company": {**org_ref, "type": "company"},
                "os": {
                    "name": os_name,
                    "version": os_version,
                    "endOfLife": os_name == "Windows 10 Pro",
                },
                "clientVersion": _weighted(rng, list(zip(versions, [70, 20, 10], strict=False))),
                "protectionStatus": status,
                "protectionStatusOverview": overview,
                "malwareState": "enabled" if overview != "warning" else "oldDefinitions",
                "firewallState": "enabled" if overview != "critical" else "disabled",
                "patchOverallState": _weighted(
                    rng,
                    [
                        ("importantUpdatesInstalled", 60),
                        ("missingImportantUpdates", 25),
                        ("missingCriticalUpdates", 10),
                        ("notScannedYet", 5),
                    ],
                ),
                "online": overview not in ("inactive",),
                "lastUser": f"user{rng.randint(1, 99):02d}@example.com",
                "subscription": {"productVariant": "computerprotection_premium_edr"},
                "statusUpdateTimestamp": fmt_ts(last_status),
                "registrationTimestamp": fmt_ts(start - timedelta(days=rng.randint(30, 700))),
            }
            devices.append(item)
        rows = [r for r in (normalize_device(i, org_id) for i in devices) if r]
        devices_n += await repo.upsert_devices(rows)
        await repo.refresh_device_status_daily(org_id)
        # Fake history for the protection status trend panel.
        async with repo.pool.connection() as conn, conn.cursor() as cur:
            history = []
            for back in range(1, min(days, 30) + 1):
                day = (now - timedelta(days=back)).date()
                total = len(devices) - rng.randint(0, 3)
                bad = rng.randint(0, max(1, total // 8))
                history += [(day, org_id, "allOk", total - bad), (day, org_id, "warning", bad)]
            await cur.executemany(
                "INSERT INTO device_status_daily VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                history,
            )

        # -------------------------------------------------------------- incidents
        incident_rows, detection_rows = [], []
        for i in range(int(days * rng.uniform(0.4, 1.2))):
            created = _rand_ts(rng, start, now)
            age = now - created
            status = (
                _weighted(rng, [("closed", 85), ("inProgress", 10), ("monitoring", 5)])
                if age > timedelta(days=3)
                else _weighted(
                    rng, [("new", 50), ("acknowledged", 20), ("inProgress", 25), ("closed", 5)]
                )
            )
            risk = _weighted(
                rng, [("info", 10), ("low", 30), ("medium", 35), ("high", 18), ("severe", 7)]
            )
            device = rng.choice(devices)
            incident_id = _uuid("incident", org_index, i)
            updated = min(now, created + timedelta(hours=rng.uniform(0, 72)))
            item = {
                "incidentId": str(incident_id),
                "incidentPublicId": f"{rng.randint(1000, 9999)}-{rng.randint(0, 0xFFFFFF):06X}",
                "organizationId": str(org_id),
                "name": f"Incident in {device['name']}",
                "status": status,
                "severity": {
                    "severe": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                    "info": "info",
                }[risk],
                "riskLevel": risk,
                "riskScore": round(rng.uniform(5, 99), 3),
                "resolution": _weighted(
                    rng,
                    [
                        ("incident", 30),
                        ("falsePositive", 25),
                        ("securityTest", 10),
                        ("acceptedBehavior", 20),
                        ("inconclusive", 15),
                    ],
                )
                if status == "closed"
                else "unconfirmed",
                "categories": rng.sample(CATEGORIES, k=rng.randint(1, 2)),
                "sources": ["endpoint"],
                "createdTimestamp": fmt_ts(created),
                "updatedTimestamp": fmt_ts(updated),
                "initialReceivedTimestamp": fmt_ts(
                    created - timedelta(seconds=rng.randint(5, 300))
                ),
            }
            row = normalize_incident(item, org_id)
            if row:
                incident_rows.append(row)
            for k in range(rng.randint(1, 5)):
                name = rng.choice(DETECTION_NAMES)
                det = {
                    "detectionId": str(_uuid("detection", org_index, i, k)),
                    "incidentId": str(incident_id),
                    "deviceId": device["id"],
                    "name": name,
                    "detectionClass": "PROCESS",
                    "severity": item["severity"],
                    "riskLevel": risk,
                    "exeName": rng.choice(
                        ["powershell.exe", "cmd.exe", "rundll32.exe", "demo-tool.exe"]
                    ),
                    "exePath": "C:\\Demo\\Path\\",
                    "exeHash": f"{rng.getrandbits(160):040x}",
                    "cmdl": "demo-tool.exe --example-argument",
                    "username": f"DEMO\\user{rng.randint(1, 99):02d}",
                    "createdTimestamp": fmt_ts(created + timedelta(minutes=k)),
                    "initialReceivedTimestamp": fmt_ts(created + timedelta(minutes=k)),
                    "mitre": MITRE[name],
                }
                drow = normalize_detection(det, incident_id, org_id)
                if drow:
                    detection_rows.append(drow)
        incidents_n += await repo.upsert_incidents(incident_rows)
        detections_n += await repo.upsert_detections(detection_rows)
        async with repo.pool.connection() as conn:
            await conn.execute(
                "UPDATE incidents SET detections_synced_at = now() WHERE organization_id = %s",
                (org_id,),
            )

        # -------------------------------------------------------- security events
        event_rows = []
        for day_back in range(days):
            day_start = now - timedelta(days=day_back + 1)
            day_end = now - timedelta(days=day_back)
            n_epp = rng.randint(20, 120)
            n_edr = rng.randint(1, 12)
            for group, n in (("epp", n_epp), ("edr", n_edr)):
                for e in range(n):
                    ts = _rand_ts(rng, day_start, day_end)
                    device = rng.choice(devices)
                    engine = _weighted(rng, EPP_ENGINES) if group == "epp" else "edr"
                    severity = (
                        _weighted(rng, [("info", 50), ("warning", 40), ("critical", 10)])
                        if group == "epp"
                        else _weighted(rng, [("warning", 40), ("critical", 60)])
                    )
                    item = {
                        "id": f"{_uuid('event', org_index, day_back, group, e)}_0",
                        "action": _weighted(
                            rng,
                            [
                                ("blocked", 40),
                                ("quarantined", 25),
                                ("reported", 25),
                                ("deleted", 10),
                            ],
                        )
                        if group == "epp"
                        else "created",
                        "engine": engine,
                        "severity": severity,
                        "serverTimestamp": fmt_ts(ts - timedelta(seconds=2)),
                        "persistenceTimestamp": fmt_ts(ts),
                        "clientTimestamp": fmt_ts(ts - timedelta(seconds=5)),
                        "acknowledged": rng.random() < 0.3,
                        "message": f"Demo {engine} event on {device['name']}",
                        "description": f"{engine} event",
                        "organization": org_ref,
                        "target": {"id": device["id"], "name": device["name"]},
                        "device": {"id": device["id"], "name": device["name"]},
                        "userName": device["lastUser"],
                        "details": {
                            "alertType": rng.choice(ALERT_TYPES)
                            if group == "epp"
                            else "edr.incident.created",
                            "infectionName": rng.choice(INFECTIONS) if group == "epp" else None,
                        },
                    }
                    row = normalize_security_event(item, group, org_id)
                    if row:
                        event_rows.append(row)
        events_n += await repo.upsert_security_events(event_rows)

        # -------------------------------------------------------------- audit logs
        audit_rows = []
        for a in range(days * rng.randint(8, 25)):
            ts = _rand_ts(rng, start, now)
            namespace, action = _weighted(rng, [((ns, act), w) for ns, act, w in AUDIT_ACTIONS])
            user = f"admin{rng.randint(1, 4)}@example.com"
            target = rng.choice(devices)
            item = {
                "id": f"demo-audit-{org_index}-{a}",
                "serverTimestamp": fmt_ts(ts),
                "transactionId": f"0000-demo{a:08d}",
                "namespace": namespace,
                "action": action,
                "username": user,
                "organization": {**org_ref, "orgPath": f"{org_id}/"},
                "target": {"id": target["id"], "name": target["name"]},
                "description": f'Administrator "{user}" performed {action} on "{target["name"]}"',
            }
            row = normalize_audit_log(item, org_id)
            if row:
                audit_rows.append(row)
        audits_n += await repo.upsert_audit_logs(audit_rows)

    counts.update(
        devices=devices_n,
        incidents=incidents_n,
        incident_detections=detections_n,
        security_events=events_n,
        audit_logs=audits_n,
    )
    counts.update(await _seed_health(repo, rng, [o for o, _ in orgs], now))
    return counts


async def _seed_health(
    repo: Repository, rng: random.Random, orgs: list[UUID], now: datetime
) -> dict[str, int]:
    collectors = {
        "incidents": 300,
        "detections": 300,
        "security_events:epp": 300,
        "security_events:edr": 300,
        "devices": 900,
        "audit_logs": 900,
    }
    endpoints = {
        "incidents": ("GET", "/incidents/v1/incidents"),
        "detections": ("GET", "/incidents/v1/detections"),
        "security_events:epp": ("POST", "/security-events/v1/security-events"),
        "security_events:edr": ("POST", "/security-events/v1/security-events"),
        "devices": ("GET", "/devices/v1/devices"),
        "audit_logs": ("GET", "/audit-logs/v1/audit-logs"),
    }
    runs, requests, states = [], [], []
    for org_id in orgs:
        for collector, interval in collectors.items():
            t = now - timedelta(hours=48)
            last_ok = None
            while t < now:
                failed = rng.random() < 0.02
                duration = timedelta(seconds=rng.uniform(0.5, 8))
                calls = rng.randint(1, 6)
                runs.append(
                    (
                        collector,
                        org_id,
                        t,
                        t + duration,
                        "error" if failed else "ok",
                        0 if failed else rng.randint(0, 80),
                        0 if failed else rng.randint(0, 80),
                        calls,
                        "HTTP 503 from API (demo)" if failed else None,
                    )
                )
                method, path = endpoints[collector]
                for c in range(calls):
                    status = (
                        503 if failed and c == calls - 1 else (429 if rng.random() < 0.01 else 200)
                    )
                    requests.append(
                        (
                            t + timedelta(milliseconds=200 * c),
                            org_id,
                            method,
                            path,
                            status,
                            int(rng.lognormvariate(5.5, 0.5)),
                            0,
                        )
                    )
                if not failed:
                    last_ok = t + duration
                t += timedelta(seconds=interval)
            states.append(
                (collector, org_id, now, now - timedelta(seconds=interval / 2), last_ok, interval)
            )
    async with repo.pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
        await cur.executemany(
            "INSERT INTO collector_runs (collector, organization_id, started_at, finished_at,"
            " status, items_fetched, items_upserted, api_calls, error)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            runs,
        )
        await cur.executemany(
            "INSERT INTO api_requests (ts, organization_id, method, endpoint, status,"
            " duration_ms, attempt) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            requests,
        )
        await cur.executemany(
            "INSERT INTO sync_state (collector, organization_id, cursor_ts, last_run_started_at,"
            " last_success_at, interval_seconds) VALUES (%s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (collector, organization_id) DO UPDATE SET"
            " cursor_ts = EXCLUDED.cursor_ts, last_run_started_at = EXCLUDED.last_run_started_at,"
            " last_success_at = EXCLUDED.last_success_at,"
            " interval_seconds = EXCLUDED.interval_seconds, consecutive_failures = 0",
            states,
        )
    return {"collector_runs": len(runs), "api_requests": len(requests)}
