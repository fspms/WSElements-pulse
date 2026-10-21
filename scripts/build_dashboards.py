#!/usr/bin/env python3
"""Generate the Grafana dashboards in grafana/dashboards/*.json.

The JSON files are committed; edit this script and re-run it rather than editing JSON by hand:

    python scripts/build_dashboards.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parent.parent / "grafana" / "dashboards"
DS = {"type": "grafana-postgresql-datasource", "uid": "elements-pulse-pg"}

# ---------------------------------------------------------------- colors
# Status palette (reserved for severity/state, always shown with its text label).
CRITICAL, SERIOUS, WARNING, GOOD = "#d03b3b", "#ec835a", "#fab219", "#0ca30c"
NEUTRAL = "#8e959e"
# Categorical palette, fixed order (never cycled).
CAT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SINGLE = CAT[0]  # one-hue magnitude bars

RISK_COLORS = {
    "severe": CRITICAL,
    "high": SERIOUS,
    "medium": WARNING,
    "low": CAT[0],
    "info": NEUTRAL,
}
INCIDENT_SEVERITY_COLORS = {
    "critical": CRITICAL,
    "high": SERIOUS,
    "medium": WARNING,
    "low": CAT[0],
    "info": NEUTRAL,
}
EVENT_SEVERITY_COLORS = {"critical": CRITICAL, "warning": WARNING, "info": NEUTRAL}
STATUS_COLORS = {
    "new": CRITICAL,
    "acknowledged": SERIOUS,
    "inProgress": WARNING,
    "monitoring": CAT[0],
    "waitingForCustomer": CAT[6],
    "closed": NEUTRAL,
}
PROTECTION_COLORS = {
    "allOk": GOOD,
    "warning": WARNING,
    "critical": CRITICAL,
    "inactive": NEUTRAL,
    "isolated": CAT[6],
    "unknown": NEUTRAL,
}
GROUP_COLORS = {"EPP": CAT[0], "EDR": CAT[1], "ECP": CAT[2], "XM": CAT[3]}
# Engines are folded to a fixed list (+ Other) so a filter never repaints a series.
ENGINES = [
    "deepGuard",
    "realtimeScanning",
    "browsingProtection",
    "webTrafficScanning",
    "firewall",
    "deviceControl",
    "edr",
]
ENGINE_COLORS = {e: CAT[i] for i, e in enumerate(ENGINES)} | {"Other": NEUTRAL}
ENGINE_CASE = "CASE WHEN engine IN ({}) THEN engine ELSE 'Other' END".format(
    ", ".join(f"'{e}'" for e in ENGINES)
)

COLLECTOR_COLORS = {
    "incidents": CAT[0],
    "detections": CAT[1],
    "security_events:epp": CAT[2],
    "security_events:edr": CAT[3],
    "devices": CAT[4],
    "audit_logs": CAT[5],
    "security_events:ecp": CAT[6],
    "security_events:xm": CAT[7],
}
ENDPOINT_COLORS = {
    "/incidents/v1/incidents": CAT[0],
    "/incidents/v1/detections": CAT[1],
    "/security-events/v1/security-events": CAT[2],
    "/devices/v1/devices": CAT[4],
    "/audit-logs/v1/audit-logs": CAT[5],
    "/as/token.oauth2": CAT[6],
    "/organizations/v1/organizations": CAT[7],
    "/whoami/v1/whoami": NEUTRAL,
}

ORG = "organization_id::text IN (${org:sqlstring})"


def org_filter(alias: str = "") -> str:
    return f"{alias}organization_id::text IN (${{org:sqlstring}})"


# ---------------------------------------------------------------- helpers
class Layout:
    def __init__(self) -> None:
        self.x = 0
        self.y = 0
        self.row_h = 0
        self.next_id = 1

    def place(self, w: int, h: int) -> dict[str, int]:
        if self.x + w > 24:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.row_h = max(self.row_h, h)
        return pos

    def newline(self) -> None:
        if self.x:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0

    def id(self) -> int:
        self.next_id += 1
        return self.next_id - 1


def target(sql: str, fmt: str = "table") -> dict[str, Any]:
    return {
        "refId": "A",
        "datasource": DS,
        "editorMode": "code",
        "rawQuery": True,
        "format": fmt,
        "rawSql": " ".join(sql.split()),
    }


def color_overrides(colors: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "matcher": {"id": "byName", "options": name},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}],
        }
        for name, color in colors.items()
    ]


def value_mappings(colors: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "type": "value",
            "options": {
                k: {"color": c, "index": i, "text": k} for i, (k, c) in enumerate(colors.items())
            },
        }
    ]


def row(lay: Layout, title: str) -> dict[str, Any]:
    lay.newline()
    return {
        "type": "row",
        "title": title,
        "id": lay.id(),
        "collapsed": False,
        "gridPos": lay.place(24, 1),
        "panels": [],
    }


def text(lay: Layout, content: str, w: int = 24, h: int = 3) -> dict[str, Any]:
    return {
        "type": "text",
        "title": "",
        "id": lay.id(),
        "gridPos": lay.place(w, h),
        "options": {"mode": "markdown", "content": content},
    }


def stat(
    lay: Layout,
    title: str,
    sql: str,
    *,
    w: int = 4,
    h: int = 4,
    unit: str = "none",
    color: str | None = None,
    thresholds: list[tuple[float | None, str]] | None = None,
    description: str = "",
    decimals: int | None = None,
) -> dict[str, Any]:
    steps = [{"color": c, "value": v} for v, c in (thresholds or [(None, color or "text")])]
    defaults: dict[str, Any] = {
        "unit": unit,
        "color": {"mode": "thresholds"},
        "thresholds": {"mode": "absolute", "steps": steps},
    }
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "type": "stat",
        "title": title,
        "description": description,
        "id": lay.id(),
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "targets": [target(sql)],
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "colorMode": "value" if thresholds else "none",
            "graphMode": "none",
            "justifyMode": "auto",
            "textMode": "value",
            "wideLayout": True,
        },
    }


def timeseries(
    lay: Layout,
    title: str,
    sql: str,
    *,
    w: int = 12,
    h: int = 8,
    colors: dict[str, str] | None = None,
    bars: bool = True,
    stacked: bool = True,
    unit: str = "none",
    description: str = "",
    min_interval: str = "1h",
) -> dict[str, Any]:
    custom = {
        "drawStyle": "bars" if bars else "line",
        "lineWidth": 2,
        "fillOpacity": 85 if bars else 0,
        "barAlignment": 0,
        "showPoints": "never",
        "stacking": {"mode": "normal" if stacked else "none", "group": "A"},
        "axisSoftMin": 0,
        "gradientMode": "none",
        "spanNulls": False,
        "axisBorderShow": False,
    }
    return {
        "type": "timeseries",
        "interval": min_interval,
        "title": title,
        "description": description,
        "id": lay.id(),
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "targets": [target(sql, "time_series")],
        "fieldConfig": {
            "defaults": {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}},
            "overrides": color_overrides(colors or {}),
        },
        "options": {
            "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
    }


def timeseries_15m(lay: Layout, title: str, sql: str, **kwargs: Any) -> dict[str, Any]:
    return timeseries(lay, title, sql, min_interval="15m", **kwargs)


def barchart(
    lay: Layout,
    title: str,
    sql: str,
    *,
    w: int = 8,
    h: int = 8,
    color: str = SINGLE,
    description: str = "",
) -> dict[str, Any]:
    """Horizontal top-N bars: first column = label, second = value."""
    return {
        "type": "barchart",
        "title": title,
        "description": description,
        "id": lay.id(),
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "targets": [target(sql)],
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "fixed", "fixedColor": color},
                "custom": {
                    "fillOpacity": 85,
                    "lineWidth": 0,
                    "axisBorderShow": False,
                    "gradientMode": "none",
                    "axisSoftMin": 0,
                },
            },
            "overrides": [],
        },
        "options": {
            "orientation": "horizontal",
            "showValue": "always",
            "barWidth": 0.7,
            "groupWidth": 0.7,
            "legend": {"showLegend": False, "displayMode": "list", "placement": "bottom"},
            "tooltip": {"mode": "single"},
            "xTickLabelRotation": 0,
            "xTickLabelMaxLength": 40,
            "stacking": "none",
        },
    }


def status_bars(
    lay: Layout,
    title: str,
    sql: str,
    colors: dict[str, str],
    *,
    w: int = 8,
    h: int = 8,
    description: str = "",
) -> dict[str, Any]:
    """Horizontal bars where each category keeps its fixed status color."""
    panel = barchart(lay, title, sql, w=w, h=h, description=description)
    panel["fieldConfig"]["defaults"]["color"] = {"mode": "thresholds"}
    panel["fieldConfig"]["defaults"]["thresholds"] = {
        "mode": "absolute",
        "steps": [{"color": SINGLE, "value": None}],
    }
    panel["options"]["colorByField"] = "label"
    panel["fieldConfig"]["overrides"] = [
        {
            "matcher": {"id": "byName", "options": "label"},
            "properties": [{"id": "mappings", "value": value_mappings(colors)}],
        }
    ]
    return panel


def table(
    lay: Layout,
    title: str,
    sql: str,
    *,
    w: int = 24,
    h: int = 10,
    colored: dict[str, dict[str, str]] | None = None,
    units: dict[str, str] | None = None,
    widths: dict[str, int] | None = None,
    description: str = "",
) -> dict[str, Any]:
    overrides = []
    for col, colors in (colored or {}).items():
        overrides.append(
            {
                "matcher": {"id": "byName", "options": col},
                "properties": [
                    {"id": "mappings", "value": value_mappings(colors)},
                    {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                ],
            }
        )
    for col, unit in (units or {}).items():
        overrides.append(
            {
                "matcher": {"id": "byName", "options": col},
                "properties": [{"id": "unit", "value": unit}],
            }
        )
    for col, width in (widths or {}).items():
        overrides.append(
            {
                "matcher": {"id": "byName", "options": col},
                "properties": [{"id": "custom.width", "value": width}],
            }
        )
    return {
        "type": "table",
        "title": title,
        "description": description,
        "id": lay.id(),
        "datasource": DS,
        "gridPos": lay.place(w, h),
        "targets": [target(sql)],
        "fieldConfig": {
            "defaults": {
                "custom": {"align": "auto", "filterable": True, "cellOptions": {"type": "auto"}}
            },
            "overrides": overrides,
        },
        "options": {
            "showHeader": True,
            "cellHeight": "sm",
            "footer": {"show": False, "reducer": ["sum"], "fields": ""},
        },
    }


def org_variable() -> dict[str, Any]:
    return {
        "name": "org",
        "label": "Organization",
        "type": "query",
        "datasource": DS,
        "query": "SELECT COALESCE(name, id::text) AS __text, id::text AS __value "
        "FROM organizations ORDER BY 1",
        "definition": "organizations",
        "refresh": 1,
        "multi": True,
        "includeAll": True,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
        "sort": 1,
        "options": [],
    }


def custom_variable(name: str, label: str, values: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": "custom",
        "query": ",".join(values),
        "multi": True,
        "includeAll": True,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
        "options": [{"selected": False, "text": v, "value": v} for v in values],
    }


def query_variable(name: str, label: str, sql: str) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": "query",
        "datasource": DS,
        "query": sql,
        "definition": sql,
        "refresh": 2,
        "multi": True,
        "includeAll": True,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
        "sort": 1,
        "options": [],
    }


def dashboard(
    uid: str,
    title: str,
    panels: list[dict[str, Any]],
    variables: list[dict[str, Any]],
    *,
    time_from: str = "now-7d",
    description: str = "",
) -> dict[str, Any]:
    return {
        "uid": uid,
        "title": title,
        "description": description,
        "tags": ["elements-pulse", "unofficial"],
        "timezone": "browser",
        "editable": True,
        "graphTooltip": 1,
        "schemaVersion": 39,
        "version": 1,
        "refresh": "5m",
        "time": {"from": time_from, "to": "now"},
        "templating": {"list": variables},
        "annotations": {"list": []},
        "links": [
            {
                "title": "WSElements-pulse",
                "type": "dashboards",
                "tags": ["elements-pulse"],
                "asDropdown": True,
                "includeVars": True,
                "keepTime": True,
            }
        ],
        "panels": panels,
    }


FOOTER = (
    "<small>Unofficial community project, not affiliated with or supported by WithSecure. "
    "Data comes from the WithSecure Elements API through the WSElements-pulse collector.</small>"
)


# ---------------------------------------------------------------- dashboards
def overview() -> dict[str, Any]:
    lay = Layout()
    p = [
        stat(
            lay,
            "Open incidents",
            f"SELECT count(*) FROM incidents WHERE {ORG} AND status <> 'closed'",
            description="All open incidents (ignores time range).",
            thresholds=[(None, "text"), (1, WARNING)],
        ),
        stat(
            lay,
            "Open severe / high",
            f"SELECT count(*) FROM incidents WHERE {ORG} "
            "AND status <> 'closed' AND risk_level IN ('severe', 'high')",
            thresholds=[(None, "text"), (1, CRITICAL)],
        ),
        stat(
            lay,
            "New incidents",
            f"SELECT count(*) FROM incidents WHERE {ORG} AND $__timeFilter(created_at)",
            description="Created in the selected time range.",
        ),
        stat(
            lay,
            "Security events",
            f"SELECT count(*) FROM security_events WHERE {ORG} AND $__timeFilter(persistence_ts)",
        ),
        stat(
            lay,
            "Critical events",
            f"SELECT count(*) FROM security_events WHERE {ORG} "
            "AND $__timeFilter(persistence_ts) AND severity = 'critical'",
            thresholds=[(None, "text"), (1, CRITICAL)],
        ),
        stat(
            lay,
            "Devices needing attention",
            f"SELECT count(*) FROM v_devices_current "
            f"WHERE {ORG} AND state = 'active' AND protection_status_overview IN "
            "('critical', 'warning', 'isolated')",
            thresholds=[(None, "text"), (1, WARNING)],
        ),
        timeseries(
            lay,
            "New incidents by risk level",
            f"SELECT $__timeGroupAlias(created_at, '1d'), risk_level AS metric, "
            f"count(*) AS value FROM incidents WHERE {ORG} AND $__timeFilter(created_at) "
            "GROUP BY 1, 2 ORDER BY 1",
            colors=RISK_COLORS,
        ),
        timeseries(
            lay,
            "Security events by severity",
            f"SELECT $__timeGroupAlias(persistence_ts, $__interval), severity AS metric, "
            f"count(*) AS value FROM security_events WHERE {ORG} "
            "AND $__timeFilter(persistence_ts) GROUP BY 1, 2 ORDER BY 1",
            colors=EVENT_SEVERITY_COLORS,
        ),
        barchart(
            lay,
            "Top devices by security events",
            f"SELECT COALESCE(device_name, target_name, device_id, 'unknown') AS device, "
            f"count(*) AS events FROM security_events WHERE {ORG} "
            "AND $__timeFilter(persistence_ts) GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
        ),
        barchart(
            lay,
            "Top detection types (EDR)",
            f"SELECT name AS detection, count(*) AS detections FROM incident_detections "
            f"WHERE {ORG} AND $__timeFilter(created_at) GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
            description="Detections attached to incidents (detections collector).",
        ),
        barchart(
            lay,
            "Top EPP threats / alert types",
            f"SELECT COALESCE(infection_name, alert_type, engine) AS threat, count(*) AS events "
            f"FROM security_events WHERE {ORG} AND engine_group = 'epp' "
            "AND $__timeFilter(persistence_ts) GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
        ),
        text(lay, FOOTER, h=2),
    ]
    return dashboard(
        "pulse-overview",
        "Elements Pulse / Overview",
        p,
        [org_variable()],
        description="Headline view of incidents, security events and devices.",
    )


def incidents() -> dict[str, Any]:
    lay = Layout()

    def incident_filter(a: str = "") -> str:
        return (
            f"{org_filter(a)} AND {a}risk_level IN (${{risk:sqlstring}}) "
            f"AND {a}status IN (${{status:sqlstring}})"
        )

    filt = incident_filter()
    p = [
        stat(
            lay,
            "Incidents created",
            f"SELECT count(*) FROM incidents WHERE {filt} AND $__timeFilter(created_at)",
        ),
        stat(
            lay,
            "Still open",
            f"SELECT count(*) FROM incidents WHERE {filt} "
            "AND $__timeFilter(created_at) AND status <> 'closed'",
            thresholds=[(None, "text"), (1, WARNING)],
        ),
        stat(
            lay,
            "Severe",
            f"SELECT count(*) FROM incidents WHERE {filt} "
            "AND $__timeFilter(created_at) AND risk_level = 'severe'",
            thresholds=[(None, "text"), (1, CRITICAL)],
        ),
        stat(
            lay,
            "False positive rate",
            f"SELECT 100.0 * count(*) FILTER (WHERE resolution "
            "IN ('falsePositive', 'autoFalsePositive')) / NULLIF(count(*) FILTER (WHERE "
            f"status = 'closed'), 0) FROM incidents WHERE {filt} AND $__timeFilter(created_at)",
            unit="percent",
            decimals=1,
            description="Share of closed incidents resolved as false positive.",
        ),
        stat(
            lay,
            "Median time to close",
            "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY "
            "EXTRACT(EPOCH FROM updated_at - created_at)) FROM incidents WHERE "
            f"{filt} AND status = 'closed' AND $__timeFilter(created_at)",
            unit="s",
            description="Approximation: last update time of closed incidents minus creation.",
        ),
        stat(
            lay,
            "Avg risk score",
            f"SELECT avg(risk_score) FROM incidents WHERE {filt} AND $__timeFilter(created_at)",
            decimals=1,
        ),
        timeseries(
            lay,
            "New incidents by risk level",
            f"SELECT $__timeGroupAlias(created_at, '$bucket'), risk_level AS metric, "
            f"count(*) AS value FROM incidents WHERE {filt} AND $__timeFilter(created_at) "
            "GROUP BY 1, 2 ORDER BY 1",
            colors=RISK_COLORS,
            w=12,
        ),
        timeseries(
            lay,
            "New incidents by current status",
            f"SELECT $__timeGroupAlias(created_at, '$bucket'), status AS metric, "
            f"count(*) AS value FROM incidents WHERE {filt} AND $__timeFilter(created_at) "
            "GROUP BY 1, 2 ORDER BY 1",
            colors=STATUS_COLORS,
            w=12,
        ),
        barchart(
            lay,
            "Categories",
            f"SELECT c AS category, count(*) AS incidents FROM incidents, "
            f"unnest(categories) AS c WHERE {filt} AND $__timeFilter(created_at) "
            "GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
        ),
        barchart(
            lay,
            "Resolutions (closed)",
            f"SELECT COALESCE(resolution, 'unknown') AS "
            f"resolution, count(*) AS incidents FROM incidents WHERE {filt} "
            "AND status = 'closed' AND $__timeFilter(created_at) GROUP BY 1 ORDER BY 2 DESC",
        ),
        barchart(
            lay,
            "MITRE ATT&CK techniques",
            "SELECT m AS technique, count(DISTINCT "
            "d.incident_id) AS incidents FROM incident_detections d JOIN incidents i ON "
            "i.incident_id = d.incident_id CROSS JOIN LATERAL unnest(d.mitre) AS m WHERE "
            f"{incident_filter('i.')} "
            "AND $__timeFilter(i.created_at) AND m LIKE 'T%' GROUP BY 1 ORDER BY 2 DESC "
            "LIMIT 10",
            description="Techniques reported by detections of these incidents.",
        ),
        table(
            lay,
            "Incidents",
            'SELECT i.public_id AS "ID", i.name AS "Name", '
            'COALESCE(o.name, i.organization_id::text) AS "Organization", '
            'i.status AS "Status", i.risk_level AS "Risk", round(i.risk_score::numeric, 1) '
            'AS "Score", i.resolution AS "Resolution", array_to_string(i.categories, \', \') '
            'AS "Categories", i.created_at AS "Created", i.updated_at AS "Updated" '
            "FROM incidents i LEFT JOIN organizations o ON o.id = i.organization_id WHERE "
            f"{incident_filter('i.')} "
            "AND $__timeFilter(i.created_at) ORDER BY i.created_at DESC LIMIT 500",
            colored={"Risk": RISK_COLORS, "Status": STATUS_COLORS},
            h=12,
            widths={"ID": 140, "Status": 110, "Risk": 90, "Score": 70},
        ),
        text(lay, FOOTER, h=2),
    ]
    variables = [
        org_variable(),
        custom_variable("risk", "Risk level", list(RISK_COLORS)),
        custom_variable("status", "Status", list(STATUS_COLORS)),
        {
            "name": "bucket",
            "label": "Bucket",
            "type": "custom",
            "query": "1d,1w",
            "current": {"selected": True, "text": "1d", "value": "1d"},
            "options": [
                {"selected": True, "text": "1d", "value": "1d"},
                {"selected": False, "text": "1w", "value": "1w"},
            ],
        },
    ]
    return dashboard(
        "pulse-incidents", "Elements Pulse / Incidents (BCDs)", p, variables, time_from="now-30d"
    )


def security_events() -> dict[str, Any]:
    lay = Layout()

    def event_filter(a: str = "") -> str:
        return (
            f"{org_filter(a)} AND {a}engine_group IN (${{group:sqlstring}}) "
            f"AND {a}severity IN (${{severity:sqlstring}}) "
            f"AND {a}engine IN (${{engine:sqlstring}}) AND $__timeFilter({a}persistence_ts)"
        )

    filt = event_filter()
    p = [
        stat(lay, "Events", f"SELECT count(*) FROM security_events WHERE {filt}"),
        stat(
            lay,
            "EPP",
            f"SELECT count(*) FROM security_events WHERE {filt} AND engine_group = 'epp'",
        ),
        stat(
            lay,
            "EDR",
            f"SELECT count(*) FROM security_events WHERE {filt} AND engine_group = 'edr'",
        ),
        stat(
            lay,
            "Critical",
            f"SELECT count(*) FROM security_events WHERE {filt} AND severity = 'critical'",
            thresholds=[(None, "text"), (1, CRITICAL)],
        ),
        stat(
            lay,
            "Distinct devices",
            f"SELECT count(DISTINCT COALESCE(device_id, target_id)) "
            f"FROM security_events WHERE {filt}",
        ),
        stat(
            lay,
            "Acknowledged",
            f"SELECT 100.0 * count(*) FILTER (WHERE acknowledged) / "
            f"NULLIF(count(*), 0) FROM security_events WHERE {filt}",
            unit="percent",
            decimals=1,
        ),
        timeseries(
            lay,
            "EPP vs EDR",
            f"SELECT $__timeGroupAlias(persistence_ts, $__interval), "
            f"upper(engine_group) AS metric, count(*) AS value FROM security_events "
            f"WHERE {filt} GROUP BY 1, 2 ORDER BY 1",
            colors=GROUP_COLORS,
        ),
        timeseries(
            lay,
            "By engine",
            f"SELECT $__timeGroupAlias(persistence_ts, $__interval), "
            f"{ENGINE_CASE} AS metric, count(*) AS value FROM security_events "
            f"WHERE {filt} GROUP BY 1, 2 ORDER BY 1",
            colors=ENGINE_COLORS,
            description="Less common engines are grouped as Other.",
        ),
        status_bars(
            lay,
            "By severity",
            f"SELECT severity AS label, count(*) AS events FROM "
            f"security_events WHERE {filt} GROUP BY 1 ORDER BY 2 DESC",
            EVENT_SEVERITY_COLORS,
        ),
        barchart(
            lay,
            "By classification (alert type)",
            "SELECT COALESCE(alert_type, "
            f"'unclassified') AS alert_type, count(*) AS events FROM security_events "
            f"WHERE {filt} GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
        ),
        barchart(
            lay,
            "By action",
            f"SELECT COALESCE(action, 'unknown') AS action, count(*) "
            f"AS events FROM security_events WHERE {filt} GROUP BY 1 ORDER BY 2 DESC",
        ),
        barchart(
            lay,
            "Top devices",
            "SELECT COALESCE(device_name, target_name, device_id, "
            f"'unknown') AS device, count(*) AS events FROM security_events WHERE {filt} "
            "GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
            w=12,
        ),
        barchart(
            lay,
            "Top threats",
            "SELECT infection_name AS threat, count(*) AS events "
            f"FROM security_events WHERE {filt} AND infection_name IS NOT NULL "
            "GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
            w=12,
        ),
        table(
            lay,
            "Latest events",
            'SELECT e.persistence_ts AS "Time", '
            'COALESCE(o.name, e.organization_id::text) AS "Organization", '
            'upper(e.engine_group) AS "Group", e.engine AS "Engine", e.severity AS '
            '"Severity", e.action AS "Action", COALESCE(e.device_name, e.target_name) AS '
            '"Device / target", e.alert_type AS "Alert type", e.message AS "Message" '
            "FROM security_events e LEFT JOIN organizations o ON o.id = e.organization_id "
            f"WHERE {event_filter('e.')} "
            "ORDER BY e.persistence_ts DESC LIMIT 500",
            colored={"Severity": EVENT_SEVERITY_COLORS},
            h=12,
            widths={"Group": 70, "Severity": 90, "Action": 100},
        ),
        text(lay, FOOTER, h=2),
    ]
    variables = [
        org_variable(),
        custom_variable("group", "Engine group", ["epp", "edr", "ecp", "xm"]),
        custom_variable("severity", "Severity", list(EVENT_SEVERITY_COLORS)),
        query_variable(
            "engine",
            "Engine",
            "SELECT DISTINCT engine FROM security_events WHERE engine IS NOT NULL ORDER BY 1",
        ),
    ]
    return dashboard("pulse-security-events", "Elements Pulse / Security events", p, variables)


def devices() -> dict[str, Any]:
    lay = Layout()
    cur = f"v_devices_current WHERE {ORG} AND type IN (${{dtype:sqlstring}})"
    p = [
        stat(lay, "Devices", f"SELECT count(*) FROM {cur} AND state = 'active'"),
        stat(lay, "Online", f"SELECT count(*) FROM {cur} AND state = 'active' AND online"),
        stat(
            lay,
            "Protection issues",
            f"SELECT count(*) FROM {cur} AND state = 'active' "
            "AND protection_status_overview IN ('critical', 'warning')",
            thresholds=[(None, "text"), (1, WARNING)],
        ),
        stat(
            lay,
            "Outdated agents",
            "SELECT count(*) FROM v_device_agent_status a JOIN "
            "v_devices_current d USING (device_id) WHERE d.organization_id::text IN "
            "(${org:sqlstring}) AND d.type IN (${dtype:sqlstring}) AND d.state = 'active' "
            "AND a.outdated",
            thresholds=[(None, "text"), (1, WARNING)],
            description="Agent version older than the newest one seen for the same org, "
            "device type and OS.",
        ),
        stat(
            lay,
            "End-of-life OS",
            f"SELECT count(*) FROM {cur} AND state = 'active' AND os_end_of_life",
            thresholds=[(None, "text"), (1, SERIOUS)],
        ),
        stat(
            lay,
            "Not seen for 7 days",
            f"SELECT count(*) FROM {cur} AND state = 'active' "
            "AND status_update_at < now() - interval '7 days'",
            thresholds=[(None, "text"), (1, WARNING)],
        ),
        status_bars(
            lay,
            "Protection status",
            "SELECT COALESCE(protection_status_overview, "
            f"'unknown') AS label, count(*) AS devices FROM {cur} AND state = 'active' "
            "GROUP BY 1 ORDER BY 2 DESC",
            PROTECTION_COLORS,
        ),
        timeseries(
            lay,
            "Protection status trend (daily)",
            "SELECT day::timestamptz AS time, "
            "protection_status_overview AS metric, sum(count) AS value FROM "
            f"device_status_daily WHERE {ORG} AND $__timeFilter(day::timestamptz) "
            "GROUP BY 1, 2 ORDER BY 1",
            colors=PROTECTION_COLORS,
            w=16,
            description="One snapshot per day, all device types.",
        ),
        barchart(
            lay,
            "Operating systems",
            f"SELECT COALESCE(os_name, 'unknown') AS os, "
            f"count(*) AS devices FROM {cur} AND state = 'active' GROUP BY 1 "
            "ORDER BY 2 DESC LIMIT 10",
        ),
        barchart(
            lay,
            "Agent versions",
            f"SELECT COALESCE(client_version, 'unknown') AS "
            f"version, count(*) AS devices FROM {cur} AND state = 'active' GROUP BY 1 "
            "ORDER BY 2 DESC LIMIT 10",
        ),
        barchart(
            lay,
            "Software updates state",
            "SELECT COALESCE(patch_overall_state, "
            f"'unknown') AS state, count(*) AS devices FROM {cur} AND state = 'active' "
            "GROUP BY 1 ORDER BY 2 DESC",
        ),
        table(
            lay,
            "Devices needing attention",
            'SELECT d.name AS "Device", '
            'COALESCE(o.name, d.organization_id::text) AS "Organization", d.type AS '
            '"Type", d.os_name AS "OS", d.client_version AS "Agent", '
            'd.protection_status_overview AS "Overview", d.protection_status AS '
            '"Status", d.malware_state AS "Malware", d.firewall_state AS "Firewall", '
            'd.patch_overall_state AS "Updates", d.online AS "Online", d.status_update_at '
            'AS "Last seen", a.outdated AS "Outdated agent" FROM v_devices_current d '
            "LEFT JOIN organizations o ON o.id = d.organization_id LEFT JOIN "
            "v_device_agent_status a USING (device_id) WHERE d.organization_id::text IN "
            "(${org:sqlstring}) AND d.type IN (${dtype:sqlstring}) AND d.state = 'active' "
            "AND (d.protection_status_overview <> 'allOk' OR a.outdated OR d.os_end_of_life "
            "OR d.status_update_at < now() - interval '7 days') ORDER BY CASE "
            "d.protection_status_overview WHEN 'critical' THEN 0 WHEN 'isolated' THEN 1 "
            "WHEN 'warning' THEN 2 ELSE 3 END, d.status_update_at NULLS FIRST LIMIT 500",
            colored={"Overview": PROTECTION_COLORS},
            h=12,
        ),
        text(lay, FOOTER, h=2),
    ]
    variables = [
        org_variable(),
        custom_variable("dtype", "Device type", ["computer", "mobile", "connector"]),
    ]
    return dashboard("pulse-devices", "Elements Pulse / Devices", p, variables, time_from="now-30d")


def audit_logs() -> dict[str, Any]:
    lay = Layout()

    def audit_filter(a: str = "") -> str:
        return (
            f"{org_filter(a)} AND {a}action IN (${{action:sqlstring}}) "
            f"AND $__timeFilter({a}server_ts)"
        )

    filt = audit_filter()
    p = [
        stat(lay, "Audit entries", f"SELECT count(*) FROM audit_logs WHERE {filt}", w=6),
        stat(
            lay,
            "Distinct users",
            f"SELECT count(DISTINCT username) FROM audit_logs WHERE {filt}",
            w=6,
        ),
        stat(
            lay, "Logins", f"SELECT count(*) FROM audit_logs WHERE {filt} AND action = 'login'", w=6
        ),
        stat(
            lay,
            "Network isolations",
            f"SELECT count(*) FROM audit_logs WHERE {filt} AND action = 'isolateFromNetwork'",
            w=6,
            thresholds=[(None, "text"), (1, WARNING)],
        ),
        timeseries(
            lay,
            "Entries over time",
            f"SELECT $__timeGroupAlias(server_ts, $__interval), "
            f"namespace AS metric, count(*) AS value FROM audit_logs WHERE {filt} "
            "GROUP BY 1, 2 ORDER BY 1",
            w=24,
            colors={"elements-core": CAT[0], "epp": CAT[1]},
        ),
        barchart(
            lay,
            "Top actions",
            f"SELECT action, count(*) AS entries FROM audit_logs "
            f"WHERE {filt} GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
            w=12,
        ),
        barchart(
            lay,
            "Top users",
            "SELECT COALESCE(username, 'system') AS username, count(*) "
            f"AS entries FROM audit_logs WHERE {filt} GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
            w=12,
        ),
        table(
            lay,
            "Entries",
            'SELECT a.server_ts AS "Time", COALESCE(o.name, '
            'a.organization_id::text) AS "Organization", a.username AS "User", a.action '
            'AS "Action", a.target_name AS "Target", a.description AS "Description" '
            "FROM audit_logs a LEFT JOIN organizations o ON o.id = a.organization_id WHERE "
            f"{audit_filter('a.')} "
            "ORDER BY a.server_ts DESC LIMIT 500",
            h=12,
        ),
        text(lay, FOOTER, h=2),
    ]
    variables = [
        org_variable(),
        query_variable(
            "action",
            "Action",
            "SELECT DISTINCT action FROM audit_logs WHERE action IS NOT NULL ORDER BY 1",
        ),
    ]
    return dashboard("pulse-audit-logs", "Elements Pulse / Audit logs", p, variables)


def collector_health() -> dict[str, Any]:
    lay = Layout()
    req = f"api_requests WHERE (organization_id IS NULL OR {ORG}) AND $__timeFilter(ts)"
    p = [
        stat(
            lay,
            "Stale collectors",
            f"SELECT count(*) FROM v_collector_health WHERE {ORG} AND stale",
            thresholds=[(None, GOOD), (1, CRITICAL)],
            description="No successful run for 3 intervals.",
        ),
        stat(
            lay,
            "Failing collectors",
            f"SELECT count(*) FROM v_collector_health WHERE {ORG} AND consecutive_failures > 0",
            thresholds=[(None, GOOD), (1, WARNING)],
        ),
        stat(lay, "API calls", f"SELECT count(*) FROM {req}"),
        stat(
            lay,
            "API error rate",
            "SELECT 100.0 * count(*) FILTER (WHERE status IS NULL OR "
            f"status >= 400) / NULLIF(count(*), 0) FROM {req}",
            unit="percent",
            decimals=2,
            thresholds=[(None, "text"), (5, WARNING)],
        ),
        stat(
            lay,
            "Rate limited (429)",
            f"SELECT count(*) FROM {req} AND status = 429",
            thresholds=[(None, "text"), (1, WARNING)],
        ),
        stat(
            lay,
            "p95 API latency",
            f"SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) FROM {req}",
            unit="ms",
        ),
        table(
            lay,
            "Collectors",
            'SELECT collector AS "Collector", COALESCE(organization_name, '
            "organization_id::text) AS \"Organization\", CASE WHEN stale THEN 'stale' WHEN "
            "consecutive_failures > 0 THEN 'failing' ELSE 'ok' END AS \"State\", "
            'last_success_at AS "Last success", cursor_ts AS "Cursor", '
            'consecutive_failures AS "Failures", interval_seconds AS "Interval", '
            'last_error AS "Last error" FROM v_collector_health WHERE '
            f"{ORG} ORDER BY stale DESC, consecutive_failures DESC, collector",
            colored={"State": {"stale": CRITICAL, "failing": WARNING, "ok": GOOD}},
            units={"Interval": "s"},
            h=9,
            widths={"State": 80, "Failures": 80},
        ),
        timeseries_15m(
            lay,
            "Items fetched per collector",
            "SELECT $__timeGroupAlias(started_at, "
            "$__interval), collector AS metric, sum(items_fetched) AS value FROM "
            f"collector_runs WHERE {ORG} AND $__timeFilter(started_at) GROUP BY 1, 2 "
            "ORDER BY 1",
            colors=COLLECTOR_COLORS,
        ),
        timeseries_15m(
            lay,
            "Failed runs",
            "SELECT $__timeGroupAlias(started_at, $__interval), "
            "collector AS metric, count(*) AS value FROM collector_runs WHERE "
            f"{ORG} AND status = 'error' AND $__timeFilter(started_at) GROUP BY 1, 2 "
            "ORDER BY 1",
            colors=COLLECTOR_COLORS,
        ),
        timeseries_15m(
            lay,
            "API latency p95 by endpoint",
            "SELECT $__timeGroupAlias(ts, "
            "$__interval), endpoint AS metric, percentile_cont(0.95) WITHIN GROUP "
            f"(ORDER BY duration_ms) AS value FROM {req} GROUP BY 1, 2 ORDER BY 1",
            colors=ENDPOINT_COLORS,
            bars=False,
            stacked=False,
            unit="ms",
        ),
        timeseries_15m(
            lay,
            "API responses by status",
            "SELECT $__timeGroupAlias(ts, $__interval), "
            "CASE WHEN status IS NULL THEN 'network error' WHEN status = 429 THEN '429' "
            "WHEN status >= 500 THEN '5xx' WHEN status >= 400 THEN '4xx' ELSE '2xx' END "
            f"AS metric, count(*) AS value FROM {req} GROUP BY 1, 2 ORDER BY 1",
            colors={
                "2xx": NEUTRAL,
                "4xx": SERIOUS,
                "429": WARNING,
                "5xx": CRITICAL,
                "network error": CAT[6],
            },
        ),
        table(
            lay,
            "Recent errors",
            'SELECT r.started_at AS "Started", r.collector AS '
            '"Collector", COALESCE(o.name, r.organization_id::text) AS "Organization", '
            'r.error AS "Error" FROM collector_runs r LEFT JOIN organizations o ON '
            "o.id = r.organization_id WHERE r.organization_id::text IN (${org:sqlstring}) AND "
            "r.status = 'error' AND $__timeFilter(r.started_at) ORDER BY r.started_at DESC "
            "LIMIT 100",
            h=8,
        ),
        text(lay, FOOTER, h=2),
    ]
    return dashboard(
        "pulse-collector-health",
        "Elements Pulse / Collector health",
        p,
        [org_variable()],
        time_from="now-24h",
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    builders = {
        "overview.json": overview,
        "incidents.json": incidents,
        "security-events.json": security_events,
        "devices.json": devices,
        "audit-logs.json": audit_logs,
        "collector-health.json": collector_health,
    }
    for name, build in builders.items():
        (OUT / name).write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
        print(f"wrote {OUT / name}")


if __name__ == "__main__":
    main()
