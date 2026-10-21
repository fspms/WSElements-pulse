-- Helper function and views used by the Grafana dashboards.

-- Turns '23.4.1234' / '25.3 build 7' into {23,4,1234} / {25,3} for version comparisons.
CREATE OR REPLACE FUNCTION pulse_version_key(v text) RETURNS integer[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN substring(v FROM '^[0-9]+(?:\.[0-9]+)*') IS NULL THEN NULL
        ELSE string_to_array(substring(v FROM '^[0-9]+(?:\.[0-9]+)*'), '.')::integer[]
    END
$$;

-- Devices currently known (not removed from Elements).
CREATE VIEW v_devices_current AS
SELECT * FROM devices WHERE removed_at IS NULL;

-- Agent version compared with the newest version seen for the same org / device type / OS.
CREATE VIEW v_device_agent_status AS
WITH cur AS (
    SELECT d.*, pulse_version_key(d.client_version) AS vkey
    FROM v_devices_current d
),
newest AS (
    SELECT organization_id, type, os_name, max(vkey) AS newest_vkey
    FROM cur
    WHERE vkey IS NOT NULL
    GROUP BY organization_id, type, os_name
)
SELECT
    cur.device_id,
    cur.organization_id,
    cur.name,
    cur.type,
    cur.os_name,
    cur.client_version,
    array_to_string(n.newest_vkey, '.') AS newest_client_version,
    (cur.vkey IS NOT NULL AND cur.vkey < n.newest_vkey) AS outdated
FROM cur
LEFT JOIN newest n
    ON n.organization_id = cur.organization_id
   AND n.type IS NOT DISTINCT FROM cur.type
   AND n.os_name IS NOT DISTINCT FROM cur.os_name;

-- Latest state per collector key / org, with a staleness flag.
CREATE VIEW v_collector_health AS
SELECT
    s.collector,
    s.organization_id,
    o.name AS organization_name,
    s.cursor_ts,
    s.last_run_started_at,
    s.last_success_at,
    s.last_error,
    s.last_error_at,
    s.consecutive_failures,
    s.interval_seconds,
    CASE
        WHEN s.last_success_at IS NULL THEN true
        WHEN s.interval_seconds IS NULL THEN false
        ELSE s.last_success_at < now() - make_interval(secs => s.interval_seconds * 3)
    END AS stale
FROM sync_state s
LEFT JOIN organizations o ON o.id = s.organization_id;
