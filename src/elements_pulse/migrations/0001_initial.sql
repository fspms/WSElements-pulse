-- WSElements-pulse initial schema.
-- Every data table carries organization_id and the raw API payload (JSONB).

CREATE TABLE organizations (
    id              uuid PRIMARY KEY,
    name            text,
    type            text,
    source          text NOT NULL CHECK (source IN ('config', 'discovered', 'observed', 'seed')),
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- One row per collector key (e.g. 'incidents', 'security_events:epp') and organization.
CREATE TABLE sync_state (
    collector             text NOT NULL,
    organization_id       uuid NOT NULL,
    cursor_ts             timestamptz,
    last_run_started_at   timestamptz,
    last_success_at       timestamptz,
    last_error            text,
    last_error_at         timestamptz,
    consecutive_failures  integer NOT NULL DEFAULT 0,
    interval_seconds      integer,
    PRIMARY KEY (collector, organization_id)
);

CREATE TABLE collector_runs (
    id               bigserial PRIMARY KEY,
    collector        text NOT NULL,
    organization_id  uuid NOT NULL,
    started_at       timestamptz NOT NULL DEFAULT now(),
    finished_at      timestamptz,
    status           text NOT NULL DEFAULT 'running'
                     CHECK (status IN ('running', 'ok', 'error', 'cancelled')),
    items_fetched    integer NOT NULL DEFAULT 0,
    items_upserted   integer NOT NULL DEFAULT 0,
    api_calls        integer NOT NULL DEFAULT 0,
    error            text
);
CREATE INDEX collector_runs_started_idx ON collector_runs (started_at);
CREATE INDEX collector_runs_collector_idx ON collector_runs (collector, organization_id, started_at DESC);

CREATE TABLE api_requests (
    id               bigserial PRIMARY KEY,
    ts               timestamptz NOT NULL,
    organization_id  uuid,
    method           text NOT NULL,
    endpoint         text NOT NULL,
    status           integer,          -- NULL = transport error / timeout
    duration_ms      integer NOT NULL,
    attempt          integer NOT NULL DEFAULT 0
);
CREATE INDEX api_requests_ts_idx ON api_requests (ts);

CREATE TABLE incidents (
    incident_id          uuid PRIMARY KEY,
    organization_id      uuid NOT NULL,
    public_id            text,
    name                 text,
    status               text,
    severity             text,
    risk_level           text,
    risk_score           double precision,
    resolution           text,
    categories           text[] NOT NULL DEFAULT '{}',
    sources              text[] NOT NULL DEFAULT '{}',
    created_at           timestamptz,
    updated_at           timestamptz,
    initial_received_at  timestamptz,
    detections_synced_at timestamptz,
    raw                  jsonb NOT NULL,
    first_collected_at   timestamptz NOT NULL DEFAULT now(),
    last_collected_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incidents_org_created_idx ON incidents (organization_id, created_at);
CREATE INDEX incidents_org_updated_idx ON incidents (organization_id, updated_at);
CREATE INDEX incidents_status_idx ON incidents (status);

CREATE TABLE incident_detections (
    detection_id      text PRIMARY KEY,
    incident_id       uuid NOT NULL,
    organization_id   uuid NOT NULL,
    device_id         text,
    name              text,
    detection_class   text,
    severity          text,
    risk_level        text,
    exe_name          text,
    exe_path          text,
    exe_hash          text,
    cmdl              text,
    username          text,
    mitre             text[] NOT NULL DEFAULT '{}',
    created_at        timestamptz,
    raw               jsonb NOT NULL,
    first_collected_at timestamptz NOT NULL DEFAULT now(),
    last_collected_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incident_detections_incident_idx ON incident_detections (incident_id);
CREATE INDEX incident_detections_org_created_idx ON incident_detections (organization_id, created_at);

CREATE TABLE security_events (
    event_id          text PRIMARY KEY,
    organization_id   uuid NOT NULL,
    engine            text,
    engine_group      text,
    severity          text,
    action            text,
    alert_type        text,
    infection_name    text,
    persistence_ts    timestamptz NOT NULL,
    server_ts         timestamptz,
    client_ts         timestamptz,
    device_id         text,
    device_name       text,
    target_id         text,
    target_name       text,
    user_name         text,
    acknowledged      boolean,
    message           text,
    description       text,
    raw               jsonb NOT NULL,
    first_collected_at timestamptz NOT NULL DEFAULT now(),
    last_collected_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX security_events_org_ts_idx ON security_events (organization_id, persistence_ts);
CREATE INDEX security_events_ts_brin ON security_events USING brin (persistence_ts);
CREATE INDEX security_events_engine_idx ON security_events (engine_group, engine);
CREATE INDEX security_events_device_idx ON security_events (device_id);

CREATE TABLE devices (
    device_id                   text PRIMARY KEY,
    organization_id             uuid NOT NULL,
    polled_organization_id      uuid NOT NULL,  -- org the snapshot was requested for
    name                        text,
    type                        text,
    state                       text,
    os_name                     text,
    os_version                  text,
    os_end_of_life              boolean,
    client_version              text,
    protection_status           text,
    protection_status_overview  text,
    malware_state               text,
    firewall_state              text,
    patch_overall_state         text,
    online                      boolean,
    last_user                   text,
    product_variant             text,
    status_update_at            timestamptz,
    registered_at               timestamptz,
    removed_at                  timestamptz,   -- set when a full snapshot no longer returns it
    raw                         jsonb NOT NULL,
    first_collected_at          timestamptz NOT NULL DEFAULT now(),
    last_collected_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX devices_org_idx ON devices (organization_id);
CREATE INDEX devices_polled_org_idx ON devices (polled_organization_id);

CREATE TABLE device_status_daily (
    day                         date NOT NULL,
    organization_id             uuid NOT NULL,
    protection_status_overview  text NOT NULL,
    count                       integer NOT NULL,
    PRIMARY KEY (day, organization_id, protection_status_overview)
);

CREATE TABLE audit_logs (
    id               text PRIMARY KEY,
    organization_id  uuid NOT NULL,
    server_ts        timestamptz NOT NULL,
    namespace        text,
    action           text,
    username         text,
    target_id        text,
    target_name      text,
    description      text,
    raw              jsonb NOT NULL,
    first_collected_at timestamptz NOT NULL DEFAULT now(),
    last_collected_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_org_ts_idx ON audit_logs (organization_id, server_ts);
CREATE INDEX audit_logs_action_idx ON audit_logs (action);
