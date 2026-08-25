-- CNServerOps Central production schema. PostgreSQL 15+ recommended.
CREATE TABLE IF NOT EXISTS runners (
    runner_id text PRIMARY KEY,
    runtime_version text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS servers (
    fingerprint_sha256 char(64) PRIMARY KEY,
    server_id text NOT NULL UNIQUE,
    vendor text NOT NULL,
    model text NOT NULL,
    system_serial text NOT NULL,
    board_serial text NOT NULL DEFAULT '',
    chassis_serial text NOT NULL DEFAULT '',
    confidence text NOT NULL,
    identity jsonb NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS servers_vendor_serial_idx ON servers(vendor, system_serial);

CREATE TABLE IF NOT EXISTS runs (
    run_id text PRIMARY KEY,
    server_fingerprint_sha256 char(64) NOT NULL REFERENCES servers(fingerprint_sha256),
    runner_id text NOT NULL REFERENCES runners(runner_id),
    runtime_version text NOT NULL,
    boot_id uuid,
    continuation_of_run_id text NOT NULL DEFAULT '',
    started_at timestamptz NOT NULL,
    workflow_mode text NOT NULL DEFAULT 'PRODUCTION',
    test_profile text NOT NULL DEFAULT 'STANDARD',
    completed_at timestamptz,
    current_stage text NOT NULL,
    collection_status text NOT NULL,
    export_status text NOT NULL,
    central_sync_status text NOT NULL,
    final_disposition text,
    reason_codes jsonb NOT NULL DEFAULT '[]'::jsonb,
    result jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS runs_server_started_idx ON runs(server_fingerprint_sha256, started_at);
CREATE INDEX IF NOT EXISTS runs_runner_started_idx ON runs(runner_id, started_at);

CREATE TABLE IF NOT EXISTS events (
    event_id text PRIMARY KEY,
    run_id text NOT NULL REFERENCES runs(run_id),
    event_type text NOT NULL,
    payload_sha256 char(64) NOT NULL,
    payload jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS events_run_received_idx ON events(run_id, received_at);

CREATE TABLE IF NOT EXISTS artifacts (
    run_id text NOT NULL REFERENCES runs(run_id),
    artifact_sha256 char(64) NOT NULL,
    artifact_type text NOT NULL,
    uri text NOT NULL,
    size_bytes bigint NOT NULL CHECK(size_bytes >= 0),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY(run_id, artifact_sha256, artifact_type)
);

CREATE TABLE IF NOT EXISTS firmware_catalog_snapshots (
    catalog_id text PRIMARY KEY,
    vendor text NOT NULL,
    checked_at timestamptz NOT NULL,
    source text NOT NULL,
    status text NOT NULL,
    entries jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS firmware_objects (
    sha256 char(64) PRIMARY KEY,
    vendor text NOT NULL,
    component text NOT NULL,
    version text NOT NULL,
    object_uri text NOT NULL,
    size_bytes bigint NOT NULL CHECK(size_bytes > 0),
    metadata jsonb NOT NULL,
    cached_at timestamptz NOT NULL DEFAULT now()
);
