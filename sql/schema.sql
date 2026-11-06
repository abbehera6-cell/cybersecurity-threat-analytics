-- ===========================================================================
-- Enterprise Cybersecurity & Threat Intelligence Analytics Platform
-- PostgreSQL 16 schema for the CICIDS2017 flow warehouse.
--
-- This file is idempotent: it can be applied to an empty database or to one
-- that already has the objects. Re-running it never drops data and never
-- duplicates the seeded labels.
--
-- Apply with:  python -m src.database --schema-only
--
-- Design notes
--   * attack_labels is a lookup table, not a text column on every flow. The 15
--     labels and their reporting families live in exactly one place, so a
--     correction to a family does not require rewriting 2.8M rows.
--   * network_flows carries flow_key = "<source file>:<row index>". That is the
--     natural key the loader upserts on, which is what makes the pipeline safe
--     to re-run.
--   * source_ip / destination_ip are nullable on purpose. The MachineLearningCSV
--     release of CICIDS2017 does not contain endpoint addresses; only the
--     pcap-derived files do. The columns exist so those files can be loaded
--     without a migration, and stay null for this release.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS attack_labels (
    label_id    SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    label       TEXT     NOT NULL UNIQUE,
    family      TEXT,
    is_attack   BOOLEAN  NOT NULL
);

COMMENT ON TABLE  attack_labels IS 'The 15 observed labels (BENIGN + 14 attack types) with their reporting family.';
COMMENT ON COLUMN attack_labels.family IS 'Reporting grouping such as DoS, DDoS, Brute Force. NULL for BENIGN.';

CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id                  TEXT        PRIMARY KEY,
    started_at              TIMESTAMPTZ NOT NULL,
    finished_at             TIMESTAMPTZ,
    status                  TEXT        NOT NULL DEFAULT 'running',
    raw_dir                 TEXT,
    source_files            TEXT[],
    rows_extracted          BIGINT      NOT NULL DEFAULT 0,
    rows_cleaned            BIGINT      NOT NULL DEFAULT 0,
    duplicates_removed      BIGINT      NOT NULL DEFAULT 0,
    invalid_rows_removed    BIGINT      NOT NULL DEFAULT 0,
    rows_loaded             BIGINT      NOT NULL DEFAULT 0,
    notes                   TEXT
);

COMMENT ON TABLE pipeline_runs IS 'One row per ETL run. Dashboard footers read provenance from here.';

CREATE TABLE IF NOT EXISTS network_flows (
    flow_id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    flow_key                TEXT        NOT NULL UNIQUE,
    run_id                  TEXT        NOT NULL REFERENCES pipeline_runs (run_id) ON DELETE CASCADE,
    captured_at             TIMESTAMP   NOT NULL,
    capture_date            DATE        NOT NULL,
    source_ip               INET,
    destination_ip          INET,
    source_port             INTEGER,
    destination_port        INTEGER,
    protocol                SMALLINT,
    duration_ms             DOUBLE PRECISION,
    total_fwd_packets       INTEGER,
    total_backward_packets  INTEGER,
    total_bytes             BIGINT,
    bytes_per_packet        DOUBLE PRECISION,
    packets_per_second      DOUBLE PRECISION,
    total_flags             INTEGER,
    label_id                SMALLINT    NOT NULL REFERENCES attack_labels (label_id),
    loaded_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  network_flows IS 'One row per cleaned CICIDS2017 flow record.';
COMMENT ON COLUMN network_flows.flow_key IS 'source_file:row_index - the natural key used for idempotent loading.';
COMMENT ON COLUMN network_flows.captured_at IS 'Flow timestamp exactly as recorded in the capture. Deliberately timestamp WITHOUT time zone: CICIDS2017 has no zone, and timestamptz would silently reinterpret it in the server locale.';

CREATE INDEX IF NOT EXISTS idx_network_flows_captured_at
    ON network_flows (captured_at);
CREATE INDEX IF NOT EXISTS idx_network_flows_capture_date
    ON network_flows (capture_date);
CREATE INDEX IF NOT EXISTS idx_network_flows_destination_port
    ON network_flows (destination_port);
CREATE INDEX IF NOT EXISTS idx_network_flows_label
    ON network_flows (label_id);
CREATE INDEX IF NOT EXISTS idx_network_flows_run
    ON network_flows (run_id);

CREATE TABLE IF NOT EXISTS flow_predictions (
    run_id              TEXT    NOT NULL REFERENCES pipeline_runs (run_id) ON DELETE CASCADE,
    flow_id             BIGINT  NOT NULL REFERENCES network_flows (flow_id) ON DELETE CASCADE,
    predicted_class     TEXT    NOT NULL,
    attack_probability  DOUBLE PRECISION,
    anomaly_score       DOUBLE PRECISION,
    is_anomaly          BOOLEAN,
    cluster_id          SMALLINT,
    risk_band           TEXT,
    PRIMARY KEY (run_id, flow_id)
);

COMMENT ON TABLE flow_predictions IS 'Model output per flow per run. Filled by the ML phase, read by the dashboard.';
COMMENT ON COLUMN flow_predictions.risk_band IS 'Derived prioritisation band. Not evidence that a flow was an attack.';

-- ---------------------------------------------------------------------------
-- Seed the label lookup. The canonical list lives in config/settings.py; this
-- block is kept in sync with it and tests/test_database.py fails if they drift.
-- ---------------------------------------------------------------------------
INSERT INTO attack_labels (label, family, is_attack) VALUES
    ('BENIGN',                    NULL,           FALSE),
    ('Bot',                       'Bot',          TRUE),
    ('DDoS',                      'DDoS',         TRUE),
    ('DoS GoldenEye',             'DoS',          TRUE),
    ('DoS Hulk',                  'DoS',          TRUE),
    ('DoS Slowloris',             'DoS',          TRUE),
    ('DoS Slowhttptest',          'DoS',          TRUE),
    ('FTP-Patator',               'Brute Force',  TRUE),
    ('Heartbleed',                'Heartbleed',   TRUE),
    ('Infiltration',              'Infiltration', TRUE),
    ('PortScan',                  'PortScan',     TRUE),
    ('SSH-Patator',               'Brute Force',  TRUE),
    ('Web Attack - Brute Force',  'Web Attack',   TRUE),
    ('Web Attack - SQL Injection','Web Attack',   TRUE),
    ('Web Attack - XSS',          'Web Attack',   TRUE)
ON CONFLICT (label) DO NOTHING;
