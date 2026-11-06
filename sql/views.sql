-- ===========================================================================
-- Reporting views for the CICIDS2017 warehouse.
--
-- These exist so the Power BI semantic model (Phase 7) and the notebooks read
-- one tested definition of each metric instead of re-deriving it. Every view is
-- CREATE OR REPLACE, so this file is safe to re-apply.
--
-- Apply with:  python -m src.database --views-only
--
-- Two conventions used throughout:
--   * nullif(..., 0) on every denominator, so an empty table returns NULL rather
--     than raising division_by_zero.
--   * FILTER (WHERE ...) instead of CASE inside aggregates, which keeps the
--     benign and malicious counts in one pass over the same rows.
-- ===========================================================================

-- Headline numbers for the Security Overview page.
CREATE OR REPLACE VIEW vw_traffic_overview AS
SELECT
    count(*)                                                AS total_events,
    count(*) FILTER (WHERE a.is_attack)                     AS malicious_events,
    count(*) FILTER (WHERE NOT a.is_attack)                 AS benign_events,
    count(DISTINCT a.label) FILTER (WHERE a.is_attack)      AS attack_label_count,
    round(100.0 * count(*) FILTER (WHERE a.is_attack)
          / nullif(count(*), 0), 2)                         AS malicious_share_pct,
    min(f.captured_at)                                      AS first_capture,
    max(f.captured_at)                                      AS last_capture,
    count(DISTINCT f.capture_date)                           AS capture_days,
    sum(f.total_bytes)                                      AS total_bytes
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id;

COMMENT ON VIEW vw_traffic_overview IS 'One row: totals and class balance for the loaded flows.';

-- Daily trend, benign and malicious in one pass.
CREATE OR REPLACE VIEW vw_daily_traffic AS
SELECT
    f.capture_date,
    count(*)                                                AS events,
    count(*) FILTER (WHERE a.is_attack)                     AS malicious_events,
    count(*) FILTER (WHERE NOT a.is_attack)                 AS benign_events,
    round(100.0 * count(*) FILTER (WHERE a.is_attack)
          / nullif(count(*), 0), 2)                         AS malicious_share_pct,
    sum(f.total_bytes)                                      AS total_bytes
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id
GROUP BY f.capture_date;

COMMENT ON VIEW vw_daily_traffic IS 'Per capture date: event counts, class balance and byte volume.';

-- Attack families, for the grouped bar on the overview page.
CREATE OR REPLACE VIEW vw_attack_family_summary AS
WITH per_family AS (
    SELECT
        coalesce(a.family, 'Unclassified')                  AS family,
        count(*)                                            AS events,
        sum(f.total_bytes)                                  AS total_bytes,
        round(avg(f.duration_ms)::numeric, 2)               AS avg_duration_ms
    FROM network_flows f
    JOIN attack_labels a ON a.label_id = f.label_id
    WHERE a.is_attack
    GROUP BY coalesce(a.family, 'Unclassified')
)
SELECT
    family,
    events,
    total_bytes,
    avg_duration_ms,
    round(100.0 * events / nullif(sum(events) OVER (), 0), 2) AS share_pct
FROM per_family;

COMMENT ON VIEW vw_attack_family_summary IS 'Malicious events grouped by reporting family, with share.';

-- Individual labels, ranked. Powers the ranked bar on the Attack Analytics page.
CREATE OR REPLACE VIEW vw_attack_label_summary AS
WITH per_label AS (
    SELECT
        a.label,
        a.family,
        count(*)                                            AS events,
        sum(f.total_bytes)                                  AS total_bytes
    FROM network_flows f
    JOIN attack_labels a ON a.label_id = f.label_id
    WHERE a.is_attack
    GROUP BY a.label, a.family
)
SELECT
    label,
    family,
    events,
    total_bytes,
    rank() OVER (ORDER BY events DESC)                      AS event_rank,
    round(100.0 * events / nullif(sum(events) OVER (), 0), 2) AS share_pct
FROM per_label;

COMMENT ON VIEW vw_attack_label_summary IS 'Every attack label with its rank and share of malicious events.';

-- Destination ports under attack.
CREATE OR REPLACE VIEW vw_port_targets AS
WITH per_port AS (
    SELECT
        f.destination_port,
        count(*)                                            AS malicious_events,
        count(DISTINCT a.label)                             AS distinct_attack_labels,
        sum(f.total_bytes)                                  AS total_bytes
    FROM network_flows f
    JOIN attack_labels a ON a.label_id = f.label_id
    WHERE a.is_attack
    GROUP BY f.destination_port
)
SELECT
    destination_port,
    malicious_events,
    distinct_attack_labels,
    total_bytes,
    round(100.0 * malicious_events / nullif(sum(malicious_events) OVER (), 0), 2) AS share_pct
FROM per_port;

COMMENT ON VIEW vw_port_targets IS 'Malicious flow counts per destination port.';

-- Protocol split, malicious against benign.
CREATE OR REPLACE VIEW vw_protocol_summary AS
SELECT
    f.protocol,
    count(*)                                                AS events,
    count(*) FILTER (WHERE a.is_attack)                     AS malicious_events,
    count(*) FILTER (WHERE NOT a.is_attack)                 AS benign_events,
    sum(f.total_bytes)                                      AS total_bytes,
    round(avg(f.duration_ms)::numeric, 2)                   AS avg_duration_ms
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id
GROUP BY f.protocol;

COMMENT ON VIEW vw_protocol_summary IS 'Flow and byte volume by protocol number, split by class.';

-- Hour-of-day profile. CICIDS2017 captures business hours only, so empty hours
-- stay absent rather than being filled with zeros.
CREATE OR REPLACE VIEW vw_hourly_traffic AS
SELECT
    date_trunc('hour', f.captured_at)                       AS hour_bucket,
    extract(hour FROM f.captured_at)                        AS hour_of_day,
    f.capture_date,
    count(*)                                                AS events,
    count(*) FILTER (WHERE a.is_attack)                     AS malicious_events,
    sum(f.total_bytes)                                      AS total_bytes
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id
GROUP BY date_trunc('hour', f.captured_at),
         extract(hour FROM f.captured_at),
         f.capture_date;

COMMENT ON VIEW vw_hourly_traffic IS 'Per capture hour: events, malicious events and bytes.';
