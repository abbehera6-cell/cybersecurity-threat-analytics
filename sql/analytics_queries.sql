-- ===========================================================================
-- Analytical queries for the CICIDS2017 warehouse.
--
-- Run the whole file with:  psql -h 127.0.0.1 -U postgres -d cyber_threat -f sql/analytics_queries.sql
-- Or execute one at a time in pgAdmin / DBeaver.
--
-- Conventions
--   * nullif(..., 0) guards every denominator, so an empty warehouse returns
--     NULL instead of raising division_by_zero.
--   * FILTER (WHERE ...) keeps benign and malicious counts in a single pass.
--   * Queries 7 and 8 exist as a pair: 7 needs endpoint addresses that this
--     release of CICIDS2017 does not contain, 8 is the equivalent that does.
-- ===========================================================================


-- ===========================================================================
-- QUERY 1 - Total number of network events
-- The baseline denominator every share is measured against.
-- ===========================================================================
SELECT count(*) AS total_events
FROM network_flows;


-- ===========================================================================
-- QUERY 2 - Distribution of normal and malicious traffic
-- One pass over the table; the window sums the two group counts so the shares
-- always add to 100 without a second query.
-- ===========================================================================
SELECT
    CASE WHEN a.is_attack THEN 'malicious' ELSE 'benign' END  AS traffic_class,
    count(*)                                                  AS events,
    round(100.0 * count(*) / nullif(sum(count(*)) OVER (), 0), 2) AS share_pct
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id
GROUP BY a.is_attack
ORDER BY events DESC;


-- ===========================================================================
-- QUERY 3 - Most frequent attack categories
-- Labels, not families: the family rollup lives in vw_attack_family_summary.
-- ===========================================================================
SELECT
    a.label,
    a.family,
    count(*)                                                  AS events,
    round(100.0 * count(*) / nullif(sum(count(*)) OVER (), 0), 2) AS share_pct
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id
WHERE a.is_attack
GROUP BY a.label, a.family
ORDER BY events DESC;


-- ===========================================================================
-- QUERY 4 - Daily attack trend
-- CICIDS2017 covers five capture days; a day with no traffic is absent rather
-- than zero-filled, because the capture ran only during business hours.
-- ===========================================================================
SELECT
    f.capture_date,
    count(*)                                                  AS events,
    count(*) FILTER (WHERE a.is_attack)                       AS malicious_events,
    round(100.0 * count(*) FILTER (WHERE a.is_attack) / nullif(count(*), 0), 2) AS malicious_share_pct
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id
GROUP BY f.capture_date
ORDER BY f.capture_date;


-- ===========================================================================
-- QUERY 5 - Most frequently targeted destination ports
-- "distinct_attack_labels" separates a port hit by one campaign from a port hit
-- by many, which is the difference between a scan and a targeted service.
-- ===========================================================================
SELECT
    f.destination_port,
    count(*)                                                  AS malicious_events,
    count(DISTINCT a.label)                                   AS distinct_attack_labels,
    round(100.0 * count(*) / nullif(sum(count(*)) OVER (), 0), 2) AS share_pct
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id
WHERE a.is_attack
GROUP BY f.destination_port
ORDER BY malicious_events DESC
LIMIT 15;


-- ===========================================================================
-- QUERY 6 - Protocol-wise traffic analysis
-- Protocol numbers are reported literally (6 = TCP, 17 = UDP); the dataset has
-- no lookup table, so inventing names here would be an assumption.
-- ===========================================================================
SELECT
    f.protocol,
    count(*)                                                  AS events,
    count(*) FILTER (WHERE a.is_attack)                       AS malicious_events,
    count(*) FILTER (WHERE NOT a.is_attack)                   AS benign_events,
    sum(f.total_bytes)                                        AS total_bytes,
    round(avg(f.duration_ms)::numeric, 2)                     AS avg_duration_ms
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id
GROUP BY f.protocol
ORDER BY events DESC;


-- ===========================================================================
-- QUERY 7 - High-frequency suspicious source IPs
-- Endpoint-dependent. The MachineLearningCSV release carries no source address,
-- so this returns zero rows against it. It is kept for the pcap-derived files,
-- which do contain addresses, and it degrades to an empty result rather than an
-- error when the column is null everywhere.
-- ===========================================================================
SELECT
    host(f.source_ip)                                         AS source_ip,
    count(*)                                                  AS malicious_events,
    count(DISTINCT a.label)                                   AS distinct_attack_labels,
    sum(f.total_bytes)                                        AS total_bytes
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id
WHERE a.is_attack
  AND f.source_ip IS NOT NULL
GROUP BY f.source_ip
ORDER BY malicious_events DESC
LIMIT 20;


-- ===========================================================================
-- QUERY 8 - Attack label ranking with cumulative share (Pareto view)
-- RANK places equal counts on the same rank; the second window accumulates
-- share in rank order, which is what answers "how few labels cover most events".
-- ===========================================================================
WITH per_label AS (
    SELECT
        a.label,
        a.family,
        count(*)                                              AS events
    FROM network_flows f
    JOIN attack_labels a ON a.label_id = f.label_id
    WHERE a.is_attack
    GROUP BY a.label, a.family
)
SELECT
    label,
    family,
    events,
    rank() OVER (ORDER BY events DESC)                        AS event_rank,
    round(100.0 * events / nullif(sum(events) OVER (), 0), 2) AS share_pct,
    round(100.0 * sum(events) OVER (
              ORDER BY events DESC
              ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
          ) / nullif(sum(events) OVER (), 0), 2)              AS cumulative_share_pct
FROM per_label
ORDER BY events DESC;


-- ===========================================================================
-- QUERY 9 - Day-over-day change in malicious events
-- LAG reads the previous capture day. The first day has no predecessor, so its
-- change is NULL instead of a misleading zero.
-- ===========================================================================
WITH daily AS (
    SELECT
        f.capture_date,
        count(*) FILTER (WHERE a.is_attack)                   AS malicious_events
    FROM network_flows f
    JOIN attack_labels a ON a.label_id = f.label_id
    GROUP BY f.capture_date
),
with_previous AS (
    SELECT
        capture_date,
        malicious_events,
        lag(malicious_events) OVER (ORDER BY capture_date)    AS previous_day_events
    FROM daily
)
SELECT
    capture_date,
    malicious_events,
    previous_day_events,
    malicious_events - previous_day_events                    AS change_events,
    round(100.0 * (malicious_events - previous_day_events)
          / nullif(previous_day_events, 0), 2)                AS change_pct
FROM with_previous
ORDER BY capture_date;


-- ===========================================================================
-- QUERY 10 - Busiest hours for attacks, smoothed with a 3-hour moving average
-- The frame clause makes the average read the current hour plus the two before
-- it, which is a moving window, not a cumulative total.
-- ===========================================================================
-- NOTE: the MachineLearningCSV release carries no timestamps, so captured_at is
-- NULL for every row and this query returns no rows against it. It runs as
-- intended on the pcap-derived release, which does record the clock time.
WITH hourly AS (
    SELECT
        date_trunc('hour', f.captured_at)                     AS hour_bucket,
        count(*)                                              AS malicious_events
    FROM network_flows f
    JOIN attack_labels a ON a.label_id = f.label_id
    WHERE a.is_attack
      AND f.captured_at IS NOT NULL
    GROUP BY date_trunc('hour', f.captured_at)
),
smoothed AS (
    SELECT
        hour_bucket,
        malicious_events,
        round(avg(malicious_events) OVER (
                  ORDER BY hour_bucket
                  ROWS BETWEEN 2 PRECEDING AND CURRENT ROW
              )::numeric, 2)                                  AS moving_avg_3h
    FROM hourly
)
SELECT
    hour_bucket,
    malicious_events,
    moving_avg_3h
FROM smoothed
ORDER BY malicious_events DESC
LIMIT 10;


-- ===========================================================================
-- QUERY 11 - Byte volume per family against event count
-- Answers "is this family noisy or is it heavy". A family with few events and a
-- large byte share matters more than its event count suggests.
-- ===========================================================================
WITH per_family AS (
    SELECT
        a.family,
        count(*)                                              AS events,
        sum(f.total_bytes)                                    AS total_bytes
    FROM network_flows f
    JOIN attack_labels a ON a.label_id = f.label_id
    WHERE a.is_attack
    GROUP BY a.family
)
SELECT
    family,
    events,
    total_bytes,
    round(total_bytes::numeric / nullif(events, 0))           AS bytes_per_event,
    round(100.0 * total_bytes / nullif(sum(total_bytes) OVER (), 0), 2) AS byte_share_pct
FROM per_family
ORDER BY total_bytes DESC;


-- ===========================================================================
-- QUERY 12 - Flows above the 99th percentile of total bytes
-- percentile_cont gives the threshold from the data itself instead of a guessed
-- cutoff. On an empty warehouse the percentile is NULL and this returns no rows.
-- ===========================================================================
WITH thresholds AS (
    -- total_bytes is BIGINT and percentile_cont has no integer overload
    SELECT percentile_cont(0.99) WITHIN GROUP (ORDER BY f.total_bytes::double precision) AS p99_bytes
    FROM network_flows f
)
SELECT
    f.flow_id,
    f.captured_at,
    f.destination_port,
    a.label,
    f.total_bytes,
    -- rate derived here rather than stored: duration_ms is milliseconds.
    -- Both sides cast to numeric, because PostgreSQL has no round(double, int).
    round(f.total_bytes::numeric / nullif(f.duration_ms, 0)::numeric * 1000, 2) AS bytes_per_second,
    t.p99_bytes
FROM network_flows f
JOIN attack_labels a ON a.label_id = f.label_id
CROSS JOIN thresholds t
WHERE f.total_bytes >= t.p99_bytes
ORDER BY f.total_bytes DESC
LIMIT 20;
