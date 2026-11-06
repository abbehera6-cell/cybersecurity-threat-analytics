"""Analytics SQL: every query in sql/analytics_queries.sql must execute, and the
reporting views must agree with the query results.

These tests create a throwaway database, load a deterministic synthetic dataset
into it and drop it afterwards. The development database is never touched, so a
test run cannot disturb a real CICIDS2017 load.

Expected shape of the synthetic data (5 days, 36 flows per day):

    per day : 16 BENIGN, 8 DDoS, 6 DoS Hulk, 4 PortScan, 2 FTP-Patator
    totals  : 180 flows = 100 malicious + 80 benign
    labels  : DDoS 40, DoS Hulk 30, PortScan 20, FTP-Patator 10
    ports   : 8080 -> DDoS, 80 -> DoS Hulk and BENIGN, 443 -> PortScan, 21 -> FTP
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pandas as pd
import pytest
from sqlalchemy import create_engine

from config import settings
from src.database import apply_views, load_dataset

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYTICS_FILE = PROJECT_ROOT / "sql" / "analytics_queries.sql"

EXPECTED_TOTAL = 180
EXPECTED_MALICIOUS = 100
EXPECTED_BENIGN = 80

VIEW_NAMES = {
    "vw_traffic_overview",
    "vw_daily_traffic",
    "vw_attack_family_summary",
    "vw_attack_label_summary",
    "vw_port_targets",
    "vw_protocol_summary",
    "vw_hourly_traffic",
}

DAILY_PLAN = (
    ("BENIGN", 16, 80),
    ("DDoS", 8, 8080),
    ("DoS Hulk", 6, 80),
    ("PortScan", 4, 443),
    ("FTP-Patator", 2, 21),
)


def synthetic_frame() -> pd.DataFrame:
    """Five capture days with a fixed, predictable label and port mix."""
    records = []
    row_index = 0

    for day in range(5):
        capture_day = pd.Timestamp("2017-07-03") + pd.Timedelta(days=day)
        for label, count, port in DAILY_PLAN:
            for offset in range(count):
                records.append(
                    {
                        "captured_at": capture_day
                        + pd.Timedelta(hours=9 + (row_index % 8), minutes=offset),
                        "capture_date": capture_day,
                        "destination_port": port,
                        "protocol": 17 if (label == "BENIGN" and offset % 5 == 0) else 6,
                        "duration_ms": float(1 + row_index % 10),
                        "total_fwd_packets": 3,
                        "total_backward_packets": 2,
                        "total_bytes": 500 + row_index,
                        "bytes_per_packet": 100.0,
                        "packets_per_second": 5.0,
                        "total_flags": 1,
                        "observed_label": label,
                        "source_file": "synthetic.csv",
                        "row_index": row_index,
                    }
                )
                row_index += 1

    return pd.DataFrame(records)


@pytest.fixture(scope="module")
def analytics_database():
    """A fresh database that is dropped when the module finishes."""
    base_url = settings.DATABASE_URL.rsplit("/", 1)[0]
    name = f"cyber_threat_test_{uuid.uuid4().hex[:8]}"

    try:
        admin = create_engine(f"{base_url}/postgres", isolation_level="AUTOCOMMIT")
        with admin.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
    except Exception as error:  # noqa: BLE001 - any failure means no database
        pytest.skip(f"PostgreSQL is not available: {error}")

    url = f"{base_url}/{name}"
    engine = create_engine(url)

    try:
        yield url, engine
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.dispose()


@pytest.fixture(scope="module")
def warehouse(analytics_database, tmp_path_factory):
    """The temporary database, loaded with the synthetic dataset and the views."""
    url, engine = analytics_database

    parquet = tmp_path_factory.mktemp("analytics") / "flows.parquet"
    synthetic_frame().to_parquet(parquet, index=False)

    summary = load_dataset(parquet, "run_sql_validation", database_url=url)
    assert summary["rows_inserted"] == EXPECTED_TOTAL

    apply_views(engine)
    return engine


def statements() -> list[str]:
    """Split the query file into executable statements.

    Comments are removed before splitting, because a comment may legitimately
    contain a semicolon and psql copes with that while a naive split does not.
    """
    raw = ANALYTICS_FILE.read_text(encoding="utf-8")
    code = "\n".join(
        line for line in raw.splitlines() if not line.strip().startswith("--")
    )

    return [part.strip() for part in code.split(";") if part.strip()]


@pytest.fixture(scope="module")
def results(warehouse) -> list[list]:
    """Execute every query once, in file order."""
    executed = []
    with warehouse.connect() as connection:
        for statement in statements():
            executed.append(connection.exec_driver_sql(statement).all())
    return executed


# ---------------------------------------------------------------------------
# The file itself
# ---------------------------------------------------------------------------
def test_query_file_contains_at_least_ten_queries():
    assert len(statements()) >= 10


def test_every_query_runs(results):
    assert len(results) == 12


# ---------------------------------------------------------------------------
# Individual query behaviour (index = position in the file, zero based)
# ---------------------------------------------------------------------------
def test_query_1_counts_every_event(results):
    assert results[0][0][0] == EXPECTED_TOTAL


def test_query_2_splits_benign_and_malicious(results):
    by_class = {row.traffic_class: row.events for row in results[1]}

    assert by_class == {"malicious": EXPECTED_MALICIOUS, "benign": EXPECTED_BENIGN}


def test_query_2_shares_add_up_to_100(results):
    total_share = sum(float(row.share_pct) for row in results[1])

    assert total_share == pytest.approx(100.0, abs=0.02)


def test_query_3_puts_the_most_frequent_label_first(results):
    first = results[2][0]

    assert first.label == "DDoS"
    assert first.events == 40


def test_query_4_returns_one_row_per_capture_day(results):
    assert len(results[3]) == 5
    assert str(results[3][0].capture_date) == "2017-07-03"


def test_query_5_ranks_the_busiest_attack_port_first(results):
    first = results[4][0]

    assert first.destination_port == 8080
    assert first.malicious_events == 40


def test_query_6_groups_by_protocol_number(results):
    protocols = {row.protocol for row in results[5]}

    assert protocols == {6, 17}


def test_query_7_returns_nothing_when_endpoints_are_absent(results):
    """This release has no source IPs, so the endpoint query must yield no rows."""
    assert results[6] == []


def test_query_8_ranks_every_label_and_reaches_full_cumulative_share(results):
    rows = results[7]

    assert [row.event_rank for row in rows] == [1, 2, 3, 4]
    assert float(rows[-1].cumulative_share_pct) == pytest.approx(100.0, abs=0.02)


def test_query_9_leaves_the_first_day_without_a_comparison(results):
    first = results[8][0]

    assert first.previous_day_events is None
    assert first.change_pct is None


def test_query_10_returns_hour_buckets_with_a_moving_average(results):
    rows = results[9]

    assert len(rows) <= 10
    assert all(row.hour_bucket is not None for row in rows)


def test_query_11_reports_bytes_per_event_for_each_family(results):
    families = {row.family for row in results[10]}

    assert families == {"DDoS", "DoS", "PortScan", "Brute Force"}


def test_query_12_respects_its_row_limit(results):
    assert 0 < len(results[11]) <= 20


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------
def test_all_reporting_views_exist(warehouse):
    with warehouse.connect() as connection:
        present = {
            row[0]
            for row in connection.exec_driver_sql(
                "SELECT table_name FROM information_schema.views WHERE table_schema = 'public'"
            )
        }

    assert VIEW_NAMES <= present


def test_overview_view_agrees_with_the_underlying_counts(warehouse):
    with warehouse.connect() as connection:
        row = connection.exec_driver_sql("SELECT * FROM vw_traffic_overview").one()

    assert row.total_events == EXPECTED_TOTAL
    assert row.malicious_events == EXPECTED_MALICIOUS
    assert row.benign_events == EXPECTED_BENIGN
    assert row.attack_label_count == 4
    assert row.capture_days == 5
    assert float(row.malicious_share_pct) == pytest.approx(55.56, abs=0.01)


def test_family_view_is_ordered_by_share_denominator(warehouse):
    with warehouse.connect() as connection:
        rows = connection.exec_driver_sql(
            "SELECT family, events FROM vw_attack_family_summary ORDER BY events DESC"
        ).all()

    assert [row.family for row in rows] == ["DDoS", "DoS", "PortScan", "Brute Force"]
    assert sum(row.events for row in rows) == EXPECTED_MALICIOUS
