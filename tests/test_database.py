"""Load-stage behaviour: schema contents, key construction, idempotent loading.

The schema and key tests run anywhere. The load tests need the local PostgreSQL
instance and skip themselves when it is not running, so the suite stays green on
a machine without a database.
"""

from __future__ import annotations

import re
import uuid

import pandas as pd
import pytest

from config import settings
from src.database import (
    SCHEMA_FILE,
    apply_schema,
    build_rows,
    create_engine_from_settings,
    load_dataset,
)
from src.errors import ValidationError
from src.pipeline import run_pipeline

EXPECTED_TABLES = ("attack_labels", "pipeline_runs", "network_flows", "flow_predictions")
EXPECTED_ROWS = 27


def _schema_text() -> str:
    return SCHEMA_FILE.read_text(encoding="utf-8")


def _require_database():
    try:
        engine = create_engine_from_settings()
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
    except Exception as error:  # noqa: BLE001 - any connection failure means skip
        pytest.skip(f"PostgreSQL is not available: {error}")


def _query(sql: str, params: dict | None = None):
    engine = create_engine_from_settings()
    with engine.connect() as connection:
        return connection.exec_driver_sql(sql, params or {}).all()


def _delete_run(run_id: str) -> None:
    engine = create_engine_from_settings()
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "DELETE FROM pipeline_runs WHERE run_id = %(run_id)s", {"run_id": run_id}
        )


# ---------------------------------------------------------------------------
# Schema contract - no database needed
# ---------------------------------------------------------------------------
def test_schema_declares_every_table():
    text = _schema_text()

    for table in EXPECTED_TABLES:
        assert f"CREATE TABLE IF NOT EXISTS {table}" in text, f"{table} is not declared"


def test_schema_seeds_match_canonical_labels():
    """The SQL seed must agree with config/settings.py, or the loader breaks."""
    text = _schema_text()
    block = text.split("INSERT INTO attack_labels", 1)[1]
    seeded = set(re.findall(r"\('([^']+)'", block))

    assert seeded == set(settings.CANONICAL_LABELS)


def test_flow_endpoints_are_nullable():
    """The MachineLearningCSV release has no IPs, so these columns must be nullable."""
    text = _schema_text()
    assert "source_ip               INET," in text
    assert "destination_ip          INET," in text


def test_loader_is_idempotent_by_construction():
    """ON CONFLICT DO NOTHING on the natural key is what makes re-runs safe."""
    from src.database import INSERT_SQL

    assert "ON CONFLICT (flow_key) DO NOTHING" in INSERT_SQL
    assert "flow_key" in _schema_text()


# ---------------------------------------------------------------------------
# Row construction - no database needed
# ---------------------------------------------------------------------------
def _frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "captured_at": pd.to_datetime(["2017-07-03 09:05", "2017-07-03 09:06"]),
            "capture_date": pd.to_datetime(["2017-07-03", "2017-07-03"]),
            "destination_port": [80, 443],
            "protocol": [6, 17],
            "duration_ms": [1.0, 0.5],
            "total_bytes": [500.0, 60.0],
            "observed_label": ["BENIGN", "PortScan"],
            "source_file": ["monday.csv", "monday.csv"],
            "row_index": [0, 1],
        }
    )


def test_build_rows_uses_file_and_row_index_as_the_key():
    rows = build_rows(_frame(), "run_x", {"BENIGN": 1, "PortScan": 11})

    assert len(rows) == 2
    assert rows[0][0] == "monday.csv:0"
    assert rows[1][0] == "monday.csv:1"


def test_build_rows_maps_labels_to_lookup_ids():
    rows = build_rows(_frame(), "run_x", {"BENIGN": 1, "PortScan": 11})

    label_ids = [row[-1] for row in rows]
    assert label_ids == [1, 11]


def test_build_rows_leaves_absent_endpoints_as_null():
    rows = build_rows(_frame(), "run_x", {"BENIGN": 1, "PortScan": 11})

    # time_source is positional 4; source_ip, destination_ip, source_port follow
    assert rows[0][4] == settings.TIME_SOURCE_CAPTURE_FILE
    assert rows[0][5] is None
    assert rows[0][6] is None
    assert rows[0][7] is None


def test_build_rows_rejects_unseeded_labels():
    with pytest.raises(ValidationError, match="labels missing from attack_labels"):
        build_rows(_frame(), "run_x", {"BENIGN": 1})


# ---------------------------------------------------------------------------
# Live database
# ---------------------------------------------------------------------------
def test_schema_applies_to_the_live_database():
    _require_database()
    apply_schema()

    tables = {row[0] for row in _query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
    )}
    assert set(EXPECTED_TABLES) <= tables


def test_captured_at_is_stored_without_a_timezone():
    """CICIDS2017 has no time zone; timestamptz would invent one from the server locale."""
    _require_database()
    apply_schema()

    data_type = _query(
        """
        SELECT data_type FROM information_schema.columns
        WHERE table_name = 'network_flows' AND column_name = 'captured_at'
        """
    )[0][0]

    assert data_type == "timestamp without time zone"


def test_labels_are_seeded_once():
    _require_database()
    apply_schema()
    apply_schema()

    count = _query("SELECT count(*) FROM attack_labels")[0][0]
    assert count == len(settings.CANONICAL_LABELS)


def test_load_inserts_then_skips_on_second_run(raw_dir, tmp_path):
    _require_database()
    parquet = tmp_path / "flows.parquet"
    run_pipeline(raw_dir, parquet)

    run_id = "test_" + uuid.uuid4().hex[:10]
    try:
        first = load_dataset(parquet, run_id)
        assert first["rows_inserted"] == EXPECTED_ROWS

        second = load_dataset(parquet, run_id)
        assert second["rows_inserted"] == 0, "a re-run must not duplicate rows"
        assert second["rows_skipped_existing"] == EXPECTED_ROWS
    finally:
        _delete_run(run_id)


def test_loaded_rows_join_back_to_their_family(raw_dir, tmp_path):
    _require_database()
    parquet = tmp_path / "flows.parquet"
    run_pipeline(raw_dir, parquet)

    run_id = "test_" + uuid.uuid4().hex[:10]
    try:
        load_dataset(parquet, run_id)

        rows = _query(
            """
            SELECT a.family, count(*)
            FROM network_flows f
            JOIN attack_labels a ON a.label_id = f.label_id
            WHERE f.run_id = %(run_id)s
            GROUP BY a.family
            ORDER BY 2 DESC
            """,
            {"run_id": run_id},
        )
        families = dict(rows)

        assert families.get(None) == 26, "benign rows must carry a null family"
        assert families.get("Web Attack") == 1
    finally:
        _delete_run(run_id)


def test_deleting_a_run_removes_its_flows(raw_dir, tmp_path):
    _require_database()
    parquet = tmp_path / "flows.parquet"
    run_pipeline(raw_dir, parquet)

    run_id = "test_" + uuid.uuid4().hex[:10]
    load_dataset(parquet, run_id)
    _delete_run(run_id)

    remaining = _query(
        "SELECT count(*) FROM network_flows WHERE run_id = %(run_id)s", {"run_id": run_id}
    )[0][0]
    assert remaining == 0
