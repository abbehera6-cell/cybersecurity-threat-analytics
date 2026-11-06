"""End-to-end behaviour of the ETL on the synthetic capture set.

Expected arithmetic, which the fixtures are built to produce:

    27 Monday rows (24 benign + 1 duplicate + 1 inf row + 1 bad timestamp)
     2 Thursday rows
    = 29 in
    - 1 exact duplicate
    - 1 unparseable timestamp
    = 27 out
"""

from __future__ import annotations

import json

import pandas as pd
import pytest

from src.pipeline import run_pipeline

EXPECTED_ROWS_IN = 29
EXPECTED_ROWS_OUT = 27


def test_pipeline_writes_parquet_and_reconciles(raw_dir, tmp_path):
    output = tmp_path / "flows_clean.parquet"

    report = run_pipeline(raw_dir, output)
    totals = report["totals"]

    assert output.exists(), "parquet was not written"
    assert totals["rows_in"] == EXPECTED_ROWS_IN
    assert totals["duplicates"] == 1
    assert totals["dropped_invalid"] == 1
    assert totals["rows_out"] == EXPECTED_ROWS_OUT
    assert totals["rows_out"] == totals["rows_in"] - totals["duplicates"] - totals["dropped_invalid"]


def test_output_contains_the_columns_later_phases_need(raw_dir, tmp_path):
    output = tmp_path / "flows_clean.parquet"
    run_pipeline(raw_dir, output)

    frame = pd.read_parquet(output)

    assert len(frame) == EXPECTED_ROWS_OUT
    assert {
        "captured_at",
        "capture_date",
        "observed_label",
        "attack_family",
        "is_attack",
        "total_bytes",
        "bytes_per_packet",
        "source_file",
        "row_index",
    } <= set(frame.columns)
    assert frame["attack_family"].notna().sum() == 1
    assert int(frame["is_attack"].sum()) == 1


def test_both_capture_files_survived_the_run(raw_dir, tmp_path):
    output = tmp_path / "flows_clean.parquet"
    run_pipeline(raw_dir, output)

    frame = pd.read_parquet(output)

    assert set(frame["source_file"]) == {
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    }


def test_metadata_records_encoding_timestamp_format_and_window(raw_dir, tmp_path):
    output = tmp_path / "flows_clean.parquet"
    run_pipeline(raw_dir, output)

    metadata = output.with_suffix(".run.json")
    assert metadata.exists()

    payload = json.loads(metadata.read_text(encoding="utf-8"))
    by_file = {entry["source_file"]: entry for entry in payload["files"]}

    thursday_name = "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    monday_name = "Monday-WorkingHours.pcap_ISCX.csv"

    assert by_file[thursday_name]["encoding"] == "cp1252"
    assert by_file[monday_name]["encoding"] == "utf-8"
    assert by_file[thursday_name]["timestamp_format"] == "%d/%m/%Y %I:%M:%S %p"
    assert payload["totals"]["rows_out"] == EXPECTED_ROWS_OUT
    assert payload["totals"]["capture_dates"] == ["2017-07-03", "2017-07-06"]


def test_second_run_overwrites_instead_of_growing(raw_dir, tmp_path):
    output = tmp_path / "flows_clean.parquet"

    first = run_pipeline(raw_dir, output)
    second = run_pipeline(raw_dir, output)

    assert first["totals"]["rows_out"] == second["totals"]["rows_out"]
    assert len(pd.read_parquet(output)) == EXPECTED_ROWS_OUT


def test_dry_run_validates_without_writing(raw_dir, tmp_path):
    output = tmp_path / "flows_clean.parquet"

    report = run_pipeline(raw_dir, output, write_output=False)

    assert report["output_path"] is None
    assert report["totals"]["rows_out"] == EXPECTED_ROWS_OUT
    assert not output.exists()


def test_empty_raw_directory_fails_with_an_explanation(tmp_path):
    empty = tmp_path / "no_data_here"
    empty.mkdir()

    with pytest.raises(FileNotFoundError, match="no CSV files"):
        run_pipeline(empty, tmp_path / "out.parquet")


def test_run_report_is_json_serialisable(raw_dir, tmp_path):
    report = run_pipeline(raw_dir, tmp_path / "flows_clean.parquet", write_output=False)

    round_tripped = json.loads(json.dumps(report))

    assert round_tripped["totals"]["rows_out"] == EXPECTED_ROWS_OUT
    assert report["duration_seconds"] >= 0
