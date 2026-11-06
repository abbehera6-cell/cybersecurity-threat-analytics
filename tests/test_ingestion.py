"""Extract-stage behaviour: header normalisation, encoding fallback, schema guard."""

from __future__ import annotations

from dataclasses import replace

import pandas as pd
import pytest

from src.data_ingestion import (
    discover_capture_files,
    normalise_column_names,
    read_capture_file,
    validate_schema,
)
from src.errors import SchemaError


def test_normalise_column_names_handles_spacing_and_collisions():
    frame = pd.DataFrame(
        columns=[
            " Destination Port",
            " Flow Packets/s",
            "Fwd Header Length",
            "Fwd Header Length.1",
        ]
    )

    renamed = normalise_column_names(frame)

    assert list(renamed.columns) == [
        "destination_port",
        "flow_packets_s",
        "fwd_header_length",
        "fwd_header_length_1",
    ]


def test_reads_utf8_file_without_falling_back(monday_capture):
    assert monday_capture.encoding == "utf-8"
    assert monday_capture.rows == 27


def test_reads_cp1252_file_after_utf8_fails(thursday_capture):
    assert thursday_capture.encoding == "cp1252"
    assert thursday_capture.frame["label"].astype(str).str.contains("Brute Force").any()


def test_validate_schema_rejects_missing_column(monday_capture):
    broken = replace(monday_capture, frame=monday_capture.frame.drop(columns=["label"]))

    with pytest.raises(SchemaError, match="missing required column"):
        validate_schema(broken)


def test_discover_capture_files_returns_sorted_csvs(raw_dir):
    files = discover_capture_files(raw_dir)

    assert len(files) == 2
    assert [path.name for path in files] == sorted(path.name for path in files)


def test_discover_capture_files_explains_empty_directory(tmp_path):
    with pytest.raises(FileNotFoundError, match="no CSV files"):
        discover_capture_files(tmp_path)


def test_plain_ascii_file_reads_and_keeps_its_rows(tmp_path):
    """The happy path, so a failure above can be attributed to encoding."""
    path = tmp_path / "minimal.csv"
    path.write_bytes(b"Destination Port,Timestamp,Label\n80,2017-07-03 09:00,BENIGN\n")

    capture = read_capture_file(path)

    assert capture.encoding == "utf-8"
    assert capture.frame.shape == (1, 3)
    assert list(capture.frame.columns) == ["destination_port", "timestamp", "label"]

