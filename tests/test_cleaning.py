"""Transform-stage behaviour: duplicates, infinities, timestamps, labels, provenance."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.data_cleaning import clean_capture_frame, parse_capture_timestamps
from src.errors import SchemaError, ValidationError


def test_removes_exact_duplicate_rows(monday_capture):
    result = clean_capture_frame(monday_capture.frame, source_file="monday")

    assert result.stats["rows_in"] == 27
    assert result.stats["duplicate_rows"] == 1
    assert result.rows == 25


def test_infinity_becomes_null_and_is_counted(monday_capture):
    result = clean_capture_frame(monday_capture.frame, source_file="monday")

    assert result.stats["infinity_cells"] == 1
    assert result.frame["flow_bytes_s"].isna().sum() == 1

    numeric = result.frame.select_dtypes(include=[np.number]).to_numpy(dtype="float64", na_value=np.nan)
    assert not np.isinf(numeric).any(), "cleaning must leave no infinity behind"


def test_twenty_four_hour_timestamps_parse_on_monday(monday_capture):
    result = clean_capture_frame(monday_capture.frame, source_file="monday")

    assert result.stats["timestamp_format"] == "%d/%m/%Y %H:%M"
    assert str(result.frame["captured_at"].dtype).startswith("datetime64")
    assert result.frame["captured_at"].dt.hour.unique().tolist() == [9, 10]


def test_twelve_hour_timestamps_parse_on_thursday(thursday_capture):
    result = clean_capture_frame(thursday_capture.frame, source_file="thursday")

    assert result.stats["timestamp_format"] == "%d/%m/%Y %I:%M:%S %p"
    assert result.frame["captured_at"].dt.hour.unique().tolist() == [9]


def test_unparseable_timestamp_row_is_dropped_and_counted(monday_capture):
    result = clean_capture_frame(monday_capture.frame, source_file="monday")

    assert result.stats["dropped_invalid"] == 1
    assert result.frame["captured_at"].isna().sum() == 0


def test_labels_are_normalised_to_canonical_form(thursday_capture):
    result = clean_capture_frame(thursday_capture.frame, source_file="thursday")

    labels = set(result.frame["observed_label"])
    assert "Web Attack - Brute Force" in labels
    assert "BENIGN" in labels


def test_unknown_label_raises_instead_of_entering_the_warehouse(monday_capture):
    frame = monday_capture.frame.copy()
    frame.loc[0, "label"] = "Mystery Attack"

    with pytest.raises(ValidationError, match="outside the canonical set"):
        clean_capture_frame(frame, source_file="monday")


def test_duplicate_column_is_dropped_but_constant_columns_are_kept(monday_capture):
    result = clean_capture_frame(monday_capture.frame, source_file="monday")
    columns = set(result.frame.columns)

    assert "fwd_header_length" in columns
    assert "fwd_header_length_1" not in columns
    assert {"fin_flag_count", "rst_flag_count"} <= columns, "constant flag columns must survive"
    assert result.stats["identical_columns_dropped"] == [
        {"dropped": "fwd_header_length_1", "kept": "fwd_header_length"}
    ]


def test_capture_date_and_provenance_columns_are_added(monday_capture):
    result = clean_capture_frame(monday_capture.frame, source_file="monday")
    frame = result.frame

    assert frame["capture_date"].notna().all()
    assert (frame["source_file"] == "monday").all()
    assert frame["row_index"].tolist() == list(range(len(frame)))
    assert "timestamp" not in frame.columns
    assert "label" not in frame.columns


def test_numeric_columns_are_narrowed_without_losing_precision(monday_capture):
    result = clean_capture_frame(monday_capture.frame, source_file="monday")
    frame = result.frame

    assert frame["destination_port"].dtype == "int32"
    assert frame["flow_duration"].dtype == "int32"
    assert frame["flow_bytes_s"].dtype == "float32"


def test_no_matching_timestamp_format_raises_schema_error():
    series = pd.Series(["yesterday", "tomorrow"])

    with pytest.raises(SchemaError, match="no timestamp format matched"):
        parse_capture_timestamps(series, "unknown.csv")


def test_mostly_unparseable_timestamps_raise_validation_error():
    series = pd.Series(["03/07/2017 09:00", "garbage", "garbage", "garbage"])

    with pytest.raises(ValidationError, match="format problem"):
        parse_capture_timestamps(series, "mostly-bad.csv")
