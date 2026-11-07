"""Transform stage: turn one raw capture frame into a typed, validated flow table.

What this module fixes, in order, and why that order:

1. **Exact duplicate rows** are dropped first, while the frame is cheapest to hash.
2. **Numbers are coerced**, so a column that arrived as text cannot break arithmetic.
3. **Duplicate columns** (`Fwd Header Length.1`) are removed, but only when the
   column actually varies - a constant column is kept even if another looks equal,
   because in one capture file a flag count can legitimately be all zeros.
4. **`inf` becomes null.** `Flow Bytes/s` divides by `Flow Duration`, so a
   zero-duration flow produces `inf`. Those rows are real flows with an undefined
   rate; they are kept, not dropped.
5. **Timestamps** are parsed with a format detected per file, because Thursday uses
   a 12-hour clock and Friday uses 24-hour.
6. **Labels** are mapped onto `settings.CANONICAL_LABELS`. Anything unrecognised
   raises, rather than quietly entering the warehouse.
7. **Rows that cannot be used** (no timestamp, no label, no port, no duration) are
   dropped and counted.

Every removal is counted in the returned stats, so the pipeline can prove that
rows in = rows out + rows removed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd

from config import settings
from src.errors import SchemaError, ValidationError

LOGGER = logging.getLogger(__name__)

TIMESTAMP_COLUMN = "timestamp"
LABEL_COLUMN = "label"

CAPTURED_AT_COLUMN = "captured_at"
OBSERVED_LABEL_COLUMN = "observed_label"

TIMESTAMP_FORMATS = (
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
)

# Below this share of parseable timestamps the chosen format is wrong, not the data.
MIN_TIMESTAMP_MATCH_RATE = 0.95

# captured_at is not required: it is null for the whole MachineLearningCSV
# release. The capture day always exists, either parsed or derived from the file.
REQUIRED_OUTPUT_COLUMNS = (
    "capture_date",
    OBSERVED_LABEL_COLUMN,
    "destination_port",
    "flow_duration",
)

INT32_MAX = 2**31 - 1


@dataclass
class CleanResult:
    """Cleaned frame plus the evidence of what was changed."""

    frame: pd.DataFrame
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def rows(self) -> int:
        return int(len(self.frame))


def parse_capture_timestamps(
    series: pd.Series,
    source_file: str = "",
) -> tuple[pd.Series, str, float]:
    """Parse timestamps with the first format that matches the whole column.

    Returns ``(parsed, format, match_rate)``. Raises when nothing matches, or when
    too few rows match for the chosen format to be credible.
    """
    best_parsed: pd.Series | None = None
    best_format: str | None = None
    best_rate = 0.0

    for fmt in TIMESTAMP_FORMATS:
        parsed = pd.to_datetime(series, format=fmt, errors="coerce")
        rate = float(parsed.notna().mean())

        if rate > best_rate:
            best_parsed, best_format, best_rate = parsed, fmt, rate
        if rate == 1.0:
            break

    if best_parsed is None or best_rate == 0.0:
        raise SchemaError(
            f"{source_file}: no timestamp format matched. Tried: {list(TIMESTAMP_FORMATS)}"
        )

    if best_rate < MIN_TIMESTAMP_MATCH_RATE:
        raise ValidationError(
            f"{source_file}: only {best_rate:.1%} of timestamps matched {best_format!r}. "
            "That is a format problem, not a few bad rows."
        )

    return best_parsed, str(best_format), round(best_rate, 6)


def drop_identical_columns(frame: pd.DataFrame) -> tuple[pd.DataFrame, list[tuple[str, str]]]:
    """Drop a column that duplicates an earlier one, e.g. `fwd_header_length_1`.

    Columns with a single distinct value are skipped on purpose: in a single
    capture file `fin_flag_count` can be all zeros and `rst_flag_count` can be all
    zeros too, and removing one of those would silently change the schema that
    later stages depend on.
    """
    signatures: dict[tuple[str, int], str] = {}
    duplicates: list[tuple[str, str]] = []

    for column in frame.columns:
        series = frame[column]

        if not pd.api.types.is_numeric_dtype(series):
            continue
        if series.nunique(dropna=False) <= 1:
            continue

        digest = int(pd.util.hash_pandas_object(series, index=False).sum())
        key = (str(series.dtype), digest)
        original = signatures.get(key)

        if original is not None and frame[original].equals(series):
            duplicates.append((column, original))
            continue

        signatures[key] = column

    if duplicates:
        frame = frame.drop(columns=[column for column, _ in duplicates])

    return frame, duplicates


def downcast_numeric(frame: pd.DataFrame) -> pd.DataFrame:
    """Store numbers at the smallest lossless width.

    Keeps the parquet cache and the PostgreSQL load at roughly half the size of
    naive float64, without inventing precision: a float is only narrowed to int32
    when every value is integral and inside the int32 range.
    """
    out = frame.copy()

    for column in out.columns:
        series = out[column]

        if not pd.api.types.is_numeric_dtype(series) or pd.api.types.is_bool_dtype(series):
            continue

        if pd.api.types.is_integer_dtype(series):
            if series.abs().max() <= INT32_MAX:
                out[column] = series.astype("int32")
            continue

        if pd.api.types.is_float_dtype(series):
            values = series.dropna()
            integral = (
                not values.empty
                and not series.isna().any()
                and bool((values == values.round(0)).all())
                and float(values.abs().max()) <= INT32_MAX
            )
            out[column] = values.round(0).astype("int32") if integral else series.astype("float32")

    return out


def clean_capture_frame(frame: pd.DataFrame, source_file: str = "") -> CleanResult:
    """Clean and validate one capture frame. Never mutates the input."""
    if frame.empty:
        raise ValidationError(f"{source_file}: capture file contains no rows")

    rows_in = int(len(frame))
    working = frame.copy()

    # 1. exact duplicates
    working = working.drop_duplicates(keep="first").reset_index(drop=True)
    duplicate_rows = rows_in - len(working)

    # 2. numeric coercion, leaving the timestamp and label columns untouched
    protected = {TIMESTAMP_COLUMN, LABEL_COLUMN}
    for column in working.columns:
        if column in protected:
            continue
        working[column] = pd.to_numeric(working[column], errors="coerce")

    # 3. redundant columns
    working, identical_columns = drop_identical_columns(working)

    # 4. infinities -> null (counted before replacing)
    numeric_columns = working.select_dtypes(include=[np.number]).columns
    infinity_cells = 0
    if len(numeric_columns):
        values = working[numeric_columns].to_numpy(dtype="float64", na_value=np.nan)
        infinity_cells = int(np.isinf(values).sum())
        working[numeric_columns] = working[numeric_columns].replace([np.inf, -np.inf], np.nan)

    # 5. time. The MachineLearningCSV release has no timestamp column, so the
    #    capture day comes from the file name and captured_at stays null. A
    #    release that does carry timestamps keeps them, and the source of the day
    #    is recorded either way.
    if TIMESTAMP_COLUMN in working.columns:
        captured_at, timestamp_format, timestamp_rate = parse_capture_timestamps(
            working[TIMESTAMP_COLUMN], source_file
        )
        working[CAPTURED_AT_COLUMN] = captured_at
        working = working.drop(columns=[TIMESTAMP_COLUMN])
        working["capture_date"] = captured_at.dt.normalize()
        time_source = settings.TIME_SOURCE_CSV_TIMESTAMP
    else:
        capture_day = settings.capture_date_for_file(source_file)
        if capture_day is None:
            raise SchemaError(
                f"{source_file}: has no timestamp column and its name does not identify "
                f"a capture day. Known prefixes: {list(settings.CAPTURE_FILE_DAYS)}"
            )
        working[CAPTURED_AT_COLUMN] = pd.NaT
        working["capture_date"] = pd.Timestamp(capture_day)
        timestamp_format, timestamp_rate = None, 0.0
        time_source = settings.TIME_SOURCE_CAPTURE_FILE

    working["time_source"] = time_source

    # 6. labels
    raw_labels = working[LABEL_COLUMN].astype("string").str.strip()
    labels = raw_labels.map(
        lambda value: settings.normalize_label(value) if isinstance(value, str) else pd.NA
    )
    unexpected = sorted(set(labels.dropna().unique()) - set(settings.CANONICAL_LABELS))
    if unexpected:
        raise ValidationError(
            f"{source_file}: labels outside the canonical set: {unexpected}. "
            "Extend settings.normalize_label before loading this file."
        )
    working[OBSERVED_LABEL_COLUMN] = labels.astype("string")
    working = working.drop(columns=[LABEL_COLUMN])

    # 7. rows that cannot be used downstream
    before_drop = len(working)
    working = working.dropna(subset=list(REQUIRED_OUTPUT_COLUMNS)).reset_index(drop=True)
    dropped_invalid = before_drop - len(working)

    working["source_file"] = source_file
    working["row_index"] = np.arange(len(working), dtype="int64")

    working = downcast_numeric(working)

    stats: dict[str, Any] = {
        "source_file": source_file,
        "rows_in": rows_in,
        "duplicate_rows": duplicate_rows,
        "dropped_invalid": dropped_invalid,
        "rows_out": int(len(working)),
        "time_source": time_source,
        "infinity_cells": infinity_cells,
        "timestamp_format": timestamp_format,
        "timestamp_match_rate": timestamp_rate,
        "identical_columns_dropped": [{"dropped": d, "kept": k} for d, k in identical_columns],
        "columns_out": int(working.shape[1]),
    }

    LOGGER.info(
        "%s: %s in -> %s out (dupes %s, invalid %s, inf %s, ts %s)",
        source_file or "<frame>",
        f"{rows_in:,}",
        f"{stats['rows_out']:,}",
        f"{duplicate_rows:,}",
        f"{dropped_invalid:,}",
        f"{infinity_cells:,}",
        timestamp_format,
    )

    return CleanResult(frame=working, stats=stats)
