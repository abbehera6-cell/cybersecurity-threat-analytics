"""Orchestrates the ETL: extract -> clean -> feature engineering -> parquet.

Run it from the project root:

    python -m src.pipeline
    python -m src.pipeline --dry-run
    python -m src.pipeline --raw-dir "D:\\data\\cictest" --output out\\sample.parquet

The pipeline is deliberately idempotent: the output parquet is overwritten, never
appended to, so running it twice leaves one file with the same row count. Appending
is the job of the PostgreSQL loader in Phase 3, which has a natural key to upsert on.

Every run ends with a reconciliation check. If `rows in` does not equal
`rows out + removed`, the run fails instead of publishing a dataset nobody can
explain.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import pandas as pd

from config import settings
from src.data_cleaning import CAPTURED_AT_COLUMN, clean_capture_frame, downcast_numeric
from src.data_ingestion import discover_capture_files, iter_capture_files
from src.errors import PipelineError, ValidationError
from src.feature_engineering import add_flow_features

LOGGER = logging.getLogger("pipeline")

DEFAULT_OUTPUT = settings.PROCESSED_DIR / "flows_clean.parquet"
LOG_FILE = settings.LOGS_DIR / "pipeline.log"
LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s | %(message)s"


def configure_logging(level: str | None = None) -> None:
    """Attach a console handler and a file handler, once per process."""
    if LOGGER.handlers:
        return

    LOGGER.setLevel(level or settings.LOG_LEVEL)
    formatter = logging.Formatter(LOG_FORMAT)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    LOGGER.addHandler(console)

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)


def reconcile(file_reports: Sequence[dict[str, Any]], rows_out: int) -> dict[str, int]:
    """Prove that every removed row is accounted for by a named reason."""
    totals = {
        "rows_in": sum(report["rows_in"] for report in file_reports),
        "duplicates": sum(report["duplicate_rows"] for report in file_reports),
        "dropped_invalid": sum(report["dropped_invalid"] for report in file_reports),
        "infinity_cells": sum(report["infinity_cells"] for report in file_reports),
    }

    removed = totals["rows_in"] - rows_out
    explained = totals["duplicates"] + totals["dropped_invalid"]

    if removed != explained:
        raise ValidationError(
            f"reconciliation failed: {totals['rows_in']} in, {rows_out} out "
            f"({removed} removed) but only {explained} removals were recorded"
        )

    return totals


def run_pipeline(
    raw_dir: Path | None = None,
    output_path: Path | None = None,
    *,
    write_output: bool = True,
    metadata_path: Path | None = None,
) -> dict[str, Any]:
    """Build the cleaned, feature-enriched dataset and return the run report."""
    started_at = datetime.now(timezone.utc)
    paths = discover_capture_files(raw_dir)

    LOGGER.info("found %s capture file(s) in %s", len(paths), raw_dir or settings.RAW_DIR)

    frames: list[pd.DataFrame] = []
    file_reports: list[dict[str, Any]] = []

    for capture in iter_capture_files(paths):
        cleaned = clean_capture_frame(capture.frame, source_file=capture.path.name)
        featured = downcast_numeric(add_flow_features(cleaned.frame))

        frames.append(featured)

        entry = dict(cleaned.stats)
        entry["encoding"] = capture.encoding
        file_reports.append(entry)

    if not frames:
        raise ValidationError("no capture files produced a dataset")

    combined = pd.concat(frames, ignore_index=True)
    if combined.empty:
        raise ValidationError("every row was removed during cleaning")

    totals = reconcile(file_reports, int(len(combined)))
    totals.update(
        {
            "rows_out": int(len(combined)),
            "attack_rows": int(combined["is_attack"].sum()),
            "benign_rows": int((~combined["is_attack"]).sum()),
            "attack_labels": int(combined.loc[combined["is_attack"], "observed_label"].nunique()),
            "columns": int(combined.shape[1]),
            "capture_dates": sorted(str(value) for value in combined["capture_date"].dt.date.unique()),
            "window_start": str(combined[CAPTURED_AT_COLUMN].min()),
            "window_end": str(combined[CAPTURED_AT_COLUMN].max()),
        }
    )

    finished_at = datetime.now(timezone.utc)
    report: dict[str, Any] = {
        "run_started_at": started_at.isoformat(),
        "run_finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 2),
        "raw_dir": str(raw_dir or settings.RAW_DIR),
        "files": file_reports,
        "totals": totals,
        "output_path": None,
    }

    if write_output:
        destination = Path(output_path) if output_path is not None else DEFAULT_OUTPUT
        destination.parent.mkdir(parents=True, exist_ok=True)
        combined.to_parquet(destination, index=False, compression="snappy")
        report["output_path"] = str(destination)
        LOGGER.info("wrote %s with %s rows", destination, f"{len(combined):,}")

        metadata = (
            Path(metadata_path)
            if metadata_path is not None
            else destination.with_suffix(".run.json")
        )
        metadata.write_text(json.dumps(report, indent=2), encoding="utf-8")
        LOGGER.info("wrote %s", metadata)

    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the cleaned CICIDS2017 flow dataset.")
    parser.add_argument("--raw-dir", type=Path, default=None, help="folder holding the capture CSVs")
    parser.add_argument("--output", type=Path, default=None, help="parquet destination")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and report without writing the parquet",
    )
    args = parser.parse_args(argv)

    configure_logging()

    try:
        report = run_pipeline(args.raw_dir, args.output, write_output=not args.dry_run)
    except (PipelineError, FileNotFoundError) as error:
        LOGGER.error("%s", error)
        return 1

    totals = report["totals"]
    print()
    print(f"rows in        : {totals['rows_in']:,}")
    print(f"duplicates     : {totals['duplicates']:,}")
    print(f"invalid rows   : {totals['dropped_invalid']:,}")
    print(f"rows out       : {totals['rows_out']:,}")
    print(f"attack rows    : {totals['attack_rows']:,}")
    print(f"attack labels  : {totals['attack_labels']}")
    print(f"capture window : {totals['window_start']} -> {totals['window_end']}")
    print(f"output         : {report['output_path'] or '(dry run, nothing written)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
