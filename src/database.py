"""Load stage: apply the schema and load the cleaned dataset into PostgreSQL.

Two properties matter here:

* **Idempotent.** `flow_key` is ``<source file>:<row index>`, so re-running the
  loader finds the same key for the same record. ``ON CONFLICT (flow_key) DO
  NOTHING`` is what makes the pipeline safe to schedule: a second run of the
  same capture adds nothing, and the inserted row count tells you so.
* **Bounded memory.** The parquet is read in row-group batches through pyarrow
  and sent with ``execute_values``. A 2.83M-row load never materialises one
  Python list of 2.83M tuples.

Run it with::

    python -m src.database --schema-only
    python -m src.database
    python -m src.database --parquet data/processed/flows_clean.parquet
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

import pandas as pd
import pyarrow.parquet as pq
from psycopg2.extras import execute_values
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from config import settings
from src.errors import PipelineError, ValidationError

LOGGER = logging.getLogger("database")

SCHEMA_FILE = settings.SQL_DIR / "schema.sql"
DEFAULT_PARQUET = settings.PROCESSED_DIR / "flows_clean.parquet"

# Column order of the INSERT. Fixed arity keeps the VALUES template static even
# when a capture release lacks endpoint columns.
INSERT_COLUMNS = (
    "flow_key",
    "run_id",
    "captured_at",
    "capture_date",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "duration_ms",
    "total_fwd_packets",
    "total_backward_packets",
    "total_bytes",
    "bytes_per_packet",
    "packets_per_second",
    "total_flags",
    "label_id",
)

INSERT_SQL = f"""
INSERT INTO network_flows ({", ".join(INSERT_COLUMNS)})
VALUES %s
ON CONFLICT (flow_key) DO NOTHING
"""

# Columns read from the parquet, in the order they are copied into INSERT_COLUMNS.
SOURCE_COLUMNS = (
    "captured_at",
    "capture_date",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "duration_ms",
    "total_fwd_packets",
    "total_backward_packets",
    "total_bytes",
    "bytes_per_packet",
    "packets_per_second",
    "total_flags",
)

REQUIRED_PARQUET_COLUMNS = ("captured_at", "capture_date", "observed_label", "source_file", "row_index")

# What to actually read from parquet: the loadable columns plus the three that
# build the row key and resolve the label. Omitting the label columns here is the
# kind of bug that only shows up against real data, so it is one tuple now.
READ_COLUMNS = SOURCE_COLUMNS + tuple(
    column for column in REQUIRED_PARQUET_COLUMNS if column not in SOURCE_COLUMNS
)

INTEGER_COLUMNS = (
    "source_port",
    "destination_port",
    "protocol",
    "total_fwd_packets",
    "total_backward_packets",
    "total_bytes",
    "total_flags",
)


def create_engine_from_settings() -> Engine:
    """Engine for the database described by `.env`."""
    return create_engine(settings.DATABASE_URL, pool_pre_ping=True)


def apply_schema(engine: Engine | None = None) -> None:
    """Create tables, indexes and label seeds. Safe to run repeatedly."""
    engine = engine or create_engine_from_settings()
    sql_text = SCHEMA_FILE.read_text(encoding="utf-8")

    with engine.begin() as connection:
        connection.exec_driver_sql(sql_text)

    LOGGER.info("schema applied from %s", SCHEMA_FILE)


def read_run_metadata(path: Path) -> dict[str, Any]:
    """Load the pipeline run record written next to the parquet, if present."""
    if not path.exists():
        return {}
    import json

    return json.loads(path.read_text(encoding="utf-8"))


def default_run_id(metadata: dict[str, Any] | None = None) -> str:
    """Derive a stable-ish run identifier from the pipeline run record."""
    started = (metadata or {}).get("run_started_at")
    if started:
        return "run_" + str(started)[:19].replace("-", "").replace(":", "")
    return "run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")


def ensure_run(cursor, run_id: str, metadata: dict[str, Any] | None = None) -> None:
    """Insert or refresh the pipeline_runs row for this load."""
    metadata = metadata or {}
    totals = metadata.get("totals", {})
    started_at = metadata.get("run_started_at") or datetime.now(timezone.utc).isoformat()
    finished_at = metadata.get("run_finished_at")
    source_files = [entry["source_file"] for entry in metadata.get("files", [])] or None

    cursor.execute(
        """
        INSERT INTO pipeline_runs (
            run_id, started_at, finished_at, status, raw_dir, source_files,
            rows_extracted, rows_cleaned, duplicates_removed, invalid_rows_removed
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (run_id) DO UPDATE
            SET finished_at = EXCLUDED.finished_at,
                status = EXCLUDED.status,
                raw_dir = EXCLUDED.raw_dir,
                source_files = EXCLUDED.source_files,
                rows_extracted = EXCLUDED.rows_extracted,
                rows_cleaned = EXCLUDED.rows_cleaned,
                duplicates_removed = EXCLUDED.duplicates_removed,
                invalid_rows_removed = EXCLUDED.invalid_rows_removed
        """,
        (
            run_id,
            started_at,
            finished_at,
            "cleaned",
            metadata.get("raw_dir"),
            source_files,
            totals.get("rows_in", 0),
            totals.get("rows_out", 0),
            totals.get("duplicates", 0),
            totals.get("dropped_invalid", 0),
        ),
    )


def fetch_label_map(cursor) -> dict[str, int]:
    """label text -> label_id, taken from the seeded lookup table."""
    cursor.execute("SELECT label, label_id FROM attack_labels")
    return {label: label_id for label, label_id in cursor.fetchall()}


def _native(value: Any) -> Any:
    """Convert numpy and pandas scalars into types psycopg2 can adapt."""
    if value is None or value is pd.NaT:
        return None
    if isinstance(value, pd.Timestamp):
        return value.to_pydatetime()
    if hasattr(value, "item"):
        try:
            return value.item()
        except (ValueError, AttributeError):
            return value
    return value


def build_rows(frame: pd.DataFrame, run_id: str, label_map: dict[str, int]) -> list[tuple]:
    """Turn one batch of parquet rows into tuples matching INSERT_COLUMNS."""
    label_ids = frame["observed_label"].map(label_map)
    if label_ids.isna().any():
        unknown = sorted(frame.loc[label_ids.isna(), "observed_label"].astype(str).unique())
        raise ValidationError(
            f"labels missing from attack_labels: {unknown}. Apply sql/schema.sql first."
        )

    out = pd.DataFrame(index=frame.index)
    out["flow_key"] = frame["source_file"].astype(str) + ":" + frame["row_index"].astype(str)
    out["run_id"] = run_id
    out["captured_at"] = frame["captured_at"]
    out["capture_date"] = frame["capture_date"]

    # Endpoint columns exist in the pcap-derived releases but not in the
    # MachineLearningCSV release, so they are optional here and load as null.
    for column in ("source_ip", "destination_ip", "source_port"):
        out[column] = frame[column] if column in frame.columns else None

    for column in SOURCE_COLUMNS[5:]:
        out[column] = frame[column] if column in frame.columns else None

    out["label_id"] = label_ids

    for column in INTEGER_COLUMNS:
        out[column] = pd.to_numeric(out[column], errors="coerce").round()

    out = out[list(INSERT_COLUMNS)]
    records = out.astype(object).where(pd.notna(out), None).itertuples(index=False, name=None)
    return [tuple(_native(value) for value in record) for record in records]


def iter_parquet_batches(
    path: Path,
    batch_size: int,
    columns: Sequence[str] = READ_COLUMNS,
) -> Iterator[pd.DataFrame]:
    """Yield the parquet in batches small enough to keep memory flat."""
    parquet = pq.ParquetFile(path)
    available = set(parquet.schema.names)

    missing = [column for column in REQUIRED_PARQUET_COLUMNS if column not in available]
    if missing:
        raise ValidationError(
            f"{path.name} is missing required column(s): {missing}. "
            "Re-run python -m src.pipeline to rebuild it."
        )

    use_columns = [column for column in columns if column in available]

    for batch in parquet.iter_batches(batch_size=batch_size, columns=use_columns):
        yield batch.to_pandas()


def load_dataset(
    parquet_path: Path | None = None,
    run_id: str | None = None,
    *,
    batch_size: int | None = None,
    apply_ddl: bool = True,
    metadata_path: Path | None = None,
) -> dict[str, Any]:
    """Load a cleaned parquet into PostgreSQL. Returns a summary of the load."""
    source = Path(parquet_path) if parquet_path is not None else DEFAULT_PARQUET
    if not source.exists():
        raise FileNotFoundError(
            f"no cleaned dataset at {source}. Run python -m src.pipeline first."
        )

    metadata = read_run_metadata(metadata_path or source.with_suffix(".run.json"))
    run_id = run_id or default_run_id(metadata)
    size = batch_size or settings.PIPELINE_BATCH_SIZE

    engine = create_engine_from_settings()
    if apply_ddl:
        apply_schema(engine)

    attempted = 0
    inserted = 0

    raw = engine.raw_connection()
    try:
        raw.autocommit = False
        cursor = raw.cursor()

        ensure_run(cursor, run_id, metadata)
        label_map = fetch_label_map(cursor)

        for frame in iter_parquet_batches(source, size):
            rows = build_rows(frame, run_id, label_map)
            if not rows:
                continue
            execute_values(cursor, INSERT_SQL, rows, page_size=min(len(rows), 5000))
            attempted += len(rows)
            inserted += max(cursor.rowcount, 0)
            LOGGER.info("loaded %s rows so far (%s inserted)", f"{attempted:,}", f"{inserted:,}")

        cursor.execute(
            "UPDATE pipeline_runs SET rows_loaded = %s, status = %s WHERE run_id = %s",
            (inserted, "loaded", run_id),
        )
        raw.commit()
        cursor.close()
    except Exception:
        raw.rollback()
        raise
    finally:
        raw.close()

    summary = {
        "run_id": run_id,
        "parquet": str(source),
        "rows_attempted": attempted,
        "rows_inserted": inserted,
        "rows_skipped_existing": attempted - inserted,
        "database": settings.DB_NAME,
    }
    LOGGER.info(
        "load complete: %s seen, %s inserted, %s already present",
        f"{attempted:,}",
        f"{inserted:,}",
        f"{attempted - inserted:,}",
    )
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Load the cleaned dataset into PostgreSQL.")
    parser.add_argument("--parquet", type=Path, default=None, help="cleaned parquet to load")
    parser.add_argument("--run-id", default=None, help="override the run identifier")
    parser.add_argument("--schema-only", action="store_true", help="apply the schema and stop")
    parser.add_argument("--batch-size", type=int, default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=settings.LOG_LEVEL,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    try:
        if args.schema_only:
            apply_schema()
            print(f"\nschema applied to {settings.DB_NAME} on {settings.DB_HOST}:{settings.DB_PORT}")
            return 0

        summary = load_dataset(args.parquet, args.run_id, batch_size=args.batch_size)
    except (PipelineError, FileNotFoundError) as error:
        LOGGER.error("%s", error)
        return 1

    print()
    print(f"run id            : {summary['run_id']}")
    print(f"rows seen         : {summary['rows_attempted']:,}")
    print(f"rows inserted     : {summary['rows_inserted']:,}")
    print(f"already present   : {summary['rows_skipped_existing']:,}")
    print(f"database          : {summary['database']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
