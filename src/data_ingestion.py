"""Extract stage: read the raw CICIDS2017 capture files and normalise their header.

Three decisions worth knowing before you read the code:

1. **One file at a time.** The largest capture file is about 700k rows, so peak
   memory is bounded by that file rather than by the full 2.83M-row dataset.
   Chunked reads would make whole-row duplicate removal unreliable across chunk
   boundaries, which matters more here than the memory saving.

2. **Encode per file, not per dataset.** The Thursday WebAttacks file carries a
   0xA0 byte inside a label and is not valid UTF-8. A single global encoding
   would either crash or silently mangle that column.

3. **Validate after renaming.** The raw header has leading spaces and a
   duplicated name (`Fwd Header Length` plus `Fwd Header Length.1`), so
   validation runs against the normalised names, never the raw ones.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

import pandas as pd

from config import settings
from src.errors import SchemaError

LOGGER = logging.getLogger(__name__)

ENCODINGS = ("utf-8", "cp1252", "latin-1")

TIMESTAMP_COLUMN = "timestamp"
LABEL_COLUMN = "label"

# Required by every later stage. Checked against the normalised header.
REQUIRED_COLUMNS = (
    "destination_port",
    "flow_duration",
    TIMESTAMP_COLUMN,
    LABEL_COLUMN,
)


@dataclass(frozen=True)
class CaptureFile:
    """One raw CSV, already renamed but not yet cleaned."""

    path: Path
    frame: pd.DataFrame
    encoding: str

    @property
    def rows(self) -> int:
        return int(len(self.frame))


def normalise_column_names(frame: pd.DataFrame) -> pd.DataFrame:
    """Return a copy whose columns are lower snake_case with no collisions.

    ``' Destination Port'``   -> ``'destination_port'``
    ``' Flow Packets/s'``     -> ``'flow_packets_s'``
    ``'Fwd Header Length.1'`` -> ``'fwd_header_length_1'``

    The trailing counter is what keeps the duplicated ``Fwd Header Length``
    pair apart instead of letting pandas rename one of them silently.
    """
    seen: dict[str, int] = {}
    renamed: list[str] = []

    for raw in frame.columns:
        name = str(raw).strip().lower().replace(" ", "_")
        name = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in name)
        name = "_".join(part for part in name.split("_") if part)

        if name in seen:
            seen[name] += 1
            name = f"{name}_{seen[name]}"
        else:
            seen[name] = 0

        renamed.append(name)

    out = frame.copy()
    out.columns = renamed
    return out


def read_capture_file(path: Path) -> CaptureFile:
    """Read one capture CSV, resolving its encoding.

    UTF-8 is tried first and cp1252 is the real fallback; latin-1 is a last
    resort that cannot fail, which is why it is last. The encoding actually used
    is returned so the pipeline report can show that the Thursday file needed
    the fallback.
    """
    path = Path(path)
    last_error: UnicodeDecodeError | None = None

    for encoding in ENCODINGS:
        try:
            frame = pd.read_csv(path, encoding=encoding, low_memory=False)
        except UnicodeDecodeError as error:
            last_error = error
            continue

        if encoding != ENCODINGS[0]:
            LOGGER.info("%s is not UTF-8, read with %s", path.name, encoding)

        return CaptureFile(
            path=path,
            frame=normalise_column_names(frame),
            encoding=encoding,
        )

    raise SchemaError(f"could not decode {path.name} with any of {ENCODINGS}") from last_error


def validate_schema(capture: CaptureFile) -> None:
    """Fail loudly when a required column is absent after renaming."""
    missing = [column for column in REQUIRED_COLUMNS if column not in capture.frame.columns]
    if missing:
        raise SchemaError(
            f"{capture.path.name} is missing required column(s): {missing}. "
            f"Columns found: {list(capture.frame.columns)[:10]}..."
        )


def discover_capture_files(raw_dir: Path | None = None) -> list[Path]:
    """Return the capture CSVs in ``raw_dir``, sorted for reproducible runs."""
    directory = Path(raw_dir) if raw_dir is not None else settings.RAW_DIR

    if not directory.exists():
        raise FileNotFoundError(f"raw data directory does not exist: {directory}")

    files = sorted(directory.glob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"no CSV files in {directory}. Download MachineLearningCSV.zip from "
            "https://www.unb.ca/cic/datasets/ids-2017.html and unzip the 8 files there."
        )

    return files


def iter_capture_files(paths: Iterable[Path]) -> Iterator[CaptureFile]:
    """Yield each file read and schema-validated, in the order given."""
    for path in paths:
        capture = read_capture_file(path)
        validate_schema(capture)
        LOGGER.info(
            "%s: %s rows, %s columns, encoding=%s",
            capture.path.name,
            f"{capture.rows:,}",
            len(capture.frame.columns),
            capture.encoding,
        )
        yield capture
