"""Synthetic CICIDS2017 fixtures.

They reproduce, at small scale, every defect the real release has:

* a header with a leading space and a duplicated column name (`Fwd Header Length.1`)
* one file that is not valid UTF-8 (cp1252 byte 0x96, an en dash inside a label)
* mixed timestamp formats (24-hour on Monday, 12-hour with AM/PM on Thursday)
* an `inf` value produced by a zero-duration flow
* exact duplicate rows and one unusable timestamp

The good-row count is chosen so the timestamp match rate clears the 0.95 gate,
which is what the real files look like: a handful of bad rows inside ~700k.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.data_ingestion import read_capture_file  # noqa: E402

MONDAY_NAME = "Monday-WorkingHours.pcap_ISCX.csv"
THURSDAY_NAME = "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"

HEADER = ",".join(
    [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Bytes/s",
        " Flow Packets/s",          # leading space is real, and must survive the fixture
        "Fwd Header Length",
        "Fwd Header Length.1",      # duplicated name is real
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "Timestamp",
        "Label",
    ]
)

BENIGN_ROWS = 24


def _row(
    port: int,
    duration: int,
    fwd_packets: int,
    bwd_packets: int,
    fwd_bytes: int,
    bwd_bytes: int,
    rate: str,
    header_length: int,
    timestamp: str,
    label: str,
) -> str:
    return (
        f"{port},{duration},{fwd_packets},{bwd_packets},{fwd_bytes},{bwd_bytes},{rate},"
        f"833.33,{header_length},{header_length},0,1,0,1,1,{timestamp},{label}"
    )


def _monday_rows() -> list[str]:
    rows = [
        _row(
            80,
            1200,
            3,
            2,
            300,
            200,
            "4166.66",
            24 if index % 3 == 0 else 20,
            f"03/07/2017 09:{5 + index:02d}",
            "BENIGN",
        )
        for index in range(BENIGN_ROWS)
    ]
    rows.append(rows[0])  # exact duplicate
    rows.append(_row(443, 0, 1, 0, 60, 0, "inf", 24, "03/07/2017 10:00", "BENIGN"))
    rows.append(_row(80, 900, 2, 2, 120, 80, "222.22", 20, "not-a-date", "PortScan"))
    return rows


def _thursday_lines() -> list[bytes]:
    """Lines already terminated with a newline.

    The attack label is assembled as bytes on purpose: byte 0x96 is the cp1252 en
    dash, which is exactly the byte that makes this file unreadable as UTF-8.
    Encoding the character U+0096 instead would produce a different file.
    """
    attack = (
        b"22,500000,40,30,2400,1800,8400.0,833.33,20,20,0,1,0,1,1,"
        b"06/07/2017 09:20:00 AM,Web Attack "
        b"\x96"
        b" Brute Force\n"
    )
    benign = (
        _row(53, 100, 1, 1, 60, 40, "1000.0", 32, "06/07/2017 09:25:00 AM", "BENIGN").encode("ascii")
        + b"\n"
    )
    return [attack, benign]


@pytest.fixture
def raw_dir(tmp_path: Path) -> Path:
    """A raw/ folder holding one UTF-8 file and one cp1252 file."""
    directory = tmp_path / "raw"
    directory.mkdir()

    monday = HEADER + "\n" + "\n".join(_monday_rows()) + "\n"
    (directory / MONDAY_NAME).write_text(monday, encoding="utf-8")

    thursday = HEADER.encode("ascii") + b"\n" + b"".join(_thursday_lines())
    (directory / THURSDAY_NAME).write_bytes(thursday)

    return directory


@pytest.fixture
def monday_path(raw_dir: Path) -> Path:
    return raw_dir / MONDAY_NAME


@pytest.fixture
def thursday_path(raw_dir: Path) -> Path:
    return raw_dir / THURSDAY_NAME


@pytest.fixture
def monday_capture(monday_path: Path):
    return read_capture_file(monday_path)


@pytest.fixture
def thursday_capture(thursday_path: Path):
    return read_capture_file(thursday_path)
