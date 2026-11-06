"""Single source of truth for paths, credentials and dataset constants.

Every stage of the project (notebooks, ETL, loader, tests) imports from this
module instead of hard-coding a path or a database URL. If a path changes, it
changes here once.

Import as:

    from config import settings
    settings.RAW_DIR
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORTS_DIR = PROJECT_ROOT / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"
MODELS_DIR = PROJECT_ROOT / "models"
LOGS_DIR = PROJECT_ROOT / "logs"
SQL_DIR = PROJECT_ROOT / "sql"

for _directory in (RAW_DIR, PROCESSED_DIR, REPORTS_DIR, FIGURES_DIR, MODELS_DIR, LOGS_DIR):
    _directory.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Environment (.env sits next to requirements.txt)
# ---------------------------------------------------------------------------
load_dotenv(PROJECT_ROOT / ".env")

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "cyber_threat")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

PIPELINE_BATCH_SIZE = int(os.getenv("PIPELINE_BATCH_SIZE", "200000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# ---------------------------------------------------------------------------
# Dataset facts - CICIDS2017, official MachineLearningCSV release
# ---------------------------------------------------------------------------
EXPECTED_FILES = 8
EXPECTED_TOTAL_ROWS = 2_830_743

# Reference values from the official release. The audit compares against them
# and reports a mismatch as a warning: mirrors and re-uploads exist, so these
# are never used as hard assertions.
REFERENCE_ATTACK_ROWS = 557_646

BENIGN_LABEL = "BENIGN"

# The 14 attack labels plus BENIGN, spelled canonically. Raw files use an en
# dash and, in the Thursday file, a 0xA0 byte - both are normalised away by
# normalize_label() below.
CANONICAL_LABELS = (
    "BENIGN",
    "Bot",
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowloris",
    "DoS Slowhttptest",
    "FTP-Patator",
    "Heartbleed",
    "Infiltration",
    "PortScan",
    "SSH-Patator",
    "Web Attack - Brute Force",
    "Web Attack - SQL Injection",
    "Web Attack - XSS",
)

# Reporting grouping used by the Power BI attack-family visual and by
# SQL queries that aggregate labels into families.
LABEL_FAMILY = {
    "BENIGN": None,
    "Bot": "Bot",
    "DDoS": "DDoS",
    "DoS GoldenEye": "DoS",
    "DoS Hulk": "DoS",
    "DoS Slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "FTP-Patator": "Brute Force",
    "Heartbleed": "Heartbleed",
    "Infiltration": "Infiltration",
    "PortScan": "PortScan",
    "SSH-Patator": "Brute Force",
    "Web Attack - Brute Force": "Web Attack",
    "Web Attack - SQL Injection": "Web Attack",
    "Web Attack - XSS": "Web Attack",
}


def _label_key(value: str) -> str:
    """Lower-case, punctuation-free key for a label.

    Collapses the differences that actually appear in CICIDS2017: the en dash
    in "Web Attack - Brute Force", the 0xA0 byte produced by the cp1252 read,
    and stray leading or trailing spaces.
    """
    cleaned = "".join(ch if ch.isalnum() else " " for ch in str(value).replace("\xa0", " "))
    return " ".join(cleaned.split()).lower()


_LABEL_LOOKUP = {_label_key(name): name for name in CANONICAL_LABELS}


def normalize_label(raw_label: str) -> str:
    """Map one raw CSV label onto CANONICAL_LABELS.

    Unknown labels are returned stripped rather than dropped, so the audit can
    surface them instead of silently losing records.
    """
    key = _label_key(raw_label)

    if key in _LABEL_LOOKUP:
        return _LABEL_LOOKUP[key]

    if key.startswith("web attack"):
        if "brute" in key:
            return "Web Attack - Brute Force"
        if "xss" in key:
            return "Web Attack - XSS"
        if "sql" in key:
            return "Web Attack - SQL Injection"

    return str(raw_label).strip()


def label_family(canonical_label: str):
    """Return the reporting family for a canonical label, or None for BENIGN."""
    return LABEL_FAMILY.get(canonical_label)
