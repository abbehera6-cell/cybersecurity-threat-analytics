"""Transform stage: derived flow features shared by SQL, the dashboards and the models.

Every division here is guarded: when the denominator is zero the result is null,
never ``inf`` and never a silent zero. That single rule is what keeps the Power BI
averages and the scikit-learn scalers honest, because both would otherwise be
poisoned by a handful of infinite rows.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd

from config import settings
from src.errors import SchemaError

LOGGER = logging.getLogger(__name__)

OBSERVED_LABEL_COLUMN = "observed_label"

REQUIRED_COLUMNS = (
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
    OBSERVED_LABEL_COLUMN,
)

# Summed into total_flags when present, skipped when a mirror of the dataset lacks them.
FLAG_COLUMNS = (
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "cwe_flag_count",
    "ece_flag_count",
)

DERIVED_COLUMNS = (
    "duration_ms",
    "total_packets",
    "total_bytes",
    "bytes_per_packet",
    "bytes_per_second",
    "packets_per_second",
    "forward_byte_ratio",
    "total_flags",
    "log_total_bytes",
    "log_duration_ms",
    "is_attack",
    "attack_family",
)


def safe_divide(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    """Divide, returning null wherever the denominator is not strictly positive."""
    return numerator / denominator.where(denominator > 0)


def add_flow_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of ``frame`` with the columns listed in DERIVED_COLUMNS added."""
    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        raise SchemaError(f"feature engineering needs columns that are absent: {missing}")

    out = frame.copy()

    duration_ms = out["flow_duration"].astype("float64") / 1000.0
    forward_packets = out["total_fwd_packets"].astype("float64")
    backward_packets = out["total_backward_packets"].astype("float64")
    forward_bytes = out["total_length_of_fwd_packets"].astype("float64")
    backward_bytes = out["total_length_of_bwd_packets"].astype("float64")

    total_packets = forward_packets + backward_packets
    total_bytes = forward_bytes + backward_bytes
    seconds = duration_ms / 1000.0

    out["duration_ms"] = duration_ms
    out["total_packets"] = total_packets
    out["total_bytes"] = total_bytes
    out["bytes_per_packet"] = safe_divide(total_bytes, total_packets)
    out["bytes_per_second"] = safe_divide(total_bytes, seconds)
    out["packets_per_second"] = safe_divide(total_packets, seconds)
    out["forward_byte_ratio"] = safe_divide(total_bytes, forward_bytes)

    flag_columns = [column for column in FLAG_COLUMNS if column in frame.columns]
    if flag_columns:
        out["total_flags"] = frame[flag_columns].sum(axis=1).astype("float64")
    else:
        out["total_flags"] = 0.0

    out["log_total_bytes"] = np.log1p(total_bytes.clip(lower=0))
    out["log_duration_ms"] = np.log1p(duration_ms.clip(lower=0))

    labels = out[OBSERVED_LABEL_COLUMN]
    out["is_attack"] = labels != settings.BENIGN_LABEL
    out["attack_family"] = labels.map(settings.LABEL_FAMILY)

    LOGGER.debug("added %s derived columns", len(DERIVED_COLUMNS))
    return out
