"""Derived-feature behaviour, especially the division guards."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.errors import SchemaError
from src.feature_engineering import add_flow_features


@pytest.fixture
def flow_frame() -> pd.DataFrame:
    """Two flows: one normal, one with zero duration and zero packets."""
    return pd.DataFrame(
        {
            "flow_duration": [1000.0, 0.0],
            "total_fwd_packets": [10.0, 0.0],
            "total_backward_packets": [5.0, 0.0],
            "total_length_of_fwd_packets": [500.0, 60.0],
            "total_length_of_bwd_packets": [100.0, 0.0],
            "fin_flag_count": [0.0, 0.0],
            "syn_flag_count": [1.0, 1.0],
            "observed_label": ["BENIGN", "PortScan"],
        }
    )


def test_totals_and_per_packet_maths(flow_frame):
    """Flow Duration in CICIDS2017 is microseconds, so 1000 us is 1 ms, not 1 s."""
    out = add_flow_features(flow_frame)

    assert out.loc[0, "total_bytes"] == 600
    assert out.loc[0, "total_packets"] == 15
    assert out.loc[0, "duration_ms"] == pytest.approx(1.0)
    assert out.loc[0, "bytes_per_packet"] == pytest.approx(40.0)
    assert out.loc[0, "bytes_per_second"] == pytest.approx(600_000.0)
    assert out.loc[0, "packets_per_second"] == pytest.approx(15_000.0)


def test_zero_denominators_produce_null_not_infinity(flow_frame):
    out = add_flow_features(flow_frame)

    assert np.isnan(out.loc[1, "bytes_per_packet"])
    assert np.isnan(out.loc[1, "bytes_per_second"])
    assert np.isnan(out.loc[1, "packets_per_second"])

    derived = out[["bytes_per_packet", "bytes_per_second", "packets_per_second"]].to_numpy(dtype="float64")
    assert not np.isinf(derived).any()


def test_attack_flag_and_family(flow_frame):
    out = add_flow_features(flow_frame)

    assert not bool(out.loc[0, "is_attack"])
    assert bool(out.loc[1, "is_attack"])
    assert out.loc[1, "attack_family"] == "PortScan"
    assert pd.isna(out.loc[0, "attack_family"]), "BENIGN has no family"


def test_flag_total_uses_the_flag_columns_present(flow_frame):
    out = add_flow_features(flow_frame)

    assert out.loc[0, "total_flags"] == 1


def test_log_transforms_are_finite_and_monotonic(flow_frame):
    out = add_flow_features(flow_frame)

    assert out["log_total_bytes"].notna().all()
    assert (out["log_total_bytes"] >= 0).all()
    assert out.loc[0, "log_total_bytes"] > out.loc[1, "log_total_bytes"]


def test_missing_required_column_raises(flow_frame):
    broken = flow_frame.drop(columns=["flow_duration"])

    with pytest.raises(SchemaError, match="columns that are absent"):
        add_flow_features(broken)
