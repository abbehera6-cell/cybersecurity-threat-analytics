"""tests/test_train_models.py
Unit tests for the machine learning training pipeline module.
"""

import os
import joblib
import pytest


def test_model_artifacts_exist():
    models_dir = os.path.join(os.path.dirname(__file__), "..", "models")
    expected_files = [
        "scaler.joblib",
        "isolation_forest.joblib",
        "random_forest.joblib",
        "pca.joblib",
        "kmeans.joblib",
        "feature_columns.joblib"
    ]
    for fname in expected_files:
        fpath = os.path.join(models_dir, fname)
        assert os.path.isfile(fpath), f"Expected artifact {fname} not found in models/"


def test_feature_columns_contract():
    models_dir = os.path.join(os.path.dirname(__file__), "..", "models")
    cols_path = os.path.join(models_dir, "feature_columns.joblib")
    assert os.path.isfile(cols_path)
    feature_cols = joblib.load(cols_path)
    assert isinstance(feature_cols, list)
    assert len(feature_cols) >= 30
    assert "destination_port" in feature_cols
    assert "flow_duration" in feature_cols
    assert "observed_label" not in feature_cols
    assert "is_attack" not in feature_cols


def test_powerbi_datasets_exist():
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data", "processed")
    assert os.path.isfile(os.path.join(data_dir, "powerbi_daily_attack_summary.csv"))
    assert os.path.isfile(os.path.join(data_dir, "powerbi_port_threat_matrix.csv"))
    assert os.path.isfile(os.path.join(data_dir, "powerbi_network_flows_sample.csv"))
    assert os.path.isfile(os.path.join(data_dir, "ml_predictions_sample.csv"))

