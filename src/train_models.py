"""src/train_models.py
Enterprise Cybersecurity & Threat Intelligence Analytics Platform
Trains Isolation Forest, Random Forest, and K-Means models.
Serializes artifacts to models/ and exports predictions for Power BI.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import numpy as np
import pandas as pd
import joblib

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    accuracy_score
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("train_models")

FEATURE_COLS = [
    'destination_port', 'flow_duration', 'total_fwd_packets', 'total_backward_packets',
    'total_length_of_fwd_packets', 'total_length_of_bwd_packets',
    'fwd_packet_length_max', 'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std',
    'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean', 'bwd_packet_length_std',
    'flow_bytes_s', 'flow_packets_s', 'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
    'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
    'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
    'fwd_header_length', 'bwd_header_length', 'min_packet_length', 'max_packet_length',
    'packet_length_mean', 'packet_length_std', 'packet_length_variance',
    'fin_flag_count', 'rst_flag_count', 'psh_flag_count', 'ack_flag_count',
    'init_win_bytes_forward', 'init_win_bytes_backward', 'act_data_pkt_fwd',
    'duration_ms', 'total_packets', 'total_bytes', 'bytes_per_packet',
    'bytes_per_second', 'packets_per_second', 'forward_byte_ratio', 'total_flags',
    'log_total_bytes', 'log_duration_ms'
]


def load_and_sample_data(parquet_path: str, sample_size: int = 150000, random_state: int = 42) -> pd.DataFrame:
    """Load cleaned parquet and perform stratified sampling to preserve rare attack classes."""
    logger.info("Reading dataset from %s", parquet_path)
    cols_to_read = FEATURE_COLS + ['observed_label', 'attack_family', 'is_attack', 'capture_date']
    df = pd.read_parquet(parquet_path, columns=cols_to_read)
    logger.info("Full dataset loaded: %d rows, %d columns", len(df), len(df.columns))

    strat_ratio = sample_size / len(df)
    sampled = df.groupby('observed_label', group_keys=False).apply(
        lambda g: g.sample(max(10, int(len(g) * strat_ratio)), random_state=random_state)
    ).reset_index(drop=True)
    
    logger.info("Stratified sample constructed: %d rows", len(sampled))
    return sampled


def train_pipeline(
    parquet_path: str = "data/processed/flows_clean.parquet",
    models_dir: str = "models",
    reports_dir: str = "reports/figures",
    processed_dir: str = "data/processed",
    sample_size: int = 150000
) -> dict:
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(processed_dir, exist_ok=True)

    df_sample = load_and_sample_data(parquet_path, sample_size=sample_size)

    X = df_sample[FEATURE_COLS].copy()
    y_multiclass = df_sample['observed_label'].values
    y_binary = df_sample['is_attack'].astype(int).values

    # Impute medians
    X_imputed = X.fillna(X.median())

    # Split dataset (70% train, 30% test)
    X_train, X_test, y_train, y_test, y_bin_train, y_bin_test = train_test_split(
        X_imputed, y_multiclass, y_binary, test_size=0.30, random_state=42, stratify=y_multiclass
    )

    # Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 1. Isolation Forest
    logger.info("Training Isolation Forest (Unsupervised Anomaly Detection)...")
    iso_forest = IsolationForest(
        n_estimators=120,
        contamination=0.165,
        max_samples=0.8,
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_train_scaled)

    iso_raw_test = iso_forest.predict(X_test_scaled)
    iso_pred_test = np.where(iso_raw_test == -1, 1, 0)
    iso_acc = accuracy_score(y_bin_test, iso_pred_test)
    iso_p, iso_r, iso_f1, _ = precision_recall_fscore_support(y_bin_test, iso_pred_test, average='binary')
    logger.info("Isolation Forest -> Acc: %.4f, Prec: %.4f, Recall: %.4f, F1: %.4f", iso_acc, iso_p, iso_r, iso_f1)

    # Plot Isolation Forest Confusion Matrix
    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(6, 5), facecolor='#111827')
    ax.set_facecolor('#1f2937')
    cm_iso = confusion_matrix(y_bin_test, iso_pred_test)
    sns.heatmap(cm_iso, annot=True, fmt=',d', cmap='Blues', cbar=False, ax=ax,
                xticklabels=['Normal (Pred)', 'Anomaly (Pred)'],
                yticklabels=['Benign (Actual)', 'Attack (Actual)'])
    ax.set_title('Isolation Forest — Anomaly Confusion Matrix', color='#f8fafc', fontsize=12, weight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(reports_dir, '04_isolation_forest_cm.png'), dpi=150, facecolor='#111827')
    plt.close()

    # 2. Random Forest Classifier
    logger.info("Training Random Forest Classifier (Multi-Class)...")
    rf_clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=20,
        min_samples_split=5,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf_clf.fit(X_train_scaled, y_train)
    rf_preds = rf_clf.predict(X_test_scaled)
    rf_acc = accuracy_score(y_test, rf_preds)
    rf_p, rf_r, rf_f1, _ = precision_recall_fscore_support(y_test, rf_preds, average='macro', zero_division=0)
    logger.info("Random Forest -> Acc: %.4f, Macro Prec: %.4f, Macro Recall: %.4f, Macro F1: %.4f", rf_acc, rf_p, rf_r, rf_f1)

    # Feature Importance Plot
    fig, ax = plt.subplots(figsize=(10, 6), facecolor='#111827')
    ax.set_facecolor('#1f2937')
    feat_imp = pd.Series(rf_clf.feature_importances_, index=FEATURE_COLS).sort_values(ascending=False).head(20)
    bars = ax.barh(feat_imp.index[::-1], feat_imp.values[::-1], color='#38bdf8', edgecolor='#0284c7')
    ax.set_title('Random Forest — Top 20 Most Discriminative Features', color='#f8fafc', fontsize=12, weight='bold')
    ax.set_xlabel('Mean Decrease in Impurity', color='#94a3b8', fontsize=10)
    plt.tight_layout()
    plt.savefig(os.path.join(reports_dir, '04_rf_feature_importance.png'), dpi=150, facecolor='#111827')
    plt.close()

    # 3. K-Means Clustering
    logger.info("Fitting PCA & K-Means Clustering...")
    pca = PCA(n_components=10, random_state=42)
    X_train_pca = pca.fit_transform(X_train_scaled)
    X_test_pca = pca.transform(X_test_scaled)

    kmeans = KMeans(n_clusters=8, random_state=42, n_init=10)
    kmeans.fit(X_train_pca)
    km_test_clusters = kmeans.predict(X_test_pca)

    # Cluster visualization in 2D
    fig, ax = plt.subplots(figsize=(8, 5), facecolor='#111827')
    ax.set_facecolor('#1f2937')
    scatter = ax.scatter(
        X_test_pca[:2500, 0], X_test_pca[:2500, 1],
        c=km_test_clusters[:2500], cmap='tab10', alpha=0.6, s=12
    )
    ax.set_title('K-Means Clusters in 2D PCA Latent Space', color='#f8fafc', fontsize=12, weight='bold')
    ax.set_xlabel('Principal Component 1', color='#94a3b8', fontsize=10)
    ax.set_ylabel('Principal Component 2', color='#94a3b8', fontsize=10)
    plt.colorbar(scatter, ax=ax, label='Cluster ID')
    plt.tight_layout()
    plt.savefig(os.path.join(reports_dir, '04_kmeans_clusters_pca.png'), dpi=150, facecolor='#111827')
    plt.close()

    # 4. Save Artifacts
    logger.info("Serializing models to %s", models_dir)
    joblib.dump(scaler, os.path.join(models_dir, 'scaler.joblib'))
    joblib.dump(iso_forest, os.path.join(models_dir, 'isolation_forest.joblib'))
    joblib.dump(rf_clf, os.path.join(models_dir, 'random_forest.joblib'))
    joblib.dump(pca, os.path.join(models_dir, 'pca.joblib'))
    joblib.dump(kmeans, os.path.join(models_dir, 'kmeans.joblib'))
    joblib.dump(FEATURE_COLS, os.path.join(models_dir, 'feature_columns.joblib'))

    # 5. Generate Scored Dataset for Power BI Dashboard
    logger.info("Generating scored dataset for Power BI Threat Intelligence Dashboard...")
    X_full_scaled = scaler.transform(X_imputed)
    df_sample['anomaly_score'] = iso_forest.decision_function(X_full_scaled)
    df_sample['is_anomaly_predicted'] = np.where(iso_forest.predict(X_full_scaled) == -1, 1, 0)
    df_sample['predicted_attack_label'] = rf_clf.predict(X_full_scaled)
    df_sample['cluster_id'] = kmeans.predict(pca.transform(X_full_scaled))

    def categorize_risk(row):
        is_anom = row['is_anomaly_predicted'] == 1
        is_att = row['predicted_attack_label'] != 'BENIGN'
        if is_anom and is_att:
            return 'CRITICAL'
        elif is_att:
            return 'HIGH'
        elif is_anom:
            return 'MEDIUM'
        return 'LOW'

    df_sample['risk_tier'] = df_sample.apply(categorize_risk, axis=1)

    export_parquet = os.path.join(processed_dir, 'ml_predictions.parquet')
    export_csv = os.path.join(processed_dir, 'ml_predictions_sample.csv')

    df_sample.to_parquet(export_parquet, index=False)
    # Save a lighter 10,000-row sample for quick Power BI Desktop imports
    df_sample.head(10000).to_csv(export_csv, index=False)
    logger.info("Saved ML predictions to %s and %s", export_parquet, export_csv)

    metrics_summary = {
        "isolation_forest": {"accuracy": float(iso_acc), "precision": float(iso_p), "recall": float(iso_r), "f1": float(iso_f1)},
        "random_forest": {"accuracy": float(rf_acc), "macro_precision": float(rf_p), "macro_recall": float(rf_r), "macro_f1": float(rf_f1)},
        "kmeans": {"clusters": 8, "pca_variance_ratio": float(pca.explained_variance_ratio_.sum())}
    }
    logger.info("Model Training Pipeline Complete: %s", metrics_summary)
    return metrics_summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train ML models for Cybersecurity Analytics")
    parser.add_argument("--parquet", default="data/processed/flows_clean.parquet", help="Path to cleaned parquet")
    parser.add_argument("--sample-size", type=int, default=150000, help="Stratified sample size")
    args = parser.parse_args()
    train_pipeline(parquet_path=args.parquet, sample_size=args.sample_size)

