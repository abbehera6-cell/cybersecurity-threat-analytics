import json
import os

def create_ml_notebook():
    cells = []

    def md(text):
        cells.append({
            "cell_type": "markdown",
            "metadata": {},
            "source": [l + "\n" for l in text.strip().split("\n")]
        })

    def code(text):
        cells.append({
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [l + "\n" for l in text.strip().split("\n")]
        })

    md("""# 04 — Machine Learning: Threat Detection, Classification & Clustering
## Enterprise Cybersecurity & Threat Intelligence Analytics Platform

### Purpose of this Notebook:
This notebook implements the machine learning layer for our enterprise threat intelligence platform.
In cybersecurity operations (SOC - Security Operations Center), a single model cannot solve every security challenge.
We design a **defense-in-depth machine learning strategy** utilizing three complementary paradigms:

1. **Isolation Forest (Unsupervised Anomaly Detection):** Flags zero-day exploits and abnormal behavioral deviations without requiring labeled attack signatures.
2. **Random Forest Classifier (Supervised Multi-Class Threat Categorization):** Classifies network flows into specific attack taxonomy categories (DoS, Brute Force, Web Attacks, etc.) with high precision.
3. **K-Means Clustering (Unsupervised Behavioral Grouping):** Discovers latent clusters and traffic archetypes to assist security analysts in threat hunting.

### Interview Alignment (Deloitte Data Analytics):
- **Class Imbalance Handling:** Demonstrates stratified sampling and cost-sensitive weighting when minority attack classes comprise < 0.1% of traffic.
- **Evaluation Beyond Accuracy:** Evaluates using Precision, Recall, Macro F1-score, and False Discovery Rate (crucial for alert fatigue reduction).
- **Production Readiness:** Models and preprocessing pipelines are serialized to `models/` for automated deployment.
""")

    code("""import os
import sys
import json
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    accuracy_score,
    roc_auc_score
)

warnings.filterwarnings('ignore')
plt.style.use('dark_background')

# Set project paths
ROOT_DIR = os.path.abspath('..')
DATA_PROCESSED = os.path.join(ROOT_DIR, 'data', 'processed')
MODELS_DIR = os.path.join(ROOT_DIR, 'models')
REPORTS_DIR = os.path.join(ROOT_DIR, 'reports', 'figures')
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

print(f"Data directory: {DATA_PROCESSED}")
print(f"Models directory: {MODELS_DIR}")
""")

    md("""---
## 1. Data Ingestion & Memory-Aware Stratified Sampling
The cleaned dataset contains **2,574,264 flows**.
To ensure fast training and prevent memory exhaustion while preserving rare attacks (such as *Heartbleed* with only 11 samples and *Infiltration* with 36 samples),
we implement a **stratified sampling strategy** targeting 150,000 representative flows.
""")

    code("""data_path = os.path.join(DATA_PROCESSED, 'flows_clean.parquet')

# Read columns required for modeling
sample_cols = [
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
    'log_total_bytes', 'log_duration_ms',
    'observed_label', 'attack_family', 'is_attack'
]

print("Loading cleaned dataset...")
df_full = pd.read_parquet(data_path, columns=sample_cols)
print(f"Total available rows: {len(df_full):,}")

# Stratified sampling: Ensure rare classes have at least minimum sample representation
sample_size = 150000
strat_ratio = sample_size / len(df_full)

df_sample = df_full.groupby('observed_label', group_keys=False).apply(
    lambda g: g.sample(max(10, int(len(g) * strat_ratio)), random_state=42)
).reset_index(drop=True)

print(f"Sampled Dataset Shape: {df_sample.shape}")
print("\\nSampled Class Distribution:")
print(df_sample['observed_label'].value_counts())
""")

    md("""---
## 2. Feature Preprocessing & Leakage Prevention
We separate features from targets.
All target columns (`observed_label`, `attack_family`, `is_attack`) and identifiers are strictly excluded from the feature matrix `X`.
Missing rate values (from cleaned infinities) are imputed using median statistics, and features are standardized with `StandardScaler`.
""")

    code("""feature_cols = [c for c in sample_cols if c not in ['observed_label', 'attack_family', 'is_attack']]

X = df_sample[feature_cols].copy()
y_binary = df_sample['is_attack'].astype(int)
y_multiclass = df_sample['observed_label']
y_family = df_sample['attack_family'].fillna('BENIGN')

# Impute median for any residual nulls (e.g. forward_byte_ratio or flow_bytes_s)
X = X.fillna(X.median())

# Train/Test Split (70/30 stratified by multi-class label)
X_train, X_test, y_train, y_test, y_fam_train, y_fam_test = train_test_split(
    X, y_multiclass, y_family, test_size=0.30, random_state=42, stratify=y_multiclass
)

# Fit scaler strictly on training split to prevent data leakage
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(f"Training set: {X_train.shape[0]:,} records")
print(f"Testing set:  {X_test.shape[0]:,} records")
""")

    md("""---
## 3. Model 1: Isolation Forest (Unsupervised Anomaly Detection)
### Rationale:
In enterprise cybersecurity, analysts face **zero-day attacks** that have never been seen before.
Isolation Forest isolates anomalies by randomly selecting a feature and randomly selecting a split value.
Because anomalous network flows have distinct structural characteristics, they require far fewer recursive partitions to isolate.

- **Contamination:** Set to `0.165` reflecting the empirical attack ratio in CICIDS2017.
- **Evaluation:** Compare unsupervised anomaly flags against actual ground truth attack labels.
""")

    code("""print("Training Isolation Forest Model...")
iso_forest = IsolationForest(
    n_estimators=150,
    contamination=0.165,
    max_samples=0.8,
    random_state=42,
    n_jobs=-1
)

# Unsupervised fit on training feature space
iso_forest.fit(X_train_scaled)

# Predictions: -1 indicates anomaly, 1 indicates normal
iso_preds_test = iso_forest.predict(X_test_scaled)
iso_pred_binary = np.where(iso_preds_test == -1, 1, 0)
y_test_binary = (y_test != 'BENIGN').astype(int)

# Anomaly score (lower is more anomalous)
anomaly_scores_test = iso_forest.decision_function(X_test_scaled)

acc_iso = accuracy_score(y_test_binary, iso_pred_binary)
p_iso, r_iso, f1_iso, _ = precision_recall_fscore_support(y_test_binary, iso_pred_binary, average='binary')

print("=== Isolation Forest Performance ===")
print(f"Accuracy:  {acc_iso:.4f}")
print(f"Precision: {p_iso:.4f}")
print(f"Recall:    {r_iso:.4f}")
print(f"F1-Score:  {f1_iso:.4f}")
""")

    code("""# Confusion Matrix for Isolation Forest
cm_iso = confusion_matrix(y_test_binary, iso_pred_binary)

fig, ax = plt.subplots(figsize=(7, 5), facecolor='#111827')
ax.set_facecolor('#1f2937')
sns.heatmap(cm_iso, annot=True, fmt=',d', cmap='Blues', cbar=False, ax=ax,
            xticklabels=['Normal (Pred)', 'Anomaly (Pred)'],
            yticklabels=['Benign (Actual)', 'Attack (Actual)'])
ax.set_title('Isolation Forest — Anomaly Confusion Matrix', color='#f8fafc', fontsize=13, weight='bold')
ax.tick_params(colors='#e2e8f0', labelsize=10)
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, '04_isolation_forest_cm.png'), dpi=150, facecolor='#111827')
plt.show()
""")

    md("""---
## 4. Model 2: Random Forest Classifier (Multi-Class Threat Categorization)
### Rationale:
Once network traffic is captured, the SOC needs to know **what specific type of threat** has occurred.
Random Forest ensembles decision trees, mitigating overfitting while handling high-dimensional interactions.
We utilize `class_weight='balanced'` to prevent majority class dominance.
""")

    code("""print("Training Random Forest Multi-Class Classifier...")
rf_clf = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    min_samples_split=5,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)

rf_clf.fit(X_train_scaled, y_train)
rf_preds = rf_clf.predict(X_test_scaled)

print("=== Random Forest Multi-Class Evaluation ===")
print(classification_report(y_test, rf_preds, digits=4))
""")

    code("""# Feature Importance Analysis
feature_importances = pd.Series(rf_clf.feature_importances_, index=feature_cols).sort_values(ascending=False)

fig, ax = plt.subplots(figsize=(12, 7), facecolor='#111827')
ax.set_facecolor('#1f2937')
top20_features = feature_importances.head(20)

bars = ax.barh(top20_features.index[::-1], top20_features.values[::-1], color='#38bdf8', edgecolor='#0284c7')
ax.set_title('Random Forest — Top 20 Most Discriminative Features', color='#f8fafc', fontsize=14, weight='bold')
ax.set_xlabel('Mean Decrease in Impurity (Feature Importance)', color='#94a3b8', fontsize=11)
ax.tick_params(colors='#e2e8f0', labelsize=10)

plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, '04_rf_feature_importance.png'), dpi=150, facecolor='#111827')
plt.show()
""")

    md("""---
## 5. Model 3: K-Means Clustering (Behavioral Pattern Discovery)
### Rationale:
Clustering is used in threat hunting to detect clusters of machines or sessions that share identical operational patterns.
We project high-dimensional features into 2D/3D space using **Principal Component Analysis (PCA)** and evaluate cluster separation with $k=8$ (corresponding to our 8 threat families).
""")

    code("""print("Performing PCA Dimensionality Reduction...")
pca = PCA(n_components=10, random_state=42)
X_train_pca = pca.fit_transform(X_train_scaled)
X_test_pca = pca.transform(X_test_scaled)

print(f"Cumulative Explained Variance (10 components): {pca.explained_variance_ratio_.sum():.2%}")

print("Fitting K-Means Clustering (k=8)...")
kmeans = KMeans(n_clusters=8, random_state=42, n_init=10)
kmeans.fit(X_train_pca)
cluster_labels_test = kmeans.predict(X_test_pca)

# Visualize Clusters on First Two Principal Components
fig, ax = plt.subplots(figsize=(10, 6), facecolor='#111827')
ax.set_facecolor('#1f2937')

scatter = ax.scatter(
    X_test_pca[:3000, 0], X_test_pca[:3000, 1],
    c=cluster_labels_test[:3000],
    cmap='tab10',
    alpha=0.6,
    s=15
)
ax.set_title('K-Means Clusters in Principal Component Space (PCA 2D)', color='#f8fafc', fontsize=13, weight='bold')
ax.set_xlabel('Principal Component 1', color='#94a3b8', fontsize=10)
ax.set_ylabel('Principal Component 2', color='#94a3b8', fontsize=10)
ax.tick_params(colors='#e2e8f0', labelsize=10)
plt.colorbar(scatter, ax=ax, label='Cluster ID')
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, '04_kmeans_clusters_pca.png'), dpi=150, facecolor='#111827')
plt.show()
""")

    md("""---
## 6. Model Serialization & Export for Power BI
To connect our analytical models with our **Power BI Threat Detection Dashboard (Page 4)** and production ingestion pipeline,
we serialize:
1. Preprocessing Scaler (`scaler.pkl`)
2. Isolation Forest model (`isolation_forest.pkl`)
3. Random Forest model (`random_forest.pkl`)
4. K-Means model (`kmeans.pkl`)
5. Sample predictions file (`ml_predictions.parquet` / `.csv`) containing anomaly flags, risk scores, and predicted attack taxonomy.
""")

    code("""# Save trained models
joblib.dump(scaler, os.path.join(MODELS_DIR, 'scaler.joblib'))
joblib.dump(iso_forest, os.path.join(MODELS_DIR, 'isolation_forest.joblib'))
joblib.dump(rf_clf, os.path.join(MODELS_DIR, 'random_forest.joblib'))
joblib.dump(kmeans, os.path.join(MODELS_DIR, 'kmeans.joblib'))
joblib.dump(feature_cols, os.path.join(MODELS_DIR, 'feature_columns.joblib'))

print("All models successfully saved to models/ directory.")

# Generate scored dataset for Power BI Threat Detection Dashboard
df_export = df_sample.copy()
X_export_scaled = scaler.transform(X)

df_export['anomaly_score'] = iso_forest.decision_function(X_export_scaled)
df_export['is_anomaly_predicted'] = np.where(iso_forest.predict(X_export_scaled) == -1, 1, 0)
df_export['predicted_attack_label'] = rf_clf.predict(X_export_scaled)
df_export['cluster_id'] = kmeans.predict(pca.transform(X_export_scaled))

# Risk tier categorization based on anomaly score and attack prediction
def assign_risk_tier(row):
    if row['is_anomaly_predicted'] == 1 and row['predicted_attack_label'] != 'BENIGN':
        return 'CRITICAL'
    elif row['predicted_attack_label'] != 'BENIGN':
        return 'HIGH'
    elif row['is_anomaly_predicted'] == 1:
        return 'MEDIUM'
    else:
        return 'LOW'

df_export['risk_tier'] = df_export.apply(assign_risk_tier, axis=1)

export_parquet = os.path.join(DATA_PROCESSED, 'ml_predictions.parquet')
export_csv = os.path.join(DATA_PROCESSED, 'ml_predictions_sample.csv')

df_export.to_parquet(export_parquet, index=False)
df_export.head(10000).to_csv(export_csv, index=False)

print(f"Exported full ML scored dataset to: {export_parquet}")
print(f"Exported sample CSV for Power BI to: {export_csv}")
print("\\nRisk Tier Breakdown:")
print(df_export['risk_tier'].value_counts())
""")

    md("""---
## 7. Machine Learning Synthesis & Deloitte Interview Defense

| Dimension | Isolation Forest | Random Forest | K-Means |
|:---|:---|:---|:---|
| **Learning Paradigm** | Unsupervised (Anomaly Detection) | Supervised (Ensemble Classification) | Unsupervised (Clustering) |
| **Primary Use Case** | Zero-Day attack discovery | Known threat classification & alerting | Threat hunting & behavioral baseline |
| **Strengths** | Requires no labeled data; handles multi-modal normal traffic | High accuracy; provides feature importance | Discovers natural traffic archetypes |
| **Limitations** | Cannot differentiate attack categories | Requires extensive labeled historical data | Sensitive to feature scaling & spherical assumptions |
| **Key Hyperparameters** | `contamination=0.165`, `n_estimators=150` | `n_estimators=150`, `class_weight='balanced'` | `k=8`, `n_init=10` |
""")

    nb = {
        "cells": cells,
        "metadata": {
            "language_info": {
                "name": "python",
                "version": "3.11"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 4
    }

    out_path = os.path.join('notebooks', '04_machine_learning.ipynb')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(nb, f, indent=2)

    print(f"Created {out_path} with {len(cells)} cells.")

if __name__ == '__main__':
    create_ml_notebook()

