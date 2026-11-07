"""scripts/generate_all_eda_figures.py
Generates high-resolution EDA figures for the technical report, notebooks, and dashboards.
"""

import os
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

plt.style.use('dark_background')
plt.rcParams['font.sans-serif'] = 'Segoe UI'
plt.rcParams['font.family'] = 'sans-serif'

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_PROCESSED = os.path.join(ROOT_DIR, 'data', 'processed')
REPORTS_DIR = os.path.join(ROOT_DIR, 'reports', 'figures')
os.makedirs(REPORTS_DIR, exist_ok=True)

print(f"Reading data from {DATA_PROCESSED}...")
parquet_path = os.path.join(DATA_PROCESSED, 'flows_clean.parquet')

# 1. Load subset for high-level distribution plots
df_meta = pd.read_parquet(
    parquet_path,
    columns=['observed_label', 'attack_family', 'is_attack', 'capture_date', 'destination_port', 'duration_ms', 'total_bytes', 'bytes_per_second']
)
print("Metadata subset loaded.")

# --- Figure 1: Label Distribution (Log scale or clean bar) ---
fig, ax = plt.subplots(figsize=(12, 6), facecolor='#111827')
ax.set_facecolor('#1f2937')
label_counts = df_meta['observed_label'].value_counts()
colors = ['#10b981' if lbl == 'BENIGN' else '#ef4444' for lbl in label_counts.index]
bars = ax.barh(label_counts.index[::-1], label_counts.values[::-1], color=colors[::-1], edgecolor='#374151')

ax.set_title('Complete Dataset Traffic Distribution by Attack Label', fontsize=14, color='#f8fafc', weight='bold')
ax.set_xlabel('Number of Flow Records (Log Scale)', fontsize=11, color='#94a3b8')
ax.set_xscale('log')
ax.tick_params(colors='#e2e8f0', labelsize=10)

for bar in bars:
    w = bar.get_width()
    ax.text(w * 1.1, bar.get_y() + bar.get_height()/2, f"{int(w):,}",
            ha='left', va='center', color='#f8fafc', fontsize=9, weight='bold')

plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, '01_label_distribution.png'), dpi=150, facecolor='#111827')
plt.close()
print("Saved 01_label_distribution.png")

# --- Figure 2: Attack Family Distribution (Attacks Only) ---
fig, ax = plt.subplots(figsize=(10, 5), facecolor='#111827')
ax.set_facecolor('#1f2937')
family_counts = df_meta[df_meta['is_attack']]['attack_family'].value_counts()
bars = ax.bar(family_counts.index, family_counts.values, color='#f43f5e', edgecolor='#be123c')

ax.set_title('Threat Hierarchy: Attack Volume by Threat Family', fontsize=13, color='#f8fafc', weight='bold')
ax.set_ylabel('Number of Attack Flows', fontsize=11, color='#94a3b8')
ax.tick_params(colors='#e2e8f0', labelsize=10, rotation=25)

for bar in bars:
    y = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2, y + 2500, f"{int(y):,}",
            ha='center', va='bottom', color='#f43f5e', fontsize=9, weight='bold')

ax.set_ylim(0, max(family_counts.values) * 1.15)
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, '01_attack_family_breakdown.png'), dpi=150, facecolor='#111827')
plt.close()
print("Saved 01_attack_family_breakdown.png")

# --- Figure 3: Daily Timeline Trends ---
fig, ax = plt.subplots(figsize=(11, 5), facecolor='#111827')
ax.set_facecolor('#1f2937')
daily_summary = df_meta.groupby([df_meta['capture_date'].dt.date, 'is_attack']).size().unstack(fill_value=0)
daily_summary.columns = ['Benign Traffic', 'Malicious Traffic']

dates = [d.strftime('%a %d %b') for d in daily_summary.index]
x = np.arange(len(dates))
width = 0.35

ax.bar(x - width/2, daily_summary['Benign Traffic'], width, label='Benign Traffic', color='#0ea5e9')
ax.bar(x + width/2, daily_summary['Malicious Traffic'], width, label='Malicious Traffic', color='#f43f5e')

ax.set_title('Daily Network Event Volume: Benign vs Cyber Attack Traffic', fontsize=13, color='#f8fafc', weight='bold')
ax.set_xticks(x)
ax.set_xticklabels(dates, color='#e2e8f0', fontsize=10)
ax.tick_params(colors='#e2e8f0', labelsize=10)
ax.legend(facecolor='#1f2937', edgecolor='#374151', labelcolor='#e2e8f0')

plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, '03_daily_attack_trends.png'), dpi=150, facecolor='#111827')
plt.close()
print("Saved 03_daily_attack_trends.png")

# --- Figure 4: Top Targeted Destination Ports ---
fig, ax = plt.subplots(figsize=(10, 5), facecolor='#111827')
ax.set_facecolor('#1f2937')
top_ports = df_meta['destination_port'].value_counts().head(12)
port_names = {
    53: 'Port 53 (DNS)',
    80: 'Port 80 (HTTP)',
    443: 'Port 443 (HTTPS)',
    123: 'Port 123 (NTP)',
    22: 'Port 22 (SSH)',
    21: 'Port 21 (FTP)',
    389: 'Port 389 (LDAP)',
    88: 'Port 88 (Kerberos)',
    137: 'Port 137 (NetBIOS)',
    465: 'Port 465 (SMTPS)',
    8080: 'Port 8080 (HTTP Proxy)',
    139: 'Port 139 (NetBIOS)'
}
labels = [port_names.get(p, f"Port {p}") for p in top_ports.index]
bars = ax.barh(labels[::-1], top_ports.values[::-1], color='#38bdf8', edgecolor='#0284c7')
ax.set_title('Top 12 Targeted Destination Ports in Enterprise Perimeter', fontsize=13, color='#f8fafc', weight='bold')
ax.set_xlabel('Flow Count (Log Scale)', fontsize=11, color='#94a3b8')
ax.set_xscale('log')
ax.tick_params(colors='#e2e8f0', labelsize=10)

plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, '03_top_targeted_ports.png'), dpi=150, facecolor='#111827')
plt.close()
print("Saved 03_top_targeted_ports.png")

# --- Figure 5: Correlation Heatmap (Selected Features on 50k sample) ---
sample_corr_cols = [
    'flow_duration', 'total_fwd_packets', 'total_backward_packets',
    'total_length_of_fwd_packets', 'total_length_of_bwd_packets',
    'fwd_packet_length_mean', 'bwd_packet_length_mean',
    'duration_ms', 'total_packets', 'total_bytes',
    'bytes_per_packet', 'bytes_per_second', 'packets_per_second', 'forward_byte_ratio'
]
df_corr_sample = pd.read_parquet(parquet_path, columns=sample_corr_cols).sample(50000, random_state=42)
corr_matrix = df_corr_sample.corr()

fig, ax = plt.subplots(figsize=(11, 9), facecolor='#111827')
ax.set_facecolor('#1f2937')
mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
sns.heatmap(corr_matrix, mask=mask, cmap='mako', vmin=-1, vmax=1, annot=True, fmt='.2f',
            annot_kws={'size': 8}, ax=ax, cbar_kws={'label': 'Pearson Correlation'})
ax.set_title('Key Network Flow Feature Correlation Matrix (Triangular)', fontsize=13, color='#f8fafc', weight='bold')
ax.tick_params(colors='#e2e8f0', labelsize=9)
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, '03_correlation_matrix.png'), dpi=150, facecolor='#111827')
plt.close()
print("Saved 03_correlation_matrix.png")

# --- Figure 6: Duplicates Removed from Run Metadata ---
run_json_path = os.path.join(DATA_PROCESSED, 'flows_clean.run.json')
if os.path.exists(run_json_path):
    with open(run_json_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    files = [f.get('file', '').replace('\\\\', '/').split('/')[-1] for f in meta.get('files_processed', [])]
    dupes = [f.get('duplicates_removed', 0) for f in meta.get('files_processed', [])]

    fig, ax = plt.subplots(figsize=(11, 5), facecolor='#111827')
    ax.set_facecolor('#1f2937')
    ax.barh(files, dupes, color='#38bdf8', edgecolor='#0284c7')
    ax.set_title('Data Cleaning Audit: Duplicates Removed Across Capture Files', fontsize=13, color='#f8fafc', weight='bold')
    ax.set_xlabel('Removed Duplicate Rows', color='#94a3b8', fontsize=10)
    ax.tick_params(colors='#e2e8f0', labelsize=9)
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, '02_duplicates_per_file.png'), dpi=150, facecolor='#111827')
    plt.close()
    print("Saved 02_duplicates_per_file.png")

print("All figures successfully generated and saved to reports/figures/!")

