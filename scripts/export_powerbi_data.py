"""scripts/export_powerbi_data.py
Exports high-performance, structured analytical datasets for Power BI Desktop.
Produces both aggregated summary tables and a clean sampled fact table.
"""

import os
import pandas as pd
import numpy as np

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_PROCESSED = os.path.join(ROOT_DIR, 'data', 'processed')

print("Loading cleaned dataset for Power BI optimization...")
parquet_path = os.path.join(DATA_PROCESSED, 'flows_clean.parquet')

cols = [
    'capture_date', 'destination_port', 'duration_ms', 'total_packets', 'total_bytes',
    'bytes_per_second', 'packets_per_second', 'forward_byte_ratio', 'total_flags',
    'observed_label', 'attack_family', 'is_attack'
]

df = pd.read_parquet(parquet_path, columns=cols)
print(f"Loaded {len(df):,} rows.")

# 1. Export Pre-aggregated Daily & Family Summary
print("Generating Daily & Attack Family Aggregations...")
daily_summary = df.groupby(['capture_date', 'observed_label', 'attack_family', 'is_attack']).agg(
    flow_count=('destination_port', 'count'),
    total_bytes=('total_bytes', 'sum'),
    avg_duration_ms=('duration_ms', 'mean'),
    avg_bytes_per_sec=('bytes_per_second', 'mean')
).reset_index()

daily_csv = os.path.join(DATA_PROCESSED, 'powerbi_daily_attack_summary.csv')
daily_summary.to_csv(daily_csv, index=False)
print(f"Saved {daily_csv} ({len(daily_summary)} rows)")

# 2. Export Port & Threat Matrix Summary
print("Generating Port-level Threat Matrix...")
top_ports = df['destination_port'].value_counts().head(50).index.tolist()
port_df = df[df['destination_port'].isin(top_ports)]

port_summary = port_df.groupby(['destination_port', 'observed_label', 'attack_family', 'is_attack']).agg(
    flow_count=('duration_ms', 'count'),
    total_bytes=('total_bytes', 'sum'),
    avg_packets=('total_packets', 'mean')
).reset_index()

port_csv = os.path.join(DATA_PROCESSED, 'powerbi_port_threat_matrix.csv')
port_summary.to_csv(port_csv, index=False)
print(f"Saved {port_csv} ({len(port_summary)} rows)")

# 3. Export Representative Fact Table Sample (50,000 stratified rows) for Interactive Visuals
print("Generating Stratified Fact Sample for Power BI...")
stratified_sample = df.groupby('observed_label', group_keys=False).apply(
    lambda g: g.sample(min(len(g), max(10, int(len(g) * (50000 / len(df))))), random_state=42)
).reset_index(drop=True)

fact_csv = os.path.join(DATA_PROCESSED, 'powerbi_network_flows_sample.csv')
stratified_sample.to_csv(fact_csv, index=False)
print(f"Saved {fact_csv} ({len(stratified_sample)} rows)")

print("All Power BI datasets ready!")

