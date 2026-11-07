"""src/app.py
Enterprise Cybersecurity & Threat Intelligence Analytics Platform
Interactive Streamlit Security Operations Center (SOC) Web Application.
Run with: streamlit run src/app.py
"""

import os
import sys
import numpy as np
import pandas as pd
import streamlit as st
import joblib

# Set page configuration
st.set_page_config(
    page_title="Cyber Threat Intelligence SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Dark Theme Styling
st.markdown("""
<style>
    .main { background-color: #0b0f19; color: #f8fafc; }
    .stMetric { background-color: #1f2937; padding: 15px; border-radius: 8px; border-left: 4px solid #38bdf8; }
    .risk-critical { background-color: #ef4444; color: white; padding: 4px 10px; border-radius: 4px; font-weight: bold; }
    .risk-high { background-color: #f97316; color: white; padding: 4px 10px; border-radius: 4px; font-weight: bold; }
    .risk-medium { background-color: #eab308; color: black; padding: 4px 10px; border-radius: 4px; font-weight: bold; }
    .risk-low { background-color: #10b981; color: white; padding: 4px 10px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(ROOT_DIR, 'data', 'processed')
MODELS_DIR = os.path.join(ROOT_DIR, 'models')


@st.cache_data
def load_datasets():
    csv_path = os.path.join(DATA_DIR, 'powerbi_network_flows_sample.csv')
    ml_path = os.path.join(DATA_DIR, 'ml_predictions_sample.csv')
    df_flows = pd.read_csv(csv_path) if os.path.exists(csv_path) else pd.DataFrame()
    df_ml = pd.read_csv(ml_path) if os.path.exists(ml_path) else pd.DataFrame()
    return df_flows, df_ml


@st.cache_resource
def load_ml_models():
    scaler_path = os.path.join(MODELS_DIR, 'scaler.joblib')
    iso_path = os.path.join(MODELS_DIR, 'isolation_forest.joblib')
    rf_path = os.path.join(MODELS_DIR, 'random_forest.joblib')
    cols_path = os.path.join(MODELS_DIR, 'feature_columns.joblib')

    scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None
    iso_forest = joblib.load(iso_path) if os.path.exists(iso_path) else None
    rf_clf = joblib.load(rf_path) if os.path.exists(rf_path) else None
    feature_cols = joblib.load(cols_path) if os.path.exists(cols_path) else []
    return scaler, iso_forest, rf_clf, feature_cols


df_flows, df_ml = load_datasets()
scaler, iso_forest, rf_clf, feature_cols = load_ml_models()

# Sidebar Navigation
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("Threat Intelligence SOC")
st.sidebar.caption("Enterprise Cybersecurity Platform")

view_mode = st.sidebar.radio(
    "Navigation Console:",
    [
        "📊 1. Security Overview",
        "🎯 2. Attack Vector Analytics",
        "🤖 3. Live Threat Predictor",
        "🔍 4. Incident Log Explorer"
    ]
)

st.sidebar.markdown("---")
st.sidebar.info("""
**Platform Specifications:**
- **Source:** CICIDS2017 Benchmark
- **Total Processed Flows:** 2,574,264
- **ETL:** Deduplicated, Infs Handled
- **Models:** Random Forest (99.7% Acc) & Isolation Forest
""")

# -------------------------------------------------------------
# VIEW 1: SECURITY OVERVIEW
# -------------------------------------------------------------
if view_mode == "📊 1. Security Overview":
    st.title("🛡️ Enterprise Threat Intelligence Posture")
    st.subheader("Perimeter Telemetry & Incident Overview")

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Events Ingested", "2,574,264")
    with col2:
        st.metric("Confirmed Malicious", "425,878", delta="16.54%", delta_color="inverse")
    with col3:
        st.metric("Benign Traffic", "2,148,386", delta="83.46%")
    with col4:
        st.metric("Active Threat Families", "8 Families")
    with col5:
        st.metric("Model Concordance", "99.72%", delta="Optimal")

    st.markdown("---")
    c1, c2 = st.columns([1, 1])

    with c1:
        st.markdown("### 🚨 Attack Family Volume Distribution")
        if not df_flows.empty:
            family_counts = df_flows[df_flows['is_attack']]['attack_family'].value_counts()
            st.bar_chart(family_counts, color="#f43f5e")

    with c2:
        st.markdown("### 🌐 Daily Traffic Timeline")
        if not df_flows.empty:
            daily_stats = df_flows.groupby(['capture_date', 'is_attack']).size().unstack(fill_value=0)
            daily_stats.columns = ['Benign Traffic', 'Malicious Traffic']
            st.line_chart(daily_stats)

# -------------------------------------------------------------
# VIEW 2: ATTACK VECTOR ANALYTICS
# -------------------------------------------------------------
elif view_mode == "🎯 2. Attack Vector Analytics":
    st.title("🎯 Attack Vector & Targeted Port Analytics")
    st.caption("Deep-dive into transport-layer exploit vectors")

    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("### 🚪 Most Frequently Targeted Ports")
        if not df_flows.empty:
            port_counts = df_flows['destination_port'].value_counts().head(10)
            st.bar_chart(port_counts, color="#38bdf8")

    with col2:
        st.markdown("### ⚠️ Port Risk Breakdown")
        port_legend = pd.DataFrame({
            "Port": [80, 443, 53, 22, 21],
            "Service": ["HTTP (Web)", "HTTPS (Encrypted)", "DNS (Resolver)", "SSH (Remote Admin)", "FTP (File Transfer)"],
            "Dominant Threat": ["DoS Hulk, Web Attacks", "Encrypted Exfiltration", "DNS Flooding", "SSH-Patator (Brute Force)", "FTP-Patator"]
        })
        st.dataframe(port_legend, hide_index=True, use_container_width=True)

    st.markdown("---")
    st.markdown("### 🔬 Attack Duration vs Bandwidth Dispersion")
    if not df_flows.empty:
        sample_scatter = df_flows[df_flows['is_attack']].sample(min(1000, len(df_flows)))
        st.scatter_chart(
            sample_scatter,
            x='duration_ms',
            y='bytes_per_second',
            color='attack_family',
            size='total_packets'
        )

# -------------------------------------------------------------
# VIEW 3: LIVE THREAT PREDICTOR (INTERACTIVE ML SANDBOX)
# -------------------------------------------------------------
elif view_mode == "🤖 3. Live Threat Predictor":
    st.title("🤖 Interactive ML Threat Detection Sandbox")
    st.write("Input simulated network connection parameters to evaluate real-time scoring across our dual-model inference pipeline.")

    with st.form("threat_predictor_form"):
        col1, col2, col3 = st.columns(3)
        with col1:
            port_input = st.number_input("Destination Port", min_value=0, max_value=65535, value=80)
            duration_input = st.number_input("Flow Duration (µs)", min_value=1, value=120000)
            fwd_pkts = st.number_input("Total Forward Packets", min_value=1, value=15)
        with col2:
            bwd_pkts = st.number_input("Total Backward Packets", min_value=0, value=25)
            fwd_len_mean = st.number_input("Fwd Packet Length Mean", min_value=0.0, value=350.0)
            bwd_len_mean = st.number_input("Bwd Packet Length Mean", min_value=0.0, value=750.0)
        with col3:
            flow_bytes_s = st.number_input("Flow Bytes / sec", min_value=0.0, value=50000.0)
            flow_pkts_s = st.number_input("Flow Packets / sec", min_value=0.0, value=350.0)
            flags_count = st.number_input("TCP Flags Active", min_value=0, value=4)

        submit_btn = st.form_submit_button("⚡ Analyze Threat Signature", use_container_width=True)

    if submit_btn:
        if scaler and iso_forest and rf_clf and feature_cols:
            # Build feature vector
            feat_dict = {col: 0.0 for col in feature_cols}
            feat_dict['destination_port'] = float(port_input)
            feat_dict['flow_duration'] = float(duration_input)
            feat_dict['total_fwd_packets'] = float(fwd_pkts)
            feat_dict['total_backward_packets'] = float(bwd_pkts)
            feat_dict['fwd_packet_length_mean'] = float(fwd_len_mean)
            feat_dict['bwd_packet_length_mean'] = float(bwd_len_mean)
            feat_dict['flow_bytes_s'] = float(flow_bytes_s)
            feat_dict['flow_packets_s'] = float(flow_pkts_s)
            feat_dict['total_packets'] = float(fwd_pkts + bwd_pkts)
            feat_dict['total_flags'] = float(flags_count)
            feat_dict['duration_ms'] = float(duration_input / 1000.0)
            feat_dict['log_duration_ms'] = float(np.log1p(duration_input / 1000.0))

            X_in = pd.DataFrame([feat_dict])[feature_cols]
            X_scaled = scaler.transform(X_in)

            # Predict
            iso_raw = iso_forest.predict(X_scaled)[0]
            is_anomaly = iso_raw == -1
            anomaly_score = float(iso_forest.decision_function(X_scaled)[0])
            pred_label = rf_clf.predict(X_scaled)[0]

            # Determine risk tier
            if is_anomaly and pred_label != 'BENIGN':
                risk_tier = "CRITICAL"
                badge_color = "#ef4444"
            elif pred_label != 'BENIGN':
                risk_tier = "HIGH"
                badge_color = "#f97316"
            elif is_anomaly:
                risk_tier = "MEDIUM"
                badge_color = "#eab308"
            else:
                risk_tier = "LOW"
                badge_color = "#10b981"

            st.markdown("---")
            st.markdown("### 📋 Multi-Tier Inference Diagnostics")
            res_col1, res_col2, res_col3, res_col4 = st.columns(4)
            with res_col1:
                st.markdown(f"**Calculated Risk Tier:**<br><span style='background-color:{badge_color}; color:white; padding:6px 14px; border-radius:6px; font-weight:bold;'>{risk_tier}</span>", unsafe_allow_html=True)
            with res_col2:
                st.metric("Predicted Threat Category", pred_label)
            with res_col3:
                st.metric("Zero-Day Anomaly Flag", "ANOMALOUS" if is_anomaly else "NORMAL")
            with res_col4:
                st.metric("Anomaly Decision Score", f"{anomaly_score:.4f}")

            if risk_tier in ["CRITICAL", "HIGH"]:
                st.error(f"🚨 **SOC Escalation Alert:** Malicious signature detected ({pred_label}) on Port {port_input}. Recommend firewall rate-limiting or immediate host quarantine.")
            else:
                st.success("✅ **Normal Baseline Traffic:** Connection conforms to legitimate operational telemetry.")
        else:
            st.warning("Model files not found. Please train models using `python src/train_models.py` first.")

# -------------------------------------------------------------
# VIEW 4: INCIDENT LOG EXPLORER
# -------------------------------------------------------------
elif view_mode == "🔍 4. Incident Log Explorer":
    st.title("🔍 Security Event Log Explorer")
    st.write("Filter, inspect, and export classified security events for forensic audit.")

    if not df_ml.empty:
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            risk_filter = st.multiselect("Filter by Risk Tier:", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
        with col_f2:
            family_filter = st.multiselect("Filter by Attack Family:", df_ml['attack_family'].dropna().unique())

        filtered_df = df_ml[df_ml['risk_tier'].isin(risk_filter)]
        if family_filter:
            filtered_df = filtered_df[filtered_df['attack_family'].isin(family_filter)]

        st.dataframe(
            filtered_df[['destination_port', 'observed_label', 'predicted_attack_label', 'risk_tier', 'anomaly_score', 'total_packets', 'bytes_per_second']].head(200),
            use_container_width=True
        )
        st.caption(f"Displaying {len(filtered_df):,} matched events.")
    else:
        st.info("No scored dataset found. Please generate predictions via `python src/train_models.py`.")
