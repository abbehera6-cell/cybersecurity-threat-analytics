# 📊 Power BI Enterprise Dashboard Design Specification
## Enterprise Cybersecurity & Threat Intelligence Analytics Platform

> **Target Audience:** Deloitte Senior Leadership, Cyber Threat Analysts, CISO Office  
> **Theme:** Dark Cybersecurity SOC (Background: `#0B0F19`, Card Containers: `#1F2937`, Accents: `#38BDF8` Sky Blue, `#10B981` Emerald Green, `#F43F5E` Alert Rose)

---

## 🏗️ 1. Semantic Data Model & Relationships

```
              ┌───────────────────────────┐
              │      AttackLabels         │ (Lookup / Dimension)
              ├───────────────────────────┤
              │ * label_id (PK)           │
              │   observed_label          │
              │   attack_family           │
              │   is_attack               │
              └─────────────┬─────────────┘
                            │ 1
                            │
                            │ *
              ┌─────────────▼─────────────┐
              │       NetworkFlows        │ (Fact Table - Parquet / SQL)
              ├───────────────────────────┤
              │ * flow_key (PK)           │
              │   capture_date            │
              │   destination_port        │
              │   duration_ms             │
              │   total_packets           │
              │   total_bytes             │
              │   bytes_per_second        │
              │   packets_per_second      │
              │   forward_byte_ratio      │
              │   total_flags             │
              │   observed_label          │
              │   attack_family           │
              │   is_attack               │
              └─────────────┬─────────────┘
                            │ 1
                            │
                            │ 1 (or 1:*)
              ┌─────────────▼─────────────┐
              │     ThreatPredictions     │ (ML Scored Fact Table)
              ├───────────────────────────┤
              │ * flow_key                │
              │   anomaly_score           │
              │   is_anomaly_predicted    │
              │   predicted_attack_label  │
              │   cluster_id              │
              │   risk_tier               │
              └───────────────────────────┘
```

---

## 📑 2. Page-by-Page Wireframe Specifications

### 🖥️ PAGE 1: SECURITY OVERVIEW
**Goal:** High-level executive posture overview answering: *What is our enterprise threat level today?*

1. **Header Banner:**
   - Title: `Enterprise Threat Intelligence Posture`
   - Subtitle: `CICIDS2017 Live Perimeter Telemetry | Security Operations Center`
   - Date Slicer: Single-select or slider across capture dates (3 Jul 2017 – 7 Jul 2017).

2. **Top KPI Cards Row:**
   - **Card 1:** `Total Network Events` -> `2.57M` (Accent: Blue `#38bdf8`)
   - **Card 2:** `Confirmed Attacks` -> `425,878` (Accent: Red `#f43f5e`)
   - **Card 3:** `Attack Ratio` -> `16.54%` (Accent: Orange `#fbbf24`)
   - **Card 4:** `Threat Families Detected` -> `8` (Accent: Purple `#a855f7`)
   - **Card 5:** `Bandwidth Transferred` -> `45.6 GB` (Accent: Emerald `#10b981`)

3. **Visual 1 (Donut Chart - Left):**
   - Legend: `is_attack` (Benign vs Malicious)
   - Values: `[Total Network Events]`
   - Colors: Benign (`#10b981`), Malicious (`#f43f5e`)
   - Tooltip: Total count, percentage share.

4. **Visual 2 (Stacked Area / Clustered Column - Center/Right):**
   - X-Axis: `capture_date`
   - Y-Axis: `[Total Network Events]`
   - Legend: `attack_family`
   - Insight: Shows attack surges across weekdays (e.g. Wednesday DoS spike, Friday PortScan spike).

5. **Visual 3 (Horizontal Ranked Bar Chart - Bottom):**
   - Y-Axis: `observed_label` (Filtered to `is_attack = TRUE()`)
   - X-Axis: `[Total Malicious Events]`
   - Data Labels: On (shows DoS Hulk: 172.8k, DDoS: 128.0k, PortScan: 90.8k).

---

### 🖥️ PAGE 2: ATTACK ANALYTICS
**Goal:** Granular threat taxonomy and attack behavior breakdown for SOC Tier 2 analysts.

1. **Left Slicer Panel:**
   - Slicer 1: `attack_family` (Multi-select: DoS, DDoS, PortScan, Brute Force, Web Attack, Bot, Infiltration, Heartbleed)
   - Slicer 2: Destination Port Range (Quick buttons: Web 80/443, Management 22/3389, DNS 53, All)

2. **Visual 1 (Treemap - Top Left):**
   - Category: `attack_family` -> `observed_label`
   - Values: `[Total Malicious Events]`
   - Color: Gradient from Gold to Dark Red based on event frequency.

3. **Visual 2 (Clustered Bar Chart - Top Right):**
   - Y-Axis: `destination_port` (Top 10 ports)
   - X-Axis: `[Total Malicious Events]`
   - Legend: `attack_family`
   - Insight: Demonstrates which services attackers target (e.g. Port 80 dominated by DoS and Web Attacks; Port 22 targeted by SSH-Patator).

4. **Visual 3 (Matrix Table with Heatmap Bars - Bottom):**
   - Rows: `attack_family` -> `observed_label`
   - Columns: `capture_date`
   - Values: `[Total Malicious Events]`, `[Avg Flow Duration MS]`, `[Avg Throughput KBps]`
   - Conditional Formatting: Background color scales on attack volume.

---

### 🖥️ PAGE 4: THREAT DETECTION & MACHINE LEARNING INSIGHTS
**Goal:** Showcase advanced data science integration — Isolation Forest & Random Forest findings.

1. **Top KPI Cards Row:**
   - **Card 1:** `Anomalies Flagged (IF)` -> `16,500+`
   - **Card 2:** `Critical Risk Incidents` -> `13,420` (IF + RF consensus)
   - **Card 3:** `Model Concordance (RF)` -> `99.72%`
   - **Card 4:** `Clustering Archetypes` -> `8 K-Means Profiles`

2. **Visual 1 (Scatter Plot - Latent Feature Space):**
   - X-Axis: `log_total_bytes`
   - Y-Axis: `log_duration_ms`
   - Legend: `risk_tier` (CRITICAL, HIGH, MEDIUM, LOW)
   - Colors: Critical (`#ef4444`), High (`#f97316`), Medium (`#eab308`), Low (`#10b981`)
   - Tooltip: `destination_port`, `predicted_attack_label`, `anomaly_score`

3. **Visual 2 (Risk Breakdown Gauge or 100% Stacked Bar):**
   - Shows proportion of flows classified into Critical, High, Medium, Low tiers.

4. **Visual 3 (Interactive Security Event Investigation Grid - Bottom):**
   - Columns: `destination_port`, `observed_label`, `predicted_attack_label`, `risk_tier`, `anomaly_score`, `total_packets`, `bytes_per_second`
   - Filtered by: Slicer on `risk_tier` (Clicking "CRITICAL" isolates actionable threats).

---

## 🚀 3. Step-by-Step Data Connection Guide in Power BI Desktop

1. Open **Power BI Desktop**.
2. Click **Get Data** -> **Text/CSV** or **Parquet**:
   - Primary File: `cybersecurity-threat-analytics/data/processed/powerbi_security_summary.csv`
   - Threat Predictions File: `cybersecurity-threat-analytics/data/processed/ml_predictions_sample.csv`
3. Click **Transform Data** (Power Query):
   - Confirm `capture_date` is detected as **Date**.
   - Confirm numeric columns (`total_packets`, `duration_ms`, `destination_port`) are **Integer / Decimal**.
4. Click **Close & Apply**.
5. Create a new measure table: Click **Enter Data** -> Name it `_DAX Measures`.
6. Copy & paste the measures from `dashboards/DAX_MEASURES.dax`.
7. Apply the dark theme: **View** -> **Themes** -> **High Contrast Dark** or import a custom JSON dark palette.

