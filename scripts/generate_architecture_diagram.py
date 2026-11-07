"""scripts/generate_architecture_diagram.py
Generates a publication-grade enterprise architecture diagram for the project report.
Saves to reports/architecture.png.
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
REPORTS_DIR = os.path.join(ROOT_DIR, 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

fig, ax = plt.subplots(figsize=(16, 10), facecolor='#0B0F19')
ax.set_facecolor('#0B0F19')
ax.set_xlim(0, 100)
ax.set_ylim(0, 100)
ax.axis('off')

# Title
ax.text(50, 95, "Enterprise Cybersecurity & Threat Intelligence Analytics Platform",
        ha='center', va='center', color='#F8FAFC', fontsize=20, weight='bold')
ax.text(50, 91, "End-to-End Enterprise Architecture: Ingestion → ETL → Warehouse → ML → BI Operations",
        ha='center', va='center', color='#94A3B8', fontsize=12)

# Helper function to draw card boxes
def draw_card(ax, x, y, w, h, title, subtitle, color, items, icon=""):
    rect = patches.FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.8,rounding_size=1.5",
        edgecolor=color, facecolor='#1F2937', linewidth=2
    )
    ax.add_patch(rect)
    # Header tag
    tag = patches.FancyBboxPatch(
        (x + 2, y + h - 5.5), w - 4, 4.5,
        boxstyle="round,pad=0.3,rounding_size=0.8",
        edgecolor='none', facecolor=color
    )
    ax.add_patch(tag)
    ax.text(x + w/2, y + h - 3.2, title.upper(), ha='center', va='center', color='#0B0F19', fontsize=11, weight='bold')
    ax.text(x + w/2, y + h - 8.5, subtitle, ha='center', va='center', color='#E2E8F0', fontsize=9.5, weight='bold')

    # Bullet items
    start_y = y + h - 13
    for i, itm in enumerate(items):
        ax.text(x + 3, start_y - (i * 4.2), f"• {itm}", ha='left', va='center', color='#CBD5E1', fontsize=8.5)

# 1. Ingestion Layer
draw_card(
    ax, 5, 48, 26, 36,
    "1. Data Ingestion & ETL",
    "Python 3.11 / Pandas / PyArrow",
    "#38BDF8",
    [
        "Raw CICIDS2017 PCAP CSVs (2.83M rows)",
        "Encoding Auto-detection (UTF-8/cp1252)",
        "Whitespace & Header Normalization",
        "256,479 Measurement Dupes Removed",
        "2,889 Division-by-Zero Infs Nullified",
        "11 Derived Domain Features Computed",
        "Downcasted Memory Optimization (~78% saved)"
    ]
)

# 2. Storage & Warehouse Layer
draw_card(
    ax, 37, 48, 26, 36,
    "2. Database & Data Lake",
    "PostgreSQL 16 & Snappy Parquet",
    "#10B981",
    [
        "Parquet Lakehouse (flows_clean.parquet)",
        "PostgreSQL 3NF Normalized Schema",
        "attack_labels (15 Canonical Labels)",
        "pipeline_runs (Audit Provenance Metadata)",
        "network_flows (Partitioned & Indexed Fact)",
        "flow_predictions (Scored Predictions Table)",
        "7 SQL Analytical Reporting Views"
    ]
)

# 3. Advanced ML Layer
draw_card(
    ax, 69, 48, 26, 36,
    "3. Threat Intelligence ML",
    "Scikit-Learn / Joblib Pipelines",
    "#F59E0B",
    [
        "Isolation Forest: Unsupervised Anomaly Detection",
        "Random Forest: 99.7% Multi-Class Threat Classifier",
        "K-Means: Unsupervised Traffic Archetype Clustering",
        "Stratified Sampling Preserving Rare Zero-Days",
        "Class Imbalance Cost-Sensitive Weighting",
        "Automated Model Serialization in models/",
        "Multi-Tier Risk Engine: Critical / High / Med / Low"
    ]
)

# 4. SQL Analytics & Views
draw_card(
    ax, 5, 6, 26, 34,
    "4. SQL Analytics Engine",
    "PostgreSQL CTEs & Windows",
    "#818CF8",
    [
        "12 Advanced Analytical Business Queries",
        "Pareto Analysis (80/20 Attack Distribution)",
        "Day-over-Day Trends with LAG() Window Functions",
        "Destination Port Threat Concentration Matrix",
        "Moving Averages & Traffic Volume Profiling",
        "Flows Exceeding 99th Percentile Bandwidth",
        "All Queries Tested via Synthetic Test Harness"
    ]
)

# 5. Business Intelligence Layer
draw_card(
    ax, 37, 6, 26, 34,
    "5. Power BI SOC Dashboard",
    "Dark-Themed 4-Page Analytics",
    "#EC4899",
    [
        "Page 1: Security Operations Executive Overview",
        "Page 2: Attack Analytics & Threat Hierarchy",
        "Page 3: Network Traffic & Port Vector Analysis",
        "Page 4: ML Anomaly Detection & Threat Hunting",
        "Extensive DAX Measure Library (20+ Measures)",
        "Dynamic Risk-Tier Slicers & Event Drill-through",
        "Real-Time Incident Table for Security Analysts"
    ]
)

# 6. Automation & Governance
draw_card(
    ax, 69, 6, 26, 34,
    "6. Orchestration & DevOps",
    "APScheduler / Git / CI Validation",
    "#F43F5E",
    [
        "Scheduled Nightly ETL & Model Re-scoring",
        "CLI Interface: Single-Shot (--run-once) or Daemon",
        "Dual-Stream Logging & File Reconciliation",
        "Comprehensive 62-Test Pytest Suite",
        "Defect-Safe Fixture Simulation",
        "Zero Hardcoded Credentials (.env Architecture)",
        "Production-Grade GitHub Repository Layout"
    ]
)

# Connecting Arrows
def draw_arrow(ax, x1, y1, x2, y2, color="#94A3B8"):
    ax.annotate(
        '', xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(
            arrowstyle="->", color=color, lw=2.5,
            mutation_scale=18, shrinkA=5, shrinkB=5
        )
    )

draw_arrow(ax, 31, 66, 37, 66, "#38BDF8")
draw_arrow(ax, 63, 66, 69, 66, "#10B981")
draw_arrow(ax, 50, 48, 50, 40, "#10B981")
draw_arrow(ax, 18, 48, 18, 40, "#38BDF8")
draw_arrow(ax, 82, 48, 82, 40, "#F59E0B")
draw_arrow(ax, 37, 23, 31, 23, "#818CF8")
draw_arrow(ax, 63, 23, 69, 23, "#EC4899")

output_path = os.path.join(REPORTS_DIR, 'architecture.png')
plt.savefig(output_path, dpi=200, bbox_inches='tight', facecolor='#0B0F19')
plt.close()
print(f"Architecture diagram generated: {output_path}")

