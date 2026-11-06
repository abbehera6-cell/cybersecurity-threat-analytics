# Enterprise Cybersecurity & Threat Intelligence Analytics Platform

End-to-end analytics on the CICIDS2017 network-flow dataset: Python ETL → PostgreSQL →
SQL analytics → exploratory analysis → anomaly detection and classification → Power BI
dashboards.

Built as a final-year B.Tech CSE project for a data analytics interview. Every figure in
the dashboards is produced by the pipeline in this repository; nothing on a page is
hand-typed.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Repository skeleton, configuration, dataset audit | **done** |
| 2 | ETL: ingestion, cleaning, feature engineering | **done** |
| 3 | PostgreSQL schema and idempotent loader | not started |
| 4 | SQL analytics: 10 queries, CTEs, window functions, views | not started |
| 5 | Exploratory data analysis notebooks and figures | not started |
| 6 | Machine learning: Random Forest, Isolation Forest, K-Means | not started |
| 7 | Power BI semantic model, four report pages, DAX | not started |
| 8 | Automation, tests, report, GitHub | not started |
| 9 | Interview preparation pack | not started |

## Dataset

**CICIDS2017**, Canadian Institute for Cybersecurity, University of New Brunswick.
Download: <https://www.unb.ca/cic/datasets/ids-2017.html> — take `MachineLearningCSV.zip`,
unzip the 8 CSVs into `data/raw/`.

The official release has **2,830,743 flow records** across 8 files, captured 3–7 July 2017
during business hours, with 78 numeric features plus `Timestamp` and `Label`. Labels are
`BENIGN` plus 14 attack types across 8 families.

The raw files are not clean, and handling that is a large part of the engineering:

| Defect | Effect on a naive pipeline |
|---|---|
| Thursday file has a `0xA0` byte inside a label | `UnicodeDecodeError`, or silently mangled labels |
| Thursday uses 12-hour `AM/PM` timestamps, Friday uses 24-hour | Half the timestamps fail to parse |
| Column names carry leading spaces, `Fwd Header Length` appears twice | Ambiguous columns, broken schema |
| `Flow Bytes/s` and `Flow Packets/s` divide by zero duration | `inf` values poison statistics and scaling |
| Tens of thousands of exact duplicate rows | Inflated counts and leaked train/test rows |

`notebooks/00_dataset_audit.ipynb` measures all five against your own copies before any
table is designed, and writes `reports/dataset_audit.json` for the later phases.

## Setup (Windows, Python 3.11)

```powershell
# Prerequisites, once per machine
winget install -e --id Python.Python.3.11
winget install -e --id PostgreSQL.PostgreSQL.16
winget install -e --id Git.Git
# Power BI Desktop: Microsoft Store, or https://powerbi.microsoft.com/desktop/

# Project environment
cd "C:\Users\AMIT BIKRAM BEHERA\Desktop\pipipithon\cybersecurity-threat-analytics"
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
python -m pip install --upgrade pip
pip install -r requirements.txt

# Database and secrets
psql -U postgres -c "CREATE DATABASE cyber_threat;"
Copy-Item .env.example .env          # then edit DB_PASSWORD
```

If a single pinned version in `requirements.txt` refuses to build on your machine, relax
that one line to `>=` and re-run; do not upgrade the whole file.

## First run

```powershell
# 1. put the 8 CICIDS2017 CSVs in data/raw/
# 2. execute the audit
jupyter lab notebooks/00_dataset_audit.ipynb
# 3. build the cleaned dataset (writes data/processed/flows_clean.parquet)
python -m src.pipeline
# 4. or validate without writing anything
python -m src.pipeline --dry-run
# 5. run the tests
python -m pytest -q
```

The audit's last cell prints a gate. All five lines should read `[x]` before the
pipeline is worth running.

The pipeline prints a reconciliation block and refuses to publish a dataset where
`rows in` does not equal `rows out + duplicates + invalid rows`:

```
rows in        : 29
duplicates     : 1
invalid rows   : 1
rows out       : 27
```

## Repository layout

```
cybersecurity-threat-analytics/
├── config/settings.py      single source of truth: paths, credentials, dataset constants
├── data/raw/               the 8 CSVs (gitignored)
├── data/processed/         parquet caches between stages (gitignored)
├── notebooks/              00_dataset_audit.ipynb, then 01-04 in later phases
├── src/                    ingestion, cleaning, features, pipeline orchestration
├── sql/                    schema.sql, analytics_queries.sql
├── models/                 fitted estimators and metrics (gitignored binaries)
├── dashboards/             powerbi_dashboard.pbix, dax_measures.md
├── reports/                project_report.md, architecture.png, dataset_audit.json
├── tests/                  pytest suites
└── logs/                   pipeline run logs (gitignored)
```

## Design documents

The database schema, dashboard pages and interview notes are built against an
architecture diagram and four Power BI page specifications held in the design canvas.
`reports/architecture.png` is exported from it in Phase 8 and referenced by the project
report; it does not exist in the repository yet.

## Not committed

Raw data, `.env`, virtual environments, trained `.joblib` binaries and logs are
gitignored. The pipeline is reproducible from the official dataset source plus
`requirements.txt`, so a fresh clone plus the 8 CSVs is enough.
