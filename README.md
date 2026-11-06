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
| 3 | PostgreSQL schema and idempotent loader | **done** |
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

`notebooks/00_dataset_audit.ipynb` measures all five before anything is modelled, and
writes `reports/dataset_audit.json` for the later stages.

**No endpoints in this release.** `MachineLearningCSV` contains `Destination Port` but no
source or destination IP address; only the pcap-derived distribution carries endpoints.
The warehouse therefore keeps `source_ip` and `destination_ip` nullable — they load as
null here and populate automatically if the pcap-derived files are ever ingested. Any
endpoint-based analysis must fall back to a protocol × destination-port view, and the
report states that rather than implying endpoint data exists.

## Setup

### This machine (provisioned 2026-11-06)

| Component | Where |
|---|---|
| Python 3.11 venv with every pinned dependency | `.venv\` |
| PostgreSQL 16.11 binaries | `%LOCALAPPDATA%\Programs\PostgreSQL\16\bin` |
| Cluster data directory | `%LOCALAPPDATA%\PostgreSQL\data16` |
| Database | `cyber_threat` on `127.0.0.1:5432`, role `postgres` |
| Credentials | `.env` (gitignored) |
| Start / stop the server | `scripts\db_start.cmd`, `scripts\db_stop.cmd` |

PostgreSQL was installed from the official EDB binaries into the user profile instead of
as a Windows service, because registering a service needs an elevated prompt this
environment does not have. The consequence is that the server must be running before any
database work: a logon entry starts it automatically, and that entry exits silently when
something else already holds port 5432, so installing a full PostgreSQL service later
will not create a conflict.

### A fresh clone on another machine

```powershell
winget install -e --id Python.Python.3.11
winget install -e --id Git.Git
# Power BI Desktop: Microsoft Store, or https://powerbi.microsoft.com/desktop/

cd "C:\Users\AMIT BIKRAM BEHERA\Desktop\pipipithon\cybersecurity-threat-analytics"
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
python -m pip install --upgrade pip
pip install -r requirements.txt

# PostgreSQL 16, either the installer or the binaries zip used here:
#   https://get.enterprisedb.com/postgresql/postgresql-16.11-1-windows-x64-binaries.zip
Copy-Item .env.example .env          # then set DB_PASSWORD to match your cluster
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
