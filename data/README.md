# Data directory

Nothing in this folder is committed to Git. CICIDS2017 is roughly 1 GB extracted
and the licence does not invite redistribution, so the pipeline is reproducible
from the official source instead of from this repository.

## `raw/`

Put the **8 CSV files** from `MachineLearningCSV.zip` here, unzipped flat:

```
data/raw/
├── Monday-WorkingHours.pcap_ISCX.csv
├── Tuesday-WorkingHours.pcap_ISCX.csv
├── Wednesday-workingHours.pcap_ISCX.csv
├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
├── Friday-WorkingHours-Morning.pcap_ISCX.csv
├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
└── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
```

Source: <https://www.unb.ca/cic/datasets/ids-2017.html> (University of New
Brunswick, Canadian Institute for Cybersecurity). The download form is short;
take `MachineLearningCSV.zip`, not the pcap archives.

Expected shape of the official release: **2,830,743 rows across the 8 files**,
78 numeric features plus `Timestamp` and `Label`. `notebooks/00_dataset_audit.ipynb`
confirms this against your own copies before any table is designed.

## `processed/`

Intermediate artefacts written by the ETL, also gitignored:

| File | Produced by | Consumed by |
|---|---|---|
| `flows_clean.parquet` | `src/data_cleaning.py` | `src/database.py`, notebooks |
| `feature_matrix.parquet` | `src/feature_engineering.py` | `src/train_models.py` |
| `dataset_audit.json` | `notebooks/00_dataset_audit.ipynb` | tests, report |

## Known defects in the raw files

Handled in Phase 2. Listed here so the behaviour is documented at the data layer,
not buried in code:

1. **Not valid UTF-8.** The Thursday file contains a `0xA0` byte inside a
   `Web Attack` label. Read with `cp1252` fallback.
2. **Mixed timestamp formats.** Thursday uses a 12-hour clock with `AM`/`PM`;
   Friday uses 24-hour `DD/MM/YYYY HH:MM`.
3. **Dirty column names.** Leading spaces, and `Fwd Header Length` appears twice
   (the second one arrives as `Fwd Header Length.1`).
4. **`inf` values.** `Flow Bytes/s` and `Flow Packets/s` divide by a zero
   duration. These are replaced with null and counted, never with zero.
