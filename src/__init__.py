"""Pipeline source package.

Modules are added phase by phase:

    data_ingestion.py    Phase 2 - read and validate the raw CSVs
    data_cleaning.py     Phase 2 - dedupe, types, timestamps, invalid values
    feature_engineering.py  Phase 2 - derived flow features
    database.py          Phase 3 - PostgreSQL connection and bulk load
    pipeline.py          Phase 2+ - orchestrates the above end to end
"""
