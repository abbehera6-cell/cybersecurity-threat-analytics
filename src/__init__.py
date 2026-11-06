"""Pipeline source package.

Modules, in execution order:

    errors.py               exceptions that mean "this run is not trustworthy"
    data_ingestion.py       read the raw CSVs, normalise the header, validate the schema
    data_cleaning.py        duplicates, types, infinities, timestamps, labels
    feature_engineering.py  derived flow features, attack flag and attack family
    pipeline.py             orchestrates the four stages and writes the parquet

Run the whole thing from the project root with:

    python -m src.pipeline
"""
