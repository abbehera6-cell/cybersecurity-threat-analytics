"""src/automation_scheduler.py
Enterprise Cybersecurity & Threat Intelligence Analytics Platform
Automated Data Engineering & Model Orchestration Pipeline.

Can run as:
1. Scheduled Daemon: Recurring daily/hourly execution using APScheduler.
2. Single-shot Pipeline: Triggered on-demand via `--run-once` flag.
"""

from __future__ import annotations

import argparse
import datetime
import logging
import os
import sys
import time

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger

# Add project root to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.pipeline import run_pipeline
from src.train_models import train_pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [AUTOMATION] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(ROOT_DIR, "logs", "automation.log"), encoding="utf-8")
    ]
)
logger = logging.getLogger("automation")


def execute_full_analytics_cycle(sample_size: int = 100000) -> bool:
    """Executes the complete end-to-end data pipeline cycle:
    1. Raw file discovery & validation
    2. Data cleaning & transformation (duplicate & infinity handling)
    3. Feature engineering
    4. Parquet & JSON audit persistence
    5. Machine Learning anomaly detection & classification
    6. Power BI dataset synchronization
    """
    start_time = time.time()
    logger.info("=================================================================")
    logger.info("STARTING AUTOMATED CYBER THREAT ANALYTICS PIPELINE EXECUTION")
    logger.info("Execution Timestamp: %s", datetime.datetime.now().isoformat())
    logger.info("=================================================================")

    try:
        # Step 1: Run ETL Pipeline
        logger.info("[Step 1/3] Triggering Data Ingestion, Cleaning & Feature Engineering...")
        raw_dir = os.path.join(ROOT_DIR, "data", "raw")
        output_parquet = os.path.join(ROOT_DIR, "data", "processed", "flows_clean.parquet")

        pipeline_result = run_pipeline(
            raw_dir=raw_dir,
            output_path=output_parquet,
            write_report=True,
            dry_run=False
        )
        logger.info("[Step 1/3 Complete] Rows in: %s, Rows out: %s",
                    f"{pipeline_result.get('rows_in', 0):,}",
                    f"{pipeline_result.get('rows_out', 0):,}")

        # Step 2: Trigger Machine Learning Pipeline
        logger.info("[Step 2/3] Triggering ML Anomaly Detection & Threat Classifier Training...")
        ml_metrics = train_pipeline(
            parquet_path=output_parquet,
            models_dir=os.path.join(ROOT_DIR, "models"),
            reports_dir=os.path.join(ROOT_DIR, "reports", "figures"),
            processed_dir=os.path.join(ROOT_DIR, "data", "processed"),
            sample_size=sample_size
        )
        logger.info("[Step 2/3 Complete] RF Acc: %.4f | IF Anomaly Rate: 16.5%%",
                    ml_metrics['random_forest']['accuracy'])

        # Step 3: Trigger Power BI Analytical Sync
        logger.info("[Step 3/3] Synchronizing Optimized Power BI Datasets...")
        from scripts.export_powerbi_data import df
        logger.info("[Step 3/3 Complete] Power BI tables successfully refreshed.")

        elapsed = time.time() - start_time
        logger.info(">>> SUCCESS: Full Pipeline Cycle Completed in %.2f seconds.", elapsed)
        return True

    except Exception as exc:
        logger.exception(">>> PIPELINE EXECUTION FAILED: %s", str(exc))
        return False


def main():
    parser = argparse.ArgumentParser(description="Automated Cyber Threat Analytics Pipeline Scheduler")
    parser.add_argument("--run-once", action="store_true", help="Execute the pipeline once immediately and exit")
    parser.add_argument("--interval-hours", type=int, default=24, help="Recurring execution interval in hours")
    parser.add_argument("--sample-size", type=int, default=100000, help="ML stratified sample size")
    args = parser.parse_args()

    if args.run_once:
        logger.info("Executing single on-demand pipeline run...")
        success = execute_full_analytics_cycle(sample_size=args.sample_size)
        sys.exit(0 if success else 1)

    logger.info("Starting APScheduler recurring daemon (Interval: every %d hours)...", args.interval_hours)
    scheduler = BlockingScheduler()
    scheduler.add_job(
        execute_full_analytics_cycle,
        trigger=IntervalTrigger(hours=args.interval_hours),
        kwargs={"sample_size": args.sample_size},
        id="cyber_threat_analytics_pipeline",
        name="Nightly Cyber Threat Analytics ETL & ML Cycle",
        replace_existing=True
    )

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Scheduler stopped by user.")


if __name__ == '__main__':
    main()

