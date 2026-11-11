"""scripts/query_backend.py
Interactive CLI Backend Explorer for PostgreSQL database.
Allows testing queries and inspecting warehouse tables.
"""

import sys
import os
import pandas as pd
from sqlalchemy import text

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.database import create_engine_from_settings

def explore_backend():
    print("==========================================================")
    print("  CYBER THREAT INTELLIGENCE PLATFORM — BACKEND EXPLORER")
    print("==========================================================")
    print("Connecting to PostgreSQL backend database...")

    try:
        engine = create_engine_from_settings()
        with engine.connect() as conn:
            print(">>> Connected successfully to 'cyber_threat' database!\n")

            # 1. Show tables
            print("--- 1. Relational Tables in Schema ---")
            tables_df = pd.read_sql(
                text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';"),
                conn
            )
            print(tables_df.to_string(index=False))

            # 2. Show views
            print("\n--- 2. Analytical Reporting Views ---")
            views_df = pd.read_sql(
                text("SELECT table_name AS view_name FROM information_schema.views WHERE table_schema = 'public';"),
                conn
            )
            print(views_df.to_string(index=False))

            # 3. Sample from traffic overview view if present
            print("\n--- 3. Live Headline KPIs from vw_traffic_overview ---")
            try:
                overview_df = pd.read_sql(text("SELECT * FROM vw_traffic_overview;"), conn)
                print(overview_df.to_string(index=False))
            except Exception as e:
                print("Could not query vw_traffic_overview:", e)

            # 4. Attack labels
            print("\n--- 4. Threat Taxonomy (attack_labels) ---")
            try:
                labels_df = pd.read_sql(text("SELECT label_id, observed_label, attack_family, is_attack FROM attack_labels;"), conn)
                print(labels_df.to_string(index=False))
            except Exception as e:
                print("Could not query attack_labels:", e)

            print("\n==========================================================")
            print("Backend is healthy and operational!")
            print("==========================================================")

    except Exception as exc:
        print("\n>>> Connection Error:", exc)
        print("\nPlease make sure PostgreSQL is started first by running:")
        print("   .\\scripts\\db_start.cmd")

if __name__ == '__main__':
    explore_backend()
