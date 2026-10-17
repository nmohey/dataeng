"""Load the curated Milestone-1 tables into the Compose stack's PostgreSQL.

Usage: ``python -m kestrel_m1.load_postgres [curated_dir]`` with DATABASE_URL set
(default postgresql+psycopg://kestrel:kestrel@localhost:5433/kestrel). Tables are
replaced on every run so the loader is idempotent.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pandas as pd
from sqlalchemy import create_engine, text

from .config import resolve_out_dir

TABLES_CSV = {
    "dim_tenant": "dim_tenant.csv", "dim_agent": "dim_agent.csv", "dim_tool": "dim_tool.csv",
    "dim_model_pricing": "dim_model_pricing.csv", "dim_sandbox_policy": "dim_sandbox_policy.csv",
    "policy_allowed_tools": "policy_allowed_tools.csv", "policy_egress_allowlist": "policy_egress_allowlist.csv",
    "policy_denied_ports": "policy_denied_ports.csv", "sandbox_host_clock_offsets": "sandbox_host_clock_offsets.csv",
    "siem_flow_correlation": "siem_flow_correlation.csv", "m1_sessions": "sessions.csv", "m1_metrics": "metrics.csv",
}


def load(curated_dir: Path | None = None, database_url: str | None = None, chunksize: int = 50_000) -> dict[str, int]:
    curated_dir = Path(curated_dir) if curated_dir else resolve_out_dir()
    url = database_url or os.environ.get("DATABASE_URL", "postgresql+psycopg://kestrel:kestrel@localhost:5433/kestrel")
    engine = create_engine(url)
    counts: dict[str, int] = {}
    for table, fname in TABLES_CSV.items():
        df = pd.read_csv(curated_dir / fname)
        df.to_sql(table, engine, if_exists="replace", index=False)
        counts[table] = len(df)
        print(f"loaded {table}: {len(df):,} rows", flush=True)
    for table, fname in {"fact_rejected_record": "rejects.parquet", "canonical_activity": "canonical_activity.parquet"}.items():
        df = pd.read_parquet(curated_dir / fname)
        df.to_sql(table, engine, if_exists="replace", index=False, chunksize=chunksize, method="multi")
        counts[table] = len(df)
        print(f"loaded {table}: {len(df):,} rows", flush=True)
    with engine.begin() as conn:
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_canonical_session ON canonical_activity (session_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_canonical_time ON canonical_activity (event_time_utc)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_canonical_type ON canonical_activity (activity_type)"))
        n = conn.execute(text("select count(*) from canonical_activity")).scalar_one()
    print(f"canonical_activity in Postgres: {n:,} rows")
    return counts


if __name__ == "__main__":
    load(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
