"""Load the curated Milestone-1 tables into the Compose stack's PostgreSQL.

Usage: ``python -m kestrel_m1.load_postgres [curated_dir]`` with DATABASE_URL set
(default postgresql+psycopg://kestrel:kestrel@localhost:5433/kestrel). Tables are
replaced on every run so the loader is idempotent.

The two large tables (canonical_activity, fact_rejected_record) are bulk-loaded with
PostgreSQL's COPY protocol through psycopg: the table is created empty with the types
pandas infers, then the rows are streamed as CSV. That loads a million rows in seconds,
where multi-row INSERTs take many minutes. If the connection is not psycopg, the loader
falls back to batched INSERTs sized under PostgreSQL's 65,535-parameter limit.
"""
from __future__ import annotations

import io
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
TABLES_PARQUET = {"fact_rejected_record": "rejects.parquet", "canonical_activity": "canonical_activity.parquet"}

#: PostgreSQL accepts at most 65,535 bound parameters per statement; a multi-row INSERT
#: binds rows x columns of them, so the fallback batch size is derived from the column count.
PG_MAX_PARAMS = 65_535


def rows_per_batch(n_columns: int, max_params: int = PG_MAX_PARAMS) -> int:
    return max(1, (max_params - 1) // max(1, n_columns))


def _csv_chunks(df: pd.DataFrame, rows: int = 100_000):
    """Yield the frame as CSV text blocks (no header). Nulls become empty fields, which
    COPY ... NULL '' turns back into SQL NULL; tz-aware timestamps are written with their
    offset, which TIMESTAMPTZ parses."""
    for start in range(0, len(df), rows):
        buf = io.StringIO()
        df.iloc[start:start + rows].to_csv(buf, index=False, header=False, na_rep="", date_format="%Y-%m-%d %H:%M:%S.%f%z")
        yield buf.getvalue()


def copy_frame(df: pd.DataFrame, table: str, engine) -> None:
    """Replace ``table`` with the frame's rows using COPY FROM STDIN (psycopg 3)."""
    df.head(0).to_sql(table, engine, if_exists="replace", index=False)  # typed, empty table
    cols = ", ".join(f'"{c}"' for c in df.columns)
    raw = engine.raw_connection()
    try:
        cur = raw.cursor()
        with cur.copy(f'COPY "{table}" ({cols}) FROM STDIN WITH (FORMAT csv, NULL \'\')') as cp:
            for block in _csv_chunks(df):
                cp.write(block)
        raw.commit()
    finally:
        raw.close()


def write_frame(df: pd.DataFrame, table: str, engine) -> str:
    """COPY when the driver is psycopg, otherwise batched INSERTs. Returns the method used."""
    if engine.dialect.driver == "psycopg":
        copy_frame(df, table, engine)
        return "COPY"
    df.to_sql(table, engine, if_exists="replace", index=False, chunksize=rows_per_batch(df.shape[1]), method="multi")
    return f"INSERT x{rows_per_batch(df.shape[1])}"


def load(curated_dir: Path | None = None, database_url: str | None = None) -> dict[str, int]:
    curated_dir = Path(curated_dir) if curated_dir else resolve_out_dir()
    url = database_url or os.environ.get("DATABASE_URL", "postgresql+psycopg://kestrel:kestrel@localhost:5433/kestrel")
    engine = create_engine(url)
    counts: dict[str, int] = {}
    for table, fname in TABLES_CSV.items():
        df = pd.read_csv(curated_dir / fname)
        method = write_frame(df, table, engine)
        counts[table] = len(df)
        print(f"loaded {table}: {len(df):,} rows ({method})", flush=True)
    for table, fname in TABLES_PARQUET.items():
        df = pd.read_parquet(curated_dir / fname)
        method = write_frame(df, table, engine)
        counts[table] = len(df)
        print(f"loaded {table}: {len(df):,} rows ({method})", flush=True)
    with engine.begin() as conn:
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_canonical_session ON canonical_activity (session_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_canonical_time ON canonical_activity (event_time_utc)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_canonical_type ON canonical_activity (activity_type)"))
        n = conn.execute(text("select count(*) from canonical_activity")).scalar_one()
    print(f"canonical_activity in Postgres: {n:,} rows", flush=True)
    return counts


if __name__ == "__main__":
    load(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
