"""Read every batch file in its own format and return *bronze* frames.

Bronze means: values exactly as exported (strings stay strings), plus two provenance
columns on every row, ``source_file`` and ``source_line``, so a rejected record can
always point back to where it came from.

* CSV      -> pandas, every column as string, empty field = null (RFC 4180 header row)
* Parquet  -> pyarrow, schema checked against the Dataset Description before loading
* JSON     -> json module, nested objects flattened with ``pd.json_normalize``
* syslog   -> line-by-line regex (``parse_syslog``), unparseable lines kept aside
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from .config import FILES

# ----------------------------------------------------------------------------- CSV


def read_csv_bronze(path: Path) -> pd.DataFrame:
    """Every column as text; '' is the CSV null. source_line is the physical line
    number (header is line 1, so the first record is line 2)."""
    df = pd.read_csv(path, dtype=str, keep_default_na=False, na_values=[""], encoding="utf-8")
    df.insert(0, "source_line", range(2, len(df) + 2))
    df.insert(0, "source_file", path.name)
    return df


# ------------------------------------------------------------------------- Parquet

#: The schema the Dataset Description promises for agent_activity.parquet
#: (section 3.5: counts int64, the three timestamps as raw strings).
ACTIVITY_SCHEMA = {
    "event_id": pa.string(), "event_time": pa.string(), "ingest_time": pa.string(),
    "sequence_number": pa.int64(), "event_type": pa.string(), "session_id": pa.string(),
    "tenant_id": pa.string(), "agent_id": pa.string(), "release_version": pa.string(),
    "sandbox_instance_id": pa.string(), "status": pa.string(), "latency_ms": pa.int64(),
    "turn_index": pa.int64(), "model_id": pa.string(), "content_source": pa.string(),
    "stated_goal": pa.string(), "injection_indicators": pa.string(), "input_tokens": pa.int64(),
    "output_tokens": pa.int64(), "finish_reason": pa.string(), "tool_id": pa.string(),
    "tool_version": pa.string(), "finished_at": pa.string(), "retry_number": pa.int64(),
    "error_class": pa.string(), "target_resource": pa.string(), "bytes_out": pa.int64(),
    "task_id": pa.string(), "task_category": pa.string(), "expected_tool_categories": pa.string(),
}


def check_parquet_schema(path: Path, expected: dict[str, pa.DataType] = ACTIVITY_SCHEMA) -> dict:
    """Compare the file's Arrow schema with the contract. Returns a report dict with
    missing/unexpected columns and type mismatches (empty lists mean the schema is as promised)."""
    pf = pq.ParquetFile(path)
    schema = pf.schema_arrow
    actual = {f.name: f.type for f in schema}
    report = {
        "num_rows": pf.metadata.num_rows,
        "num_row_groups": pf.metadata.num_row_groups,
        "compression": pf.metadata.row_group(0).column(0).compression,
        "created_by": pf.metadata.created_by,
        "missing_columns": [c for c in expected if c not in actual],
        "unexpected_columns": [c for c in actual if c not in expected],
        "type_mismatches": {c: (str(expected[c]), str(actual[c])) for c in expected if c in actual and actual[c] != expected[c]},
    }
    report["ok"] = not (report["missing_columns"] or report["unexpected_columns"] or report["type_mismatches"])
    return report


def read_activity_bronze(path: Path) -> tuple[pd.DataFrame, dict]:
    """Read agent_activity.parquet after checking its schema. Integer columns become
    pandas nullable Int64 (so nulls do not silently turn the column into floats);
    timestamps stay raw strings. source_line is the 1-based row ordinal in the file."""
    report = check_parquet_schema(path)
    table = pq.read_table(path)
    df = table.to_pandas(types_mapper={pa.int64(): pd.Int64Dtype()}.get)
    df.insert(0, "source_line", range(1, len(df) + 1))
    df.insert(0, "source_file", path.name)
    return df, report


# ---------------------------------------------------------------------------- JSON


def read_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def read_policies_bronze(path: Path) -> tuple[pd.DataFrame, list[dict]]:
    """sandbox_policies.json is an array of policy-version objects with nested
    network/filesystem/resources blocks. Returns the flattened frame (one row per
    policy version; nested keys become dotted columns, lists stay lists) and the raw list."""
    raw = read_json(path)
    flat = pd.json_normalize(raw)
    flat.insert(0, "source_line", range(0, len(flat)))  # index in the JSON array
    flat.insert(0, "source_file", path.name)
    # a policy version without a network block has no network.* columns at all for that row
    for col in ["network.egress_allowlist", "network.denied_ports", "network.max_egress_mb"]:
        if col not in flat.columns:
            flat[col] = None
    flat["has_network_block"] = [("network" in p) for p in raw]
    return flat, raw


def read_siem_bronze(path: Path) -> tuple[pd.DataFrame, dict]:
    """siem_alerts.json is an envelope {generated_at, source, alerts:[...]}. Returns the
    flattened alerts (destination.* and technique.* become columns) and the envelope."""
    raw = read_json(path)
    envelope = {k: v for k, v in raw.items() if k != "alerts"}
    envelope["n_alerts"] = len(raw["alerts"])
    flat = pd.json_normalize(raw["alerts"])
    flat.insert(0, "source_line", range(0, len(flat)))  # index in the alerts[] array
    flat.insert(0, "source_file", path.name)
    return flat, envelope


# -------------------------------------------------------------------------- syslog

#: "Mar 14 11:22:04 sbx-eu-113 kestrel-sandbox[8841]: key=value key=value ..."
SYSLOG_HEADER_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<process>[^\[\s]+)\[(?P<pid>\d+)\]:\s(?P<message>.*)$"
)
SYSLOG_KV_RE = re.compile(r"(\w+)=(\S*)")
SYSLOG_FIELDS = ["session", "instance", "decision", "action", "target", "reason", "policy_version"]
SYSLOG_FIELD_RENAMES = {"session": "session_id", "instance": "sandbox_instance_id"}


def parse_syslog_line(line: str) -> dict | None:
    """One line -> dict of header fields + key=value fields, or None if the header
    does not match. Missing keys are absent from the dict (the caller decides)."""
    m = SYSLOG_HEADER_RE.match(line)
    if not m:
        return None
    rec = m.groupdict()
    rec.update(dict(SYSLOG_KV_RE.findall(rec.pop("message"))))
    return rec


def read_syslog_bronze(path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Parse sandbox_audit.log. Returns (parsed, unparsed):

    * parsed   one row per line whose header matched; k=v fields as columns, missing
               keys as null; ``-`` kept as is (it is the syslog null; the cleaner maps it)
    * unparsed lines whose header did not match, with their line number and raw text
    """
    rows, bad = [], []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            rec = parse_syslog_line(line)
            if rec is None:
                bad.append({"source_file": path.name, "source_line": lineno, "raw_line": line})
                continue
            rec["source_line"] = lineno
            rec["raw_line"] = line
            rows.append(rec)
    parsed = pd.DataFrame(rows)
    for col in SYSLOG_FIELDS:
        if col not in parsed.columns:
            parsed[col] = None
    parsed = parsed.rename(columns=SYSLOG_FIELD_RENAMES)
    parsed.insert(0, "source_file", path.name)
    unparsed = pd.DataFrame(bad, columns=["source_file", "source_line", "raw_line"])
    return parsed, unparsed


# ------------------------------------------------------------------- convenience


def read_all_bronze(raw_dir: Path) -> dict:
    """Read the nine Milestone-1 inputs. Returns a dict of frames and side reports."""
    raw_dir = Path(raw_dir)
    out: dict = {}
    for key in ["tenants", "agents", "tools", "model_pricing", "network_flows"]:
        out[key] = read_csv_bronze(raw_dir / FILES[key])
    out["agent_activity"], out["activity_schema_report"] = read_activity_bronze(raw_dir / FILES["agent_activity"])
    out["sandbox_policies"], out["sandbox_policies_raw"] = read_policies_bronze(raw_dir / FILES["sandbox_policies"])
    out["siem_alerts"], out["siem_envelope"] = read_siem_bronze(raw_dir / FILES["siem_alerts"])
    out["sandbox_audit"], out["sandbox_audit_unparsed"] = read_syslog_bronze(raw_dir / FILES["sandbox_audit"])
    return out
