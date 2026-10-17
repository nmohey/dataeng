"""Paths, closed enums and policy constants shared by the whole pipeline."""
from __future__ import annotations

import os
from pathlib import Path

M1_DIR = Path(__file__).resolve().parent.parent


def resolve_raw_dir() -> Path:
    """Where the telemetry pack lives.

    Order: $KESTREL_RAW_DIR, then M1/data/raw, then ../kestrel-telemetry-pack-v1
    (the pack sitting next to M1/ at the repository root).
    """
    env = os.environ.get("KESTREL_RAW_DIR")
    candidates = [Path(env)] if env else []
    candidates += [M1_DIR / "data" / "raw", M1_DIR.parent / "kestrel-telemetry-pack-v1"]
    for c in candidates:
        if (c / "agent_activity.parquet").exists():
            return c
    raise FileNotFoundError(
        "Telemetry pack not found. Set KESTREL_RAW_DIR, or unzip kestrel-telemetry-pack-v1 "
        "into M1/data/raw or next to the M1 folder. Looked in: " + ", ".join(map(str, candidates))
    )


def resolve_out_dir() -> Path:
    env = os.environ.get("KESTREL_OUT_DIR")
    return Path(env) if env else M1_DIR / "data" / "curated"


# ---------------------------------------------------------------- file inventory
FILES = {
    "tenants": "tenants.csv",
    "agents": "agents.csv",
    "tools": "tools.csv",
    "model_pricing": "model_pricing.csv",
    "sandbox_policies": "sandbox_policies.json",
    "agent_activity": "agent_activity.parquet",
    "network_flows": "network_flows.csv",
    "sandbox_audit": "sandbox_audit.log",
    "siem_alerts": "siem_alerts.json",
}

# ---------------------------------------------------------------- closed enums
# Rejection reasons, in precedence order (Dataset Description section 4).
REJECT_REASONS = [
    "DUPLICATE_EVENT_ID",
    "UNKNOWN_AGENT_ID",
    "UNKNOWN_TENANT_ID",
    "MALFORMED_TIMESTAMP",
    "ORPHAN_EVENT",
    "INVALID_EVENT_TYPE",
    "MISSING_REQUIRED_FIELD",
    "INVALID_NUMERIC_RANGE",
    "LATE_BEYOND_WATERMARK",
    "UNPARSEABLE_RECORD",
    "SCHEMA_VIOLATION",
]

EVENT_TYPES = ["session.start", "llm.turn", "tool.call", "session.end", "session.error"]
LIFECYCLE_TYPES = ["session.start", "session.end", "session.error"]
TERMINAL_TYPES = ["session.end", "session.error"]

STATUS_LIFECYCLE_TURN = ["ok", "error"]
STATUS_TOOL = ["success", "failure", "denied", "timeout"]
STATUS_ALIASES = {"succeeded": "success", "ok.": "ok", "failed": "failure", "fail": "failure"}

CONTENT_SOURCES = ["user", "system", "retrieved_web", "tool_output"]
FINISH_REASONS = ["stop", "length", "tool_call", "content_filter"]
INJECTION_INDICATORS = [
    "instruction_override", "role_confusion", "exfil_request",
    "encoded_payload", "tool_coercion", "policy_probe",
]
ERROR_CLASSES = ["TIMEOUT", "AUTH_DENIED", "RATE_LIMIT", "POLICY_DENIED", "TARGET_UNREACHABLE", "INVALID_ARGS"]
TASK_CATEGORIES = [
    "market_research", "ticket_triage", "report_generation",
    "data_query", "code_review", "incident_response",
]

FLOW_PROTOCOLS = ["https", "http", "ssh", "smb", "dns", "rdp"]
FLOW_VERDICTS = ["allowed", "blocked", "logged_only"]

AUDIT_DECISIONS = ["ALLOW", "DENY"]
AUDIT_ACTIONS = ["socket_connect", "file_read", "file_write", "process_spawn", "setuid", "mount", "ptrace"]
ESCALATION_ACTIONS = ["setuid", "mount", "ptrace"]

SIEM_SEVERITIES = ["low", "medium", "high", "critical"]

TENANT_INDUSTRIES = ["finance", "healthcare", "logistics", "retail", "public_sector"]
TENANT_PLANS = ["starter", "growth", "enterprise"]
TENANT_REGIONS = ["eu-west-1", "us-east-1", "me-south-1"]
AGENT_TYPES = ["research", "support", "ops", "analytics", "coding"]
AUTONOMY_LEVELS = ["supervised", "semi_autonomous", "autonomous"]
TOOL_CATEGORIES = ["retrieval", "database", "shell", "network", "filesystem", "messaging", "code_exec"]
RISK_TIERS = ["low", "medium", "high", "critical"]

# ---------------------------------------------------------------- policies
#: A record is "late" when ingest_time - event_time exceeds this (Appendix A).
LATE_THRESHOLD_S = 10.0
#: Batch watermark. None = batch accepts every late record and flags it; the
#: 60 s watermark of Appendix B applies to the Kafka consumer in Milestone 2.
BATCH_WATERMARK_S: float | None = None
#: SIEM <-> network-flow correlation tolerance |detected_at - flow_time| (seconds).
SIEM_TOLERANCE_S = 60.0
#: Year of the syslog file (syslog lines carry no year) and the fallback offset
#: used for a host whose clock cannot be lined up with other sources.
SYSLOG_YEAR = 2026
SYSLOG_DEFAULT_OFFSET_S = 2 * 3600
#: Minimum number of unambiguous audit<->tool.call pairs before a per-host
#: clock offset is trusted; below this the regional/default offset is used.
SYSLOG_MIN_PAIRS = 20
#: Missing token counts are kept as null and excluded from token sums ("null-excluded").
MISSING_TOKENS_POLICY = "null-excluded"
