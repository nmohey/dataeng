"""Clean every source: normalise, validate, and split into accepted rows and a rejects
table where each rejected record carries exactly one reason from the closed enum.

How a reason is chosen
----------------------
For every record a boolean *reasons matrix* is built with one column per enum value.
The record's reason is the first True column in enum order (Dataset Description 4).
ORPHAN_EVENT depends on which session.start rows are accepted, so it is evaluated
against the starts that survive the row-local rules; it still sits at its place in the
precedence order when the final reason is picked.

What is repaired (kept, flagged) versus rejected
------------------------------------------------
Repaired, with a ``quality_flags`` entry: alias identifiers (``v2.3.1`` -> ``2.3.1``,
tool names used as tool ids, tn_004 -> tn_003), spelling variants of status
(``succeeded`` -> ``success``), timestamps in a different but decodable format
(epoch ms, dd/mm/yyyy), late records, missing token counts, finished_at before
event_time, latency that disagrees with the derived duration.
Rejected: duplicates, unknown agent/tenant, undecodable timestamps, orphans, invalid
event types, missing required fields, negative counts, unparseable syslog lines,
and values outside a closed enum (SCHEMA_VIOLATION).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from . import config as C
from .entities import normalise_release_version, normalise_status
from .timestamps import (FORMAT_DMY_NAIVE, FORMAT_EPOCH_MS, FORMAT_ISO_OFFSET, FORMAT_ISO_Z, FORMAT_MISSING,
                         infer_host_clock_offsets, lateness_seconds, parse_mixed_timestamps, parse_syslog_naive,
                         syslog_to_utc)

PROVENANCE = ["source_file", "source_line"]
IPV4_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")


# ------------------------------------------------------------------ rejects helper


@dataclass
class RejectCollector:
    """Accumulates rejected records from every source into one table."""
    frames: list[pd.DataFrame] = field(default_factory=list)

    def add(self, rows: pd.DataFrame, raw: pd.DataFrame, source_format: str, key_col: str | None,
            reasons: pd.Series, details: pd.Series) -> None:
        if len(rows) == 0:
            return
        payload_cols = [c for c in raw.columns if c not in PROVENANCE]
        payload = raw.loc[rows.index, payload_cols]
        out = pd.DataFrame({
            "source_file": rows["source_file"].values,
            "source_format": source_format,
            "source_line": rows["source_line"].astype("int64").values,
            "record_key": rows[key_col].astype("string").values if key_col else pd.array([pd.NA] * len(rows), dtype="string"),
            "reject_reason": reasons.loc[rows.index].values,
            "detail": details.loc[rows.index].values,
            "raw_payload": [json.dumps(r, default=str, ensure_ascii=False) for r in payload.astype(object).where(payload.notna(), None).to_dict("records")],
        })
        self.frames.append(out)

    def table(self) -> pd.DataFrame:
        cols = ["source_file", "source_format", "source_line", "record_key", "reject_reason", "detail", "raw_payload"]
        if not self.frames:
            return pd.DataFrame(columns=cols)
        t = pd.concat(self.frames, ignore_index=True)[cols]
        t["reject_reason"] = pd.Categorical(t["reject_reason"], categories=C.REJECT_REASONS)
        t = t.sort_values(["source_file", "source_line"]).reset_index(drop=True)
        t.insert(0, "reject_id", range(1, len(t) + 1))
        t["reject_reason"] = t["reject_reason"].astype(str)
        return t


def first_reason(matrix: pd.DataFrame) -> pd.Series:
    """First True column, in REJECT_REASONS order; None when no reason applies."""
    m = matrix.reindex(columns=[r for r in C.REJECT_REASONS if r in matrix.columns]).fillna(False).astype(bool)
    arr = m.to_numpy()
    cols = np.array(m.columns, dtype=object)
    any_true = arr.any(axis=1)
    values = np.where(any_true, cols[arr.argmax(axis=1)], None)
    return pd.Series(values, index=m.index, dtype="object")


def join_flags(flags: dict[str, pd.Series], index: pd.Index) -> pd.Series:
    """{flag_name: boolean mask} -> pipe-separated string per row (None when no flag)."""
    names = list(flags)
    if not names:
        return pd.Series(None, index=index, dtype="object")
    mat = np.column_stack([flags[n].reindex(index).fillna(False).astype(bool).to_numpy() for n in names])
    arr = np.array(names, dtype=object)
    out = ["|".join(arr[row]) if row.any() else None for row in mat]
    return pd.Series(out, index=index, dtype="object")


def _detail(frame: pd.DataFrame, reason: pd.Series, detail_by_reason: dict[str, pd.Series | str]) -> pd.Series:
    """Human-readable detail per rejected row, chosen by its reason (a Series per reason,
    or one constant string)."""
    d = pd.Series(None, index=frame.index, dtype="object")
    for r, s in detail_by_reason.items():
        m = (reason == r).fillna(False).astype(bool)
        if m.any():
            d[m] = s if isinstance(s, str) else s.reindex(frame.index)[m].astype("string").values
    return d.fillna(reason.astype("string"))


# --------------------------------------------------------------------- activity


def clean_activity(bronze: pd.DataFrame, dim_tenant: pd.DataFrame, tenant_alias: dict, dim_agent: pd.DataFrame,
                   agent_alias: dict, dim_tool: pd.DataFrame, tool_alias: dict, pricing: pd.DataFrame,
                   rejects: RejectCollector, naive_offset_hours: float = 0.0) -> tuple[pd.DataFrame, dict]:
    """Normalise and validate agent_activity.parquet. Returns (accepted, report)."""
    raw = bronze
    df = bronze.copy()
    n_received = len(df)
    flags: dict[str, pd.Series] = {}

    # --- 1. normalise identifiers and spellings (repairs, each one flagged)
    rv = normalise_release_version(df["release_version"])
    flags["release_version_alias"] = (rv != df["release_version"]).fillna(False)
    df["release_version"] = rv
    key = list(zip(df["agent_id"], df["release_version"]))
    aliased = [agent_alias.get(k, k) for k in key]
    df["release_version"] = [k[1] for k in aliased]
    df["agent_id"] = [k[0] for k in aliased]

    tenant_new = df["tenant_id"].replace(tenant_alias)
    flags["tenant_alias"] = (tenant_new != df["tenant_id"]).fillna(False)
    df["tenant_id"] = tenant_new

    tool_new = df["tool_id"].map(lambda t: tool_alias.get(t, t) if isinstance(t, str) else t)
    flags["tool_name_resolved_to_id"] = (tool_new != df["tool_id"]).fillna(False) & df["tool_id"].notna()
    df["tool_id"] = tool_new

    status_new, status_changed = normalise_status(df["status"])
    flags["status_spelling_normalised"] = status_changed
    df["status"] = status_new.astype("object").where(status_new.notna(), None)

    # --- 2. timestamps -> UTC
    df["event_time_utc"], ev_fmt = parse_mixed_timestamps(df["event_time"], naive_offset_hours)
    df["ingest_time_utc"], in_fmt = parse_mixed_timestamps(df["ingest_time"], naive_offset_hours)
    df["finished_at_utc"], _ = parse_mixed_timestamps(df["finished_at"], naive_offset_hours)
    df["event_time_format"] = ev_fmt
    df["lateness_s"] = lateness_seconds(df["event_time_utc"], df["ingest_time_utc"])
    flags["event_time_epoch_ms"] = ev_fmt == FORMAT_EPOCH_MS
    flags["event_time_dd_mm_yyyy_naive"] = ev_fmt == FORMAT_DMY_NAIVE
    flags["late_event"] = df["lateness_s"] > C.LATE_THRESHOLD_S
    flags["negative_lateness"] = df["lateness_s"] < 0

    # --- 3. reasons matrix, in enum order
    R = pd.DataFrame(index=df.index)
    order = df.assign(_it=df["ingest_time_utc"]).sort_values(["_it", "source_line"], na_position="last")
    dup = order["event_id"].duplicated(keep="first")  # earliest ingest_time copy survives
    R["DUPLICATE_EVENT_ID"] = dup.reindex(df.index)

    agent_keys = set(zip(dim_agent["agent_id"], dim_agent["release_version"]))
    R["UNKNOWN_AGENT_ID"] = ~pd.Series([k in agent_keys for k in zip(df["agent_id"], df["release_version"])], index=df.index)
    R["UNKNOWN_TENANT_ID"] = ~df["tenant_id"].isin(set(dim_tenant["tenant_id"]))

    R["MALFORMED_TIMESTAMP"] = ((df["event_time"].notna() & df["event_time_utc"].isna())
                                | (df["ingest_time"].notna() & df["ingest_time_utc"].isna()))

    R["INVALID_EVENT_TYPE"] = ~df["event_type"].isin(C.EVENT_TYPES)

    required_all = ["event_id", "event_time", "ingest_time", "sequence_number", "event_type", "session_id",
                    "tenant_id", "agent_id", "release_version", "sandbox_instance_id", "status"]
    missing = df[required_all].isna().any(axis=1)
    is_turn, is_tool, is_start = df["event_type"] == "llm.turn", df["event_type"] == "tool.call", df["event_type"] == "session.start"
    missing |= is_turn & df[["model_id", "turn_index", "input_tokens"]].isna().any(axis=1)
    missing |= is_tool & df[["tool_id", "tool_version", "retry_number"]].isna().any(axis=1)
    missing |= is_start & df["task_id"].isna()
    R["MISSING_REQUIRED_FIELD"] = missing

    num_rules = {"sequence_number": 1, "latency_ms": 0, "turn_index": 0, "input_tokens": 0, "output_tokens": 0,
                 "retry_number": 0, "bytes_out": 0}
    bad_num = pd.Series(False, index=df.index)
    num_detail = pd.Series(None, index=df.index, dtype="object")
    for col, lo in num_rules.items():
        v = pd.to_numeric(df[col], errors="coerce")
        m = v.notna() & (v < lo)
        num_detail[m & ~bad_num] = col + "=" + v[m & ~bad_num].astype("Int64").astype(str) + f" (< {lo})"
        bad_num |= m
    R["INVALID_NUMERIC_RANGE"] = bad_num

    R["LATE_BEYOND_WATERMARK"] = (df["lateness_s"] > C.BATCH_WATERMARK_S) if C.BATCH_WATERMARK_S is not None else False

    schema = pd.Series(False, index=df.index)
    schema_detail = pd.Series(None, index=df.index, dtype="object")
    def _viol(mask, text):
        nonlocal schema
        schema_detail[mask & ~schema] = text
        schema |= mask
    lifecycle_or_turn = df["event_type"].isin(C.LIFECYCLE_TYPES + ["llm.turn"])
    _viol(lifecycle_or_turn & df["status"].notna() & ~df["status"].isin(C.STATUS_LIFECYCLE_TURN), "status not in {ok,error}")
    _viol(is_tool & df["status"].notna() & ~df["status"].isin(C.STATUS_TOOL), "tool status not in enum")
    _viol(is_turn & df["content_source"].notna() & ~df["content_source"].isin(C.CONTENT_SOURCES), "content_source not in enum")
    _viol(is_turn & df["finish_reason"].notna() & ~df["finish_reason"].isin(C.FINISH_REASONS), "finish_reason not in enum")
    ind_ok = df["injection_indicators"].fillna("").map(lambda s: all(tok in C.INJECTION_INDICATORS for tok in s.split("|") if tok))
    _viol(is_turn & ~ind_ok, "injection_indicators token not in enum")
    _viol(is_tool & df["error_class"].notna() & ~df["error_class"].isin(C.ERROR_CLASSES), "error_class not in enum")
    _viol(is_start & df["task_category"].notna() & ~df["task_category"].isin(C.TASK_CATEGORIES), "task_category not in enum")
    tool_keys = set(zip(dim_tool["tool_id"], dim_tool["tool_version"]))
    _viol(is_tool & df["tool_id"].notna() & ~pd.Series([k in tool_keys for k in zip(df["tool_id"], df["tool_version"])], index=df.index), "tool (id, version) not in tools.csv")
    _viol(is_turn & df["model_id"].notna() & ~df["model_id"].isin(set(pricing["model_id"])), "model_id not in model_pricing.csv")
    R["SCHEMA_VIOLATION"] = schema

    # ORPHAN_EVENT: non-start rows whose session has no start that survives the row-local rules
    local = R.drop(columns=[c for c in R.columns if c == "ORPHAN_EVENT"]).fillna(False).astype(bool).any(axis=1)
    accepted_starts = set(df.loc[is_start & ~local, "session_id"])
    R["ORPHAN_EVENT"] = ~is_start & ~df["session_id"].isin(accepted_starts)

    reason = first_reason(R)
    rejected_mask = reason.notna()
    details = _detail(df, reason, {
        "DUPLICATE_EVENT_ID": "event_id " + df["event_id"].astype(str) + " already accepted with earlier ingest_time",
        "UNKNOWN_AGENT_ID": "(" + df["agent_id"].astype(str) + ", " + df["release_version"].astype(str) + ") not in agents.csv",
        "UNKNOWN_TENANT_ID": "tenant_id " + df["tenant_id"].astype(str) + " not in tenants.csv",
        "MALFORMED_TIMESTAMP": "event_time=" + df["event_time"].astype(str) + " ingest_time=" + df["ingest_time"].astype(str),
        "ORPHAN_EVENT": "session " + df["session_id"].astype(str) + " has no accepted session.start",
        "INVALID_EVENT_TYPE": "event_type=" + df["event_type"].astype(str),
        "MISSING_REQUIRED_FIELD": "null in: " + df[required_all + ["model_id", "turn_index", "input_tokens", "tool_id", "tool_version", "retry_number", "task_id"]].isna().apply(lambda r: ",".join(r.index[r]), axis=1),
        "INVALID_NUMERIC_RANGE": num_detail,
        "SCHEMA_VIOLATION": schema_detail,
    })
    rejects.add(df[rejected_mask], raw, "parquet", "event_id", reason, details)

    # --- 4. accepted rows: typed columns and quality flags
    acc = df[~rejected_mask].copy()
    for col in ["sequence_number", "latency_ms", "turn_index", "input_tokens", "output_tokens", "retry_number", "bytes_out"]:
        acc[col] = pd.to_numeric(acc[col], errors="coerce").astype("Int64")
    acc_is_turn, acc_is_tool = acc["event_type"] == "llm.turn", acc["event_type"] == "tool.call"
    flags["missing_output_tokens"] = acc_is_turn & acc["output_tokens"].isna()
    flags["finished_before_event_time"] = acc_is_tool & acc["finished_at_utc"].notna() & (acc["finished_at_utc"] < acc["event_time_utc"])
    fin_lat = (acc["finished_at_utc"] - acc["event_time_utc"]).dt.total_seconds() * 1000
    flags["latency_disagrees_with_finished_at"] = acc_is_tool & acc["latency_ms"].notna() & fin_lat.notna() & ((fin_lat - acc["latency_ms"].astype("float")).abs() > 1)
    flags["status_conflicts_with_error_class"] = acc_is_tool & (acc["status"] == "success") & acc["error_class"].notna()
    acc["quality_flags"] = join_flags({k: v for k, v in flags.items()}, acc.index)

    # sequence gaps per session (computed on accepted rows; used by trace completeness)
    seq = acc.groupby("session_id")["sequence_number"].agg(["min", "max", "count"])
    gap_sessions = set(seq.index[(seq["min"] != 1) | (seq["max"] != seq["count"])])
    acc["session_has_sequence_gap"] = acc["session_id"].isin(gap_sessions)

    report = {
        "received": n_received,
        "accepted": int(len(acc)),
        "rejected": int(rejected_mask.sum()),
        "rejected_by_reason": reason[rejected_mask].value_counts().to_dict(),
        "event_time_formats": ev_fmt.value_counts().to_dict(),
        "repairs": {k: int(v.reindex(acc.index).fillna(False).sum()) for k, v in flags.items()},
        "late_accepted": int(flags["late_event"].reindex(acc.index).fillna(False).sum()),
        "sessions_with_sequence_gap": len(gap_sessions),
    }
    return acc, report


# ------------------------------------------------------------------------ flows


def clean_flows(bronze: pd.DataFrame, accepted_sessions: set, session_instance: pd.Series,
                rejects: RejectCollector) -> tuple[pd.DataFrame, dict]:
    raw = bronze
    df = bronze.copy()
    df["flow_time_utc"], fmt = parse_mixed_timestamps(df["flow_time"])
    for c in ["bytes_sent", "bytes_received", "dst_port"]:
        df[c + "_num"] = pd.to_numeric(df[c], errors="coerce")

    R = pd.DataFrame(index=df.index)
    order = df.sort_values(["flow_time_utc", "source_line"], na_position="last")
    R["DUPLICATE_EVENT_ID"] = order["flow_id"].duplicated(keep="first").reindex(df.index)
    R["MALFORMED_TIMESTAMP"] = df["flow_time"].notna() & df["flow_time_utc"].isna()
    required = ["flow_id", "session_id", "sandbox_instance_id", "flow_time", "src_ip", "dst_ip", "dst_port", "protocol",
                "bytes_sent", "bytes_received", "verdict"]
    R["MISSING_REQUIRED_FIELD"] = df[required].isna().any(axis=1)
    bad_num = ((df["bytes_sent_num"] < 0) | (df["bytes_received_num"] < 0)
               | (df["dst_port_num"].notna() & ~df["dst_port_num"].between(1, 65535))
               | (df["bytes_sent"].notna() & df["bytes_sent_num"].isna()) | (df["bytes_received"].notna() & df["bytes_received_num"].isna()))
    R["INVALID_NUMERIC_RANGE"] = bad_num
    schema = (~df["protocol"].isin(C.FLOW_PROTOCOLS) & df["protocol"].notna()) | (~df["verdict"].isin(C.FLOW_VERDICTS) & df["verdict"].notna())
    schema |= df["src_ip"].notna() & ~df["src_ip"].astype(str).str.match(IPV4_RE)
    schema |= df["dst_ip"].notna() & ~df["dst_ip"].astype(str).str.match(IPV4_RE)
    R["SCHEMA_VIOLATION"] = schema
    R["ORPHAN_EVENT"] = ~df["session_id"].isin(accepted_sessions)

    reason = first_reason(R)
    rejected_mask = reason.notna()
    details = _detail(df, reason, {
        "DUPLICATE_EVENT_ID": "flow_id " + df["flow_id"].astype(str) + " repeated",
        "MALFORMED_TIMESTAMP": "flow_time=" + df["flow_time"].astype(str),
        "ORPHAN_EVENT": "session " + df["session_id"].astype(str) + " has no accepted session.start",
        "MISSING_REQUIRED_FIELD": "null in: " + df[required].isna().apply(lambda r: ",".join(r.index[r]), axis=1),
        "INVALID_NUMERIC_RANGE": "bytes_sent=" + df["bytes_sent"].astype(str) + " bytes_received=" + df["bytes_received"].astype(str) + " dst_port=" + df["dst_port"].astype(str),
        "SCHEMA_VIOLATION": "protocol=" + df["protocol"].astype(str) + " verdict=" + df["verdict"].astype(str),
    })
    rejects.add(df[rejected_mask], raw, "csv", "flow_id", reason, details)

    acc = df[~rejected_mask].copy()
    acc["dst_port"] = acc["dst_port_num"].astype("Int64")
    acc["bytes_sent"] = acc["bytes_sent_num"].astype("Int64")
    acc["bytes_received"] = acc["bytes_received_num"].astype("Int64")
    acc = acc.drop(columns=["bytes_sent_num", "bytes_received_num", "dst_port_num"])
    flags = {
        "dst_host_missing_ip_only_flow": acc["dst_host"].isna(),
        "geo_country_missing": acc["geo_country"].isna(),
        "instance_differs_from_activity": acc["session_id"].map(session_instance).notna() & (acc["session_id"].map(session_instance) != acc["sandbox_instance_id"]),
    }
    acc["quality_flags"] = join_flags(flags, acc.index)
    report = {"received": len(df), "accepted": int(len(acc)), "rejected": int(rejected_mask.sum()),
              "rejected_by_reason": reason[rejected_mask].value_counts().to_dict(),
              "flow_time_formats": fmt.value_counts().to_dict(),
              "flags": {k: int(v.sum()) for k, v in flags.items()}}
    return acc, report


# ------------------------------------------------------------------------ audit


def clean_audit(parsed: pd.DataFrame, unparsed: pd.DataFrame, accepted_sessions: set, session_instance: pd.Series,
                accepted_tool_calls: pd.DataFrame, rejects: RejectCollector) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Validate the regex-parsed syslog, infer per-host clock offsets, convert to UTC.
    Returns (accepted, host_offsets, report)."""
    df = parsed.copy()
    raw = parsed.copy()
    df["log_time_naive"] = parse_syslog_naive(df["mon"], df["day"], df["time"], C.SYSLOG_YEAR)
    df["policy_version_log"] = pd.to_numeric(df["policy_version"].replace("-", None), errors="coerce").astype("Int64")

    # header-level failures (lines the regex could not read at all)
    if len(unparsed):
        u = unparsed.copy()
        rsn = pd.Series("UNPARSEABLE_RECORD", index=u.index)
        det = pd.Series("syslog header does not match '<Mon> <dd> <HH:MM:SS> <host> <proc>[pid]: ...'", index=u.index)
        rejects.add(u, u, "syslog", None, rsn, det)

    R = pd.DataFrame(index=df.index)
    kv_fields = ["session_id", "sandbox_instance_id", "decision", "action", "target", "reason", "policy_version"]
    truncated = df[kv_fields].isna().any(axis=1)
    R["UNPARSEABLE_RECORD"] = truncated  # a key=value field is missing: the line was cut short
    natural_key = ["mon", "day", "time", "host", "pid"] + kv_fields
    R["DUPLICATE_EVENT_ID"] = df.duplicated(natural_key, keep="first") & ~truncated
    R["MALFORMED_TIMESTAMP"] = df["log_time_naive"].isna()
    R["ORPHAN_EVENT"] = ~df["session_id"].isin(accepted_sessions) & ~truncated
    R["SCHEMA_VIOLATION"] = (~truncated & (~df["decision"].isin(C.AUDIT_DECISIONS) | ~df["action"].isin(C.AUDIT_ACTIONS)
                                           | (df["policy_version"].notna() & ~df["policy_version"].astype(str).str.fullmatch(r"-|\d+"))))
    reason = first_reason(R)
    rejected_mask = reason.notna()
    details = _detail(df, reason, {
        "UNPARSEABLE_RECORD": "truncated line, missing: " + df[kv_fields].isna().apply(lambda r: ",".join(r.index[r]), axis=1),
        "DUPLICATE_EVENT_ID": "identical line already accepted (natural key = time, host, pid and all key=value fields)",
        "MALFORMED_TIMESTAMP": "log time " + df["mon"].astype(str) + " " + df["day"].astype(str) + " " + df["time"].astype(str),
        "ORPHAN_EVENT": "session " + df["session_id"].astype(str) + " has no accepted session.start",
        "SCHEMA_VIOLATION": "decision=" + df["decision"].astype(str) + " action=" + df["action"].astype(str) + " policy_version=" + df["policy_version"].astype(str),
    })
    rejects.add(df[rejected_mask], raw.drop(columns=[c for c in ["raw_line"] if c in raw.columns]).assign(raw_line=raw["raw_line"]),
                "syslog", "session_id", reason, details)

    acc = df[~rejected_mask].copy()
    # clock: per-host offset from unambiguous (session, target) alignment with tool calls
    host_offsets = infer_host_clock_offsets(acc[["host", "session_id", "target", "log_time_naive"]],
                                            accepted_tool_calls[["session_id", "target_resource", "event_time_utc"]])
    acc["log_time_utc"] = syslog_to_utc(acc["log_time_naive"], acc["host"], host_offsets)
    acc["policy_version_log"] = acc["policy_version_log"]
    default_hosts = set(host_offsets.loc[host_offsets["method"] == "default_offset", "host"])
    flags = {
        "policy_version_missing_in_log": acc["policy_version"] == "-",
        "host_offset_defaulted": acc["host"].isin(default_hosts),
        "instance_differs_from_activity": acc["session_id"].map(session_instance).notna() & (acc["session_id"].map(session_instance) != acc["sandbox_instance_id"]),
        "escalation_attempt": acc["action"].isin(C.ESCALATION_ACTIONS),
    }
    acc["quality_flags"] = join_flags(flags, acc.index)
    report = {"received": len(parsed) + len(unparsed), "header_unparseable": int(len(unparsed)), "accepted": int(len(acc)),
              "rejected": int(rejected_mask.sum()) + int(len(unparsed)),
              "rejected_by_reason": {**reason[rejected_mask].value_counts().to_dict(), **({"UNPARSEABLE_RECORD(header)": int(len(unparsed))} if len(unparsed) else {})},
              "flags": {k: int(v.sum()) for k, v in flags.items()},
              "hosts": int(host_offsets.shape[0]), "hosts_defaulted": len(default_hosts)}
    return acc, host_offsets, report


# ------------------------------------------------------------------------- siem


def clean_siem(bronze: pd.DataFrame, rejects: RejectCollector) -> tuple[pd.DataFrame, dict]:
    raw = bronze
    df = bronze.copy()
    df["detected_at_utc"], fmt = parse_mixed_timestamps(df["detected_at"])
    df["detected_at_offset"] = df["detected_at"].astype("string").str.extract(r"([+-]\d{2}:\d{2}|Z)$")[0]
    df["confidence_num"] = pd.to_numeric(df["confidence"], errors="coerce")
    df["dst_port_num"] = pd.to_numeric(df["destination.port"], errors="coerce")

    R = pd.DataFrame(index=df.index)
    order = df.sort_values(["detected_at_utc", "source_line"], na_position="last")
    R["DUPLICATE_EVENT_ID"] = order["alert_id"].duplicated(keep="first").reindex(df.index)
    R["MALFORMED_TIMESTAMP"] = df["detected_at"].notna() & df["detected_at_utc"].isna()
    required = ["alert_id", "detected_at", "source_ip", "destination.host", "destination.port", "severity", "technique.id"]
    R["MISSING_REQUIRED_FIELD"] = df[required].isna().any(axis=1)
    R["INVALID_NUMERIC_RANGE"] = ((df["confidence_num"].notna() & ~df["confidence_num"].between(0, 1))
                                  | (df["dst_port_num"].notna() & ~df["dst_port_num"].between(1, 65535)))
    R["SCHEMA_VIOLATION"] = ((df["severity"].notna() & ~df["severity"].isin(C.SIEM_SEVERITIES))
                             | (df["source_ip"].notna() & ~df["source_ip"].astype(str).str.match(IPV4_RE))
                             | (df["technique.id"].notna() & ~df["technique.id"].astype(str).str.fullmatch(r"T\d{4}(\.\d{3})?")))
    reason = first_reason(R)
    rejected_mask = reason.notna()
    details = _detail(df, reason, {
        "DUPLICATE_EVENT_ID": "alert_id " + df["alert_id"].astype(str) + " repeated",
        "MALFORMED_TIMESTAMP": "detected_at=" + df["detected_at"].astype(str),
        "MISSING_REQUIRED_FIELD": "null in: " + df[required].isna().apply(lambda r: ",".join(r.index[r]), axis=1),
        "INVALID_NUMERIC_RANGE": "confidence=" + df["confidence"].astype(str) + " port=" + df["destination.port"].astype(str),
        "SCHEMA_VIOLATION": "severity=" + df["severity"].astype(str) + " source_ip=" + df["source_ip"].astype(str) + " technique=" + df["technique.id"].astype(str),
    })
    rejects.add(df[rejected_mask], raw, "json", "alert_id", reason, details)
    acc = df[~rejected_mask].copy()
    acc = acc.rename(columns={"destination.host": "destination_host", "destination.port": "destination_port",
                              "technique.id": "technique_id", "technique.name": "technique_name"})
    acc["destination_port"] = acc["dst_port_num"].astype("Int64")
    acc["confidence"] = acc["confidence_num"]
    acc = acc.drop(columns=["dst_port_num", "confidence_num"])
    report = {"received": len(df), "accepted": int(len(acc)), "rejected": int(rejected_mask.sum()),
              "rejected_by_reason": reason[rejected_mask].value_counts().to_dict(),
              "detected_at_offsets_by_source_system": pd.crosstab(df["source_system"], df["detected_at_offset"]).to_dict()}
    return acc, report


# -------------------------------------------------------------- reference tables


def reject_reference_duplicates(tools_bronze: pd.DataFrame, rejects: RejectCollector) -> int:
    """tools.csv carries an exact duplicate row for (tl_vector_search, 2.0.1): keep the
    first, reject the copy as DUPLICATE_EVENT_ID (natural key = tool_id, tool_version)."""
    body = tools_bronze.drop(columns=PROVENANCE)
    dup = body.duplicated(keep="first")
    if dup.any():
        reason = pd.Series("DUPLICATE_EVENT_ID", index=tools_bronze.index)
        det = "tool (" + tools_bronze["tool_id"].astype(str) + ", " + tools_bronze["tool_version"].astype(str) + ") already present"
        rejects.add(tools_bronze[dup], tools_bronze, "csv", "tool_id", reason, det)
    return int(dup.sum())
