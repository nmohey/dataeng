"""Build the canonical activity table (Dataset Description section 5) from the
accepted rows of every source, plus the conformed dimensions.

One row shape for everything:

activity_id, source_file, source_format, source_line, event_time_utc, ingest_time_utc,
lateness_s, tenant_id, agent_sk, session_id, task_id, activity_type, activity_subtype,
status, verdict, target_resource, policy_version_applied, is_policy_violation,
risk_indicators, tokens_in, tokens_out, cost_usd, quality_flags

followed by a few *extension* columns that Milestone 2 needs and that would otherwise
have to be re-derived (agent_id, release_version, sequence_number, sandbox_instance_id,
tool_id, model_id, error_class, retry_number, bytes, host, ...). They are documented in
docs/DATA_DICTIONARY.md.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import config as C
from .cleaning import join_flags
from .entities import price_at
from .policies import effective_policy, egress_policy_violation, tool_policy_violation

CANONICAL_COLUMNS = [
    "activity_id", "source_file", "source_format", "source_line",
    "event_time_utc", "ingest_time_utc", "lateness_s",
    "tenant_id", "agent_sk", "session_id", "task_id",
    "activity_type", "activity_subtype", "status", "verdict", "target_resource",
    "policy_version_applied", "is_policy_violation", "risk_indicators",
    "tokens_in", "tokens_out", "cost_usd", "quality_flags",
]
EXTENSION_COLUMNS = [
    "source_record_id", "agent_id", "release_version", "sandbox_instance_id", "sequence_number",
    "tool_id", "tool_version", "model_id", "error_class", "retry_number", "bytes_out", "bytes_in",
    "src_ip", "dst_ip", "dst_port", "protocol", "host", "is_late", "is_terminal", "task_category",
    "expected_tool_categories", "stated_goal", "content_source", "siem_match_status",
]
ACTIVITY_TYPE_OF_EVENT = {"session.start": "lifecycle", "session.end": "lifecycle", "session.error": "lifecycle",
                          "llm.turn": "prompt_turn", "tool.call": "tool_call"}


def _merge_flags(*cols: pd.Series) -> pd.Series:
    df = pd.concat(cols, axis=1)
    return df.apply(lambda r: "|".join(dict.fromkeys(x for v in r if isinstance(v, str) for x in v.split("|") if x)) or None, axis=1)


def session_context(activity_acc: pd.DataFrame, dim_agent: pd.DataFrame) -> pd.DataFrame:
    """One row per accepted session (from its session.start): tenant, agent_sk, profile,
    task fields, start time. Everything else joins to this by session_id."""
    starts = activity_acc[activity_acc["event_type"] == "session.start"].drop_duplicates("session_id")
    sk = dim_agent.set_index(["agent_id", "release_version"])[["agent_sk", "sandbox_profile_id"]]
    ctx = starts[["session_id", "tenant_id", "agent_id", "release_version", "sandbox_instance_id", "task_id",
                  "task_category", "expected_tool_categories", "event_time_utc"]].rename(columns={"event_time_utc": "session_start_utc"})
    ctx = ctx.join(sk, on=["agent_id", "release_version"])
    return ctx.set_index("session_id")


def canonical_from_activity(acc: pd.DataFrame, ctx: pd.DataFrame, dim_agent: pd.DataFrame, dim_policy: pd.DataFrame,
                            policy_allowed_tools: pd.DataFrame, pricing: pd.DataFrame) -> pd.DataFrame:
    a = acc.copy()
    sk = dim_agent.set_index(["agent_id", "release_version"])[["agent_sk", "sandbox_profile_id"]]
    a = a.join(sk, on=["agent_id", "release_version"])
    a["task_id"] = a["session_id"].map(ctx["task_id"])
    a["task_category"] = a["session_id"].map(ctx["task_category"])
    a["expected_tool_categories"] = a["session_id"].map(ctx["expected_tool_categories"])
    pol = effective_policy(a["sandbox_profile_id"], a["event_time_utc"], dim_policy)
    a["policy_sk"], a["policy_version_applied"] = pol["policy_sk"], pol["policy_version_applied"]
    is_tool = a["event_type"] == "tool.call"
    is_turn = a["event_type"] == "llm.turn"
    viol = pd.Series(pd.NA, index=a.index, dtype="boolean")
    viol[is_tool] = tool_policy_violation(a.loc[is_tool, "tool_id"], a.loc[is_tool, "policy_sk"], policy_allowed_tools)
    a["is_policy_violation"] = viol
    # tokens and cost at the price effective at turn time (null-excluded policy: null tokens -> null cost)
    prices = price_at(a["model_id"], a["event_time_utc"], pricing)
    tin = a["input_tokens"].astype("Float64"); tout = a["output_tokens"].astype("Float64")
    a["cost_usd"] = (tin / 1000 * prices["input_price_per_1k"] + tout / 1000 * prices["output_price_per_1k"]).round(6)
    # risk indicators: injection indicators + denials + violations
    ind = a["injection_indicators"].fillna("").astype(str)
    denied = pd.Series(np.where(is_tool & (a["status"] == "denied"), "tool_denied", ""), index=a.index)
    pviol = pd.Series(np.where(a["is_policy_violation"].fillna(False).astype(bool), "policy_violation", ""), index=a.index)
    a["risk_indicators"] = _merge_flags(ind, denied, pviol)
    extra_flags = join_flags({
        "no_policy_for_profile": a["sandbox_profile_id"].notna() & a["policy_sk"].isna(),
        "agent_profile_missing": a["sandbox_profile_id"].isna(),
        "price_missing_for_model": is_turn & prices["input_price_per_1k"].isna(),
        "session_sequence_gap": a["session_has_sequence_gap"],
    }, a.index)
    out = pd.DataFrame({
        "activity_id": "act:" + a["event_id"].astype(str),
        "source_file": a["source_file"], "source_format": "parquet", "source_line": a["source_line"],
        "event_time_utc": a["event_time_utc"], "ingest_time_utc": a["ingest_time_utc"], "lateness_s": a["lateness_s"].round(3),
        "tenant_id": a["tenant_id"], "agent_sk": a["agent_sk"].astype("Int64"), "session_id": a["session_id"], "task_id": a["task_id"],
        "activity_type": a["event_type"].map(ACTIVITY_TYPE_OF_EVENT), "activity_subtype": a["event_type"],
        "status": a["status"], "verdict": None, "target_resource": a["target_resource"],
        "policy_version_applied": a["policy_version_applied"], "is_policy_violation": a["is_policy_violation"],
        "risk_indicators": a["risk_indicators"], "tokens_in": a["input_tokens"], "tokens_out": a["output_tokens"], "cost_usd": a["cost_usd"],
        "quality_flags": _merge_flags(a["quality_flags"], extra_flags),
        "source_record_id": a["event_id"], "agent_id": a["agent_id"], "release_version": a["release_version"],
        "sandbox_instance_id": a["sandbox_instance_id"], "sequence_number": a["sequence_number"],
        "tool_id": a["tool_id"], "tool_version": a["tool_version"], "model_id": a["model_id"], "error_class": a["error_class"],
        "retry_number": a["retry_number"], "bytes_out": a["bytes_out"], "bytes_in": pd.array([pd.NA] * len(a), dtype="Int64"),
        "src_ip": None, "dst_ip": None, "dst_port": pd.array([pd.NA] * len(a), dtype="Int64"), "protocol": None, "host": None,
        "is_late": a["lateness_s"] > C.LATE_THRESHOLD_S, "is_terminal": a["event_type"].isin(C.TERMINAL_TYPES),
        "task_category": a["task_category"], "expected_tool_categories": a["expected_tool_categories"],
        "stated_goal": a["stated_goal"], "content_source": a["content_source"], "siem_match_status": None,
    }, index=a.index)
    return out


def canonical_from_flows(flows: pd.DataFrame, ctx: pd.DataFrame, dim_policy: pd.DataFrame, egress_allowlist: pd.DataFrame,
                         denied_ports: pd.DataFrame, siem_corr: pd.DataFrame) -> pd.DataFrame:
    f = flows.copy()
    for col in ["tenant_id", "agent_sk", "task_id", "sandbox_profile_id", "agent_id", "release_version"]:
        f[col] = f["session_id"].map(ctx[col])
    pol = effective_policy(f["sandbox_profile_id"], f["flow_time_utc"], dim_policy)
    f["policy_sk"], f["policy_version_applied"] = pol["policy_sk"], pol["policy_version_applied"]
    viol, why = egress_policy_violation(f["dst_host"], f["dst_port"], f["policy_sk"], dim_policy, egress_allowlist, denied_ports)
    f["is_policy_violation"], f["violation_reason"] = viol, why
    alerts_per_flow = siem_corr.dropna(subset=["matched_flow_id"]).groupby("matched_flow_id").size()
    f["n_siem_alerts"] = f["flow_id"].map(alerts_per_flow).fillna(0).astype(int)
    risk = _merge_flags(
        pd.Series(np.where(f["verdict"] == "blocked", "egress_blocked", ""), index=f.index),
        pd.Series(np.where(f["verdict"] == "logged_only", "egress_logged_only", ""), index=f.index),
        pd.Series(np.where(f["is_policy_violation"].fillna(False).astype(bool), "egress_violation:" + f["violation_reason"].astype(str), ""), index=f.index),
        pd.Series(np.where(f["n_siem_alerts"] > 0, "siem_alerted", ""), index=f.index),
    )
    extra = join_flags({
        "no_policy_for_profile": f["sandbox_profile_id"].notna() & f["policy_sk"].isna(),
        "runtime_allowed_despite_policy": (f["verdict"] == "allowed") & f["is_policy_violation"].fillna(False).astype(bool),
    }, f.index)
    return pd.DataFrame({
        "activity_id": "nf:" + f["flow_id"].astype(str),
        "source_file": f["source_file"], "source_format": "csv", "source_line": f["source_line"],
        "event_time_utc": f["flow_time_utc"], "ingest_time_utc": pd.NaT, "lateness_s": np.nan,
        "tenant_id": f["tenant_id"], "agent_sk": f["agent_sk"].astype("Int64"), "session_id": f["session_id"], "task_id": f["task_id"],
        "activity_type": "network_flow", "activity_subtype": "egress:" + f["protocol"].astype(str),
        "status": None, "verdict": f["verdict"], "target_resource": f["dst_host"].where(f["dst_host"].notna(), f["dst_ip"]),
        "policy_version_applied": f["policy_version_applied"], "is_policy_violation": f["is_policy_violation"],
        "risk_indicators": risk, "tokens_in": pd.array([pd.NA] * len(f), dtype="Int64"), "tokens_out": pd.array([pd.NA] * len(f), dtype="Int64"), "cost_usd": np.nan,
        "quality_flags": _merge_flags(f["quality_flags"], extra),
        "source_record_id": f["flow_id"], "agent_id": f["agent_id"], "release_version": f["release_version"],
        "sandbox_instance_id": f["sandbox_instance_id"], "sequence_number": pd.array([pd.NA] * len(f), dtype="Int64"),
        "tool_id": None, "tool_version": None, "model_id": None, "error_class": None, "retry_number": pd.array([pd.NA] * len(f), dtype="Int64"),
        "bytes_out": f["bytes_sent"], "bytes_in": f["bytes_received"], "src_ip": f["src_ip"], "dst_ip": f["dst_ip"], "dst_port": f["dst_port"],
        "protocol": f["protocol"], "host": None, "is_late": pd.array([pd.NA] * len(f), dtype="boolean"), "is_terminal": False,
        "task_category": None, "expected_tool_categories": None, "stated_goal": None, "content_source": None, "siem_match_status": None,
    }, index=f.index)


def canonical_from_audit(audit: pd.DataFrame, ctx: pd.DataFrame, dim_policy: pd.DataFrame) -> pd.DataFrame:
    s = audit.copy()
    for col in ["tenant_id", "agent_sk", "task_id", "sandbox_profile_id", "agent_id", "release_version"]:
        s[col] = s["session_id"].map(ctx[col])
    pol = effective_policy(s["sandbox_profile_id"], s["log_time_utc"], dim_policy)
    s["policy_version_applied"] = pol["policy_version_applied"]
    is_deny = s["decision"] == "DENY"
    disagree = s["policy_version_log"].notna() & s["policy_version_applied"].notna() & (s["policy_version_log"] != s["policy_version_applied"])
    risk = _merge_flags(
        pd.Series(np.where(is_deny, "sandbox_deny:" + s["reason"].astype(str), ""), index=s.index),
        pd.Series(np.where(is_deny & s["action"].isin(C.ESCALATION_ACTIONS), "escalation_denied", ""), index=s.index),
        pd.Series(np.where(s["reason"].isin(["NO_NETWORK_POLICY", "WILDCARD_MATCH_UNVERIFIED"]), "runtime_allow_unverified:" + s["reason"].astype(str), ""), index=s.index),
    )
    extra = join_flags({
        "no_policy_for_profile": s["sandbox_profile_id"].notna() & pol["policy_sk"].isna(),
        "policy_version_log_disagrees_with_derived": disagree,
        "syslog_clock_offset_inferred": pd.Series(True, index=s.index),
    }, s.index)
    return pd.DataFrame({
        "activity_id": "sb:" + s["source_file"].astype(str) + "#" + s["source_line"].astype(str),
        "source_file": s["source_file"], "source_format": "syslog", "source_line": s["source_line"],
        "event_time_utc": s["log_time_utc"], "ingest_time_utc": pd.NaT, "lateness_s": np.nan,
        "tenant_id": s["tenant_id"], "agent_sk": s["agent_sk"].astype("Int64"), "session_id": s["session_id"], "task_id": s["task_id"],
        "activity_type": "sandbox_decision", "activity_subtype": s["action"],
        "status": s["decision"].str.lower(), "verdict": s["reason"], "target_resource": s["target"],
        "policy_version_applied": s["policy_version_applied"], "is_policy_violation": is_deny.astype("boolean"),
        "risk_indicators": risk, "tokens_in": pd.array([pd.NA] * len(s), dtype="Int64"), "tokens_out": pd.array([pd.NA] * len(s), dtype="Int64"), "cost_usd": np.nan,
        "quality_flags": _merge_flags(s["quality_flags"], extra),
        "source_record_id": s["source_file"].astype(str) + "#" + s["source_line"].astype(str), "agent_id": s["agent_id"], "release_version": s["release_version"],
        "sandbox_instance_id": s["sandbox_instance_id"], "sequence_number": pd.array([pd.NA] * len(s), dtype="Int64"),
        "tool_id": None, "tool_version": None, "model_id": None, "error_class": None, "retry_number": pd.array([pd.NA] * len(s), dtype="Int64"),
        "bytes_out": pd.array([pd.NA] * len(s), dtype="Int64"), "bytes_in": pd.array([pd.NA] * len(s), dtype="Int64"),
        "src_ip": None, "dst_ip": None, "dst_port": pd.array([pd.NA] * len(s), dtype="Int64"), "protocol": None, "host": s["host"],
        "is_late": pd.array([pd.NA] * len(s), dtype="boolean"), "is_terminal": False,
        "task_category": None, "expected_tool_categories": None, "stated_goal": None, "content_source": None, "siem_match_status": None,
    }, index=s.index)


def canonical_from_siem(alerts: pd.DataFrame, siem_corr: pd.DataFrame, ctx: pd.DataFrame) -> pd.DataFrame:
    s = alerts.merge(siem_corr[["alert_id", "match_status", "matched_flow_id", "matched_session_id", "nearest_flow_delta_s", "unmatched_reason"]], on="alert_id", how="left")
    s.index = alerts.index
    for col in ["tenant_id", "agent_sk", "task_id", "agent_id", "release_version", "sandbox_instance_id"]:
        s[col] = s["matched_session_id"].map(ctx[col])
    risk = _merge_flags(
        pd.Series("siem:" + s["technique_id"].astype(str), index=s.index),
        pd.Series("siem_severity:" + s["severity"].astype(str), index=s.index),
    )
    extra = join_flags({
        "siem_unmatched": s["match_status"] == "unmatched",
        "siem_ambiguous_flow": s["match_status"] == "ambiguous",
        "siem_source_outside_platform": s["unmatched_reason"] == "source_ip_not_a_sandbox",
    }, s.index)
    return pd.DataFrame({
        "activity_id": "al:" + s["alert_id"].astype(str),
        "source_file": s["source_file"], "source_format": "json", "source_line": s["source_line"],
        "event_time_utc": s["detected_at_utc"], "ingest_time_utc": pd.NaT, "lateness_s": np.nan,
        "tenant_id": s["tenant_id"], "agent_sk": s["agent_sk"].astype("Int64"), "session_id": s["matched_session_id"], "task_id": s["task_id"],
        "activity_type": "siem_alert", "activity_subtype": s["rule"],
        "status": s["severity"], "verdict": s["match_status"], "target_resource": s["destination_host"].astype(str) + ":" + s["destination_port"].astype(str),
        "policy_version_applied": pd.array([pd.NA] * len(s), dtype="Int64"), "is_policy_violation": pd.array([pd.NA] * len(s), dtype="boolean"),
        "risk_indicators": risk, "tokens_in": pd.array([pd.NA] * len(s), dtype="Int64"), "tokens_out": pd.array([pd.NA] * len(s), dtype="Int64"), "cost_usd": np.nan,
        "quality_flags": extra,
        "source_record_id": s["alert_id"], "agent_id": s["agent_id"], "release_version": s["release_version"],
        "sandbox_instance_id": s["sandbox_instance_id"], "sequence_number": pd.array([pd.NA] * len(s), dtype="Int64"),
        "tool_id": None, "tool_version": None, "model_id": None, "error_class": None, "retry_number": pd.array([pd.NA] * len(s), dtype="Int64"),
        "bytes_out": pd.array([pd.NA] * len(s), dtype="Int64"), "bytes_in": pd.array([pd.NA] * len(s), dtype="Int64"),
        "src_ip": s["source_ip"], "dst_ip": s["destination_host"], "dst_port": s["destination_port"], "protocol": None, "host": s["source_system"],
        "is_late": pd.array([pd.NA] * len(s), dtype="boolean"), "is_terminal": False,
        "task_category": None, "expected_tool_categories": None, "stated_goal": None, "content_source": None, "siem_match_status": s["match_status"],
    }, index=s.index)


def assemble(parts: list[pd.DataFrame]) -> pd.DataFrame:
    cols = CANONICAL_COLUMNS + EXTENSION_COLUMNS
    out = pd.concat([p[cols] for p in parts], ignore_index=True)
    out["is_policy_violation"] = out["is_policy_violation"].astype("boolean")
    out["policy_version_applied"] = out["policy_version_applied"].astype("Int64")
    for c in ["tokens_in", "tokens_out", "sequence_number", "retry_number", "bytes_out", "bytes_in", "dst_port", "agent_sk"]:
        out[c] = out[c].astype("Int64")
    out["is_late"] = out["is_late"].astype("boolean")
    for c in ["event_time_utc", "ingest_time_utc"]:
        out[c] = pd.to_datetime(out[c], utc=True).astype("datetime64[us, UTC]")
    out = out.sort_values(["event_time_utc", "activity_id"]).reset_index(drop=True)
    return out
