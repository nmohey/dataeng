"""The four Milestone-1 metrics (Project Description 4, numbers 1, 2, 8, 9) computed in
pandas over the curated output, each reported with the policy behind it.

Conventions (Dataset Description, Appendix A):
* terminal session   = accepted session with a session.end or session.error row
* duration           = terminal event_time_utc - session.start event_time_utc
* late event         = ingest_time - event_time > 10 s
* trace complete     = terminal session with >= 1 llm.turn and no gap in accepted sequence_numbers
* percentiles        = linear interpolation between closest ranks (numpy default)
* missing tokens     = null-excluded (declared; the effect is shown in ``token_policy_sensitivity``)
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import config as C


def _metric(name, value, numerator=None, denominator=None, **policy):
    return {"metric": name, "value": value, "numerator": numerator, "denominator": denominator, **policy}


def _sessions(canon: pd.DataFrame) -> pd.DataFrame:
    """Per-session frame from the canonical activity rows (parquet-sourced only)."""
    act = canon[canon["source_format"] == "parquet"]
    starts = act[act["activity_subtype"] == "session.start"].groupby("session_id")["event_time_utc"].min().rename("start_utc")
    term = act[act["activity_subtype"].isin(C.TERMINAL_TYPES)].sort_values("event_time_utc").drop_duplicates("session_id", keep="last").set_index("session_id")
    s = pd.DataFrame({"start_utc": starts})
    s["terminal_type"] = term["activity_subtype"].reindex(s.index)
    s["terminal_utc"] = term["event_time_utc"].reindex(s.index)
    s["n_turns"] = act[act["activity_subtype"] == "llm.turn"].groupby("session_id").size().reindex(s.index).fillna(0).astype(int)
    s["n_tool_calls"] = act[act["activity_subtype"] == "tool.call"].groupby("session_id").size().reindex(s.index).fillna(0).astype(int)
    seq = act.groupby("session_id")["sequence_number"].agg(["min", "max", "count"]).reindex(s.index)
    s["sequence_contiguous"] = (seq["min"] == 1) & (seq["max"] == seq["count"])
    s["is_terminal"] = s["terminal_type"].notna()
    s["duration_s"] = (s["terminal_utc"] - s["start_utc"]).dt.total_seconds()
    s["tenant_id"] = act[act["activity_subtype"] == "session.start"].drop_duplicates("session_id").set_index("session_id")["tenant_id"].reindex(s.index)
    s["agent_id"] = act[act["activity_subtype"] == "session.start"].drop_duplicates("session_id").set_index("session_id")["agent_id"].reindex(s.index)
    return s


def metric_1_session_volume(sessions: pd.DataFrame) -> list[dict]:
    term = sessions[sessions["is_terminal"]]
    n = int(len(term))
    succ = int((term["terminal_type"] == "session.end").sum())
    err = int((term["terminal_type"] == "session.error").sum())
    pol = dict(population_filter="accepted sessions with an accepted session.start AND a terminal row (session.end or session.error)",
               late_event_policy="late rows are accepted (batch has no watermark), so they count",
               null_policy="n/a (counts of rows)")
    return [
        _metric("1a. session volume (terminal sessions)", n, n, None, denominator_definition="distinct session_id with a terminal event", **pol),
        _metric("1b. success rate", round(succ / n, 6) if n else None, succ, n, denominator_definition="terminal sessions", **pol),
        _metric("1c. error rate", round(err / n, 6) if n else None, err, n, denominator_definition="terminal sessions", **pol),
        _metric("1d. sessions started but not terminated (excluded from 1a-1c)", int((~sessions["is_terminal"]).sum()), None, None, **pol),
    ]


def metric_2_duration(sessions: pd.DataFrame) -> list[dict]:
    d = sessions.loc[sessions["is_terminal"], "duration_s"].dropna()
    pol = dict(population_filter="terminal (completed) sessions; duration = terminal event_time_utc - session.start event_time_utc",
               late_event_policy="late rows accepted; a late terminal row still defines the session end",
               null_policy="sessions whose start or terminal timestamp was rejected (MALFORMED_TIMESTAMP) have no duration and are excluded",
               percentile_method="linear interpolation between closest ranks (numpy.percentile default)")
    return [
        _metric("2a. p50 session duration (s)", round(float(np.percentile(d, 50)), 3), None, int(len(d)), **pol),
        _metric("2b. p95 session duration (s)", round(float(np.percentile(d, 95)), 3), None, int(len(d)), **pol),
        _metric("2c. negative or zero durations", int((d <= 0).sum()), None, int(len(d)), **pol),
    ]


def metric_8_completeness_and_coverage(sessions: pd.DataFrame, siem_corr: pd.DataFrame) -> list[dict]:
    term = sessions[sessions["is_terminal"]]
    complete = term["sequence_contiguous"] & (term["n_turns"] >= 1)
    n = int(len(term))
    pol = dict(population_filter="terminal sessions; complete = has >= 1 accepted llm.turn and accepted sequence_numbers run 1..max without a gap",
               late_event_policy="late rows accepted, so a late row closes a gap rather than opening one",
               null_policy="rows rejected for any reason are absent, so a rejected row in the middle of a session creates a gap")
    tot = int(len(siem_corr))
    matched_session = int(siem_corr["matched_session_id"].notna().sum())
    matched_flow = int((siem_corr["match_status"] == "matched").sum())
    inplat = int((siem_corr["unmatched_reason"] != "source_ip_not_a_sandbox").sum())
    cpol = dict(population_filter="all accepted SIEM alerts",
                correlation_rule=f"source_ip = src_ip AND destination.host = dst_ip AND destination.port = dst_port AND |detected_at - flow_time| <= {siem_corr['tolerance_s'].iloc[0] if len(siem_corr) else C.SIEM_TOLERANCE_S} s",
                late_event_policy="n/a (no ingest_time on alerts or flows)",
                null_policy="alerts whose source_ip is not a sandbox address are unmatched by construction and stay in the denominator")
    return [
        _metric("8a. trace completeness", round(float(complete.sum()) / n, 6) if n else None, int(complete.sum()), n, **pol),
        _metric("8b. terminal sessions with a sequence gap", int((~term["sequence_contiguous"]).sum()), None, n, **pol),
        _metric("8c. terminal sessions with no llm.turn", int((term["n_turns"] == 0).sum()), None, n, **pol),
        _metric("8d. correlation coverage (alerts linked to a session / all alerts)", round(matched_session / tot, 6) if tot else None, matched_session, tot, **cpol),
        _metric("8e. correlation coverage (alerts matched to exactly one flow / all alerts)", round(matched_flow / tot, 6) if tot else None, matched_flow, tot, **cpol),
        _metric("8f. correlation coverage among alerts from sandbox addresses", round(matched_session / inplat, 6) if inplat else None, matched_session, inplat, **cpol),
    ]


def metric_9_rejected_and_late(reports: dict, rejects: pd.DataFrame, canon: pd.DataFrame) -> list[dict]:
    received = {k: v["received"] for k, v in reports.items()}
    rejected = rejects.groupby("source_file").size().to_dict()
    out = []
    tot_rec = sum(received.values()); tot_rej = int(len(rejects))
    pol = dict(population_filter="every record received from the nine input files (rows for CSV/Parquet, array elements for JSON, lines for syslog)",
               late_event_policy="LATE_BEYOND_WATERMARK is never raised in batch (watermark = none); late rows are accepted and flagged",
               null_policy="a record is rejected when a required field is null; optional nulls are kept")
    out.append(_metric("9a. rejected-record rate (all sources)", round(tot_rej / tot_rec, 6), tot_rej, tot_rec, **pol))
    for f, n in received.items():
        r = int(rejected.get(f, 0))
        out.append(_metric(f"9a. rejected-record rate: {f}", round(r / n, 6) if n else None, r, n, **pol))
    act = canon[canon["source_format"] == "parquet"]
    late = int(act["is_late"].fillna(False).sum()); acc = int(len(act))
    out.append(_metric("9b. late-event rate (late accepted / accepted activity rows)", round(late / acc, 6), late, acc,
                       population_filter="accepted agent_activity rows (the only source that carries ingest_time)",
                       late_definition=f"ingest_time_utc - event_time_utc > {C.LATE_THRESHOLD_S} s", **{k: v for k, v in pol.items() if k != "population_filter"}))
    by_reason = rejects["reject_reason"].value_counts()
    for reason, n in by_reason.items():
        out.append(_metric(f"9c. rejected by reason: {reason}", int(n), int(n), tot_rec, **pol))
    return out


def token_policy_sensitivity(canon: pd.DataFrame) -> pd.DataFrame:
    """Effect of the missing-token policy on token statistics: null-excluded vs zero-filled."""
    turns = canon[canon["activity_subtype"] == "llm.turn"]
    tout = turns["tokens_out"].astype("Float64")
    rows = []
    for policy, series in [("null-excluded (declared)", tout.dropna()), ("zero-filled", tout.fillna(0))]:
        rows.append({"policy": policy, "turns_in_denominator": int(len(series)), "mean_output_tokens_per_turn": round(float(series.mean()), 3),
                     "total_output_tokens": int(series.sum()), "p50_output_tokens": float(series.median())})
    rows.append({"policy": "turns with null output_tokens", "turns_in_denominator": int(tout.isna().sum()), "mean_output_tokens_per_turn": None, "total_output_tokens": None, "p50_output_tokens": None})
    return pd.DataFrame(rows)


def latency_cross_check(sessions: pd.DataFrame, accepted_activity: pd.DataFrame | None, tolerance_s: float = 1.0) -> list[dict]:
    """latency_ms on the terminal row is per-event and only a cross-check: report how often
    it disagrees with the derived duration by more than ``tolerance_s``."""
    if accepted_activity is None or "latency_ms" not in accepted_activity.columns:
        return []
    term = accepted_activity[accepted_activity["event_type"].isin(C.TERMINAL_TYPES)].drop_duplicates("session_id").set_index("session_id")
    chk = pd.DataFrame({"derived_s": sessions["duration_s"], "latency_s": term["latency_ms"].astype("Float64").reindex(sessions.index) / 1000}).dropna()
    if len(chk) == 0:
        return []
    disagree = int(((chk["derived_s"] - chk["latency_s"].astype(float)).abs() > tolerance_s).sum())
    return [_metric(f"2d. terminal latency_ms disagrees with derived duration by > {tolerance_s:g} s (cross-check only)",
                    round(disagree / len(chk), 6), disagree, int(len(chk)),
                    population_filter="terminal sessions with both a derived duration and a terminal latency_ms",
                    late_event_policy="n/a", null_policy="sessions missing either value are excluded")]


def compute_all(canon: pd.DataFrame, rejects: pd.DataFrame, siem_corr: pd.DataFrame, reports: dict,
                accepted_activity: pd.DataFrame | None = None) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    sessions = _sessions(canon)
    rows = (metric_1_session_volume(sessions) + metric_2_duration(sessions) + latency_cross_check(sessions, accepted_activity)
            + metric_8_completeness_and_coverage(sessions, siem_corr) + metric_9_rejected_and_late(reports, rejects, canon))
    return pd.DataFrame(rows), sessions, token_policy_sensitivity(canon)
