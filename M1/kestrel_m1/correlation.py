"""SIEM <-> network-flow correlation.

The SIEM feed has no session_id. An alert is linked to a flow on
``source_ip == src_ip`` and ``destination.host == dst_ip`` and ``destination.port == dst_port``
and ``|detected_at_utc - flow_time_utc| <= tolerance``.

Tolerance: 60 s. In the pack the alert follows its flow by 0..60 s for 97% of the
alerts that can be matched at all; there is then a gap with no alerts between 60 s
and 150 s, and a thin tail of 67 alerts 2.5-6.5 minutes after their flow (a slower
detection path). 60 s sits in the empty gap, so the choice is stable: 30 s would lose
real matches, 120 s would add none. ``correlation_sweep`` shows every alternative.

Outcome per alert: ``matched`` (exactly one flow), ``ambiguous`` (several flows within
tolerance; the session is still recorded when all candidates share one session) or
``unmatched`` (none). Alerts whose source_ip never appears as a sandbox address are
``unmatched`` with sub-reason ``source_ip_not_a_sandbox``: they come from systems outside
the platform and are not forced onto a session.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import SIEM_TOLERANCE_S

JOIN_KEYS_ALERT = ["source_ip", "destination_host", "destination_port"]
JOIN_KEYS_FLOW = ["src_ip", "dst_ip", "dst_port"]


def _candidates(alerts: pd.DataFrame, flows: pd.DataFrame) -> pd.DataFrame:
    a = alerts[["alert_id", "detected_at_utc"] + JOIN_KEYS_ALERT].copy()
    f = flows[["flow_id", "session_id", "flow_time_utc", "verdict"] + JOIN_KEYS_FLOW].copy()
    a["_port"] = pd.to_numeric(a["destination_port"], errors="coerce").astype("Int64")
    f["_port"] = pd.to_numeric(f["dst_port"], errors="coerce").astype("Int64")
    c = a.merge(f, left_on=["source_ip", "destination_host", "_port"], right_on=["src_ip", "dst_ip", "_port"], how="inner")
    c["delta_s"] = (c["flow_time_utc"] - c["detected_at_utc"]).dt.total_seconds()
    return c


def correlate_siem_flows(alerts: pd.DataFrame, flows: pd.DataFrame, tolerance_s: float = SIEM_TOLERANCE_S) -> tuple[pd.DataFrame, dict]:
    """Returns (per-alert correlation table, summary counts)."""
    cand = _candidates(alerts, flows)
    within = cand[cand["delta_s"].abs() <= tolerance_s].copy()
    sandbox_ips = set(flows["src_ip"].dropna())

    g = within.groupby("alert_id")
    agg = g.agg(n_candidate_flows=("flow_id", "nunique"), n_candidate_sessions=("session_id", "nunique"))
    nearest = within.loc[within.groupby("alert_id")["delta_s"].apply(lambda s: s.abs().idxmin())]
    nearest = nearest.set_index("alert_id")

    out = alerts[["alert_id", "source_system", "severity", "rule", "technique_id", "detected_at_utc", "source_ip", "destination_host", "destination_port"]].copy()
    out = out.set_index("alert_id")
    out["n_candidate_flows"] = agg["n_candidate_flows"].reindex(out.index).fillna(0).astype(int)
    out["n_candidate_sessions"] = agg["n_candidate_sessions"].reindex(out.index).fillna(0).astype(int)
    out["match_status"] = np.select([out["n_candidate_flows"] == 1, out["n_candidate_flows"] > 1], ["matched", "ambiguous"], "unmatched")
    out["matched_flow_id"] = np.where(out["match_status"] == "matched", nearest["flow_id"].reindex(out.index), None)
    uniq_sess = within.groupby("alert_id")["session_id"].agg(lambda s: s.iloc[0] if s.nunique() == 1 else None).reindex(out.index)
    out["matched_session_id"] = np.where(out["match_status"] != "unmatched", uniq_sess, None)
    out["nearest_flow_id"] = nearest["flow_id"].reindex(out.index)
    out["nearest_flow_delta_s"] = nearest["delta_s"].reindex(out.index).round(3)
    out["matched_flow_verdict"] = nearest["verdict"].reindex(out.index)
    # why unmatched
    any_cand = cand.groupby("alert_id")["delta_s"].apply(lambda s: s.abs().min()).reindex(out.index)
    out["unmatched_reason"] = np.select(
        [out["match_status"] != "unmatched", ~out["source_ip"].isin(sandbox_ips), any_cand.isna(), any_cand.notna()],
        [None, "source_ip_not_a_sandbox", "no_flow_with_same_src_dst_port", "nearest_flow_beyond_tolerance"], None)
    out["nearest_any_delta_s"] = any_cand.round(3)
    out["tolerance_s"] = tolerance_s
    out = out.reset_index()

    summary = {
        "tolerance_s": tolerance_s,
        "alerts": int(len(out)),
        "matched": int((out["match_status"] == "matched").sum()),
        "ambiguous": int((out["match_status"] == "ambiguous").sum()),
        "ambiguous_but_single_session": int(((out["match_status"] == "ambiguous") & out["matched_session_id"].notna()).sum()),
        "unmatched": int((out["match_status"] == "unmatched").sum()),
        "unmatched_by_reason": out.loc[out["match_status"] == "unmatched", "unmatched_reason"].value_counts().to_dict(),
        "alerts_with_a_session": int(out["matched_session_id"].notna().sum()),
        "distinct_sessions_with_alerts": int(out["matched_session_id"].nunique()),
        "flows_matched_by_more_than_one_alert": int((out.dropna(subset=["matched_flow_id"]).groupby("matched_flow_id").size() > 1).sum()),
        "alert_after_flow_share": float((out.loc[out["match_status"] == "matched", "nearest_flow_delta_s"] <= 0).mean()) if (out["match_status"] == "matched").any() else None,
    }
    return out, summary


def correlation_sweep(alerts: pd.DataFrame, flows: pd.DataFrame, tolerances=(5, 10, 30, 60, 120, 300, 600)) -> pd.DataFrame:
    """Matched / ambiguous / unmatched counts for a range of tolerances."""
    cand = _candidates(alerts, flows)
    rows = []
    for tol in tolerances:
        w = cand[cand["delta_s"].abs() <= tol]
        n = w.groupby("alert_id")["flow_id"].nunique()
        rows.append({"tolerance_s": tol, "matched": int((n == 1).sum()), "ambiguous": int((n > 1).sum()),
                     "unmatched": int(len(alerts) - len(n))})
    return pd.DataFrame(rows)
