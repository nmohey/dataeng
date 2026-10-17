import pandas as pd

from kestrel_m1.correlation import correlate_siem_flows
from kestrel_m1.policies import effective_policy, egress_policy_violation, host_matches_allowlist, tool_policy_violation


def _policy():
    dim = pd.DataFrame({"policy_sk": [1, 2, 3], "sandbox_profile_id": ["sp", "sp", "sp2"], "policy_version": [2, 3, 1],
                        "valid_from_utc": pd.to_datetime(["2026-01-01", "2026-01-25", "2026-01-01"], utc=True),
                        "valid_to_utc": pd.to_datetime(["2026-02-01", None, None], utc=True), "has_network_block": [True, True, False]})
    tools = pd.DataFrame({"policy_sk": [1, 2, 2], "tool_id": ["tl_a", "tl_a", "tl_b"]})
    egress = pd.DataFrame({"policy_sk": [1, 2, 2], "pattern": ["api.kestrel.ai", "api.kestrel.ai", "*.public-data.example"]})
    ports = pd.DataFrame({"policy_sk": [1, 2], "port": [445, 445]})
    return dim, tools, egress, ports


def test_overlap_latest_version_wins():
    dim, *_ = _policy()
    prof = pd.Series(["sp", "sp", "sp", "sp2", "none"])
    at = pd.to_datetime(["2026-01-10", "2026-01-28", "2026-03-01", "2026-03-01", "2026-03-01"], utc=True)
    out = effective_policy(prof, pd.Series(at), dim)
    assert out["policy_version_applied"].tolist() == [2, 3, 3, 1, pd.NA] or out["policy_version_applied"].astype(object).tolist()[:4] == [2, 3, 3, 1]


def test_wildcards_match_not_compare():
    assert host_matches_allowlist("stats.public-data.example", ["*.public-data.example"])
    assert not host_matches_allowlist("public-data.example", ["*.public-data.example"])
    assert not host_matches_allowlist(None, ["*"])


def test_violations():
    dim, tools, egress, ports = _policy()
    v = tool_policy_violation(pd.Series(["tl_a", "tl_b", "tl_b"]), pd.Series([1, 1, 2], dtype="Int64"), tools)
    assert v.tolist() == [False, True, False]
    viol, why = egress_policy_violation(pd.Series(["api.kestrel.ai", None, "x.public-data.example", "api.kestrel.ai"]),
                                        pd.Series([443, 445, 443, 443]), pd.Series([2, 2, 2, 3], dtype="Int64"), dim, egress, ports)
    assert viol.tolist() == [False, True, False, True]
    assert why.tolist() == ["allowed_by_policy", "denied_port", "allowed_by_policy", "no_network_block"]


def test_correlation_statuses():
    alerts = pd.DataFrame({"alert_id": ["a1", "a2", "a3", "a4"], "source_system": "s", "severity": "high", "rule": "r", "technique_id": "T1",
                           "detected_at_utc": pd.to_datetime(["2026-02-01 10:00:30", "2026-02-01 11:00:30", "2026-02-01 12:00:00", "2026-02-01 13:00:00"], utc=True),
                           "source_ip": ["10.20.1.10", "10.20.1.10", "10.44.1.1", "10.20.1.10"], "destination_host": ["10.20.4.1"] * 4, "destination_port": [445] * 4})
    flows = pd.DataFrame({"flow_id": ["f1", "f2", "f3", "f4"], "session_id": ["s1", "s2", "s2", "s3"], "verdict": "blocked",
                          "flow_time_utc": pd.to_datetime(["2026-02-01 10:00:00", "2026-02-01 11:00:00", "2026-02-01 11:00:20", "2026-02-01 12:50:00"], utc=True),
                          "src_ip": ["10.20.1.10"] * 4, "dst_ip": ["10.20.4.1"] * 4, "dst_port": [445] * 4})
    out, summary = correlate_siem_flows(alerts, flows, 60)
    st = dict(zip(out["alert_id"], out["match_status"]))
    assert st == {"a1": "matched", "a2": "ambiguous", "a3": "unmatched", "a4": "unmatched"}
    assert out.set_index("alert_id").loc["a2", "matched_session_id"] == "s2"  # both candidates in one session
    assert dict(zip(out["alert_id"], out["unmatched_reason"]))["a3"] == "source_ip_not_a_sandbox"
    assert dict(zip(out["alert_id"], out["unmatched_reason"]))["a4"] == "nearest_flow_beyond_tolerance"
    assert summary["matched"] == 1 and summary["ambiguous"] == 1 and summary["unmatched"] == 2
