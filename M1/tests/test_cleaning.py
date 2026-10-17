import pandas as pd

from kestrel_m1.cleaning import RejectCollector, clean_activity, first_reason, join_flags
from kestrel_m1.config import REJECT_REASONS
from kestrel_m1.entities import resolve_agents, resolve_model_pricing, resolve_tenants, resolve_tools


def test_first_reason_follows_enum_precedence():
    m = pd.DataFrame({"ORPHAN_EVENT": [True, False, False], "MISSING_REQUIRED_FIELD": [True, True, False], "DUPLICATE_EVENT_ID": [False, False, False]})
    r = first_reason(m)
    assert r.tolist()[:2] == ["ORPHAN_EVENT", "MISSING_REQUIRED_FIELD"] and pd.isna(r.iloc[2])
    assert REJECT_REASONS.index("ORPHAN_EVENT") < REJECT_REASONS.index("MISSING_REQUIRED_FIELD")


def test_join_flags():
    idx = pd.Index([0, 1])
    out = join_flags({"a": pd.Series([True, False], index=idx), "b": pd.Series([True, True], index=idx)}, idx)
    assert out.tolist() == ["a|b", "b"]


def _dims():
    tenants = pd.DataFrame({"source_file": "t", "source_line": [2, 3], "tenant_id": ["tn_001", "tn_002"], "tenant_name": ["A Ltd.", "a"],
                            "industry": ["finance"] * 2, "plan_tier": ["growth"] * 2, "region": ["eu-west-1"] * 2,
                            "onboarded_at": ["2025-01-01T00:00:00Z"] * 2, "is_active": ["true"] * 2, "security_contact": ["x@a.example"] * 2})
    dim_tenant, tenant_alias = resolve_tenants(tenants)
    agents = pd.DataFrame({"source_file": "a", "source_line": [2, 3], "agent_id": ["ag_1", "ag_1"], "release_version": ["1.0.0", "v1.0.0"],
                           "agent_name": ["x", "X"], "agent_type": ["ops"] * 2, "model_id": ["m1"] * 2, "tenant_id": ["tn_001"] * 2,
                           "sandbox_profile_id": ["sp"] * 2, "owner_team": ["t"] * 2, "autonomy_level": ["supervised"] * 2,
                           "max_tool_calls_per_session": ["10"] * 2, "launch_date": ["2025-01-01"] * 2, "is_deprecated": ["false"] * 2})
    dim_agent, agent_alias = resolve_agents(agents, tenant_alias)
    tools = pd.DataFrame({"source_file": "tl", "source_line": [2, 3], "tool_id": ["tl_x", "tl_x"], "tool_version": ["1.0.0", "1.1.0"],
                          "tool_name": ["x", "x_alias"], "tool_category": ["shell"] * 2, "risk_tier": ["low"] * 2, "requires_approval": ["false"] * 2, "owner_team": ["t"] * 2})
    dim_tool, tool_alias = resolve_tools(tools)
    pricing = resolve_model_pricing(pd.DataFrame({"source_file": "p", "source_line": [2], "model_id": ["m1"], "model_family": ["f"], "input_price_per_1k": ["0.001"],
                                                  "output_price_per_1k": ["0.002"], "currency": ["USD"], "effective_from": ["2025-01-01T00:00:00Z"], "effective_to": [None]}))
    return dim_tenant, tenant_alias, dim_agent, agent_alias, dim_tool, tool_alias, pricing


def test_entity_resolution_maps_aliases():
    dim_tenant, tenant_alias, dim_agent, agent_alias, dim_tool, tool_alias, _ = _dims()
    assert tenant_alias == {"tn_002": "tn_001"} and len(dim_tenant) == 1
    assert agent_alias == {("ag_1", "v1.0.0"): ("ag_1", "1.0.0")} and len(dim_agent) == 1
    assert tool_alias == {"x": "tl_x", "x_alias": "tl_x"}


def _row(**kw):
    base = {"source_file": "agent_activity.parquet", "source_line": 1, "event_id": "ev_1", "event_time": "2026-02-01T10:00:00.000Z",
            "ingest_time": "2026-02-01T10:00:01.000Z", "sequence_number": 1, "event_type": "session.start", "session_id": "ss_1",
            "tenant_id": "tn_001", "agent_id": "ag_1", "release_version": "1.0.0", "sandbox_instance_id": "sbx_1", "status": "ok",
            "latency_ms": None, "turn_index": None, "model_id": None, "content_source": None, "stated_goal": None, "injection_indicators": None,
            "input_tokens": None, "output_tokens": None, "finish_reason": None, "tool_id": None, "tool_version": None, "finished_at": None,
            "retry_number": None, "error_class": None, "target_resource": None, "bytes_out": None, "task_id": "tk_1", "task_category": "data_query",
            "expected_tool_categories": "database"}
    base.update(kw)
    return base


def test_clean_activity_rules():
    dims = _dims()
    rows = [
        _row(),  # accepted start
        _row(source_line=2, event_id="ev_2", sequence_number=2, event_type="llm.turn", status="ok", model_id="m1", turn_index=0, input_tokens=10, output_tokens=5,
             content_source="user", finish_reason="tool_call", injection_indicators="", event_time="1769940000000"),  # epoch ms, accepted
        _row(source_line=3, event_id="ev_2", sequence_number=2, event_type="llm.turn", status="ok", model_id="m1", turn_index=0, input_tokens=10, output_tokens=5,
             content_source="user", finish_reason="tool_call", injection_indicators="", event_time="1769940000000", ingest_time="2026-02-01T10:06:00.000Z"),  # duplicate, later ingest
        _row(source_line=4, event_id="ev_3", sequence_number=3, event_type="tool.call", status="succeeded", tool_id="x_alias", tool_version="1.1.0", retry_number=0,
             target_resource="/bin/x", release_version="v1.0.0"),  # alias version + tool name + status spelling: accepted with flags
        _row(source_line=5, event_id="ev_4", sequence_number=4, event_type="tool.call", status="success", tool_id="tl_x", tool_version="1.0.0", retry_number=-1, target_resource="/bin/x"),  # negative retry
        _row(source_line=6, event_id="ev_5", sequence_number=5, event_type="agent.telepathy", status="ok"),  # invalid type
        _row(source_line=7, event_id="ev_6", sequence_number=6, event_type="session.end", status="ok", event_time="not-a-time"),  # malformed
        _row(source_line=8, event_id="ev_7", sequence_number=1, event_type="tool.call", session_id="ss_orphan", status="success", tool_id="tl_x", tool_version="1.0.0", retry_number=0, target_resource="/bin/x"),  # orphan
        _row(source_line=9, event_id="ev_8", sequence_number=7, event_type="llm.turn", status=None, model_id="m1", turn_index=1, input_tokens=1, content_source="user", finish_reason="stop", injection_indicators=""),  # missing status
        _row(source_line=10, event_id="ev_9", sequence_number=8, event_type="session.end", tenant_id="tn_777", status="ok"),  # unknown tenant
        _row(source_line=11, event_id="ev_10", sequence_number=9, event_type="session.end", agent_id="ag_999", status="ok"),  # unknown agent
    ]
    bronze = pd.DataFrame(rows)
    rejects = RejectCollector()
    acc, report = clean_activity(bronze, *dims, rejects)
    rej = rejects.table()
    reasons = dict(zip(rej["record_key"], rej["reject_reason"]))
    assert reasons == {"ev_2": "DUPLICATE_EVENT_ID", "ev_4": "INVALID_NUMERIC_RANGE", "ev_5": "INVALID_EVENT_TYPE", "ev_6": "MALFORMED_TIMESTAMP",
                       "ev_7": "ORPHAN_EVENT", "ev_8": "MISSING_REQUIRED_FIELD", "ev_9": "UNKNOWN_TENANT_ID", "ev_10": "UNKNOWN_AGENT_ID"}
    assert set(acc["event_id"]) == {"ev_1", "ev_2", "ev_3"}
    kept_dup = acc[acc["event_id"] == "ev_2"].iloc[0]
    assert kept_dup["source_line"] == 2  # earliest ingest_time copy survives
    assert kept_dup["event_time_utc"] == pd.Timestamp(1769940000000, unit="ms", tz="UTC")
    fixed = acc[acc["event_id"] == "ev_3"].iloc[0]
    assert fixed["release_version"] == "1.0.0" and fixed["tool_id"] == "tl_x" and fixed["status"] == "success"
    assert {"release_version_alias", "tool_name_resolved_to_id", "status_spelling_normalised"} <= set(fixed["quality_flags"].split("|"))
    assert (rej["source_line"] > 0).all() and rej["raw_payload"].str.contains("event_id").all()
