"""End-to-end Milestone 1 run: read -> profile -> clean -> integrate -> canonical ->
metrics, writing every output to data/curated. ``python -m kestrel_m1.pipeline``."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pandas as pd

from . import config as C
from .canonical import (assemble, canonical_from_activity, canonical_from_audit, canonical_from_flows, canonical_from_siem,
                        session_context)
from .cleaning import RejectCollector, clean_activity, clean_audit, clean_flows, clean_siem, reject_reference_duplicates
from .correlation import correlate_siem_flows, correlation_sweep
from .entities import flag_agent_profiles, resolve_agents, resolve_model_pricing, resolve_tenants, resolve_tools
from .metrics import compute_all
from .policies import flatten_policies, policy_window_report
from .readers import read_all_bronze


def _log(msg: str, t0: float) -> None:
    print(f"[{time.time() - t0:7.1f}s] {msg}", flush=True)


def run(raw_dir: Path | None = None, out_dir: Path | None = None, write_csv_samples: bool = True) -> dict:
    t0 = time.time()
    raw_dir = Path(raw_dir) if raw_dir else C.resolve_raw_dir()
    out_dir = Path(out_dir) if out_dir else C.resolve_out_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    _log(f"raw dir: {raw_dir}", t0)
    _log(f"out dir: {out_dir}", t0)

    # 1. read every file in its own format
    b = read_all_bronze(raw_dir)
    _log("read all nine inputs; parquet schema ok=" + str(b["activity_schema_report"]["ok"]), t0)

    # 2. reference data -> conformed dimensions + alias maps
    rejects = RejectCollector()
    dim_tenant, tenant_alias = resolve_tenants(b["tenants"])
    dim_agent, agent_alias = resolve_agents(b["agents"], tenant_alias)
    dim_tool, tool_alias = resolve_tools(b["tools"])
    reject_reference_duplicates(b["tools"], rejects)
    pricing = resolve_model_pricing(b["model_pricing"])
    dim_policy, pol_tools, pol_egress, pol_ports = flatten_policies(b["sandbox_policies"])
    dim_agent = flag_agent_profiles(dim_agent, dim_policy)
    _log(f"dims: {len(dim_tenant)} tenants (alias {tenant_alias}), {len(dim_agent)} agent versions (alias {len(agent_alias)}), "
         f"{len(dim_tool)} tools (name aliases {tool_alias}), {len(dim_policy)} policy versions", t0)

    # 3. clean the facts
    act, rep_act = clean_activity(b["agent_activity"], dim_tenant, tenant_alias, dim_agent, agent_alias, dim_tool, tool_alias, pricing, rejects)
    _log(f"activity: {rep_act['received']:,} received -> {rep_act['accepted']:,} accepted, {rep_act['rejected']:,} rejected {rep_act['rejected_by_reason']}", t0)
    accepted_sessions = set(act.loc[act["event_type"] == "session.start", "session_id"])
    session_instance = act[act["event_type"] == "session.start"].drop_duplicates("session_id").set_index("session_id")["sandbox_instance_id"]

    flows, rep_flows = clean_flows(b["network_flows"], accepted_sessions, session_instance, rejects)
    _log(f"flows: {rep_flows['received']:,} -> {rep_flows['accepted']:,} accepted, {rep_flows['rejected']:,} rejected {rep_flows['rejected_by_reason']}", t0)

    tool_calls = act[act["event_type"] == "tool.call"]
    audit, host_offsets, rep_audit = clean_audit(b["sandbox_audit"], b["sandbox_audit_unparsed"], accepted_sessions, session_instance, tool_calls, rejects)
    _log(f"audit: {rep_audit['received']:,} -> {rep_audit['accepted']:,} accepted, {rep_audit['rejected']:,} rejected {rep_audit['rejected_by_reason']}; "
         f"{rep_audit['hosts']} hosts, offsets {host_offsets['offset_s'].min()}..{host_offsets['offset_s'].max()} s", t0)

    siem, rep_siem = clean_siem(b["siem_alerts"], rejects)
    _log(f"siem: {rep_siem['received']:,} -> {rep_siem['accepted']:,} accepted, {rep_siem['rejected']:,} rejected", t0)

    # 4. correlate SIEM <-> flows
    siem_corr, corr_summary = correlate_siem_flows(siem, flows, C.SIEM_TOLERANCE_S)
    sweep = correlation_sweep(siem, flows)
    _log(f"correlation @ {C.SIEM_TOLERANCE_S}s: matched {corr_summary['matched']}, ambiguous {corr_summary['ambiguous']}, unmatched {corr_summary['unmatched']} {corr_summary['unmatched_by_reason']}", t0)

    # 5. canonical activity table
    ctx = session_context(act, dim_agent)
    parts = [
        canonical_from_activity(act, ctx, dim_agent, dim_policy, pol_tools, pricing),
        canonical_from_flows(flows, ctx, dim_policy, pol_egress, pol_ports, siem_corr),
        canonical_from_audit(audit, ctx, dim_policy),
        canonical_from_siem(siem, siem_corr, ctx),
    ]
    canon = assemble(parts)
    rejects_table = rejects.table()
    _log(f"canonical rows: {len(canon):,} ({canon['activity_type'].value_counts().to_dict()}); rejects: {len(rejects_table):,}", t0)

    # 6. metrics
    reports = {"agent_activity.parquet": rep_act, "network_flows.csv": rep_flows, "sandbox_audit.log": rep_audit, "siem_alerts.json": rep_siem,
               "tools.csv": {"received": len(b["tools"])}, "tenants.csv": {"received": len(b["tenants"])}, "agents.csv": {"received": len(b["agents"])},
               "model_pricing.csv": {"received": len(b["model_pricing"])}, "sandbox_policies.json": {"received": len(b["sandbox_policies"])}}
    metrics, sessions, token_sens = compute_all(canon, rejects_table, siem_corr, reports, accepted_activity=act)
    _log("metrics computed", t0)

    result = {"canonical": canon, "rejects": rejects_table, "metrics": metrics, "sessions": sessions, "siem_corr": siem_corr, "sweep": sweep,
              "host_offsets": host_offsets, "dims": {"tenant": dim_tenant, "agent": dim_agent, "tool": dim_tool, "pricing": pricing, "policy": dim_policy,
                                                     "policy_allowed_tools": pol_tools, "policy_egress": pol_egress, "policy_ports": pol_ports},
              "accepted": {"activity": act, "flows": flows, "audit": audit, "siem": siem}, "reports": reports, "token_sensitivity": token_sens,
              "aliases": {"tenant": tenant_alias, "agent": agent_alias, "tool": tool_alias}, "bronze_meta": {"activity_schema_report": b["activity_schema_report"], "siem_envelope": b["siem_envelope"]},
              "raw_dir": raw_dir, "seconds": round(time.time() - t0, 1), "correlation_summary": corr_summary}
    write_outputs(result, out_dir, write_csv_samples)
    _log(f"wrote outputs to {out_dir}", t0)
    return result


def write_outputs(res: dict, out_dir: Path, write_csv_samples: bool = True) -> None:
    """Write every curated artefact (parquet for the two big tables, CSV for the rest,
    JSON run report, Markdown metrics) to ``out_dir``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    canon, rejects_table, metrics, sessions = res["canonical"], res["rejects"], res["metrics"], res["sessions"]
    siem_corr, sweep, host_offsets, token_sens, dims = res["siem_corr"], res["sweep"], res["host_offsets"], res["token_sensitivity"], res["dims"]
    canon.to_parquet(out_dir / "canonical_activity.parquet", index=False, compression="zstd")
    rejects_table.to_parquet(out_dir / "rejects.parquet", index=False, compression="zstd")
    rejects_table.to_csv(out_dir / "rejects.csv", index=False)
    if write_csv_samples:
        canon.sample(min(2000, len(canon)), random_state=1).sort_values("event_time_utc").to_csv(out_dir / "canonical_activity_sample.csv", index=False)
    dims["tenant"].to_csv(out_dir / "dim_tenant.csv", index=False)
    dims["agent"].to_csv(out_dir / "dim_agent.csv", index=False)
    dims["tool"].to_csv(out_dir / "dim_tool.csv", index=False)
    dims["pricing"].to_csv(out_dir / "dim_model_pricing.csv", index=False)
    dims["policy"].to_csv(out_dir / "dim_sandbox_policy.csv", index=False)
    dims["policy_allowed_tools"].to_csv(out_dir / "policy_allowed_tools.csv", index=False)
    dims["policy_egress"].to_csv(out_dir / "policy_egress_allowlist.csv", index=False)
    dims["policy_ports"].to_csv(out_dir / "policy_denied_ports.csv", index=False)
    host_offsets.to_csv(out_dir / "sandbox_host_clock_offsets.csv", index=False)
    siem_corr.to_csv(out_dir / "siem_flow_correlation.csv", index=False)
    sweep.to_csv(out_dir / "siem_flow_correlation_sweep.csv", index=False)
    sessions.reset_index().to_csv(out_dir / "sessions.csv", index=False)
    metrics.to_csv(out_dir / "metrics.csv", index=False)
    token_sens.to_csv(out_dir / "metrics_token_policy_sensitivity.csv", index=False)
    agent_alias = res["aliases"]["agent"]
    run_report = {
        "raw_dir": str(res["raw_dir"]), "out_dir": str(out_dir), "seconds": res["seconds"],
        "activity_schema_report": res["bronze_meta"]["activity_schema_report"], "siem_envelope": res["bronze_meta"]["siem_envelope"],
        "tenant_alias": res["aliases"]["tenant"], "agent_alias": {f"{k[0]}|{k[1]}": f"{v[0]}|{v[1]}" for k, v in agent_alias.items()}, "tool_alias": res["aliases"]["tool"],
        "policy_windows": policy_window_report(dims["policy"]).astype(str).to_dict("records"),
        "activity": res["reports"]["agent_activity.parquet"], "flows": res["reports"]["network_flows.csv"], "audit": res["reports"]["sandbox_audit.log"],
        "siem": res["reports"]["siem_alerts.json"], "correlation": res["correlation_summary"],
        "canonical_rows": int(len(canon)), "canonical_by_type": canon["activity_type"].value_counts().to_dict(),
        "rejects": int(len(rejects_table)), "rejects_by_reason": rejects_table["reject_reason"].value_counts().to_dict(),
        "rejects_by_file": rejects_table["source_file"].value_counts().to_dict(),
    }
    (out_dir / "run_report.json").write_text(json.dumps(run_report, indent=2, default=str))
    metrics_md = ["# Milestone 1 metrics", "", f"Generated by `kestrel_m1.pipeline` from `{Path(res['raw_dir']).name}`.", "",
                  metrics[["metric", "value", "numerator", "denominator"]].to_markdown(index=False), "",
                  "## Policies per metric", ""]
    for _, r in metrics.iterrows():
        pols = {k: v for k, v in r.items() if k not in ("metric", "value", "numerator", "denominator") and isinstance(v, str)}
        metrics_md.append(f"**{r['metric']}** = `{r['value']}`  ")
        for k, v in pols.items():
            metrics_md.append(f"- {k}: {v}")
        metrics_md.append("")
    metrics_md += ["## Missing-token policy sensitivity", "", token_sens.to_markdown(index=False), ""]
    (out_dir / "metrics.md").write_text("\n".join(metrics_md))
if __name__ == "__main__":
    raw = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    run(raw, out)
