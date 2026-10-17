"""Sandbox policies: flatten the nested JSON, resolve validity windows, and derive
policy violations by joining a record to the policy version effective at its time.

Rules established from the data (see findings):

* Overlapping windows (sp_research_std v2 valid_to 2026-02-01 vs v3 valid_from 2026-01-25):
  the *higher policy_version* wins inside the overlap. The sandbox's own audit log reports
  policy_version=3 for every research session on 2026-01-31, which confirms the rule.
* A policy version with no ``network`` block allows no egress at all (Dataset Description
  3.4), even though the runtime allowed those flows with reason NO_NETWORK_POLICY.
* Allowlist entries can be wildcards (``*.public-data.example``) and are matched with
  shell-style globbing, never compared as strings.
"""
from __future__ import annotations

import fnmatch

import numpy as np
import pandas as pd


def flatten_policies(flat: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """From the json_normalize'd policy frame build

    * dim_policy         one row per (sandbox_profile_id, policy_version) with scalar columns
    * policy_allowed_tools, policy_egress_allowlist, policy_denied_ports: the list
      attributes exploded to one row per element (bridge tables).
    """
    p = flat.copy()
    p["valid_from_utc"] = pd.to_datetime(p["valid_from"], utc=True, errors="coerce")
    p["valid_to_utc"] = pd.to_datetime(p["valid_to"], utc=True, errors="coerce")
    p["policy_version"] = pd.to_numeric(p["policy_version"], errors="coerce").astype("Int64")
    p["n_allowed_tools"] = p["allowed_tools"].map(lambda v: len(v) if isinstance(v, list) else 0)
    p["n_egress_allowlist"] = p["network.egress_allowlist"].map(lambda v: len(v) if isinstance(v, list) else 0)
    p = p.sort_values(["sandbox_profile_id", "valid_from_utc", "policy_version"]).reset_index(drop=True)
    p.insert(0, "policy_sk", range(1, len(p) + 1))

    def explode(col, name):
        e = p[["policy_sk", "sandbox_profile_id", "policy_version", col]].explode(col).dropna(subset=[col])
        return e.rename(columns={col: name}).reset_index(drop=True)

    allowed_tools = explode("allowed_tools", "tool_id")
    egress = explode("network.egress_allowlist", "pattern")
    egress["is_wildcard"] = egress["pattern"].astype(str).str.contains(r"[*?\[]", regex=True)
    ports = explode("network.denied_ports", "port")
    ports["port"] = ports["port"].astype(int)
    scalar_cols = [c for c in p.columns if c not in ("allowed_tools", "network.egress_allowlist", "network.denied_ports",
                                                      "filesystem.read_scope", "filesystem.write_scope")]
    dim = p[scalar_cols].copy()
    dim["filesystem_read_scope"] = p["filesystem.read_scope"].map(lambda v: "|".join(v) if isinstance(v, list) else None)
    dim["filesystem_write_scope"] = p["filesystem.write_scope"].map(lambda v: "|".join(v) if isinstance(v, list) else None)
    dim = dim.rename(columns={"network.max_egress_mb": "max_egress_mb", "resources.max_runtime_s": "max_runtime_s",
                              "resources.max_memory_mb": "max_memory_mb"})
    return dim, allowed_tools, egress, ports


def policy_window_report(dim_policy: pd.DataFrame) -> pd.DataFrame:
    """One row per adjacent pair of windows of a profile with the relationship
    (contiguous / overlap / gap) so the overlap rule is visible."""
    rows = []
    for sp, g in dim_policy.sort_values(["sandbox_profile_id", "valid_from_utc"]).groupby("sandbox_profile_id"):
        g = g.reset_index(drop=True)
        for i in range(len(g) - 1):
            end, nxt = g.loc[i, "valid_to_utc"], g.loc[i + 1, "valid_from_utc"]
            rel = "open_ended_overlap" if pd.isna(end) else ("overlap" if end > nxt else ("gap" if end < nxt else "contiguous"))
            rows.append({"sandbox_profile_id": sp, "from_version": int(g.loc[i, "policy_version"]), "to_version": int(g.loc[i + 1, "policy_version"]),
                         "valid_to": end, "next_valid_from": nxt, "relationship": rel,
                         "overlap_days": None if pd.isna(end) or end <= nxt else (end - nxt).days})
    return pd.DataFrame(rows)


def effective_policy(profile: pd.Series, at_utc: pd.Series, dim_policy: pd.DataFrame) -> pd.DataFrame:
    """Validity-window join: for each (profile, time) return the policy_sk and policy_version
    whose [valid_from, valid_to) contains the time. Where windows overlap the highest
    policy_version wins. Rows without a profile, or whose profile has no policy covering
    the time, get null."""
    out = pd.DataFrame({"policy_sk": pd.array([pd.NA] * len(profile), dtype="Int64"),
                        "policy_version_applied": pd.array([pd.NA] * len(profile), dtype="Int64")}, index=profile.index)
    for sp, pol in dim_policy.sort_values("policy_version").groupby("sandbox_profile_id"):
        rows = (profile == sp).to_numpy()
        if not rows.any():
            continue
        t = at_utc[rows]
        for _, w in pol.iterrows():  # ascending version: a later (higher) version overwrites in overlaps
            m = (t >= w["valid_from_utc"]) & (pd.isna(w["valid_to_utc"]) | (t < w["valid_to_utc"]))
            idx = t.index[m.to_numpy()]
            out.loc[idx, "policy_sk"] = int(w["policy_sk"])
            out.loc[idx, "policy_version_applied"] = int(w["policy_version"])
    return out


def host_matches_allowlist(host: str | None, patterns: list[str]) -> bool:
    """Glob match of a destination host against the egress allowlist. IP-only flows have
    no host and therefore never match a hostname pattern."""
    if not isinstance(host, str) or not host:
        return False
    return any(fnmatch.fnmatchcase(host.lower(), p.lower()) for p in patterns)


def tool_policy_violation(tool_id: pd.Series, policy_sk: pd.Series, allowed_tools: pd.DataFrame) -> pd.Series:
    """A tool call is a policy violation when its (resolved) tool_id is not in the
    allowed_tools of the policy effective at its event_time. Null policy -> null (unknown)."""
    allowed = allowed_tools.groupby("policy_sk")["tool_id"].agg(set).to_dict()
    values = [pd.NA if pd.isna(sk) else (t not in allowed.get(int(sk), set())) for t, sk in zip(tool_id, policy_sk)]
    return pd.Series(pd.array(values, dtype="boolean"), index=tool_id.index)


def egress_policy_violation(dst_host: pd.Series, dst_port: pd.Series, policy_sk: pd.Series,
                            dim_policy: pd.DataFrame, egress_allowlist: pd.DataFrame,
                            denied_ports: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    """A flow violates egress policy when (a) the effective policy has no network block,
    (b) dst_port is in denied_ports, or (c) dst_host matches no allowlist pattern.
    Returns (is_violation [nullable boolean], reason string)."""
    patterns = egress_allowlist.groupby("policy_sk")["pattern"].agg(list).to_dict()
    ports = denied_ports.groupby("policy_sk")["port"].agg(set).to_dict()
    has_net = dim_policy.set_index("policy_sk")["has_network_block"].to_dict()
    viol = pd.Series(pd.NA, index=dst_host.index, dtype="boolean")
    why = pd.Series(None, index=dst_host.index, dtype="object")
    port_num = pd.to_numeric(dst_port, errors="coerce")
    for i in dst_host.index[policy_sk.notna().to_numpy()]:
        sk = int(policy_sk[i])
        if not has_net.get(sk, False):
            viol[i], why[i] = True, "no_network_block"
        elif pd.notna(port_num[i]) and int(port_num[i]) in ports.get(sk, set()):
            viol[i], why[i] = True, "denied_port"
        elif not host_matches_allowlist(dst_host[i], patterns.get(sk, [])):
            viol[i], why[i] = True, "host_not_allowlisted"
        else:
            viol[i], why[i] = False, "allowed_by_policy"
    why[policy_sk.isna()] = "no_policy"
    return viol, why
