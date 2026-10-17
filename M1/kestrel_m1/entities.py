"""Entity resolution and conformed dimensions.

The same real-world thing shows up under more than one identifier in this pack:

* tenants  tn_003 "NILEBANK Ltd." and tn_004 "nilebank" (identical attributes)
* agents   (ag_007, "2.3.1") and (ag_007, "v2.3.1"); activity also uses "v2.2.0"
* tools    tl_web_fetch is called web_fetch / http_get / webfetch; activity rows use
           the *name* as tool_id for two of the versions
* pricing  mdl_kst_pro_1 has two open-ended price windows (the older one was never closed)

Each resolver returns the conformed dimension plus an alias map that the cleaner
applies to the fact rows *before* referential-integrity checks, so a row is only
rejected as UNKNOWN_* when it points at an entity that really does not exist.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import (AGENT_TYPES, AUTONOMY_LEVELS, RISK_TIERS, STATUS_ALIASES, TENANT_INDUSTRIES,
                     TENANT_PLANS, TENANT_REGIONS, TOOL_CATEGORIES)
from .profiling import normalise_name


def _join_flags(*flag_series: pd.Series) -> pd.Series:
    """Combine several optional-flag Series (string or null) into one pipe-separated column."""
    df = pd.concat(flag_series, axis=1)
    return df.apply(lambda r: "|".join([v for v in r if isinstance(v, str) and v]), axis=1).replace("", None)


# --------------------------------------------------------------------------- tenants


def resolve_tenants(tenants: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, str]]:
    """Two tenant rows that share a normalised name and every other attribute are one
    tenant. The lower tenant_id is canonical; the other becomes an alias. Returns
    (dim_tenant, alias_map) where alias_map maps alias id -> canonical id."""
    t = tenants.copy()
    t["name_key"] = normalise_name(t["tenant_name"])
    attrs = ["industry", "plan_tier", "region", "onboarded_at", "is_active", "security_contact"]
    alias: dict[str, str] = {}
    for _, g in t.groupby("name_key"):
        if len(g) > 1 and (g[attrs].fillna("").nunique() <= 1).all():
            canon = g["tenant_id"].min()
            for tid in g["tenant_id"]:
                if tid != canon:
                    alias[tid] = canon
    dim = t[~t["tenant_id"].isin(alias)].copy()
    dim["aliases"] = dim["tenant_id"].map(lambda c: "|".join(sorted(k for k, v in alias.items() if v == c)) or None)
    dim["is_active"] = dim["is_active"].map({"true": True, "false": False})
    dim["onboarded_at_utc"] = pd.to_datetime(dim["onboarded_at"], utc=True, errors="coerce")
    dim["quality_flags"] = _join_flags(
        pd.Series(np.where(~dim["region"].isin(TENANT_REGIONS), "region_not_in_enum", None), index=dim.index),
        pd.Series(np.where(~dim["industry"].isin(TENANT_INDUSTRIES), "industry_not_in_enum", None), index=dim.index),
        pd.Series(np.where(~dim["plan_tier"].isin(TENANT_PLANS), "plan_tier_not_in_enum", None), index=dim.index),
        pd.Series(np.where(dim["security_contact"].isna(), "security_contact_missing", None), index=dim.index),
        pd.Series(np.where(dim["aliases"].notna(), "has_alias_ids", None), index=dim.index),
    )
    dim = dim.drop(columns=["name_key"]).reset_index(drop=True)
    return dim, alias


# ---------------------------------------------------------------------------- agents


def normalise_release_version(s: pd.Series) -> pd.Series:
    """'v2.3.1' -> '2.3.1'. Semver has no leading v."""
    return s.astype("string").str.strip().str.replace(r"^[vV]", "", regex=True)


def resolve_agents(agents: pd.DataFrame, tenant_alias: dict[str, str] | None = None) -> tuple[pd.DataFrame, dict]:
    """Conform agents.csv into a Type-2 dimension keyed by agent_sk.

    * release_version is normalised (leading 'v' dropped); rows that then collide on the
      natural key (agent_id, release_version) are one version. The row whose spelling
      already followed the convention wins; the other's attributes are kept as a note.
    * valid_from = launch_date, valid_to = the next version's launch_date (open for the
      newest), so ``agent_sk`` is the version current at any event_time.
    Returns (dim_agent, alias_map) where alias_map maps (agent_id, raw_version) -> (agent_id, canonical_version).
    """
    a = agents.copy()
    a["release_version_raw"] = a["release_version"]
    a["release_version"] = normalise_release_version(a["release_version"])
    if tenant_alias:
        a["tenant_id"] = a["tenant_id"].replace(tenant_alias)
    a["_canonical_spelling"] = a["release_version_raw"] == a["release_version"]
    a = a.sort_values(["agent_id", "release_version", "_canonical_spelling"], ascending=[True, True, False])
    dup = a.duplicated(["agent_id", "release_version"], keep="first")
    alias = {}
    conflicts = {}
    for (aid, ver), g in a.groupby(["agent_id", "release_version"]):
        if len(g) > 1:
            keep = g.iloc[0]
            for _, r in g.iloc[1:].iterrows():
                alias[(aid, r["release_version_raw"])] = (aid, ver)
                diff = {c: (keep[c], r[c]) for c in ["agent_name", "autonomy_level", "model_id", "sandbox_profile_id", "is_deprecated"] if keep[c] != r[c]}
                if diff:
                    conflicts[(aid, ver)] = diff
    dim = a[~dup].copy()
    dim["launch_date"] = pd.to_datetime(dim["launch_date"], errors="coerce")
    dim = dim.sort_values(["agent_id", "launch_date", "release_version"]).reset_index(drop=True)
    dim["valid_from_utc"] = dim["launch_date"].dt.tz_localize("UTC")
    dim["valid_to_utc"] = dim.groupby("agent_id")["valid_from_utc"].shift(-1)
    dim["is_current"] = dim["valid_to_utc"].isna()
    dim.insert(0, "agent_sk", range(1, len(dim) + 1))
    dim["max_tool_calls_per_session"] = pd.to_numeric(dim["max_tool_calls_per_session"], errors="coerce").astype("Int64")
    dim["is_deprecated"] = dim["is_deprecated"].map({"true": True, "false": False})
    dim["alias_versions"] = [
        "|".join(sorted(raw for (x, raw), (y, v) in alias.items() if x == aid and v == ver)) or None
        for aid, ver in zip(dim["agent_id"], dim["release_version"])
    ]
    dim["alias_conflicts"] = [str(conflicts.get((aid, ver))) if (aid, ver) in conflicts else None for aid, ver in zip(dim["agent_id"], dim["release_version"])]
    dim["quality_flags"] = _join_flags(
        pd.Series(np.where(dim["alias_versions"].notna(), "version_alias_merged", None), index=dim.index),
        pd.Series(np.where(dim["alias_conflicts"].notna(), "alias_attributes_conflict", None), index=dim.index),
        pd.Series(np.where(~dim["agent_type"].isin(AGENT_TYPES), "agent_type_not_in_enum", None), index=dim.index),
        pd.Series(np.where(~dim["autonomy_level"].isin(AUTONOMY_LEVELS), "autonomy_not_in_enum", None), index=dim.index),
    )
    dim = dim.drop(columns=["_canonical_spelling"])
    return dim, alias


def flag_agent_profiles(dim_agent: pd.DataFrame, dim_policy: pd.DataFrame) -> pd.DataFrame:
    """Mark agent versions whose sandbox_profile_id has no policy at all."""
    known = set(dim_policy["sandbox_profile_id"])
    d = dim_agent.copy()
    missing = ~d["sandbox_profile_id"].isin(known)
    d["has_policy"] = ~missing
    extra = pd.Series(np.where(missing, "sandbox_profile_without_policy", None), index=d.index)
    d["quality_flags"] = _join_flags(d["quality_flags"], extra)
    return d


# ----------------------------------------------------------------------------- tools


def resolve_tools(tools: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, str]]:
    """Drop exact duplicate rows, build the name -> tool_id alias map (so activity rows
    that carry a tool *name* in tool_id can be resolved), and flag tool_ids whose
    category differs across versions (the canonical category is the newest version's)."""
    t = tools.copy()
    exact_dups = t.drop(columns=["source_file", "source_line"]).duplicated(keep="first")
    dim = t[~exact_dups].copy()
    alias = {name: tid for name, tid in zip(dim["tool_name"], dim["tool_id"]) if name != tid}
    cats = dim.groupby("tool_id")["tool_category"].nunique()
    inconsistent = set(cats[cats > 1].index)
    dim["_v"] = dim["tool_version"].map(lambda v: tuple(int(x) if x.isdigit() else 0 for x in str(v).split(".")))
    canon_cat = dim.sort_values("_v").groupby("tool_id")["tool_category"].last()
    dim["tool_category_canonical"] = dim["tool_id"].map(canon_cat)
    dim["requires_approval"] = dim["requires_approval"].map({"true": True, "false": False})
    dim["quality_flags"] = _join_flags(
        pd.Series(np.where(dim["tool_id"].isin(inconsistent), "category_differs_across_versions", None), index=dim.index),
        pd.Series(np.where(~dim["tool_category"].isin(TOOL_CATEGORIES), "category_not_in_enum", None), index=dim.index),
        pd.Series(np.where(~dim["risk_tier"].isin(RISK_TIERS), "risk_tier_not_in_enum", None), index=dim.index),
    )
    dim = dim.drop(columns=["_v"]).reset_index(drop=True)
    return dim, alias


# -------------------------------------------------------------------------- pricing


def resolve_model_pricing(pricing: pd.DataFrame) -> pd.DataFrame:
    """Close overlapping open-ended price windows: a window with no effective_to that is
    followed by a later window for the same model ends when the later one starts
    (Type-2 repair). Null prices are kept null and flagged."""
    p = pricing.copy()
    p["effective_from_utc"] = pd.to_datetime(p["effective_from"], utc=True, errors="coerce")
    p["effective_to_utc"] = pd.to_datetime(p["effective_to"], utc=True, errors="coerce")
    p = p.sort_values(["model_id", "effective_from_utc"]).reset_index(drop=True)
    next_from = p.groupby("model_id")["effective_from_utc"].shift(-1)
    repaired = p["effective_to_utc"].isna() & next_from.notna()
    overlapping = p["effective_to_utc"].notna() & next_from.notna() & (p["effective_to_utc"] > next_from)
    p.loc[repaired | overlapping, "effective_to_utc"] = next_from[repaired | overlapping]
    for c in ["input_price_per_1k", "output_price_per_1k"]:
        p[c] = pd.to_numeric(p[c], errors="coerce")
    p["quality_flags"] = _join_flags(
        pd.Series(np.where(repaired, "open_window_closed_at_next_effective_from", None), index=p.index),
        pd.Series(np.where(overlapping, "overlapping_window_truncated", None), index=p.index),
        pd.Series(np.where(p["input_price_per_1k"].isna() | p["output_price_per_1k"].isna(), "price_missing", None), index=p.index),
    )
    return p


def price_at(model_id: pd.Series, at_utc: pd.Series, pricing: pd.DataFrame) -> pd.DataFrame:
    """Price effective at each row's time (validity-window join on the repaired pricing
    windows). Returns input_price_per_1k / output_price_per_1k, null when the model has
    no price or no window covers the time."""
    out = pd.DataFrame({"input_price_per_1k": np.nan, "output_price_per_1k": np.nan}, index=model_id.index)
    for mid, g in pricing.groupby("model_id"):
        rows = (model_id == mid).to_numpy()
        if not rows.any():
            continue
        t = at_utc[rows]
        for _, w in g.iterrows():
            m = (t >= w["effective_from_utc"]) & (pd.isna(w["effective_to_utc"]) | (t < w["effective_to_utc"]))
            idx = t.index[m.to_numpy()]
            out.loc[idx, "input_price_per_1k"] = w["input_price_per_1k"]
            out.loc[idx, "output_price_per_1k"] = w["output_price_per_1k"]
    return out


# --------------------------------------------------------------------------- status


def normalise_status(status: pd.Series) -> tuple[pd.Series, pd.Series]:
    """Trim/lower-case and map the known spelling variants ('succeeded' -> 'success').
    Returns (normalised, changed_mask)."""
    s = status.astype("string").str.strip().str.lower()
    out = s.replace(STATUS_ALIASES)
    changed = (out != s).fillna(False).astype(bool)
    return out, changed
