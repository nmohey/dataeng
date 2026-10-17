# Kestrel · Milestone 1 · Data-quality findings

Every problem found in `kestrel-telemetry-pack-v1`, **how it was detected**, and **what was decided**. The detection code is in `notebooks/01_profiling.ipynb` (section numbers below refer to it); the decisions are implemented in `kestrel_m1/` and applied in `notebooks/02_cleaning_integration_metrics.ipynb`. Counts are from the pipeline run on the pack (`data/curated/run_report.json`).

Legend for the decision column: **REJECT** = goes to the rejects table with the enum reason given; **REPAIR** = fixed and flagged in `quality_flags`; **RESOLVE** = entity resolution; **KEEP+FLAG** = kept as is with a flag; **RULE** = a convention established and documented.

## A. `agent_activity.parquet` (937,752 rows → 924,775 accepted, 12,977 rejected)

| # | problem | how it was detected | decision | count / effect |
|---|---|---|---|---|
| A1 | **Redelivered events**: 7,427 `event_id`s appear exactly twice; the copies are identical except `ingest_time`, the second arriving ~5.5 min later | `event_id.duplicated()`; column-by-column diff of the copies; distribution of the ingest gap (§1.6) | **REJECT `DUPLICATE_EVENT_ID`** for the copy with the later `ingest_time` (Appendix A convention: keep the earliest) | 7,427 rows; also removes 7,329 of the 21,256 "late" rows |
| A2 | **Five timestamp shapes in `event_time`**: ISO `Z` (922,618), 13-digit epoch (14,029), `dd/mm/yyyy HH:MM:SS` with no offset (392), `2026-02-30T10:00:00Z` (366), `not-a-time` (347) | digit-masked shape counts (§1.4) | **RULE + REPAIR**: epoch = UTC milliseconds; slash = day-first, UTC (flags `event_time_epoch_ms`, `event_time_dd_mm_yyyy_naive`). **REJECT `MALFORMED_TIMESTAMP`** for Feb-30 and `not-a-time` | 14,240 repaired (13,853 + 387 accepted); 708 rejected |
| A2a | *Epoch zone*: which zone are the 13-digit values in? | read as UTC ms, their lateness distribution equals the ISO rows' (median 0.92 s, p99 ~14 min); any other zone would shift by whole hours (§1.4) | UTC milliseconds | — |
| A2b | *Slash rows*: day-first or month-first, and which offset? | first field > 12 on 250 rows and the second never → day-first; `ingest_time − naive` rounds to 0 h on all 392 rows; the row sits between its session neighbours only at offset 0 (§1.4, nb 02) | day-first, written in UTC | — |
| A3 | **Late events**: 21,256 rows with `ingest − event > 10 s` (up to 55 min); none negative | lateness buckets and histogram (§1.5) | **KEEP+FLAG `late_event`**; batch has **no watermark** (`LATE_BEYOND_WATERMARK` is for the Milestone 2 stream); counted in metric 9 | 13,865 late rows accepted (1.50%) |
| A4 | **Invalid event types**: `agent.telepathy` (152), `llm.thought` (150); they also have null `sequence_number` | enum check (§1.2) | **REJECT `INVALID_EVENT_TYPE`** (precedence over `MISSING_REQUIRED_FIELD`) | 302 |
| A5 | **Null `status`** on 400 turns and 338 tool calls | null count by event type (§1.2) | **REJECT `MISSING_REQUIRED_FIELD`** (status is required on every row and cannot be inferred) | 730 (8 were also duplicates) |
| A6 | **`status = succeeded`** (160 tool calls); 17 of them carry an `error_class` | enum check; crosstab status × error_class (§1.2) | **REPAIR** `succeeded → success` (flag `status_spelling_normalised`); **KEEP+FLAG `status_conflicts_with_error_class`** for the 17 | 160 / 17 |
| A7 | **Unknown tenant `tn_777`** on 736 rows, inside sessions whose other rows carry the real tenant | FK to `tenants.csv`; tenant varies within 727 sessions (§1.7) | **REJECT `UNKNOWN_TENANT_ID`**. Alternative considered and documented: repairing from the agent's tenant; rejected because the closed enum names this exact case and reference values are computed that way | 730 (6 were duplicates) |
| A8 | **Unknown agents `ag_999`, `ag_321` (v `9.9.9`)**: 333 whole sessions on instance `sbx_0000`, every type-specific field null | FK to `agents.csv`; the "hollow row" check (§1.3, §1.7) | **REJECT `UNKNOWN_AGENT_ID`** (precedence over `MISSING_REQUIRED_FIELD`) | 1,332 rows, 333 sessions |
| A9 | **`release_version` with a leading `v`** (`v2.3.1`, `v2.2.0` for `ag_007`); the version changes mid-session in 1,888 sessions | FK to `agents.csv`; semver pattern; per-session nunique (§1.7) | **RESOLVE** strip `v` (flag `release_version_alias`); after resolution 0 sessions change version | 2,311 accepted rows |
| A10 | **Tool names used as `tool_id`**: `http_get` (490), `webfetch` (490) | FK to `tools.csv` fails; the values are `tool_name`s of `tl_web_fetch` 1.1.0 / 1.0.0 (§1.7) | **RESOLVE** name → id via `tools.csv` (flag `tool_name_resolved_to_id`) | 972 accepted rows |
| A11 | **Negative counts**: `latency_ms < 0` (411 turns), `input_tokens < 0` (830 turns), `retry_number = −1` (321 tool calls) | min of every numeric column (§1.8) | **REJECT `INVALID_NUMERIC_RANGE`** — the true value is unknown; the enum has a reason for exactly this. Documented alternative: null + flag, which would keep 1,548 rows and lower metric 9 by 0.13 pp | 1,548 |
| A12 | **Missing `output_tokens`** on 4,116 turns (4,098 accepted) | null count vs `input_tokens` (§1.8) | **KEEP+FLAG `missing_output_tokens`**; **null-excluded** policy declared; effect shown: mean output tokens/turn 239.8 (null-excluded) vs 237.4 (zero-filled), totals unchanged | 4,098 |
| A13 | **Orphan rows**: 200 sessions consist of a single `tool.call` and never had a `session.start` (`ss_8xxxxx`) | session structure (§1.9) | **REJECT `ORPHAN_EVENT`** | 200 |
| A14 | **Sessions that never terminate**: 2,248 sessions have no `session.end`/`session.error` | session structure (§1.9) | **KEEP**; by definition excluded from session volume, success/error and duration (metric 1d reports 2,048 after cleaning) | 2,048 accepted sessions |
| A15 | **Sequence gaps**: 700 sessions already have `max(sequence) ≠ count`; cleaning adds more | per-session min/max/count (§1.9) | **MEASURE**: this is what trace completeness (metric 8) reports — 4,035 terminal sessions with a gap after cleaning | 95.9% complete |
| A16 | **`finished_at` before `event_time`** on 1,591 tool calls; `latency_ms` ≠ `finished_at − event_time` on the same rows; terminal `latency_ms` ≠ derived duration (> 1 s) on 1.98% of sessions | cross-checks (§1.9) | **KEEP+FLAG** (`finished_before_event_time`, `latency_disagrees_with_finished_at`); duration is **always derived** from `event_time`; the disagreement rate is reported with metric 2 | 1,603 / 1,760 / 1,942 |
| A17 | Traffic concentration: `tn_001` 56% of sessions, `ag_004 3.0.2` 27%, three sandbox instances 47% of rows | group-by (§1.10) | **RECORD** for Milestone 2's Spark skew handling | — |

## B. Reference tables

| # | file | problem | how it was detected | decision | effect |
|---|---|---|---|---|---|
| B1 | `tenants.csv` | `tn_003 NILEBANK Ltd.` and `tn_004 nilebank` are **one tenant under two ids** (identical industry, plan, region, onboarding time, contact) | normalised-name match + attribute equality (§2) | **RESOLVE** `tn_004 → tn_003`; alias recorded in `dim_tenant.aliases` | 5 tenants; 0 fact rows needed the alias |
| B2 | `tenants.csv` | `tn_005` region `eu-central-9` **not in the enum**; `security_contact` empty | enum check; null (§2) | **KEEP+FLAG** `region_not_in_enum`, `security_contact_missing` (no evidence for a repair; its sandboxes are in the `eu` racks) | 1 |
| B3 | `tenants.csv` | `tn_006` inactive but has 2,063 sessions | join to activity (§2) | **not a defect** (declared in the description); kept | — |
| B4 | `agents.csv` | `(ag_007, v2.3.1, "Market Research Agent", autonomous)` is the **same version** as `(ag_007, 2.3.1, "market-research-agent", semi_autonomous)` | normalised natural key (§2) | **RESOLVE** into `2.3.1`; the conventional row's attributes win; the autonomy conflict is recorded in `dim_agent.alias_conflicts` | 21 agent versions |
| B5 | `agents.csv` | `ag_019 → sp_missing_profile`, a profile **with no policy** | FK to `sandbox_policies.json` (§2) | **KEEP+FLAG** `sandbox_profile_without_policy`; its 6,200 sessions get null `policy_version_applied` / `is_policy_violation` and `no_policy_for_profile` | 52,234 canonical rows |
| B6 | `tools.csv` | exact duplicate row `(tl_vector_search, 2.0.1)` | `duplicated()` (§2) | **REJECT `DUPLICATE_EVENT_ID`** (line 6) | 1 |
| B7 | `tools.csv` | `tl_web_fetch` has three names across versions; `tl_code_exec` is `shell` in 0.9.0 and `code_exec` in 0.9.1 | group-by `tool_id` (§2) | name → id alias map; `tool_category_canonical` = newest version's, both rows flagged `category_differs_across_versions` | — |
| B8 | `model_pricing.csv` | `mdl_kst_pro_1` has **two open-ended windows** (Jan price never closed when the Mar price started) | window-overlap check (§2) | **REPAIR**: close the first at `2026-03-01` (flag `open_window_closed_at_next_effective_from`) | cost is unambiguous at any turn time |
| B9 | `model_pricing.csv` | `mdl_kst_nano_1` has **no prices** | null check (§2) | **KEEP+FLAG** `price_missing`; `cost_usd` null for its 28,663 turns (`price_missing_for_model`) | — |

## C. `sandbox_policies.json` (10 policy versions)

| # | problem | how it was detected | decision |
|---|---|---|---|
| C1 | `sp_research_std` **v2 and v3 overlap for 7 days** (v2 valid to Feb 1, v3 from Jan 25); one day (Jan 31) is inside the pack | window report (§3) | **RULE: the higher `policy_version` wins inside an overlap.** Confirmed by the sandbox's own log: all 346 research decisions on Jan 31 report `policy_version=3`, none 2 (§5.2). Derived vs logged version agree on 100% of 181,031 lines |
| C2 | `sp_ops_elevated` **v4 has no `network` block** | key-set check per policy object (§3) | **RULE** (Dataset Description §3.4): no network block ⇒ no egress allowed ⇒ every flow under v4 is an egress violation (`egress_violation:no_network_block`). The runtime nevertheless allowed 3,718 of them with reason `NO_NETWORK_POLICY` → flagged `runtime_allowed_despite_policy` |
| C3 | Six of eleven allowlist entries are wildcards (`*.public-data.example`, `*.status.kestrel.ai`, `*.pkg-mirror.example`) | bridge table `policy_egress_allowlist.is_wildcard` (§3) | **RULE**: glob matching (`fnmatch`), never string equality |
| C4 | `sp_missing_profile` is referenced by an agent but absent | set difference (§3) | see B5 |

## D. `network_flows.csv` (42,392 → 42,308 accepted, 84 rejected)

| # | problem | how it was detected | decision | count |
|---|---|---|---|---|
| D1 | **84 flows reference sessions `ss_7000xx`** that exist in no other file | FK to activity sessions (§4) | **REJECT `ORPHAN_EVENT`** | 84 |
| D2 | `dst_host` null on 3,514 flows; `geo_country` null on 2,088 | null pattern by protocol / verdict / `dst_ip` range (§4) | **structural, KEEP+FLAG** (`dst_host_missing_ip_only_flow`, `geo_country_missing`): IP-only destinations — lateral movement to `10.20.4.x` on 22/445/3389 and HTTPS uploads to `203.0.113.x`; geo is null exactly for internal `10.x` targets. `target_resource` falls back to `dst_ip` | 3,507 / 2,084 accepted |
| D3 | Clock check: is `flow_time` on the same clock as `event_time`? | every flow lies inside its session's `[first, last]` activity window (§4) | **RULE**: UTC as written, no adjustment | 0 outside |
| D4 | `src_ip ↔ sandbox_instance_id` one-to-one; flow instance = activity instance for every session | group-by nunique (§4) | **RULE**: `src_ip` is a reliable correlation key for the SIEM feed | 0 mismatches |
| D5 | Runtime verdict vs policy: 4,775 flows **allowed** by the sandbox but forbidden by the effective policy (3,718 `no_network_block`, 1,057 `host_not_allowlisted` IP-only uploads allowed as `WILDCARD_MATCH_UNVERIFIED`); every blocked/logged-only flow is also a violation by our rule | crosstab verdict × derived violation (nb 02 §7) | canonical `is_policy_violation = true` **+ flag `runtime_allowed_despite_policy`**, so Milestone 2 can report both the policy view and the runtime view | 4,775 |

## E. `sandbox_audit.log` (184,005 lines → 183,477 accepted, 528 rejected)

| # | problem | how it was detected | decision | count |
|---|---|---|---|---|
| E1 | **Truncated lines**: 524 lines stop mid-field (`decision=AL`, `target=/workspace/out/report_`, `session=ss_09`) | header regex matches, but one or more of the seven `key=value` fields is missing (§5) | **REJECT `UNPARSEABLE_RECORD`**; the fragment is the payload. Reasoning: a partial value (`AL`, `proc`) is not a decision, and a truncated `session_id` cannot be joined | 524 |
| E2 | 4 exact duplicate lines | `duplicated()` on the full line (§5) | **REJECT `DUPLICATE_EVENT_ID`** (declared natural key = the whole line; the log has no record id) | 4 |
| E3 | `policy_version=-` on 2,446 lines | value counts (§5) | **`-` is the syslog null**: kept null, flag `policy_version_missing_in_log`; all belong to `ag_019` (no policy) | 2,446 |
| E4 | **No year, no offset.** The log runs into April although the pack ends Mar 31 UTC | header format; month counts (§5) | **RULE**: year 2026 (the pack's); offset measured (E5) | — |
| E5 | **Hosts write UTC+2 with a per-host clock skew of −90.3 … +87.4 s**, stable over all nine weeks, in all three regions (`eu`, `me`, `us`) | lined up 121k unambiguous `(session, target)` pairs between audit lines and tool calls; per host `log_time − event_time_utc` is a cluster with p05–p95 within 1.1 s; subtracting a flat 2 h leaves 5% of lines inside their session window, subtracting the per-host offset puts 100% inside (§5.1, nb 02 §4) | **RULE**: `log_time_utc = naive − offset(host)`; offsets published in `sandbox_host_clock_offsets.csv`; flag `syslog_clock_offset_inferred` on every decision; fallback 7200 s for a host with < 20 pairs (never needed) | 42 hosts |
| E6 | `NO_NETWORK_POLICY` (3,705) and `WILDCARD_MATCH_UNVERIFIED` (425) **ALLOW** decisions | reason × decision crosstab (§5) | **KEEP**; `risk_indicators = runtime_allow_unverified:<reason>`; they explain D5 | 4,130 |
| E7 | `policy_version` in the log vs the version derived by validity window | compared on every complete line with a profile (nb 02 §7) | 100% agreement → the overlap rule C1 is right; flag `policy_version_log_disagrees_with_derived` exists for future exports (0 rows) | 181,031 |
| E8 | Escalation-class syscalls (`setuid` 726, `ptrace` 152), all denied | action × decision (§5) | **KEEP**; flag `escalation_attempt`, risk indicator `escalation_denied` | 877 |

## F. `siem_alerts.json` (3,754 alerts → 3,754 accepted)

| # | problem | how it was detected | decision | count |
|---|---|---|---|---|
| F1 | **Three clocks**: `detected_at` carries `+02:00` (corp-siem), `+03:00` (egress-proxy), `−05:00` (cloud-ids); `generated_at` is `+02:00` | offset suffix × `source_system` (§6) | **RULE**: parse as written; everything to UTC | 1,912 / 591 / 1,251 |
| F2 | **1,251 alerts (all `cloud-ids`) come from `10.44.x.x`**, addresses that are never a sandbox | `source_ip ∉ flows.src_ip` (§6) | **unmatched, never forced** (`unmatched_reason = source_ip_not_a_sandbox`); they stay in the coverage denominator | 1,251 |
| F3 | No `session_id` at all (by design) | schema (§6) | **correlation rule declared**: `(source_ip = src_ip, destination.host = dst_ip, destination.port = dst_port, \|Δt\| ≤ 60 s)` | — |
| F4 | **Choice of N**: nearest-flow Δt is 0–60 s for 97% of matchable alerts, **empty between 60 and 150 s**, then 67 alerts at 150–400 s | Δt histogram and sweep 5–600 s (§6.1) | **N = 60 s** (in the empty band; identical result at 120 s). Sweep published; at 600 s the 67 slow alerts would match with one more ambiguous case | matched 2,409 · ambiguous 27 · unmatched 1,318 |
| F5 | **Ambiguous** alerts: 27 match two flows within 60 s (port sweeps / SMB bursts to the same host) | `n_candidate_flows > 1` | kept `ambiguous`; `matched_session_id` filled when all candidates share one session (26 of 27) | 27 |
| F6 | 243 flows matched by more than one alert | group-by `matched_flow_id` | legitimate many-to-one (several SIEM rules on one flow); kept | 243 |
| F7 | Direction: on 2,498 of 2,503 matchable alerts the alert comes **after** its flow | sign of Δt (§6.1) | consistent with detection latency; a symmetric window is used because the description specifies \|Δt\| | — |

## G. Things that look wrong but are not

* Inactive tenant `tn_006` with traffic (B3) — declared in the overview.
* `dst_host`/`geo_country` nulls on flows (D2) — IP-only destinations.
* `error_class` null on successes, `bytes_out` null on non-network tools, type-specific columns null on other event types — the row's `event_type` decides which columns are filled.
* `expected_tool_categories` listing the same categories in different orders (`database|retrieval|filesystem` vs `database|filesystem|retrieval`) — a set, compared as a set in Milestone 2.
* The SIEM `severity` — the target system's opinion; carried in `status`, never used as ours.
* Session durations of 2–110 s — short, but consistent across `event_time`, terminal `latency_ms` (98% agreement) and the audit log.

## H. Effect on the four metrics

| metric | value | the decision that moves it most |
|---|---|---|
| 1 session volume / success / error | 97,952 · 92.5% · 7.5% | excluding 2,048 started-but-not-terminated sessions; rejecting the 333 hollow sessions (A8) |
| 2 p50 / p95 duration | 17.6 s / 39.6 s | deriving from `event_time` (A16); the two numbers are insensitive to all other decisions |
| 8 trace completeness | 95.9% | every row rejection inside a session (A5, A7, A11, A2) opens a gap: with null+flag instead of reject for A11 it would be 97.3% (1,365 of the 4,035 gap sessions lose only INVALID_NUMERIC_RANGE rows) |
| 8 correlation coverage | 64.9% of all alerts (97.3% of sandbox-sourced) | N = 60 s (F4): 66.0% at 300 s, 66.6% at 600 s; the 1,251 external alerts (F2) cap it at 66.7% |
| 9 rejected-record rate | 1.16% | A1 duplicates are 55% of all rejects; A11 (reject vs flag) is ±0.13 pp |
| 9 late-event rate | 1.50% | deduplication first (A1): the redelivered copies were themselves late |
