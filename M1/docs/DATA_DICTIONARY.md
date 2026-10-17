# Kestrel · Milestone 1 · Data dictionary and policies

This document is the contract for what `kestrel_m1` produces: the **canonical activity table**, the **rejects table**, the conformed **dimensions**, and the **policies** behind them (null, timezone, entity resolution, deduplication, rejection precedence, policy-violation derivation, SIEM correlation, late events, metrics). Field-level detail of the *inputs* is in the course's Dataset Description; this document describes the *outputs* and every decision taken between the two.

Contents

1. [Canonical activity table](#1-canonical-activity-table)
2. [Rejects table (`fact_rejected_record`)](#2-rejects-table-fact_rejected_record)
3. [Dimensions and side tables](#3-dimensions-and-side-tables)
4. [Null policy](#4-null-policy)
5. [Timezone policy](#5-timezone-policy)
6. [Entity-resolution policy](#6-entity-resolution-policy)
7. [Deduplication policy](#7-deduplication-policy)
8. [Rejection policy and precedence](#8-rejection-policy-and-precedence)
9. [Policy-violation derivation](#9-policy-violation-derivation)
10. [SIEM ↔ network-flow correlation policy](#10-siem--network-flow-correlation-policy)
11. [Late-event policy](#11-late-event-policy)
12. [Metric definitions](#12-metric-definitions)
13. [Glossary of `quality_flags` and `risk_indicators`](#13-glossary-of-quality_flags-and-risk_indicators)

---

## 1. Canonical activity table

File: `data/curated/canonical_activity.parquet` (zstd) · Postgres table `canonical_activity` · 1,154,314 rows · one row per accepted record from any source. Sorted by `event_time_utc`.

### 1.1 Required fields (Dataset Description §5)

| field | type | source of truth / derivation | null when |
|---|---|---|---|
| `activity_id` | string, **PK** | the source record's primary key prefixed by source: `act:<event_id>`, `nf:<flow_id>`, `sb:sandbox_audit.log#<line>`, `al:<alert_id>` | never |
| `source_file` | string | input file name | never |
| `source_format` | enum `parquet` · `csv` · `syslog` · `json` | | never |
| `source_line` | int | Parquet: 1-based row ordinal · CSV: physical line (header = 1) · syslog: physical line · JSON: 0-based index in the array | never |
| `event_time_utc` | timestamp (µs, UTC) | when it happened, normalised per §5 (parquet `event_time`, flow `flow_time`, syslog line time, SIEM `detected_at`) | never (unparseable → rejected) |
| `ingest_time_utc` | timestamp (µs, UTC) | when the platform received it — exists only in `agent_activity.parquet` | flows, sandbox decisions, SIEM alerts (structural) |
| `lateness_s` | float | `ingest_time_utc − event_time_utc` in seconds | same as above |
| `tenant_id` | string, FK → `dim_tenant` | resolved (alias `tn_004 → tn_003`); for flows/decisions from the session's `session.start`; for alerts from the matched session | SIEM alerts not linked to a session |
| `agent_sk` | int, FK → `dim_agent.agent_sk` | the Type-2 surrogate of the `(agent_id, release_version)` current at `event_time_utc` (after alias resolution); flows/decisions/alerts via session | SIEM alerts not linked to a session |
| `session_id` | string | the source's `session_id`; alerts: the correlated session | SIEM alerts not linked to a session |
| `task_id` | string | from the session's `session.start` row | SIEM alerts not linked |
| `activity_type` | enum `lifecycle` · `prompt_turn` · `tool_call` · `network_flow` · `sandbox_decision` · `siem_alert` | from the source and its event type | never |
| `activity_subtype` | string | the source's own name: `session.start`/`llm.turn`/`tool.call`/`session.end`/`session.error`; `egress:<protocol>`; the syslog `action`; the SIEM `rule` | never |
| `status` | string | normalised outcome: activity `status` (`ok`/`error`/`success`/`failure`/`denied`/`timeout`, spelling variants mapped); decisions `allow`/`deny`; alerts: `severity` | network flows (they have a verdict, not a status) |
| `verdict` | string | flows: `allowed`/`blocked`/`logged_only`; decisions: the syslog `reason`; alerts: correlation outcome `matched`/`ambiguous`/`unmatched` | activity rows |
| `target_resource` | string | tool calls: host/table/path/command; flows: `dst_host`, or `dst_ip` when there is no host; decisions: `target`; alerts: `destination_host:port` | lifecycle rows, prompt turns |
| `policy_version_applied` | int | the `policy_version` whose `[valid_from, valid_to)` contains `event_time_utc` for the session's `sandbox_profile_id` (§9) | profile has no policy (`ag_019`); SIEM alerts |
| `is_policy_violation` | boolean | tool calls: tool not in the effective allowlist; flows: outside the effective egress policy (§9); decisions: `decision == DENY` (an attempted action the sandbox refused) | lifecycle, prompt turns, alerts (not applicable); no policy |
| `risk_indicators` | pipe-separated string | union of: injection indicators of the turn; `tool_denied`; `policy_violation`; `egress_blocked` / `egress_logged_only` / `egress_violation:<reason>` / `siem_alerted`; `sandbox_deny:<reason>` / `escalation_denied` / `runtime_allow_unverified:<reason>`; `siem:<technique>` / `siem_severity:<level>` | no indicator |
| `tokens_in`, `tokens_out` | int | prompt turns: `input_tokens`, `output_tokens` | non-turn rows; `tokens_out` on 4,098 turns that arrived without it (kept null, see §4) |
| `cost_usd` | decimal(6) | `tokens_in/1000 × input_price + tokens_out/1000 × output_price` at the price **effective at `event_time_utc`** (repaired pricing windows, §6.4) | non-turn rows; turns of `mdl_kst_nano_1` (no price); turns with a null token count (null-excluded policy) |
| `quality_flags` | pipe-separated string | non-fatal issues retained rather than silently fixed (§13) | no flag |

### 1.2 Extension columns

Kept because Milestone 2 needs them and they would otherwise have to be re-derived from the sources. They never replace a required field.

| column | content |
|---|---|
| `source_record_id` | the un-prefixed source key (`event_id`, `flow_id`, `alert_id`, `file#line`) |
| `agent_id`, `release_version` | the resolved natural key behind `agent_sk` |
| `sandbox_instance_id` | the running container (activity, flows, decisions; alerts via session) |
| `sequence_number` | activity rows only, per session from 1 |
| `tool_id`, `tool_version`, `model_id`, `error_class`, `retry_number`, `bytes_out` | activity rows (resolved `tool_id`) |
| `bytes_in`, `src_ip`, `dst_ip`, `dst_port`, `protocol` | flows (`bytes_received`, …); alerts fill `src_ip`/`dst_ip`/`dst_port` from `source_ip`/`destination` |
| `host` | syslog host (decisions) or `source_system` (alerts) |
| `is_late` | `lateness_s > 10` (activity rows; null elsewhere) |
| `is_terminal` | `session.end` or `session.error` |
| `task_category`, `expected_tool_categories`, `stated_goal`, `content_source` | goal-drift inputs, from the start row / the turn |
| `siem_match_status` | alerts: `matched` / `ambiguous` / `unmatched` |

## 2. Rejects table (`fact_rejected_record`)

File: `data/curated/rejects.parquet` and `rejects.csv` · Postgres `fact_rejected_record` · 13,590 rows. **Nothing is ever silently dropped**: a record is in the canonical table or here.

| field | type | content |
|---|---|---|
| `reject_id` | int, PK | 1..n |
| `source_file` | string | input file |
| `source_format` | enum | `parquet` · `csv` · `syslog` · `json` |
| `source_line` | int | as in §1.1 — the pointer back into the file |
| `record_key` | string | the record's natural key when it has one (`event_id`, `flow_id`, `alert_id`, `tool_id`, syslog `session_id`) |
| `reject_reason` | enum (closed, §8) | **exactly one** of the eleven reasons |
| `detail` | string | human-readable evidence, e.g. `event_time=not-a-time`, `input_tokens=-5901 (< 0)`, `truncated line, missing: reason,policy_version` |
| `raw_payload` | JSON string | the record exactly as read (all bronze columns; for syslog the raw line) |

## 3. Dimensions and side tables

| table | grain | key columns and notes |
|---|---|---|
| `dim_tenant` | one tenant | `tenant_id` PK; `aliases` (`tn_004` folded into `tn_003`); `is_active` boolean; `onboarded_at_utc`; `quality_flags` (`region_not_in_enum`, `security_contact_missing`, `has_alias_ids`) |
| `dim_agent` | one agent **version** (Type-2) | `agent_sk` PK; natural key `(agent_id, release_version)` (normalised, no `v`); `valid_from_utc = launch_date`, `valid_to_utc` = next version's launch (null = current), `is_current`; `alias_versions`, `alias_conflicts`; `has_policy`; `quality_flags` |
| `dim_tool` | one tool version | `(tool_id, tool_version)`; `tool_name`; `tool_category` as exported and `tool_category_canonical` (newest version's); `requires_approval` boolean |
| `dim_model_pricing` | one price window | `(model_id, effective_from_utc)`; `effective_to_utc` **repaired** (open windows closed at the next window's start); `quality_flags` (`open_window_closed_at_next_effective_from`, `price_missing`) |
| `dim_sandbox_policy` | one policy version | `policy_sk` PK; `(sandbox_profile_id, policy_version)`; `valid_from_utc`, `valid_to_utc`; `has_network_block`; `max_egress_mb`, `max_runtime_s`, `max_memory_mb`, `escalation_allowed`; filesystem scopes pipe-joined |
| `policy_allowed_tools` / `policy_egress_allowlist` / `policy_denied_ports` | bridge rows | `policy_sk` → `tool_id` / `pattern` (+ `is_wildcard`) / `port` |
| `sandbox_host_clock_offsets` | one syslog host | `offset_s` (seconds to subtract from the naive log time), `n_pairs`, `p05_s`, `p95_s`, `method`, `whole_hours`, `skew_s` |
| `siem_flow_correlation` | one alert | `match_status`, `matched_flow_id`, `matched_session_id`, `n_candidate_flows`, `n_candidate_sessions`, `nearest_flow_delta_s`, `unmatched_reason`, `tolerance_s` |
| `siem_flow_correlation_sweep` | one tolerance | matched / ambiguous / unmatched at 5, 10, 30, 60, 120, 300, 600 s |
| `sessions` | one accepted session | `start_utc`, `terminal_type`, `terminal_utc`, `duration_s`, `n_turns`, `n_tool_calls`, `sequence_contiguous`, `is_terminal`, `tenant_id`, `agent_id` |
| `metrics`, `metrics_token_policy_sensitivity` | one metric / one policy | §12 |

## 4. Null policy

| situation | decision | why |
|---|---|---|
| empty CSV field, JSON `null`, Parquet null, syslog `-` | read as null | the pack's declared null conventions (Dataset Description §0) |
| a **required** field is null (`event_id`, `event_time`, `ingest_time`, `sequence_number`, `event_type`, `session_id`, `tenant_id`, `agent_id`, `release_version`, `sandbox_instance_id`, `status`; plus per type: turn → `model_id`, `turn_index`, `input_tokens`; tool call → `tool_id`, `tool_version`, `retry_number`; start → `task_id`; flow → all columns except `dst_host`, `geo_country`; alert → `alert_id`, `detected_at`, `source_ip`, `destination`, `severity`, `technique.id`) | **reject** `MISSING_REQUIRED_FIELD` | the record cannot be placed or interpreted |
| a **structural** null (`dst_host`/`geo_country` on IP-only flows; type-specific columns on other event types; `ingest_time` outside the platform feed; `error_class` on successes; `bytes_out` on non-network tools) | keep null, flag where informative (`dst_host_missing_ip_only_flow`, `geo_country_missing`) | the value correctly does not exist |
| `output_tokens` null on a turn (4,098 accepted turns) | keep null, flag `missing_output_tokens`; **null-excluded** from token sums and from `cost_usd` | zero would invent a measurement; the effect is shown in `metrics_token_policy_sensitivity.csv` (mean output tokens per turn 239.8 null-excluded vs 237.4 zero-filled; totals unchanged) |
| price missing (`mdl_kst_nano_1`) | `cost_usd` null, flag `price_missing_for_model` | cannot be priced; 28,663 turns |
| `policy_version=-` in the syslog | null, flag `policy_version_missing_in_log` | the sandbox had no policy to apply (all are `ag_019`) |
| policy fields for a profile with no policy (`sp_missing_profile`) | `policy_version_applied` and `is_policy_violation` null, flag `no_policy_for_profile` | unknown is not "no violation"; 52,234 rows |
| SIEM alert without a session | `tenant_id`, `agent_sk`, `session_id`, `task_id` null, flag `siem_unmatched` / `siem_source_outside_platform` | never forced onto a session |

## 5. Timezone policy

Everything in the canonical table is **UTC**, tz-aware, microsecond precision. How each source's convention was established (evidence in `notebooks/01_profiling.ipynb` §1.4, §5.1, §6):

| source · field | written as | convention | how it was established |
|---|---|---|---|
| `agent_activity.parquet` · `ingest_time`, `finished_at` | ISO-8601 `Z` | UTC | 100% parse; explicit `Z` |
| `agent_activity.parquet` · `event_time` (98.4%) | ISO-8601 `Z` | UTC | explicit `Z`; lateness 0.3–1.5 s on 99% of rows |
| `agent_activity.parquet` · `event_time` (14,029 rows) | 13-digit integer | **Unix epoch milliseconds, UTC** | interpreted as UTC ms they reproduce the ISO rows' lateness distribution (median 0.92 s); any other zone shifts by whole hours |
| `agent_activity.parquet` · `event_time` (392 rows) | `dd/mm/yyyy HH:MM:SS`, no offset | **day-first, UTC** | first field > 12 on 250 rows, second never; `ingest_time − naive` rounds to 0 h on every row; each row sits between its session neighbours only at offset 0 |
| `agent_activity.parquet` · `event_time` (713 rows) | `2026-02-30T10:00:00Z`, `not-a-time` | undecodable | rejected `MALFORMED_TIMESTAMP` |
| `network_flows.csv` · `flow_time` | ISO-8601 `Z` | UTC | 100% parse; every flow lies inside its session's UTC activity window |
| `sandbox_audit.log` · `Mon dd HH:MM:SS` | no year, no offset | year **2026**; `utc = naive − offset(host)` where `offset(host)` = **7200 s + a per-host skew of −90.3 … +87.4 s** | the sandbox logs the very tool calls the activity feed records; where `(session, target)` is unique on both sides, `log_time − event_time_utc` is the host's offset. 42 hosts, 121k unambiguous pairs, p05–p95 within 1.1 s per host, constant over all nine weeks. Subtracting a flat 2 h leaves 5% of lines inside their session window; the per-host offsets put 100% inside. Hosts in all three regions (`eu`, `me`, `us`) write UTC+2. Fallback for a host with < 20 pairs: 7200 s (never needed) |
| `siem_alerts.json` · `detected_at` | ISO-8601 with offset | as written: `+02:00` (corp-siem), `+03:00` (egress-proxy), `−05:00` (cloud-ids) | explicit offsets; after conversion matched flows precede their alerts by 0–60 s |
| `sandbox_policies.json`, `model_pricing.csv`, `tenants.csv` | ISO-8601 `Z` | UTC | explicit |

Dates and hour bands (`dim_date`, `dim_time`) are not built in this milestone.

## 6. Entity-resolution policy

Resolution runs **before** referential-integrity checks, so `UNKNOWN_*` is only raised for entities that truly do not exist.

### 6.1 Tenants
Two rows are one tenant when their normalised names match (lower-case, punctuation and corporate suffixes removed) **and** every other attribute is identical. `tn_004 nilebank` ≡ `tn_003 NILEBANK Ltd.` → the lower id (`tn_003`) is canonical, `tn_004` is recorded in `dim_tenant.aliases` and mapped on every fact row (flag `tenant_alias`; 0 rows needed it, `tn_004` has no traffic).

### 6.2 Agents
`release_version` is normalised (`v2.3.1 → 2.3.1`). Rows that then share `(agent_id, release_version)` are one version: the row whose spelling already followed semver wins; the other's differing attributes are kept in `alias_conflicts` (`ag_007 2.3.1`: autonomy `semi_autonomous` kept, `autonomous` recorded). Activity rows carrying `v2.3.1`/`v2.2.0` are mapped (2,311 rows, flag `release_version_alias`). `agent_sk` is the Type-2 key: one per version, `valid_from = launch_date`, `valid_to` = next launch; in this pack no event falls outside its own version's window, so `(agent_id, release_version)` and `(agent_id, event_time)` resolve to the same key.

### 6.3 Tools
Exact duplicate rows are dropped (one copy rejected `DUPLICATE_EVENT_ID`). `tool_name → tool_id` builds the alias map; activity rows whose `tool_id` is a *name* (`http_get`, `webfetch`, 972 accepted rows) are mapped to `tl_web_fetch` (flag `tool_name_resolved_to_id`). Where a tool's category differs across versions (`tl_code_exec`: `shell` vs `code_exec`), `tool_category_canonical` is the newest version's and both rows are flagged.

### 6.4 Model pricing
A price window with no `effective_to` that is followed by a later window for the same model ends when the later one starts (`mdl_kst_pro_1`: 2026-01-01 window closed at 2026-03-01). Prices are then looked up by validity window at turn time.

### 6.5 Statuses
`succeeded → success` (160 rows, flag `status_spelling_normalised`); values are trimmed and lower-cased. A `success` that still carries an `error_class` is flagged `status_conflicts_with_error_class` (17 rows).

### 6.6 Hosts and sandboxes
`src_ip ↔ sandbox_instance_id` is one-to-one in the flows; `instance ↔ host` is consistent between the syslog and the activity feed (0 mismatches on accepted lines). These are checks, not merges.

## 7. Deduplication policy

| source | declared natural key | which copy wins | result |
|---|---|---|---|
| `agent_activity.parquet` | `event_id` | the copy with the **earliest `ingest_time`** (ties: lowest row ordinal) | 7,427 later copies rejected `DUPLICATE_EVENT_ID`; the copies differed only in `ingest_time` (redelivery ~5.5 min later) |
| `network_flows.csv` | `flow_id` | earliest `flow_time`, then line | 0 |
| `sandbox_audit.log` | the whole line: `(month, day, time, host, pid, session, instance, decision, action, target, reason, policy_version)` — the log has no record id | first occurrence | 4 |
| `siem_alerts.json` | `alert_id` | earliest `detected_at`, then index | 0 |
| `tools.csv` | `(tool_id, tool_version)` | first row | 1 |
| `agents.csv`, `tenants.csv` | `(agent_id, release_version)` after normalisation; tenant identity | **merged**, not rejected (§6) | 1 version, 1 tenant |

## 8. Rejection policy and precedence

Each rejected record carries **exactly one** reason. When several apply, the first in this order wins (Dataset Description §4), and the data-quality findings say so where it mattered:

| # | reason | raised when | sources where it occurred |
|---|---|---|---|
| 1 | `DUPLICATE_EVENT_ID` | a later copy of a natural key already accepted (§7) | activity 7,427 · syslog 4 · tools 1 |
| 2 | `UNKNOWN_AGENT_ID` | `(agent_id, release_version)` not in `dim_agent` after alias resolution | activity 1,332 (`ag_999`, `ag_321` v`9.9.9`) |
| 3 | `UNKNOWN_TENANT_ID` | `tenant_id` not in `dim_tenant` after alias resolution | activity 730 (`tn_777`) |
| 4 | `MALFORMED_TIMESTAMP` | a non-null timestamp string that cannot be decoded by any of the recognised formats (`2026-02-30…`, `not-a-time`) | activity 708 |
| 5 | `ORPHAN_EVENT` | a non-start record whose session has no `session.start` that survives the row-local rules (also applies to flows and sandbox decisions) | activity 200 · flows 84 |
| 6 | `INVALID_EVENT_TYPE` | `event_type` outside the five-value enum | activity 302 (`agent.telepathy`, `llm.thought`) |
| 7 | `MISSING_REQUIRED_FIELD` | a required field is null (§4) | activity 730 (null `status`) |
| 8 | `INVALID_NUMERIC_RANGE` | `sequence_number < 1`, or `latency_ms`, `turn_index`, `input_tokens`, `output_tokens`, `retry_number`, `bytes_out`, `bytes_*` `< 0`, port outside 1–65535, confidence outside [0, 1] | activity 1,548 |
| 9 | `LATE_BEYOND_WATERMARK` | `lateness_s > BATCH_WATERMARK_S` — **the batch watermark is `None`**, so this is never raised in Milestone 1 (it is the Kafka consumer's 60 s rule in Milestone 2) | — |
| 10 | `UNPARSEABLE_RECORD` | a syslog line whose header does not match, or that is truncated (any of the seven `key=value` fields missing) | syslog 524 |
| 11 | `SCHEMA_VIOLATION` | Parquet schema differs from the contract, or a value is outside a closed enum after normalisation (`status`, `content_source`, `finish_reason`, `error_class`, `task_category`, injection-indicator tokens, `protocol`, `verdict`, `decision`, `action`, `severity`, IPv4 shape, technique-id shape), or an FK the enum has no name for (`(tool_id, tool_version)` ∉ `tools.csv`, `model_id` ∉ `model_pricing.csv`) | 0 after resolution |

Precedence mattered for: the 333 hollow sessions of `ag_999`/`ag_321` (also missing every type-specific field → `UNKNOWN_AGENT_ID`, rule 2 before 7); the 302 invalid event types (also null `sequence_number` → rule 6 before 7); the redelivered copies that are also late (rule 1; late is never a rejection in batch anyway). A null raw timestamp would be `MISSING_REQUIRED_FIELD` (rule 7), not `MALFORMED_TIMESTAMP`, because rule 4 requires a non-null, undecodable string; the pack contains none.

Repaired rather than rejected (kept with a flag): alias identifiers, spelling variants, decodable non-standard timestamp formats, late records, missing token counts, `finished_at` before `event_time` (1,603), `latency_ms` disagreeing with `finished_at` (1,760), structural nulls, runtime decisions that contradict the policy.

## 9. Policy-violation derivation

1. The session's `sandbox_profile_id` comes from `dim_agent` via the session's `(agent_id, release_version)`.
2. The effective policy is the version whose `[valid_from_utc, valid_to_utc)` contains the record's **own** `event_time_utc` (tool call time, flow time, decision time) — never the current version.
3. **Overlapping windows: the higher `policy_version` wins.** `sp_research_std` v2 (to 2026-02-01) and v3 (from 2026-01-25) overlap; the sandbox's own log reports v3 for every research session on 2026-01-31, which confirms the rule. The derived version agrees with the logged version on 100% of 181,031 audit lines.
4. **Tool call** violation: resolved `tool_id` ∉ `allowed_tools` of the effective policy. Every call the sandbox denied is a violation by this rule; 2,100 further violating calls completed with `timeout`/`failure`/`success`.
5. **Flow (egress)** violation, in order: the policy has **no `network` block** → violation (`no_network_block`; Dataset Description §3.4: such a version allows no egress); `dst_port` ∈ `denied_ports` → violation (`denied_port`); `dst_host` matches no allowlist pattern with shell-style globbing (`fnmatch`, case-insensitive; an IP-only flow has no host and never matches) → violation (`host_not_allowlisted`); otherwise allowed. The reason is carried in `risk_indicators` as `egress_violation:<reason>`.
6. **Sandbox decision**: `is_policy_violation = (decision == DENY)` — the attempted action was outside policy and the runtime refused it.
7. Where the runtime **allowed** a flow the policy forbids (4,775 flows: 3,718 under `sp_ops_elevated` v4 with reason `NO_NETWORK_POLICY`, 1,057 IP-only uploads under `WILDCARD_MATCH_UNVERIFIED`), the canonical row is a violation **and** carries `quality_flags = runtime_allowed_despite_policy`, so both views can be reported.
8. No policy for the profile (`ag_019`, `sp_missing_profile`): both fields null, flag `no_policy_for_profile`.

## 10. SIEM ↔ network-flow correlation policy

* **Rule**: `alert.source_ip = flow.src_ip` ∧ `alert.destination.host = flow.dst_ip` ∧ `alert.destination.port = flow.dst_port` ∧ `|detected_at_utc − flow_time_utc| ≤ N`, with **N = 60 s** (symmetric).
* **Why 60 s**: 97% of the alerts that can be matched at all are raised 0–60 s after their flow; no alert falls between 60 s and 150 s; 67 alerts trail by 150–400 s. 60 s sits in the empty band, so the result is stable (identical at 120 s). The sweep over 5–600 s is published in `siem_flow_correlation_sweep.csv`; at 600 s the 67 slow alerts would match at the cost of one extra ambiguous case.
* **Outcomes**: `matched` (exactly one flow within N) · `ambiguous` (more than one flow; when all candidates share one session, `matched_session_id` is still filled — 26 of 27) · `unmatched` with `unmatched_reason` ∈ {`source_ip_not_a_sandbox` (1,251: `10.44.x.x` sources, activity outside the platform — never forced), `nearest_flow_beyond_tolerance` (67), `no_flow_with_same_src_dst_port` (0)}.
* **Result**: 2,409 matched · 27 ambiguous · 1,318 unmatched. 243 flows are matched by more than one alert (several SIEM rules on one flow): legitimate many-to-one.
* The matched session supplies `tenant_id`, `agent_sk`, `task_id` of the alert row; flows gain `siem_alerted` in `risk_indicators`.

## 11. Late-event policy

* Late = `ingest_time_utc − event_time_utc > 10 s` (Appendix A). Only `agent_activity.parquet` carries `ingest_time`.
* **Batch has no watermark**: every late record is accepted and flagged `late_event`; `is_late` is a column. `LATE_BEYOND_WATERMARK` is reserved for the 60 s watermark of the Milestone 2 stream.
* Watermarks are defined on `event_time`, never on `ingest_time`.
* Received: 21,256 late rows; of these 7,329 were redelivered duplicate copies (rejected as duplicates) and 62 were rejected for other reasons; **13,865 late rows accepted** (1.50% of accepted activity rows).

## 12. Metric definitions

Computed in pandas over the curated output (`kestrel_m1/metrics.py`); values in `docs/METRICS.md`. Percentiles use linear interpolation between closest ranks.

| metric | numerator | denominator | population filter | late-event policy | null policy |
|---|---|---|---|---|---|
| **1 session volume** | — | distinct `session_id` with a terminal event | accepted sessions with an accepted `session.start` **and** a `session.end`/`session.error` row | late rows accepted, so they count | n/a (row counts) |
| **1 success rate / error rate** | terminal sessions ending in `session.end` / in `session.error` | terminal sessions | as above (2,048 started-but-not-terminated sessions excluded) | same | n/a |
| **2 p50 / p95 duration** | — | terminal sessions with a derived duration | duration = terminal `event_time_utc` − `session.start` `event_time_utc`; `latency_ms` is a cross-check only (disagrees > 1 s on 1.98%) | a late terminal row still defines the end | sessions whose start/terminal timestamp was rejected have no duration and are excluded |
| **8 trace completeness** | terminal sessions with ≥ 1 accepted `llm.turn` and accepted `sequence_number`s running 1..max without a gap | terminal sessions | as metric 1 | a late row closes a gap rather than opening one | rows rejected for any reason are absent, so a rejected row inside a session creates a gap |
| **8 correlation coverage** | alerts linked to a session (matched + ambiguous-single-session) | all accepted alerts | — ; also reported: strict (exactly one flow) and restricted to alerts from sandbox addresses | n/a (no `ingest_time`) | external-source alerts stay in the denominator |
| **9 rejected-record rate** | rejected records | records received from the nine input files (rows / array elements / lines) | per file and overall | batch raises no `LATE_BEYOND_WATERMARK` | required-null → reject; optional nulls kept |
| **9 late-event rate** | accepted activity rows with lateness > 10 s | accepted activity rows | `agent_activity.parquet` only (the only source with `ingest_time`) | as §11 | n/a |
| missing-token sensitivity | mean / total `tokens_out` per turn | turns (403,364 null-excluded vs 407,462 zero-filled) | prompt turns | — | **null-excluded** declared; effect shown |

## 13. Glossary of `quality_flags` and `risk_indicators`

### quality_flags (non-fatal, retained)

| flag | meaning |
|---|---|
| `late_event` | `lateness_s > 10` |
| `event_time_epoch_ms` / `event_time_dd_mm_yyyy_naive` | the timestamp arrived in that format and was decoded |
| `release_version_alias` / `tenant_alias` / `tool_name_resolved_to_id` / `status_spelling_normalised` | an identifier or value was mapped to its canonical form |
| `missing_output_tokens` | turn without `output_tokens` (null-excluded) |
| `finished_before_event_time` / `latency_disagrees_with_finished_at` | tool-call cross-check failures |
| `status_conflicts_with_error_class` | `success` with an `error_class` |
| `session_sequence_gap` | the row's session has a gap in accepted sequence numbers |
| `no_policy_for_profile` / `agent_profile_missing` | no policy version exists for the agent's profile |
| `price_missing_for_model` | no price → `cost_usd` null |
| `runtime_allowed_despite_policy` | the sandbox allowed a flow the effective policy forbids |
| `dst_host_missing_ip_only_flow` / `geo_country_missing` | structural nulls on flows |
| `instance_differs_from_activity` | flow/decision instance ≠ the session's instance (0 rows) |
| `policy_version_missing_in_log` / `policy_version_log_disagrees_with_derived` | syslog `policy_version` was `-` / differed from the validity-window join (0 rows) |
| `syslog_clock_offset_inferred` | the UTC time came from the per-host offset model |
| `host_offset_defaulted` | the host had too few pairs and got the 7200 s fallback (0 rows) |
| `escalation_attempt` | decision on `setuid` / `ptrace` / `mount` |
| `siem_unmatched` / `siem_ambiguous_flow` / `siem_source_outside_platform` | correlation outcome of the alert |

### risk_indicators (signals for Milestone 2)

`instruction_override`, `role_confusion`, `exfil_request`, `encoded_payload`, `tool_coercion`, `policy_probe` (the turn's detector output — noisy, not truth) · `tool_denied` · `policy_violation` · `egress_blocked` · `egress_logged_only` · `egress_violation:no_network_block|denied_port|host_not_allowlisted` · `siem_alerted` · `sandbox_deny:<reason>` · `escalation_denied` · `runtime_allow_unverified:NO_NETWORK_POLICY|WILDCARD_MATCH_UNVERIFIED` · `siem:<MITRE technique id>` · `siem_severity:<level>` (the target system's opinion, not ours).
