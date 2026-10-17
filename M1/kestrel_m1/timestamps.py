"""Every timestamp to UTC, and how each source's clock convention was established.

Conventions found in the pack (see docs/DATA_QUALITY_FINDINGS.md for the evidence):

* ISO-8601 with ``Z`` or an explicit offset  -> parsed as written.
* 13-digit integers                          -> Unix epoch milliseconds, UTC. Established by
  comparing with ingest_time: lateness has the same distribution as the ISO rows.
* ``dd/mm/yyyy HH:MM:SS`` (no offset)        -> day-first (the first field exceeds 12, the
  second never does) and already UTC: ingest_time minus the naive value is ~0 h, and
  the value sits between its session neighbours only at offset 0.
* syslog ``Mon dd HH:MM:SS``                 -> no year, no offset. Year from the pack
  window (2026). Offset per *host*: every host runs UTC+2 plus its own fixed skew
  (-90 s .. +87 s), measured by lining up audit lines with the tool calls they log.
* SIEM ``detected_at``                       -> explicit offsets, three different ones
  (+02:00 corp-siem, +03:00 egress-proxy, -05:00 cloud-ids); parsed as written.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import SYSLOG_DEFAULT_OFFSET_S, SYSLOG_MIN_PAIRS, SYSLOG_YEAR

FORMAT_ISO_Z = "iso_utc"
FORMAT_ISO_OFFSET = "iso_offset"
FORMAT_EPOCH_MS = "epoch_ms"
FORMAT_DMY_NAIVE = "dmy_naive"
FORMAT_INVALID_DATE = "invalid_calendar_date"
FORMAT_UNPARSEABLE = "unparseable"
FORMAT_MISSING = "missing"

_ISO_Z = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z"
_ISO_OFF = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?[+-]\d{2}:\d{2}"
_EPOCH_MS = r"\d{13}"
_DMY = r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}(:\d{2})?"


def classify_timestamp_format(series: pd.Series) -> pd.Series:
    """Label each raw timestamp string with the format it is written in."""
    s = series.astype("string")
    labels = pd.Series(FORMAT_UNPARSEABLE, index=series.index, dtype="object")
    labels[s.isna()] = FORMAT_MISSING
    iso_z = s.str.fullmatch(_ISO_Z).fillna(False).astype(bool)
    iso_off = s.str.fullmatch(_ISO_OFF).fillna(False).astype(bool)
    epoch = s.str.fullmatch(_EPOCH_MS).fillna(False).astype(bool)
    dmy = s.str.fullmatch(_DMY).fillna(False).astype(bool)
    labels[iso_z] = FORMAT_ISO_Z
    labels[iso_off] = FORMAT_ISO_OFFSET
    labels[epoch] = FORMAT_EPOCH_MS
    labels[dmy] = FORMAT_DMY_NAIVE
    # an ISO-looking string that is not a real calendar date (e.g. 2026-02-30)
    iso_like = iso_z | iso_off
    parsed = pd.to_datetime(s.where(iso_like), format="ISO8601", utc=True, errors="coerce")
    labels[iso_like & parsed.isna()] = FORMAT_INVALID_DATE
    return labels


def parse_mixed_timestamps(series: pd.Series, naive_offset_hours: float = 0.0) -> tuple[pd.Series, pd.Series]:
    """Parse a column holding several timestamp formats into one tz-aware UTC column.

    Returns (utc_timestamps, format_labels). Values that cannot be parsed are NaT and
    keep their label (``unparseable`` / ``invalid_calendar_date``) so the caller can reject
    them with MALFORMED_TIMESTAMP. ``naive_offset_hours`` is the UTC offset the naive
    dd/mm rows were written in (established from the data, 0 for this pack).
    """
    labels = classify_timestamp_format(series)
    s = series.astype("string")
    out = pd.Series(pd.NaT, index=series.index, dtype="datetime64[ns, UTC]")
    iso = labels.isin([FORMAT_ISO_Z, FORMAT_ISO_OFFSET])
    if iso.any():
        out[iso] = pd.to_datetime(s[iso], format="ISO8601", utc=True, errors="coerce")
    ep = labels == FORMAT_EPOCH_MS
    if ep.any():
        out[ep] = pd.to_datetime(s[ep].astype("int64"), unit="ms", utc=True)
    dmy = labels == FORMAT_DMY_NAIVE
    if dmy.any():
        naive = pd.to_datetime(s[dmy], format="%d/%m/%Y %H:%M:%S", errors="coerce")
        short = naive.isna()
        if short.any():  # dd/mm/yyyy HH:MM without seconds
            naive[short] = pd.to_datetime(s[dmy][short], format="%d/%m/%Y %H:%M", errors="coerce")
        out[dmy] = (naive - pd.to_timedelta(naive_offset_hours * 3600, unit="s")).dt.tz_localize("UTC")
    return out, labels


def infer_naive_offset_hours(naive: pd.Series, reference_utc: pd.Series) -> pd.DataFrame:
    """For naive timestamps that have a trustworthy UTC companion on the same row
    (here: ingest_time), tabulate round(reference - naive) in hours. The modal value
    is the offset the naive values were written in (0 => already UTC)."""
    diff_h = (reference_utc.dt.tz_localize(None) - naive).dt.total_seconds() / 3600
    tab = diff_h.round().value_counts().rename("rows").to_frame()
    tab["share"] = (tab["rows"] / tab["rows"].sum()).round(4)
    tab.index.name = "offset_hours_naive_minus_utc"
    return tab


# ------------------------------------------------------------------------- syslog


def parse_syslog_naive(month: pd.Series, day: pd.Series, time: pd.Series, year: int = SYSLOG_YEAR) -> pd.Series:
    """'Mar','14','11:22:04' -> naive Timestamp 2026-03-14 11:22:04 (host-local, no offset)."""
    txt = f"{year} " + month.astype(str) + " " + day.astype(str).str.zfill(2) + " " + time.astype(str)
    return pd.to_datetime(txt, format="%Y %b %d %H:%M:%S", errors="coerce")


def infer_host_clock_offsets(audit: pd.DataFrame, tool_calls: pd.DataFrame,
                             default_offset_s: float = SYSLOG_DEFAULT_OFFSET_S,
                             min_pairs: int = SYSLOG_MIN_PAIRS) -> pd.DataFrame:
    """Work out each sandbox host's offset from UTC by lining up audit lines with the
    tool calls they describe.

    A ``socket_connect`` to ``host:443`` / ``process_spawn`` of ``/usr/bin/df`` /
    ``file_write`` of a path is the sandbox's view of the tool.call whose
    ``target_resource`` is that host / command / path, in the same session. Where a
    (session, target) pair occurs exactly once on both sides the match is unambiguous, and
    ``log_time_naive - event_time_utc`` is the host's offset. Every host gives a tight
    cluster (p05..p95 within one second), so the median is used.

    Inputs: ``audit`` with columns host, session_id, target, log_time_naive;
    ``tool_calls`` with session_id, target_resource, event_time_utc (accepted rows).
    Returns one row per host: n_pairs, offset_s (median), p05_s, p95_s, method.
    """
    a = audit.dropna(subset=["log_time_naive", "target", "session_id"]).copy()
    a["target_key"] = a["target"].astype(str).str.replace(r":\d+$", "", regex=True)
    a = a[~a.duplicated(["session_id", "target_key"], keep=False)]
    t = tool_calls.dropna(subset=["event_time_utc", "target_resource"]).copy()
    t = t[~t.duplicated(["session_id", "target_resource"], keep=False)]
    j = a.merge(t[["session_id", "target_resource", "event_time_utc"]],
                left_on=["session_id", "target_key"], right_on=["session_id", "target_resource"])
    j["delta_s"] = (j["log_time_naive"].dt.tz_localize("UTC") - j["event_time_utc"]).dt.total_seconds()
    per = j.groupby("host")["delta_s"].agg(n_pairs="size", offset_s="median",
                                          p05_s=lambda x: x.quantile(0.05), p95_s=lambda x: x.quantile(0.95))
    hosts = pd.Index(sorted(audit["host"].dropna().unique()), name="host")
    per = per.reindex(hosts)
    per["n_pairs"] = per["n_pairs"].fillna(0).astype(int)
    per["method"] = np.where(per["n_pairs"] >= min_pairs, "aligned_with_tool_calls", "default_offset")
    per.loc[per["method"] == "default_offset", "offset_s"] = default_offset_s
    per["offset_s"] = per["offset_s"].round(1)
    per["whole_hours"] = (per["offset_s"] / 3600).round(2)
    per["skew_s"] = (per["offset_s"] - round(per["offset_s"].median() / 3600) * 3600).round(1)
    return per.reset_index()


def syslog_to_utc(log_time_naive: pd.Series, host: pd.Series, host_offsets: pd.DataFrame,
                  default_offset_s: float = SYSLOG_DEFAULT_OFFSET_S) -> pd.Series:
    """Apply the per-host offsets: utc = naive - offset(host)."""
    off = host.map(host_offsets.set_index("host")["offset_s"]).fillna(default_offset_s)
    return (log_time_naive - pd.to_timedelta(off, unit="s")).dt.tz_localize("UTC")


def lateness_seconds(event_time_utc: pd.Series, ingest_time_utc: pd.Series) -> pd.Series:
    return (ingest_time_utc - event_time_utc).dt.total_seconds()
