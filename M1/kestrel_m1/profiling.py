"""Profiling helpers: say what is in the data before anything is fixed."""
from __future__ import annotations

import re

import numpy as np
import pandas as pd


def profile(frame: pd.DataFrame, max_top: int = 3, exclude: tuple[str, ...] = ("source_file", "source_line", "raw_line")) -> pd.DataFrame:
    """One row per column: dtype, Python types inside, missing count/rate, distinct
    values, min/max (numeric or text), and the most common values (the Lab 3 profile)."""
    rows = {}
    for name, column in frame.items():
        if name in exclude:
            continue
        non_null = column.dropna()
        is_listy = non_null.map(lambda v: isinstance(v, (list, dict))).any() if len(non_null) else False
        numeric = pd.api.types.is_numeric_dtype(column) and not pd.api.types.is_bool_dtype(column)
        if is_listy:
            distinct, vmin, vmax, top = None, None, None, None
        else:
            distinct = column.nunique()
            try:
                vmin, vmax = (non_null.min(), non_null.max()) if len(non_null) else (None, None)
            except TypeError:
                vmin, vmax = None, None
            top = column.value_counts(dropna=True).head(max_top).to_dict()
        rows[name] = {
            "dtype": str(column.dtype),
            "python_types": ", ".join(sorted(non_null.map(lambda v: type(v).__name__).unique())) if len(non_null) else "",
            "missing": int(column.isna().sum()),
            "missing_rate": round(float(column.isna().mean()), 4) if len(column) else 0.0,
            "distinct": distinct,
            "min": vmin if numeric or isinstance(vmin, str) else vmin,
            "max": vmax if numeric or isinstance(vmax, str) else vmax,
            "most_common": top,
        }
    return pd.DataFrame.from_dict(rows, orient="index")


def digit_mask(series: pd.Series) -> pd.Series:
    """Replace every digit with 9, so '2026-03-14T09:22:01.412Z' becomes
    '9999-99-99T99:99:99.999Z'. Groups values by *shape* rather than value."""
    return series.astype("string").str.replace(r"\d", "9", regex=True)


def timestamp_shapes(series: pd.Series, examples: int = 2) -> pd.DataFrame:
    """Count the distinct shapes a timestamp column takes and show examples of each."""
    shapes = digit_mask(series)
    out = shapes.value_counts(dropna=False).rename("rows").to_frame()
    out["share"] = (out["rows"] / len(series)).round(5)
    out["examples"] = [series[shapes == s].head(examples).tolist() if pd.notna(s) else series[series.isna()].head(examples).tolist() for s in out.index]
    return out


def enum_check(series: pd.Series, allowed: list[str]) -> pd.DataFrame:
    """Value counts with a flag for values outside the closed enum."""
    vc = series.value_counts(dropna=False).rename("rows").to_frame()
    vc["in_enum"] = [(v in allowed) if pd.notna(v) else False for v in vc.index]
    return vc


def fill_pattern_by_type(frame: pd.DataFrame, type_col: str, exclude: tuple[str, ...] = ("source_file", "source_line")) -> pd.DataFrame:
    """Share of non-null values per column, per event type: shows which columns a
    type fills and reveals rows that should be filled but are not."""
    cols = [c for c in frame.columns if c not in exclude and c != type_col]
    return frame.groupby(type_col)[cols].apply(lambda g: g.notna().mean()).round(3).T


def numeric_ranges(frame: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    """describe() plus a count of negatives for each numeric column."""
    num = frame[cols].apply(pd.to_numeric, errors="coerce")
    desc = num.describe(percentiles=[0.001, 0.01, 0.5, 0.99, 0.999]).T
    desc["negatives"] = (num < 0).sum()
    desc["non_numeric"] = frame[cols].notna().sum() - num.notna().sum()
    return desc


def summarize_windows(frame: pd.DataFrame, key: str, start: str, end: str) -> list[str]:
    """Report overlapping or gapping validity windows per key (policies, pricing)."""
    notes = []
    f = frame.copy()
    f[start] = pd.to_datetime(f[start], utc=True)
    f[end] = pd.to_datetime(f[end], utc=True)
    for k, g in f.sort_values(start).groupby(key):
        g = g.sort_values(start)
        for i in range(len(g) - 1):
            this_end, next_start = g[end].iloc[i], g[start].iloc[i + 1]
            if pd.isna(this_end):
                notes.append(f"{k}: window starting {g[start].iloc[i].date()} is open-ended but a later window starts {next_start.date()} (overlap)")
            elif this_end > next_start:
                notes.append(f"{k}: window ending {this_end.date()} overlaps the next window starting {next_start.date()}")
            elif this_end < next_start:
                notes.append(f"{k}: gap between {this_end.date()} and {next_start.date()}")
    return notes


def normalise_name(s: pd.Series) -> pd.Series:
    """Lower-case, drop punctuation/whitespace and corporate suffixes, for matching
    names that are the same entity spelled differently."""
    return (
        s.astype("string").str.lower()
        .str.replace(r"\b(ltd|inc|llc|gmbh|plc|co|corp|group)\b\.?", "", regex=True)
        .str.replace(r"[^a-z0-9]", "", regex=True)
    )
