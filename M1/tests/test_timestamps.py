import pandas as pd

from kestrel_m1.timestamps import (FORMAT_DMY_NAIVE, FORMAT_EPOCH_MS, FORMAT_INVALID_DATE, FORMAT_ISO_OFFSET, FORMAT_ISO_Z,
                                   FORMAT_UNPARSEABLE, classify_timestamp_format, infer_host_clock_offsets, parse_mixed_timestamps,
                                   parse_syslog_naive, syslog_to_utc)


def test_classify_every_format_in_the_pack():
    s = pd.Series(["2026-03-14T09:22:01.412Z", "1772435438897", "28/02/2026 11:24:43", "2026-02-30T10:00:00Z",
                   "not-a-time", "2026-03-14T13:22:41+02:00", None])
    labels = classify_timestamp_format(s).tolist()
    assert labels == [FORMAT_ISO_Z, FORMAT_EPOCH_MS, FORMAT_DMY_NAIVE, FORMAT_INVALID_DATE, FORMAT_UNPARSEABLE, FORMAT_ISO_OFFSET, "missing"]


def test_parse_mixed_to_utc():
    s = pd.Series(["2026-03-14T09:22:01.412Z", "1772435438897", "28/02/2026 11:24:43", "2026-03-14T13:22:41+02:00", "not-a-time"])
    utc, labels = parse_mixed_timestamps(s)
    assert str(utc.dtype) == "datetime64[ns, UTC]"
    assert utc[0] == pd.Timestamp("2026-03-14 09:22:01.412", tz="UTC")
    assert utc[1] == pd.Timestamp(1772435438897, unit="ms", tz="UTC")
    assert utc[2] == pd.Timestamp("2026-02-28 11:24:43", tz="UTC")  # day-first, written in UTC
    assert utc[3] == pd.Timestamp("2026-03-14 11:22:41", tz="UTC")  # +02:00 removed
    assert pd.isna(utc[4])


def test_syslog_offset_inference_and_conversion():
    # audit lines on host A run 2h + 30s ahead of UTC, host B 2h - 10s
    tool_calls = pd.DataFrame({"session_id": ["s1", "s1", "s2"], "target_resource": ["/usr/bin/df", "/bin/sh", "/usr/bin/df"],
                               "event_time_utc": pd.to_datetime(["2026-03-01 10:00:00", "2026-03-01 10:00:10", "2026-03-01 11:00:00"], utc=True)})
    audit = pd.DataFrame({"host": ["A", "A", "B"], "session_id": ["s1", "s1", "s2"], "target": ["/usr/bin/df", "/bin/sh", "/usr/bin/df"],
                          "log_time_naive": pd.to_datetime(["2026-03-01 12:00:30", "2026-03-01 12:00:40", "2026-03-01 12:59:50"])})
    off = infer_host_clock_offsets(audit, tool_calls, min_pairs=1)
    assert dict(zip(off["host"], off["offset_s"])) == {"A": 7230.0, "B": 7190.0}
    utc = syslog_to_utc(audit["log_time_naive"], audit["host"], off)
    assert utc.tolist() == tool_calls["event_time_utc"].tolist()


def test_syslog_naive_parse_adds_year():
    t = parse_syslog_naive(pd.Series(["Mar"]), pd.Series(["14"]), pd.Series(["11:22:04"]), 2026)
    assert t[0] == pd.Timestamp("2026-03-14 11:22:04")
