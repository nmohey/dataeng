"""kestrel_m1: reusable ingestion, profiling, cleaning and integration code for
Kestrel Milestone 1 (pipeline stages 1 and 2: ingest/normalise, clean/integrate).

Every transformation lives here as a function so it can be re-run on a new export
and unit-tested. The notebooks only call these functions and display results.
"""

__version__ = "1.0.0"
