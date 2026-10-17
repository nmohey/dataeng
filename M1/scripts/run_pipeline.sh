#!/usr/bin/env sh
# Run the Milestone-1 pipeline on your laptop (no Docker needed for this step).
#   sh scripts/run_pipeline.sh            uses ../kestrel-telemetry-pack-v1 (or $KESTREL_RAW_DIR)
set -e
cd "$(dirname "$0")/.."
if [ -d .venv ]; then . .venv/bin/activate; fi
python -m kestrel_m1.pipeline "$@"
