#!/usr/bin/env sh
# Re-execute both notebooks in place so their saved outputs match the code.
set -e
cd "$(dirname "$0")/.."
if [ -d .venv ]; then . .venv/bin/activate; fi
jupyter nbconvert --to notebook --execute --inplace --ExecutePreprocessor.timeout=1800 notebooks/01_profiling.ipynb
jupyter nbconvert --to notebook --execute --inplace --ExecutePreprocessor.timeout=1800 notebooks/02_cleaning_integration_metrics.ipynb
