# The Milestone-1 pipeline as a container: reads the telemetry pack mounted at /data/raw,
# writes the curated tables to /data/curated and loads them into the stack's Postgres.
FROM python:3.12-slim

WORKDIR /app
COPY requirements-pipeline.txt .
RUN pip install --no-cache-dir --quiet -r requirements-pipeline.txt
COPY kestrel_m1 ./kestrel_m1
COPY scripts ./scripts

ENV KESTREL_RAW_DIR=/data/raw \
    KESTREL_OUT_DIR=/data/curated \
    PYTHONUNBUFFERED=1

CMD ["sh", "-c", "python -m kestrel_m1.pipeline && python -m kestrel_m1.load_postgres"]
