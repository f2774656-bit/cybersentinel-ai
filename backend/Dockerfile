FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/workspace/backend:/workspace

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /workspace/backend/requirements.txt

RUN pip install --no-cache-dir -r /workspace/backend/requirements.txt

COPY backend /workspace/backend
COPY scanner /workspace/scanner
COPY workers /workspace/workers

EXPOSE 8000

CMD ["sh", "-c", "cd /workspace/backend && for i in $(seq 1 30); do if alembic -c alembic.ini upgrade head; then exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'; fi; echo \"waiting for PostgreSQL ($i/30)\"; sleep 2; done; echo \"database migration failed after 30 attempts\" >&2; exit 1"]
RUN echo "===== CHECK BACKEND =====" && ls -la /workspace/backend && echo "===== CHECK ALEMBIC =====" && ls -la /workspace/backend/alembic