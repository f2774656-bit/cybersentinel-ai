# Railway service map

Create separate Railway services from the repository root:

- `frontend`: `frontend/Dockerfile`, health path `/health`.
- `api`: `backend/Dockerfile`, health path `/ready`.
- `scanner-worker`: `workers/Dockerfile`, start command `python workers/scan_worker.py`.
- `ai-worker`: `workers/Dockerfile`, start command `python workers/ai_worker.py`.
- `report-worker`: `workers/Dockerfile`, start command `python workers/report_worker.py`.
- PostgreSQL: Railway Postgres plugin.
- Redis: Railway Redis plugin.

For each application service, inject `DATABASE_URL` and/or `REDIS_URL` from the Railway reference variables. The API and workers must receive the same JWT/encryption and Cloudflare/AI settings. The frontend only needs `NEXT_PUBLIC_API_URL`.

The API image runs Alembic migrations with a bounded retry loop before starting Uvicorn. Workers retry Redis/DB dependencies inside their loops. Do not place secrets in source control.
