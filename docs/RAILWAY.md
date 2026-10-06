# Railway Service Matrix

| Service | Dockerfile | Command | Health |
|---|---|---|---|
| API | `backend/Dockerfile` | default | `/ready` |
| Frontend | `frontend/Dockerfile` | default | Next.js HTTP |
| Scanner | `workers/Dockerfile` | `python /workspace/workers/scan_worker.py` | heartbeat in Redis |
| AI | `workers/Dockerfile` | `python /workspace/workers/ai_worker.py` | heartbeat in Redis |
| Report | `workers/Dockerfile` | `python /workspace/workers/report_worker.py` | heartbeat in Redis |
| PostgreSQL | managed | managed | Railway-managed |
| Redis | managed | managed | Railway-managed |
