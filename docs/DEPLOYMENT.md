# Production Deployment on Railway

CyberSentinel AI is an isolated monorepo: the frontend, API, and workers share the repository root but have independent Dockerfiles. Railway should therefore deploy every application service from the **repository root (`/`)** and use a service-specific Dockerfile path. Railway documents this pattern for monorepos and supports `RAILWAY_DOCKERFILE_PATH` for a Dockerfile outside the root. citehttps://docs.railway.com/builds/dockerfileshttps://docs.railway.com/deployments/monorepo

## 1. Create the infrastructure

Create one Railway project with these services:

| Service | Source root | Dockerfile | Public | Health / command |
|---|---|---|---|---|
| `frontend` | `/` | `frontend/Dockerfile` | Yes | health path `/health` |
| `api` | `/` | `backend/Dockerfile` | Yes | health path `/ready` |
| `scanner-worker` | `/` | `workers/Dockerfile` | No | start `python /workspace/workers/scan_worker.py` |
| `ai-worker` | `/` | `workers/Dockerfile` | No | start `python /workspace/workers/ai_worker.py` |
| `report-worker` | `/` | `workers/Dockerfile` | No | start `python /workspace/workers/report_worker.py` |
| PostgreSQL | managed | Railway managed | No | managed |
| Redis | managed | Railway managed | No | managed |

Railway injects `PORT`; the API and frontend already bind to it. Railway healthchecks wait for a 2xx response before activating a new deployment. citehttps://docs.railway.com/deployments/healthcheckshttps://docs.railway.com/variables/reference

## 2. Configure each service

For `api`, set:

```text
RAILWAY_DOCKERFILE_PATH=backend/Dockerfile
DATABASE_URL=${{Postgres.DATABASE_URL}}
REDIS_URL=${{Redis.REDIS_URL}}
JWT_SECRET=<64+ random characters>
ENCRYPTION_KEY=<Fernet key>
CORS_ORIGINS=https://<frontend-domain>
ENVIRONMENT=production
REGISTRATION_ENABLED=true
LOG_LEVEL=INFO
```

The API accepts Railway's normal `postgres://` / `postgresql://` connection strings and normalizes them for `asyncpg` at runtime. Railway's PostgreSQL service exposes `DATABASE_URL`; Redis exposes `REDIS_URL`. citehttps://docs.railway.com/databases/postgresqlhttps://docs.railway.com/databases/redis

For every worker, set `RAILWAY_DOCKERFILE_PATH=workers/Dockerfile` plus the same `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, and `ENCRYPTION_KEY` as the API. The AI worker additionally needs:

```text
CLOUDFLARE_ACCOUNT_ID=<account id>
CLOUDFLARE_AI_TOKEN=<Workers AI token>
CLOUDFLARE_AI_MODEL=@cf/meta/llama-3.1-8b-instruct
```

The workers do not need public domains.

For `frontend`, set:

```text
RAILWAY_DOCKERFILE_PATH=frontend/Dockerfile
NEXT_PUBLIC_API_URL=https://<api-domain>
```

Because `NEXT_PUBLIC_API_URL` is a Next.js public build-time variable, it must be present for the frontend image build as well as at runtime. Railway documents that service variables are available to the build process and deployment. citehttps://docs.railway.com/variables

## 3. Generate domains

Generate one public domain for `api` and one for `frontend`. Use the exact API domain in `NEXT_PUBLIC_API_URL`, then set `CORS_ORIGINS` to the exact frontend origin, for example:

```text
CORS_ORIGINS=https://cybersentinel.example.com
NEXT_PUBLIC_API_URL=https://api-cybersentinel.example.com
```

Do not use `*` for `CORS_ORIGINS` in production.

## 4. First deployment order

Deploy PostgreSQL and Redis first.

Deploy `api` next. Its container runs `alembic upgrade head` with a bounded retry loop before Uvicorn starts, and Railway should use `/ready` as its healthcheck.

Deploy the three workers after `api`, then deploy `frontend` after the API has a stable public domain.

Railway supports custom Dockerfile paths and custom start commands for Dockerfile-based services. citehttps://docs.railway.com/builds/dockerfileshttps://docs.railway.com/deployments/start-command

## 5. First login / registration

Keep `REGISTRATION_ENABLED=true` only for the initial bootstrap. The first registered account becomes `ADMIN`; subsequent accounts become `VIEWER` until an administrator changes their role.

Immediately after creating the first administrator, set:

```text
REGISTRATION_ENABLED=false
```

and redeploy the API. Re-enable it only for a controlled onboarding window.

## 6. Cloudflare and AI

Cloudflare is optional for the baseline scanner. Without Cloudflare credentials, the core scanner still works; Cloudflare posture and Workers AI features remain unavailable.

For Cloudflare-managed functionality, keep API tokens server-side only. Never put Cloudflare credentials into frontend variables such as `NEXT_PUBLIC_*`.

## 7. Release verification

After deployment, verify:

```text
GET https://<api-domain>/health       -> 200
GET https://<api-domain>/ready        -> 200 with postgres=true, redis=true
GET https://<api-domain>/docs         -> 200
GET https://<frontend-domain>/health -> 200
GET https://<frontend-domain>/        -> redirects to /dashboard
```

Then create an account, authorize a target you control, queue one scan, confirm the scanner heartbeat, and verify that findings and reports complete.

## 8. Useful Railway CLI configuration

From a checked-out repository, link the project and apply service configuration. Railway supports service-level configuration through `railway environment edit`. citehttps://docs.railway.com/cli/environment

Example pattern:

```bash
railway link
railway environment edit --service-config api source.rootDirectory /
railway environment edit --service-config api variables.RAILWAY_DOCKERFILE_PATH.value backend/Dockerfile
railway environment edit --service-config frontend source.rootDirectory /
railway environment edit --service-config frontend variables.RAILWAY_DOCKERFILE_PATH.value frontend/Dockerfile
```

Set the worker start commands in their service Settings or through the equivalent service configuration.

## Security notes

Keep PostgreSQL and Redis private. Only the frontend and API should have public HTTP domains.

Use unique production secrets. Never commit `.env`, real API tokens, or production database credentials.

The scanner is intended for explicitly authorized defensive assessment only. Do not authorize destinations you do not own or have permission to test.
