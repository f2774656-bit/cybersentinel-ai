# CYBERSENTINEL AI

Production-oriented authorized web security assessment platform for defensive security teams.

## What it does

CyberSentinel AI runs bounded, evidence-backed assessments: passive DNS reconnaissance, HTTP/HTTPS inspection, TLS/certificate validation, security headers, cookies, CORS behavior, safe HTTP method checks, technology indicators, robots/sitemap discovery, Cloudflare posture, deterministic scoring, AI-assisted analysis, and professional reports.

The scanner is not an exploitation engine. It rejects private/loopback/link-local/metadata destinations, enforces explicit authorization, revalidates redirects, pins DNS resolution per request, caps response size/time, and never exposes a generic HTTP proxy endpoint.

## Repository

- `backend/` FastAPI API, ORM, auth, Cloudflare client, scoring, reporting
- `scanner/` SSRF-safe scanner engine and modules
- `workers/` scanner, AI, and report workers using Redis queues
- `frontend/` Next.js dashboard
- `docs/` architecture, security, API, deployment and testing
- `shared/` cross-service API contract definitions
- `infra/` Railway service mapping
- `tests/` automated unit/integration-oriented tests

## Local setup

1. Copy `.env.example` to `.env` and generate real values.
2. Start services: `docker compose up --build`.
3. Open `http://localhost:3000`.
4. The first registered account becomes `ADMIN`. A `mriranfa.site` target is created in `PENDING` state.
5. Set that target to `AUTHORIZED` only when you have explicit authorization, then queue a scan.

Generate a Fernet key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Generate a JWT secret with a password manager or:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

## API

FastAPI publishes OpenAPI at `/docs` and ReDoc at `/redoc`.

## Tests

```bash
pytest -q
```

The test suite uses mocks and does not require real Cloudflare credentials.

## Production principles

- PostgreSQL is the source of truth.
- Redis is a queue/cache/rate-limit layer, never durable business state.
- Cloudflare credentials stay server-side and are encrypted at rest when persisted.
- AI cannot alter the deterministic security score.
- Findings contain explicit evidence and confidence.
- Authorization is required before a scan can start.

## Deployment

See `docs/DEPLOYMENT.md` for Railway service mapping and commands. See `docs/VALIDATION.md` for the performed validation and environment limitations. Railway runs each Dockerfile as an independent service; Compose is a local-development topology, not the production runtime.
