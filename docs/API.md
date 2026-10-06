# API

Authentication: `Authorization: Bearer <access-token>`.

Core routes:

- POST `/api/auth/register`
- POST `/api/auth/login`
- POST `/api/auth/refresh`
- POST `/api/auth/logout`
- GET `/api/auth/me`
- GET/POST `/api/targets`
- GET/PATCH/DELETE `/api/targets/{id}`
- POST `/api/scans`
- GET `/api/scans`
- GET `/api/scans/{id}`
- POST `/api/scans/{id}/cancel`
- GET `/api/findings`
- GET `/api/findings/{id}`
- POST `/api/cloudflare/connect`
- GET `/api/cloudflare/status`
- GET `/api/cloudflare/accounts`
- GET `/api/cloudflare/zones`
- GET `/api/cloudflare/zones/{id}`
- GET `/api/cloudflare/zones/{id}/dns`
- GET `/api/cloudflare/zones/{id}/security`
- POST `/api/ai/analyze/{scan_id}`
- GET `/api/ai/analyze/{scan_id}/latest`
- POST `/api/reports/{scan_id}/generate`
- GET `/api/reports/{scan_id}`
- GET `/health`
- GET `/ready`

Every API error is returned as a FastAPI error response; unexpected failures are logged with a request ID.
