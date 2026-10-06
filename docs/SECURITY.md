# Security Model

CyberSentinel AI is designed for authorized defensive assessment only.

## Scanner controls

- Explicit `AUTHORIZED` target state is required.
- Domains are normalized with IDNA.
- Only HTTP/HTTPS and standard ports 80/443 are accepted.
- Resolved IPs are checked against loopback, RFC1918/private, link-local, carrier-grade NAT, multicast, IPv6 ULA and IPv4-mapped private ranges.
- Common cloud metadata destinations are blocked.
- Every redirect is normalized, DNS-resolved and checked against the target's scope.
- DNS is resolved immediately before each connection and a pinned resolver prevents a second DNS answer from changing the destination within that request.
- Request timeouts, maximum response size and redirect count are bounded.
- Scanner concurrency is deliberately low and requests are throttled.
- No credentials, password dictionaries, brute force, destructive methods, malware, persistence, DoS or arbitrary SSRF endpoint exists.

## Application controls

- Argon2 password hashing.
- Short-lived access JWTs and revocable refresh sessions.
- Login throttling and temporary lockout.
- RBAC: ADMIN, ANALYST, VIEWER.
- Server-side Cloudflare token storage; tokens are never returned to the frontend.
- Audit logs intentionally omit secret-like fields.
- CORS is explicit through `CORS_ORIGINS`.
- Security headers are emitted by the API.

## Limitations

A remote application can change behavior after a scanner request. The scanner therefore reports observations, not proof of exploitability. Technology detection uses CONFIRMED / LIKELY / POSSIBLE evidence levels. CORS reflection testing uses a benign Origin value and performs no credentialed exploit.
