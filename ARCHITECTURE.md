# Architecture

## Runtime topology

Browser -> Next.js frontend -> FastAPI API -> PostgreSQL
                                      |-> Redis queues -> scanner worker
                                      |-> Redis queues -> AI worker -> Cloudflare Workers AI
                                      |-> Redis queues -> report worker
                                      |-> Cloudflare API (server-side, read-only posture)

## Trust boundaries

1. Browser is untrusted.
2. API validates identity, RBAC, target ownership and authorization state.
3. Scanner validates every URL against the target scope and a public-IP policy.
4. External HTTP is performed by the scanner only; the API never accepts arbitrary proxy requests.
5. AI receives structured evidence already captured by the scanner.

## Scan state machine

`QUEUED -> VALIDATING -> RUNNING -> COMPLETED`

Optional terminal states are `FAILED` and `CANCELLED`. Each module writes event telemetry into PostgreSQL.

## Queue semantics

Redis lists are used for compact job dispatch. PostgreSQL stores scan/job state so a worker restart cannot silently manufacture completion. A deployment can later replace the dispatcher with Redis Streams without changing the domain model.

## Deterministic score

Starting score is 100.

Penalty = sum(severity_weight × confidence_multiplier) + category_factor + affected_url_factor.

Severity weights: CRITICAL 35, HIGH 20, MEDIUM 10, LOW 4, INFO 1.

Confidence multipliers: HIGH 1.0, MEDIUM 0.7, LOW 0.4.

Category factor = min(12, unique_categories × 1.2).

Affected URL factor = min(8, unique_affected_urls × 0.5).

Final score is clamped to [0,100]. The AI never participates in this calculation.
