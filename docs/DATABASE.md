# Database

PostgreSQL is the durable source of truth.

Tables:

`users`, `sessions`, `targets`, `target_scopes`, `scans`, `scan_modules`, `scan_events`, `findings`, `finding_evidence`, `cloudflare_connections`, `ai_analyses`, `reports`, `audit_logs`, `system_settings`.

UUID primary keys are used for entity tables. Foreign keys cascade for child scan/target data where appropriate and preserve audit references to deleted users with `SET NULL`.

Migrations are managed by Alembic.
