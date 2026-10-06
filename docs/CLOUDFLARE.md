# Cloudflare

Use a Cloudflare API token, not a global API key. Recommended permissions should be limited to the read operations needed by the connected zone/account: Zone Read, DNS Read, Zone Settings Read, Analytics Read when analytics is explicitly enabled, and Account/Zone Rulesets Read where WAF posture is required.

The application stores a Fernet-encrypted token in `cloudflare_connections`. The browser never receives the token.

Current integration uses Cloudflare's v4 API resources for zones, DNS records, zone settings and rulesets. The security view is intentionally read-only.

Workers AI is configured separately with:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_AI_MODEL`
- `CLOUDFLARE_AI_TOKEN`

The provider calls `POST /accounts/{account_id}/ai/run/{model_name}` and sends model-specific input directly in the request body.


## Security Events / Analytics

The integration can query recent Cloudflare Security Events through the GraphQL Analytics API using `firewallEventsAdaptive`, scoped to a zone tag. The query is bounded to at most 24 hours and 100 returned events by the application. The token needs the zone-scoped **Analytics Read** permission in addition to the read permissions required for zones, DNS, settings and rulesets. Cloudflare documents `Analytics Read` as the zone permission for analytics and recommends API Tokens with resource restrictions.
