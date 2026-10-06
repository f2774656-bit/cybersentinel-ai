# Testing

Run:

```bash
pytest -q
```

The suite covers authentication primitives, token validation, scope normalization, private-IP/metadata blocking, deterministic scoring, Cloudflare REST behavior with mocked HTTP, report generation and queue serialization.

For full integration testing, run the local Docker topology and exercise `/health`, `/ready`, registration, authorization and a deliberately authorized disposable test host. Do not test against systems outside your authorization boundary.
