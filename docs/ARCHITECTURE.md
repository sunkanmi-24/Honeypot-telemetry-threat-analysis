# Architecture

## 1. Bird's-eye view

```
Internet
   │  HTTPS
   ▼
Render reverse proxy (1 hop, verified — PROXY_TRUSTED_HOPS)
   │
   ▼
Gunicorn (WSGI, 2 workers × 4 threads)
   │
   ▼
Flask app (app.py factory)
   ├── honeypot_bp  (honeypot/views.py)     deceptive routes + capture
   └── dashboard_bp (honeypot/dashboard.py) dashboard, events, exports
                    │
                    ▼
            honeypot/telemetry.py TelemetryStore
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
  SQLite (dev/data dir)   PostgreSQL (DATABASE_URL, production)
```

Supporting modules:

| Module | Responsibility |
|---|---|
| `config.py` | env-var config and validation (`ConfigError` for bad values) |
| `honeypot/classification.py` | route-category facts + behavioral inference (pure, cached) |
| `honeypot/mitre.py` | evidence-based MITRE mapping + references |
| `honeypot/clientip.py` | tested trusted-proxy IP resolution semantics |
| `honeypot/geoip.py` | optional, replaceable GeoLite2 resolver ("unknown" default) |
| `honeypot/views.py` | deceived-route table + telemetry event builder |
| `analyze.py` | reproducible pandas/matplotlib analysis pipeline |

## 2. Request lifecycle

1. **Route match** — a decoy route (from the single route table) or
   dashboard route responds; any unknown path hits the global 404
   handler.
2. **after_request hook** (`app.py`) — if the path is *not*
   observer-owned (`/health`, `/dashboard*`, `/export*`, `/static/*`),
   `record_telemetry` builds the event:
   - source IP via trusted-hop resolver (default: socket peer only);
   - classification + optional prior-login-probe frequency query;
   - MITRE mapping with rationale/confidence;
   - credential-field presence flags (names only, never values);
   - synthetic flag for loopback/private sources.
3. **Storage** — parameterised INSERT; failure never breaks the HTTP
   response.

Security headers (`X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`) ride along on every response.

## 3. Storage design

- Single `events` table; schema in `honeypot/telemetry.py`
  (`SCHEMA_COLUMNS`), created idempotently by `init_db()` with indexes
  on `timestamp_utc`, `source_ip`, `path`, `classification`,
  `synthetic`.
- SQLite (dev / data dir) or PostgreSQL (production `DATABASE_URL`);
  the engine difference is isolated to placeholder style and null-safe
  cutoff SQL.
- Exports stream from queries, so a large dataset doesn't need to fit
  in memory for one response.
- JSONL import (migration from the legacy prototype format) is
  read-only toward the source file and skips malformed lines — see
  `tests/test_telemetry.py`.

## 4. IPv4/IPv6 / loopback handling

`looks_local()` marks loopback/private addresses (e.g. localhost
browsing, functional tests) so they can be excluded from observed
Internet statistics via `MARK_LOCAL_SYNTHETIC`.

## 5. GeoIP option

`GEOIP_DB_PATH` + the optional `geoip2` package enables country lookups
from a licensed MMDB file. Provider errors or the absence of an address
in the database degrade to "unknown" and never block collection. When no
provider is configured the dashboard says enrichment is disabled instead
of guessing.

## 6. Deployment topology

See docs/DEPLOYMENT.md: Gunicorn binds `0.0.0.0:$PORT` on Render
(never the Flask dev server), one verified proxy hop via Werkzeug
`ProxyFix`, managed PostgreSQL recommended for a 96-hour window.
