# Project Audit — Telemetry & Threat Analysis Honeypot

Audit performed: 2026-10-29 (local Windows machine, Python 3.11.9)

This document records what the existing project contained, what was wrong with
it, what was kept, what was replaced, and the implementation plan. Nothing was
deleted by the audit; no telemetry files existed, so nothing could be lost.

---

## 1. Complete project structure at audit time

```
telemetry-threat-analysis/
├── app.py                       Flask prototype (298 lines)
├── analyze.py                   Console summary script (31 lines)
├── requirement.txt              DUPLICATE dependency file (typo name)
├── requirements.txt             Dependency file
├── render.yaml                  Render service definition
├── Procfile                     web: gunicorn app:app
├── README.md                    Setup instructions
├── NEXT_STEPS.md                Roadmap notes
├── AGENTS.md                    Agent working instructions
├── telemetry.jsonl.example      Placeholder (one comment line)
├── static/
│   └── Css/style.css            Small stylesheet (wrong capitalisation)
└── tests/
    └── test_app.py              2 tests (/health, /)
```

No `telemetry.jsonl` existed. There is **no collected telemetry** in the
repository — neither synthetic nor real. The `telemetry.jsonl.example` file is
an empty placeholder. Therefore the project starts with a clean evidence base.

## 2. Framework and startup

- Framework: Flask 3.1.3 (was already installed).
- Entry point: `python app.py` → `app.run(debug=True)` (development server).
- Production target: `gunicorn app:app` via `Procfile` / `render.yaml`.
- Baseline verification run (this audit): `python -m pytest -q` →
  **2 passed**. The prototype runs.

## 3. Findings (problems to fix)

### Correctness / structure
1. **Duplicate dependency file** — `requirement.txt` (typo) duplicates
   `requirements.txt`. Must be fixed by keeping only `requirements.txt`
   (deployment-friendliness; tools look for `requirements.txt`).
2. **Static path capitalisation bug** — CSS lives at `static/Css/style.css`
   but the dashboard links `/static/css/style.css`. This works on the Windows
   case-insensitive filesystem but **breaks on Render (Linux)**. Fixed by
   moving the file to `static/css/style.css`.
3. **Classification logic is a small path-keyed dict** — only 7 paths, no
   categories, no method/frequency evidence, no separation of observed facts
   from inference.
4. **No MITRE ATT&CK mapping module**, no evidence/rationale/confidence fields.
5. **`analyze.py` is fragile** — calls `json.loads(line)` without error
   handling (would crash on a malformed line), discloses nothing about
   synthetic data, and its classification counter is buggy (the last
   classification is incremented outside the loop at lines 18–19).
6. **Telemetry stored as JSON Lines only** — no indexes, no concurrency
   control, no pagination, and appending to a file relies on the local
   filesystem being persistent (it is not on Render's free plan).

### Security findings
7. **`before_request` logs every request**, including the dashboard — the
   observer's own monitoring traffic pollutes the dataset. Should exclude
   dashboard/export/health paths.
8. **No credential-value protection** — current code never reads the body, so
   no password is stored (good), but this safety property must be preserved
   and tested once credential-field *presence* detection is added.
9. **`/dashboard` is unauthenticated** — acceptable for the assignment, but
   must be excluded from telemetry and documented. On a public URL this
   reveals aggregated scanner traffic to scanners; acceptable, warning added.
10. **`debug=True` in the development entry point** — leaks tracebacks if it
    is ever run publicly. Replaced with env-var-gated debug.
11. **`request.remote_addr` trusted blindly in a deployment behind a proxy** —
    on Render every event would record the proxy's internal IP (`127.0.0.1`).
    Added a tested client-IP resolver with configurable trusted hop count
    (default: 0 — headers not trusted).
12. **No security headers** — added `X-Content-Type-Options`,
    `X-Frame-Options`, `Referrer-Policy` in the new app.

### Missing features (vs. assignment requirements)
13. Most required deceptive endpoints (`/wp-admin`, `/.env`, `/.git/config`,
    `/phpmyadmin`, `/backup.zip`, `/actuator/env`, `/phpinfo.php`, …) did not
    exist.
14. No exports (JSON/CSV), no event detail data, no pagination, no empty
    states, no synthetic-vs-observed separation in the dashboard.
15. No analysis pipeline (`reports/tables`, `reports/figures`, JSON summary).
16. No geographic enrichment (must stay *unknown*, never guessed).
17. Deployment files existed but were incomplete (no port binding via `$PORT`
    in the Gunicorn command, no persistent-disk / PostgreSQL guidance).
18. No documentation set (`docs/…` required by the assignment).

## 4. Data-origin determination

- `telemetry.jsonl.example`: an authored placeholder comment — not data.
- No `.jsonl` file: the app has never collected events on this machine.
- Conclusion: **this is local development traffic only; no evidence of real
  Internet observation exists yet.** All new synthetic events written by the
  test suite or by localhost browsing are flagged `synthetic = 1` in the new
  schema and are excluded from observed-Internet statistics.

## 5. What is retained / replaced / new

| Decision | Item |
|----------|------|
| Keep | Flask, Gunicorn-on-Render, Procfile, render.yaml, JSONL export path |
| Rewrite | `app.py` (factory, blueprints, error handlers, headers) |
| Rewrite | `analyze.py` (pandas/matplotlib pipeline, malformed-line tolerance) |
| Replace | `requirement.txt` → delete; single `requirements.txt` |
| Move | `static/Css/style.css` → `static/css/style.css` |
| New | `config.py`, `honeypot/` package (telemetry, classification, mitre, clientip, geoip, views) |
| New | SQLite telemetry store (dev) with PostgreSQL (production via `DATABASE_URL`) |
| New | Dashboard with pagination, filters, exports, empty states |
| New | pytest suite covering routes/schema/IP/classification/MITRE/persistence |
| New | `docs/` set, `reports/` outputs, final report template |

## 6. Implementation plan (phases)

1. **Config + telemetry store** — env-validated `config.py`; SQLite/Postgres
   store with schema, indexes, and JSONL import/export. Test persistence.
2. **Client-IP resolution** — pure, tested resolver + Werkzeug `ProxyFix`
   wiring with `PROXY_TRUSTED_HOPS` (default 0; Render value to be verified).
3. **Deceptive endpoints** — full route table with safe fake responses only.
4. **Classification + MITRE** — separate, evidence-based, documented modules.
5. **Dashboard + exports** — real DB data, pagination, synthetic separation.
6. **Tests** — pytest for everything above; run `python -m pytest -q`.
7. **Analysis pipeline** — reproducible `python analyze.py` → CSV tables,
   PNG charts, JSON summary; malformed-line tolerant; synthetic filter.
8. **Deployment prep** — `requirements.txt`, `render.yaml`, `Procfile`,
   `docs/DEPLOYMENT.md` with exact user-side steps.
9. **Documentation** — README + docs/ set + final report template with
   pending results marked as pending.

## 7. Constraints acknowledged

- No deployment can be performed from this machine (no Render account access).
- No observation period has started; every results section will be marked
  pending until real data exists.
- No artificial traffic will be generated against the public deployment.
- Geographic enrichment is optional/off by default and never guesses.

---

## 8. Implementation outcome (added after the build)

| Plan item | Result |
|---|---|
| Config + telemetry store | ✅ `config.py`, `honeypot/telemetry.py` (SQLite/PostgreSQL, indexes, JSONL import/export) |
| Client-IP resolution | ✅ `honeypot/clientip.py` + ProxyFix wiring, tested |
| Full deceptive route list | ✅ 30+ safe decoys in `honeypot/views.py` |
| Classification + MITRE modules | ✅ `honeypot/classification.py`, `honeypot/mitre.py` |
| Dashboard + exports | ✅ `honeypot/dashboard.py`, `templates/`, `static/css/style.css` |
| pytest suite | ✅ **67 passed** (`python -m pytest -q`) |
| Analysis pipeline | ✅ `analyze.py` → `reports/tables`, `reports/figures`, `reports/summary.json` |
| Deployment config | ✅ `requirements.txt`, `render.yaml`, `Procfile`, `.python-version`, `.env.example` |
| Documentation set | ✅ README + PROJECT_* + DESIGN/ROADMAP + `docs/*` + `reports/final-report.md` template |

Remaining: actual deployment (user's Render account), verifying
`PROXY_TRUSTED_HOPS` on the live service, confirming MITRE technique
pages online (unreachable from this machine at build time), then the
96-hour observation window and the report results.

