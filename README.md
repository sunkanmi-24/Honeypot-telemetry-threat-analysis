# Telemetry & Threat Analysis Honeypot

A **defensive, low-interaction HTTP honeypot** for an academic
telemetry and threat-analysis assignment. It presents deceptive but
completely non-functional endpoints (admin panels, config files,
diagnostic pages), records structured telemetry about real requests, and
turns that telemetry into reproducible charts/tables for a
MITRE-mapped threat report.

## Current status

- ✅ Local application runs; **67 tests pass** (`python -m pytest -q`).
- ✅ Dashboard, exports, classification, MITRE mapping, client-IP
      handling, SQLite/**PostgreSQL via Supabase** (managed), storage,
      tests, analysis.
- ✅ Render deployment configuration is prepared (see below).
- ⏳ **Not yet deployed** — deployment requires your Render account;
      follow `docs/DEPLOYMENT.md`.
- ⏳ **Observation window not started** — plan is in
      `docs/OBSERVATION_PLAN.md`; no real observations exist yet, so all
      report results remain "pending" until real data exists.

## Documentation map

| Document | Purpose |
|---|---|
| `PROJECT_AUDIT.md` | audit of the original prototype and what changed |
| `PROJECT_CONTEXT.md` | one-page project overview for humans and agents |
| `DESIGN.md` | design decisions and rationale |
| `ROADMAP.md` | phase history and what remains |
| `docs/ARCHITECTURE.md` | request lifecycle and storage design |
| `docs/BEGINNER_GUIDE.md` | step-by-step Windows usage |
| `docs/DEPLOYMENT.md` | Render deployment, storage options, IP verification |
| `docs/OBSERVATION_PLAN.md` | the 96-hour observation methodology |
| `docs/THREAT_MODEL.md` | assets, boundaries, claim limits |
| `docs/MITRE_MAPPING.md` | every mapping with evidence/confidence/limits |
| `docs/ETHICS_AND_SCOPE.md` | what is collected and what is never claimed |
| `docs/EVIDENCE_COLLECTION.md` | screenshots/artifacts checklist |
| `docs/TROUBLESHOOTING.md` | common problems and fixes |
| `reports/final-report.md` | the assignment report (results pending) |

## Quick start (Windows CMD)

```cmd
python --version
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

Then:

- `http://127.0.0.1:5000/` — landing page (decoy service description)
- `http://127.0.0.1:5000/health` — health JSON
- `http://127.0.0.1:5000/dashboard` — live dashboard
- decoys: `/admin`, `/login`, `/.env`, `/wp-login.php`,
  `/phpmyadmin`, `/server-status`, `/actuator`, `/xmlrpc.php`, …

Stop with `Ctrl+C`. Your own localhost browsing is automatically flagged
`synthetic` and excluded from observed-Internet statistics.

## Run the tests

```cmd
python -m pytest -q
```

## Analysis

```cmd
python analyze.py --input exports\observed-events.jsonl
python analyze.py                       :: local SQLite instead
```

Writes `reports/tables/*.csv`, `reports/figures/*.png`,
`reports/summary.json`. Never merges synthetic test traffic into the
observed dataset unless you explicitly pass `--include-synthetic`.

## Deployment (Render)

Configuration is prepared (`render.yaml`, `Procfile`,
`.python-version`, `/health` check). Account-specific steps — creating
the database, pushing to GitHub, deploying, verifying the proxy hop
count — are documented exactly in `docs/DEPLOYMENT.md`. **Do not run
the Flask dev server publicly**; production uses Gunicorn bound to
Render's `$PORT`.

## Project rules (unchanged from AGENTS.md)

- Never scan or exploit third-party systems.
- Never expose real configuration or credentials; **credential values
  are never stored** — only that a credential-shaped field was present.
- Never trust arbitrary forwarded IP headers; only a verified proxy
  configuration sets `PROXY_TRUSTED_HOPS`.
- Never fabricate telemetry, IPs, countries, timestamps, or findings.
- Synthetic/local traffic is labelled and excluded from real-Internet
  statistics.
- Never call a source "botnet" merely because requests look suspicious —
  classifications carry evidence, confidence, and alternatives.
