# PROJECT_CONTEXT

*One-page living context for any human or agent resuming this project.*

## What this is

A defensive, low-interaction HTTP honeypot (Flask + Gunicorn, SQLite →
PostgreSQL) for an academic telemetry/threat-analysis assignment:
decoy endpoints, structured telemetry, tested proxy-safe IP
resolution, evidence-based classification and MITRE ATT&CK mapping, a
dashboard, exports, reproducible analysis, and a planned 96-hour
public observation window on Render.

## Where things stand (as of this build)

| Area | State |
|---|---|
| App + decoys + dashboard + exports | ✅ implemented |
| Tests | ✅ 67 passing (`python -m pytest -q`) |
| Analysis pipeline | ✅ implemented, honest empty/missing handling |
| Deployment artifacts | ✅ prepared (render.yaml, Procfile, .python-version) |
| Actual Render deployment | ⏳ user action (no account access from build machine) |
| 96 h observation | ⏳ not started (plan ready) |
| Final report | ⏳ template ready, results marked pending |

## Non-negotiable project rules

1. No scanning/exploitation of anything not owned by the researcher.
2. No plaintext credential storage — only field *presence* flags.
3. `PROXY_TRUSTED_HOPS` must be **verified** on the deployment before
   any IP claim; default 0 trusts no forwarded header.
4. No fabricated data anywhere; synthetic traffic is labelled and
   separable; countries are never guessed (unknown until a documented
   GeoIP provider is enabled).
5. No "botnet"/actor attribution from IP addresses alone.
6. Report results stay "pending" until real observations exist.

## Getting productive fast

```cmd
.venv\Scripts\activate
python -m pytest -q      &:: tests
python app.py            &:: server at http://127.0.0.1:5000
```

Key files: `app.py` (factory), `honeypot/*.py` (behaviour),
`templates/`, `static/css/`, `analyze.py` (reports), `config.py`
(env vars), tests in `tests/`. The original prototype is preserved in
`backup/original/`.

## Next user actions

1. Push to GitHub (private); deploy on Render per `docs/DEPLOYMENT.md`.
2. Verify persistence + `PROXY_TRUSTED_HOPS` (docs/DEPLOYMENT.md §6–8).
3. Start the observation window per `docs/OBSERVATION_PLAN.md`
   (record exact UTC start/end; log downtime; no artificial traffic).
4. Export real data, run `python analyze.py --input exports\...`,
   fill `reports/final-report.md` results from `reports/summary.json`.
5. Collect evidence per `docs/EVIDENCE_COLLECTION.md`.
