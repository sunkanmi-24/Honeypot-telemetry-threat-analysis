# Troubleshooting Guide

## Local (Windows) issues

### `python` is not recognised
Install Python 3.11+, tick **Add python.exe to PATH** during setup, then
reopen Command Prompt.

### `pip install` fails / times out
Use `python -m pip install --upgrade pip` first; retry; check proxy/VPN.

### `cannot import name 'Config'` / strange import errors
You are probably in the wrong folder or the venv isn't active:

```cmd
cd C:\Users\dell\Downloads\telemetry-threat-analysis-ready\telemetry-threat-analysis
.venv\Scripts\activate
python -m pytest -q
```

### Port already in use (`OSError: [WinError 10048]`)
Start on another port: `python app.py --port 5001`.

### Tests fail after editing code
Run one file to isolate: `python -m pytest tests\test_telemetry.py -q`.
The database used by tests is temporary; wiping `telemetry.db` fixes
state-related surprises in manual browsing, never inside tests.

## Data issues

### Dashboard shows "No telemetry yet" unexpectedly
You're probably in the default *observed only* view while all your
events are synthetic (local). Use `/dashboard?view=all`.

### A row has `unknown` for a field
Fields that weren't sent (e.g., no Referer header) are stored as unknown
by design — never guessed.

### Database file locked (`database is locked`)
Close other consoles holding `telemetry.db` open (Excel, DB
browsers). The app itself uses short-lived connections and WAL-safe
writes.

### Migrating the old prototype's JSONL
```cmd
python -c "from honeypot.telemetry import TelemetryStore; from app import get_config; c = get_config(); s = TelemetryStore(database_url=c.database_url, data_dir=c.data_dir); s.init_db(); print(s.import_jsonl('telemetry.jsonl'))"
```
The source file is never modified; malformed lines are skipped and
counted.

## Deployment (Render) issues

### Build fails with dependency errors
Confirm `requirements.txt` (not `requirement.txt`) is in the repo root
and renders **Flask**, **gunicorn**, **psycopg2-binary**, etc.
Render builds on Linux; Windows-only PATH issues do not apply.

### Service boots then dies with "Failure to bind"
You are probably running `python app.py` in production. Render requires
binding `$PORT` through Gunicorn — use the exact **Start command** from
`Procfile` / `render.yaml`.

### `/health` shows 502 after provisional deployment
The service may have been asleep (free plan) — first request after
sleep takes ~30 s; retry once. Persist failing → check the logs.

### All source IPs show the same internal address on the dashboard
`PROXY_TRUSTED_HOPS` is misconfigured. With 0, headers are never
trusted and only the proxy's hop address appears. Verify docs/DEPLOYMENT.md §6
step-by-step rather than guessing.

### Data lost after restart (free plan + SQLite)
Free plans have an ephemeral filesystem. Move to managed PostgreSQL
(`DATABASE_URL`) or a paid instance + persistent disk
(docs/DEPLOYMENT.md §3). Record the loss honestly in the observation
plan.

### `DATABASE_URL` wrong region/format
Copy Render's **Internal Database URL** (starts with
`postgres://`). External URLs are possible but slower; internal is
preferred.

## Analysis issues

### `ModuleNotFoundError: pandas`/`matplotlib`
Activate the venv and re-install requirements:
`python -m pip install -r requirements.txt`.

### Charts don't appear
Check `reports/figures/`, and rerun with more data. With zero records,
charts are intentionally skipped (`reports/summary.json` notes this).

### Non-ASCII characters in charts
matplotlib renders standard fonts on Windows; if you see boxes instead
of characters, switch system font settings or use the default Agg
backend (already configured in `analyze.py`).
