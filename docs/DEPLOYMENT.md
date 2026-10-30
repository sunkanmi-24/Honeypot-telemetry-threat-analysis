# Deployment Guide (Render)

This guide gets the honeypot running on Render with a production WSGI
server (Gunicorn) and explains every account-specific step you must do
yourself. Nothing here requires secrets in the repo.

---

## 1. Prerequisites (your actions)

1. A GitHub account and a new **private** repository
   (e.g. `telemetry-threat-analysis`).
2. A Render account (free tier works, with limits documented in section
   7).
3. Decide the storage option (section 3) — do this **before** the
   96-hour observation window.

## 2. Push the code (do not skip project hygiene)

From the project folder in CMD:

```cmd
git init
git add .
git commit -m "Honeypot: telemetry, classification, MITRE mapping, dashboard, tests"
git branch -M main
git remote add origin https://github.com/<your-username>/telemetry-threat-analysis.git
git push -u origin main
```

`.gitignore` already excludes `.venv/`, `.env`, `telemetry.db`,
`telemetry.jsonl`, exports, and local backups. Never commit real
credentials.

## 3. Storage decision (important for a 96-hour observation window)

Render's **free web services have an EPHEMERAL filesystem**: a restart
or redeploy wipes local files. This matters because SQLite lives on disk.

| Option | Plan needed | Persistence | Recommendation |
|---|---|---|---|
| **Supabase PostgreSQL** (managed) | Supabase free tier (or paid) | survives restarts/redeploys of the web service | **Recommended for this project now** |
| Render PostgreSQL | Render Postgres | survives restarts/redeploys | Equivalent option (also fine) |
| SQLite + Render persistent disk | paid plan | survives restarts | acceptable alternative |
| SQLite on free web service | free | **NO** — data loss on restart | only for local-style trials |

### Using **Supabase** as the managed database (recommended now)

1. Create a Supabase project (dashboard: *New → Project*). Use the free tier.
2. Copy the **PostgreSQL connection string** from Supabase → Database → Connection.
   Typical format: `postgresql://postgres:YOUR_PASSWORD@db.abcdefgh.supabase.co:5432/postgres?sslmode=require`
3. Set it as an environment variable on the Render web service:
   - Key: `DATABASE_URL`
   - Value: the full connection string (keep `?sslmode=require` — managed Postgres providers require SSL).
4. The application automatically detects the `postgresql://` / `postgres://` prefix and uses the PostgreSQL backend.
5. The free tier is sufficient for this study's expected volume; monitor usage during observation.

**Option A — PostgreSQL (recommended):**
1. In Render: *New → PostgreSQL*. Choose the plan; note the region
   (pick the same region as the web service).
2. When ready, copy the **Internal Database URL**.
3. Set it on the web service as env var `DATABASE_URL` (never in git).

**Option B — Persistent disk:** in `render.yaml`, uncomment the `disk:`
block (paid plan required) and set env var `DATA_DIR=/var/data`.

## 4. Create the web service

1. Render dashboard: *New → Web Service* → connect your GitHub repo.
2. Runtime **Python**. Render reads:
   - `.python-version` (3.11.9) automatically;
   - `render.yaml` (blueprint) if you choose "Blueprint" — recommended,
     because it sets the build/start commands and env vars for you.
3. Otherwise set manually:
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:**
     `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 60 --access-logfile - --error-logfile -`
   - **Health check path:** `/health`

## 5. Environment variables on the web service

| Variable | Value | Notes |
|---|---|---|
| `PYTHON_VERSION` | `3.11.9` | set by `render.yaml` |
| `PROXY_TRUSTED_HOPS` | `1` | See section 6 — verify before trusting IPs |
| `MARK_LOCAL_SYNTHETIC` | `1` | local/loopback events flagged synthetic |
| `DATABASE_URL` | *(paste managed Postgres URL, e.g. Supabase)* | with `?sslmode=require` for Supabase; leave unset only with Option B |
| `DATA_DIR` | `/var/data` | Option B only |
| `GEOIP_DB_PATH` | *(unset)* | optional; leave unset to keep countries "unknown" |

Do **not** set `APP_DEBUG` in production. Debug mode is off by default.

## 6. Verify the proxy hop count (required before the observation)

Render terminates TLS and proxies to your app, so with default
`PROXY_TRUSTED_HOPS=1`, `request.remote_addr` is the address Render's
proxy observed (render.yaml documents this and the caveat). Verify it:

1. Deploy. Then open **Shell** (Render → your service → Shell) and
   check the access logs for requests to the public URL: the recorded
   `source_ip` should be a **public** IP, not `127.0.0.1`.
2. Make a safe controlled request from your own machine, e.g. from a
   browser visit `https://<your-app>.onrender.com/health` then check
   `/dashboard?view=all`: the source IP shown should match your public
   IP (look it up yourself; the dashboard cannot guess).
3. Extra check (safe header test): from a terminal,
   ```cmd
   curl -H "X-Forwarded-For: 203.0.113.111" https://<your-app>.onrender.com/robots.txt
   ```
   then confirm on `/dashboard?view=all` that the recorded source is
   **not** `203.0.113.111` (a client must never choose its own IP).
4. If step 2 shows the proxy's internal address instead of your public
   IP, adjust `PROXY_TRUSTED_HOPS` accordingly and re-verify. Do not
   guess the value.

## 7. Free-plan limitations (document them honestly in your report)

- Free web services **spin down after ~15 minutes idle** and take tens
  of seconds to start on the next request; the plan also restarts
  periodically. Log every restart/redeploy in the observation log —
  downtime rows are required by `docs/OBSERVATION_PLAN.md`.
- Free PostgreSQL instances (including Supabase free tier) may expire
  or reset — export data before the window ends.
- The first request after sleep still works on `/health` but the
  dashboard's first load can be slow; this is expected and should be
  recorded, not hidden.

## 8. Post-deployment verification checklist

- [ ] First deploy did not error and `/health` returns
      `{"status": "ok"}` over HTTPS.
- [ ] Render logs show no traceback (`--error-logfile -` sends them to
      Render's log stream; debug tracebacks are never exposed over HTTP).
- [ ] `/dashboard` loads with the empty-state message (no fake data).
- [ ] Telemetry persists across restart:
      visit `/admin` from a browser, confirm the (non-synthetic) row in
      `/dashboard/events?view=observed`, then restart the service
      (Render → Manual Restart) and confirm the row is still there.
- [ ] Client-IP verification (section 6) completed.
- [ ] `/export/events.csv?view=observed` downloads real stored rows.

## 9. Troubleshooting quick answers

See `docs/TROUBLESHOOTING.md`. Deployment-side issues (build failures,
crash loops, disk mounting) are covered there with commands and log
locations.
