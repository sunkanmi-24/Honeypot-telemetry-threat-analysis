# Beginner Guide — running and understanding this project on Windows

This guide assumes only Python installed (3.11+ shown) and Command
Prompt. Do everything from the project folder.

## 1. First run (one-time setup)

```cmd
python --version
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

(`.venv\Scripts\activate` may need `.venv\Scripts\activate.bat` on very
old shells. Each new CMD window needs the activation step again.)

## 2. Run the honeypot locally

```cmd
python app.py
```

Visit in a browser:

- `http://127.0.0.1:5000/` — landing page
- `http://127.0.0.1:5000/health` — health JSON
- `http://127.0.0.1:5000/dashboard` — dashboard (empty state at first)
- try `http://127.0.0.1:5000/admin`, `/login`, `/.env`, `/wp-login.php`
  — decoy endpoints

Every page you visit adds rows to the local SQLite database at
`telemetry.db`. Because your browser is on `127.0.0.1` (loopback), the
rows are automatically flagged `synthetic = 1`; the dashboard's default
"observed only" view ignores them.

Useful extra windows:

```cmd
python app.py --port 5001          :: second instance on another port
python app.py --debug              :: NOT for public use (debugger!)
```

Stop the server with `Ctrl+C`.

## 3. Run the tests

```cmd
python -m pytest -q
```

All should pass (67 tests as of this build). If something fails, check
you're in the project folder and the venv is activated.

## 4. Explore the data

Dashboard pages:

| Page | What it shows |
|---|---|
| `/dashboard` | summary cards, over-time counts, top routes/IPs/agents, classifications, MITRE table, recent events |
| `/dashboard/events` | paginated filterable event list |
| `/dashboard?view=synthetic` | your local/test traffic only |
| `/dashboard?view=observed` | non-synthetic traffic only |
| `/export/events.csv?view=…` / `/export/events.jsonl?view=…` | full data downloads |

Filters: date range (`from`/`to`), source IP, classification.

## 5. Run the analysis

After exporting (or pointing at the local DB):

```cmd
python analyze.py
python analyze.py --input exports\observed-events.jsonl
python analyze.py --input exports\observed-events.jsonl --include-synthetic
```

Outputs: `reports/tables/*.csv`, `reports/figures/*.png`,
`reports/summary.json`. Nothing is invented: with no data you get an
empty summary and no charts.

## 6. Where the code lives (reading order for beginners)

1. `app.py` — how the app is built and configured
2. `honeypot/views.py` — the decoy route table + telemetry capture
3. `honeypot/classification.py` — how requests get categories
4. `honeypot/mitre.py` — how categories map to MITRE ATT&CK
5. `honeypot/clientip.py` — why a client can't fake its IP
6. `honeypot/telemetry.py` — the database and exports
7. `templates/` + `static/css/` — dashboard pages

## 7. Safety habits

- Never run the app publicly without Gunicorn + verified
  `PROXY_TRUSTED_HOPS` (docs/DEPLOYMENT.md).
- Never edit `.env.example` to contain real secrets.
- The decoys never collect passwords: even if you type one into a fake
  login page, the system stores only "a password-shaped field was
  present", not the value (tests prove this).
