# Evidence Collection Checklist

Collect each artifact during development/deployment, and keep screens
crop clean (no API keys, tokens, database URLs, personal files). Name
files clearly. Suggested folder: `evidence/` (git-ignored).

> All items marked ⚠ include possibly sensitive numbers — crop or blur
> addresses/id values that identify your accounts.

## A. Project and environment

| # | Artifact | How |
|---|---|---|
| A1 | Project tree | `tree /F > evidence\project-tree.txt` (exclude .venv/backup) |
| A2 | Python version | `python --version` screenshot |
| A3 | Dependency install | screenshot of `python -m pip install -r requirements.txt` output |
| A4 | Passing tests | screenshot of `python -m pytest -q` (67 passed, plus your reruns) |
| A5 | `.env.example` contents | screenshot (template values only) |

## B. Local run

| # | Artifact | How |
|---|---|---|
| B1 | App starting locally | `python app.py` terminal output |
| B2 | Health endpoint | browser at `http://127.0.0.1:5000/health` |
| B3 | Deceptive endpoints | one screenshot with 2–3 decoy pages open (`/admin`, `/wp-login.php`, `/.env`) |
| B4 | Telemetry records | `/dashboard/events?view=(all)` with visible rows |
| B5 | Dashboard full view | `/dashboard` with data |
| B6 | Empty state | fresh database (temp DATA_DIR) showing "No telemetry yet" |
| B7 | Exports | download CSV + JSONL, open in a text editor |
| B8 | Analysis outputs | terminal output of `python analyze.py --input …` + `reports/figures/` PNGs |

## C. Source control and deployment

| # | Artifact | How |
|---|---|---|
| C1 | GitHub repository | repo homepage (private is fine, blur name if desired) |
| C2 | A meaningful commit history page | *Commits* tab |
| C3 | Render service dashboard | ⚠ crop secrets; show service + environment (make sure `DATABASE_URL` shows its redacted value only) |
| C4 | First successful deploy log | Render *Events/Logs* |
| C5 | Live public URL | browser address bar + `/health` result |

## D. Observation window

| # | Artifact | How |
|---|---|---|
| D1 | Start timestamp | screenshot of your UTC clock source + this repo's `docs/OBSERVATION_PLAN.md` table row |
| D2 | Storage persistence check | before/after-restart dashboard screenshots |
| D3 | Client-IP verification | from §6 of docs/DEPLOYMENT.md — dashboard row showing your public IP, and the forged-XFF test outcome |
| D4 | Daily dashboard snapshots | at least one per 24 h |
| D5 | Restart/downtime events | Render events tab screenshots |
| D6 | End timestamp + final exports | OBSERVATION_PLAN.md final rows + export file listing (`dir exports\`) |
| D7 | Final analysis | `python analyze.py --input exports\observed-events.jsonl` output |

## E. Final deliverables

| # | Artifact | Location |
|---|---|---|
| E1 | Final report | `reports/final-report.md` (export to PDF for submission if required) |
| E2 | Summary tables | `reports/tables/` |
| E3 | Figures | `reports/figures/` |
| E4 | JSON analysis summary | `reports/summary.json` |
| E5 | MITRE mapping rationale | `docs/MITRE_MAPPING.md` (+ your verification of technique pages) |

## F. Do NOT put in the repository or evidence

- Real `.env`, API keys, database URLs/passwords.
- Full-size screenshots of dashboards showing sensitive personal data of
  others beyond what the assignment needs (IPs are required evidence;
  that's acceptable and described in the report's ethics section).
- Any "made-up" numbers or charts used to impress — every artifact must
  trace to a command you actually ran (keep the commands next to each
  screenshot and record them in the observation log).
