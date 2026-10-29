# Next Steps — continue from the completed implementation

> Status: the earlier phases (1–7) listed in the original prototype are
> implemented and tested. This file replaced the old checklist; what
> remains mostly requires *your* accounts.

## Phase 8 — Deployment (you)

1. Create a **private** GitHub repo and push (commands in
   `docs/DEPLOYMENT.md` §2).
2. Deploy on Render per `docs/DEPLOYMENT.md` §4 (choose PostgreSQL —
   §3 — before the observation window).
3. Verify the deployment checklist §8 and the proxy hop count §6.
4. Record the verification in `docs/OBSERVATION_PLAN.md` §B.

## Phase 9 — Observation window (96 h)

Follow `docs/OBSERVATION_PLAN.md` exactly: pre-observation gates, UTC
start/end, daily health checks, downtime log, end-of-window export
procedure. **No artificial traffic.**

## Phase 10 — Analysis and report

1. `python analyze.py --input exports\observed-events.jsonl`
2. Fill `reports/final-report.md` §13 (Results) from
   `reports/summary.json` and the exported tables — pending marks stay
   only for what genuinely didn't happen.
3. Verify MITRE technique names/descriptions on
   https://attack.mitre.org/ and note the verification date in
   `docs/MITRE_MAPPING.md`.
4. Assemble evidence per `docs/EVIDENCE_COLLECTION.md`.

## Housekeeping suggestions

- Suggested commit messages:
  - `feat: honeypot telemetry store with SQLite/PostgreSQL support`
  - `feat: tested trusted-proxy client IP resolution`
  - `feat: deceptive endpoint suite with safety guarantees`
  - `feat: evidence-based classification and MITRE mapping`
  - `feat: live dashboard with exports and filters`
  - `feat: reproducible analysis pipeline (pandas/matplotlib)`
  - `docs: full documentation set and report template`
- Tag the submission: `git tag -a v1.0-observation-ready -m "ready for 96h window"`
