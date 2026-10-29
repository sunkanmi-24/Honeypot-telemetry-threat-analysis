# Observation Plan — 96-hour public exposure window (72–120 h acceptable)

> **Status: NOT STARTED.** Every timestamp, downtime row, and result in
> the final report must come from this log. Nothing gets filled in
> prospectively or retrospectively without evidence.

## A. Pre-observation gates (all must pass before starting the clock)

- [ ] All tests pass locally (`python -m pytest -q`).
- [ ] Deployment is live and `/health` verifies over HTTPS from outside.
- [ ] Storage persistence verified across a restart (docs/DEPLOYMENT.md §8).
- [ ] Client-IP configuration verified with a safe, controlled request.
- [ ] Observation metadata recorded **below** (deployment URL, commit,
      exact UTC start time).
- [ ] Storage-backed export capability tested once
      (`/export/events.csv?view=observed` downloads currently-stored rows).

## B. Observation metadata (fill in as facts occur)

| Field | Value |
|---|---|
| Public deployment URL | *(pending — first Render deploy)* |
| Deployment commit / version | *(pending — record `git rev-parse --short HEAD` used)* |
| Planned duration | 96 hours |
| Exact start (UTC) | *(pending)* |
| Exact end (UTC) | *(pending)* |
| Storage option used | *(pending — PostgreSQL or persistent disk)* |
| `PROXY_TRUSTED_HOPS` used | *(pending — verified value)* |

## C. Event log (append rows as they happen)

| Event (UTC) | Type | Notes |
|---|---|---|
| *(pending)* | restart/deploys/downtime/idle-sleeps | one row each |
| | | |

Known downtime categories to log: idle spin-down/restart (free plan),
manual restarts, redeploys, Render incidents. If the free plan sleeps,
state explicitly in the final report that **continuous 96 h exposure was
not achieved** and quantify idle gaps from the log.

## D. Daily routine (every 24 h while observing)

1. Visit `/health` and note HTTP 200 (screenshot if feasible).
2. Visit `/dashboard` and note the running totals (screenshot).
3. Append any Render events to section C (Actions/Events tab shows
   deploy/restart times UTC).
4. Optional: download `/export/events.jsonl` as an interim backup.

## E. Rules during the window

- **Do not generate artificial traffic** toward the public URL
  (no bots, no paid visitors, no "scanner simulators"). Only organic,
  unrequested traffic counts as observed data.
- Local, synthetic test traffic (e.g., your own browser, test scripts)
  is allowed but must be labelled: on the deployed service your own
  requests are *observed* status only if you use the public URL; use
  `/dashboard/events?view=…` filters to keep them in context, and say
  in the report which requests were yours.
- Do not modify the code during the window (a redeploy resets the
  process and complicates the evidence trail). Bugfixes are allowed but
  must be logged in section C.

## F. End-of-window procedure

1. Record exact end time (UTC) in the table above.
2. Download full exports immediately (before any plan expiry):
   ```cmd
   curl -o exports/observed-events.jsonl "https://<your-app>.onrender.com/export/events.jsonl?view=observed"
   curl -o exports/observed-events.csv  "https://<your-app>.onrender.com/export/events.csv?view=observed"
   curl -o exports/all-events.jsonl     "https://<your-app>.onrender.com/export/events.jsonl?view=all"
   ```
3. Copy the Render event history (deploys/restarts) into section C.
4. Run the reproducible analysis locally:
   ```cmd
   python analyze.py --input exports\observed-events.jsonl
   ```
5. Confirm `reports/` contains the new tables/figures and
   `reports/summary.json`; commit them (they contain no secrets).
6. Complete `reports/final-report.md` section 13 (Results) **only from
   these outputs**, and mark any unavailable fields as "not available"
   rather than estimating.

## G. Honesty notes for the report

- Counts of "requests" are counts of **recorded HTTP events**, not
  unique attacks and not unique adversaries.
- If your own visits are inside the data, they are labelled in context;
  keep the count small and state it.
- If storage failed at any point, the report must say when and what was
  lost.
