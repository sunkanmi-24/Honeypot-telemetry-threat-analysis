# ROADMAP.md — phases, state, and what remains

## Completed phases

| Phase | Scope | Evidence |
|---|---|---|
| 1. Audit | read all originals, duplicated dep file removed, `requirement.txt` deleted, audit written | `PROJECT_AUDIT.md`, `backup/original/` |
| 2. Config + storage | `config.py` validation, SQLite/PostgreSQL store, indexes, JSONL migration | tests/test_telemetry.py |
| 3. Client-IP | pure resolver + ProxyFix wiring + tests, verified-hop policy | tests/test_classify_ip_mitre.py |
| 4. Deceptive routes | 30+ safe decoys + safety doctrine + tests | tests/test_route_safety.py |
| 5. Classification + MITRE | categories, frequency-gated repeated probing, qualified mapping | tests/test_classify_ip_mitre.py, docs/MITRE_MAPPING.md |
| 6. Dashboard + exports | real DB data, pagination, filters, empty states, escaping | tests/test_dashboard_exports.py |
| 7. Analysis | reproducible pandas/matplotlib pipeline, honest empties | tests/test_analysis.py |
| 8. Deployment prep | render.yaml, Procfile, .python-version, requirements.txt | `python -m pytest -q` = 67 passed |
| 9. Documentation | README + docs/* set + report template | `reports/final-report.md`, `docs/` |

## Remaining (user actions or requires deployment)

| # | Action | Why it needs you |
|---|---|---|
| 1 | Create GitHub repo + push | your account authorization |
| 2 | Deploy to Render (web service + database choice) | your Render account |
| 3 | Verify `PROXY_TRUSTED_HOPS` on the live service | requires the deployment |
| 4 | Confirm MITRE names on attack.mitre.org | site unreachable from build machine at build time |
| 5 | Run the 96-hour observation window | only after 1–3 |
| 6 | Export real data, run analysis, fill the report results | depends on 5 |
| 7 | Collect evidence artifacts | throughout |

## Optional improvements (not required for submission)

- Enable geographic enrichment (GeoLite2 MMDB + `geoip2`) and document
  provider accuracy in the report.
- Move dashboard heavy tables to server-side pagination limits for very
  large datasets (currently limited/aggregate queries).
- Add an `/export/stats.json` convenience endpoint mirroring
  `reports/summary.json`.
