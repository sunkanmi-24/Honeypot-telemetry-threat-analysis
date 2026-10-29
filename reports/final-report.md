# Final Report — Telemetry and Threat Analysis of a Deployed HTTP Honeypot

> **Status:** template with the methodology fully written and every
> results field marked **pending** until the 96-hour observation window
> (see `docs/OBSERVATION_PLAN.md`) produces real data. No fictional
> values are used anywhere in this document, and none may be added.

---

## 1. Abstract

*(pending — write after §13 exists; summarise the deployment, the
96-hour window, headline counts, and the MITRE-mapped behavioural
insight in ~150 words, strictly from recorded data.)*

## 2. Introduction

Attackers and automated scanners continuously probe exposed HTTP
services for administrative interfaces, forgotten configuration and
backup artefacts, and login endpoints. A honeypot is a defensive system
with no production purpose whose value lies in recording who tries what.
This project designs such a honeypot, exposes it on public cloud
infrastructure for one observation window, and analyses the requests it
receives with defensible classifications and MITRE ATT&CK mappings.

## 3. Problem statement

How can a single, ethically bounded HTTP honeypot produce *defensible*
telemetry — that is, telemetry whose source-IP handling, behavioural
classification, and ATT&CK mapping can each be traced to evidence, and
whose presentation never confuses local testing with public
observation?

## 4. Objectives

1. Implement a non-functional decoy endpoint set resembling commonly
   probed assets.
2. Record structured, credential-safe, length-truncated telemetry in a
   queryable store.
3. Resolve client IP addresses correctly behind a verified reverse
   proxy.
4. Classify behaviour with reproducible, evidence-based rules.
5. Map only genuinely supported behaviour to MITRE ATT&CK techniques.
6. Provide a live dashboard and JSONL/CSV exports.
7. Produce reproducible tables/charts from exported data only.
8. Deploy on Render with a production WSGI server and verify
   persistence.
9. Observe for 96 hours (72–120 acceptable) and record start/end,
   downtime, and restarts exactly.

## 5. Scope and ethical considerations

Collection happens only on infrastructure the researcher controls
`docs/ETHICS_AND_SCOPE.md`): no third-party probing, no credential
storage (values never captured; only field-presence flags), no
attribution of individuals or organisations to IP addresses, no
fabrication of any data. `robots.txt` is served normally. Visitors see
a page describing the service as defensive research. Retention covers
the observation window until submission; exports are stored in a
private repository.

## 6. Architecture

`docs/ARCHITECTURE.md` documents the full request lifecycle:
reverse proxy → Gunicorn → Flask factory → decoy or dashboard blueprint
→ telemetry capture (after response) → SQLite/PostgreSQL. Capture is in
an `after_request` hook so observed facts (status, response size) are
accurate and telemetry failures cannot break responses.

## 7. Technology stack

Python 3.11.9 · Flask 3.1 · Gunicorn 26 · SQLite (dev) / PostgreSQL
(production) · Jinja2 · pandas + matplotlib for analysis · pytest
(67 tests) · Render (cloud) · Git/GitHub (private repo). Optional:
GeoLite2 via `geoip2` for country enrichment (disabled ⇒ "unknown").

## 8. Honeypot endpoint design

30+ decoy routes (`honeypot/views.py` `DECEPTIVE_ROUTES`) grouped into:
fake login pages (admin/WordPress/phpMyAdmin/Tomcat), hardened 404-style
JSON responses for configuration/backup/vcs probes, fake diagnostic
pages (phpinfo/server-status), XML-RPC fault, actuator stubs,
`/robots.txt`, landing and `/health`. Safety invariants (tested):
no file serving, no auth binding, no execution of input, no echoing of
submitted values, unknown methods rejected (405).

## 9. Telemetry collection and privacy

Schema (`honeypot/telemetry.py` `SCHEMA_COLUMNS`): event id, UTC ISO
timestamp, source IP, method, path, query, user agent, referer, host,
status, response size, route category, classification, MITRE
technique/rationale/confidence, credential-presence flags, synthetic
flag, collector version. Values of credential-like fields, cookies, and
authorization headers are never stored; field lengths are capped;
malformed inserts are refused without breaking the response; observer
paths are never recorded.

## 10. Reverse-proxy IP handling

Default: socket peer only. Forwarded headers are consulted **only**
when the deployed proxy hop count is verified and set
(`PROXY_TRUSTED_HOPS`), implemented with Werkzeug `ProxyFix` and the
tested resolver in `honeypot/clientip.py` (multi-hop semantics,
malformed-header fallback, forge-resistance). Deployment-side
verification procedure: `docs/DEPLOYMENT.md` §6. *(pending: the
verified value used in production)*.

## 11. Cloud deployment

Render web service, blueprint via `render.yaml`; build
`pip install -r requirements.txt`; start command runs Gunicorn bound to
Render's `$PORT`; health check `/health`. Storage options and migration
guidance in `docs/DEPLOYMENT.md`. *(pending: actual service URL,
database choice, deploy date, restart journal)*.

## 12. Observation methodology

96-hour window (start/end recorded in UTC), pre-observation gates
(tests pass, `/health` verified, persistence verified, IP handling
verified), daily health/dashboard checks, event log for restarts and
downtime, no artificial traffic, end-of-window export + reproducible
analysis. Full plan: `docs/OBSERVATION_PLAN.md`.

## 13. Results

> Everything in this section **must** come from
> `reports/summary.json` and the exported CSVs of the real
> observation. Until then: not available.

| Metric | Value |
|---|---|
| Observation window (UTC start–end) | *pending* |
| Deployment uptime / downtime record | *pending* |
| Total recorded requests (non-synthetic) | *pending* |
| Non-synthetic discovery-related requests | *pending* |
| Unique source IPs | *pending* |
| Top requested routes | *pending* |
| Method distribution | *pending* |
| Status distribution | *pending* |
| Top user agents | *pending* |
| Classification distribution | *pending* |
| Repeated-probing sources (≥3 login probes) | *pending* |
| Aggregate T1046 candidates (≥3 categories) | *pending* |
| Country distribution | *pending / not available if enrichment disabled* |
| Figures | see `reports/figures/` |
| Summary tables | see `reports/tables/` |

## 14. Threat analysis

*(pending — discuss real observations only: which behaviours were
observed, in what proportions, and what they do/don't indicate. Distinguish
clearly between "observed facts" and "inferred classifications". No
actor attribution.)*

## 15. MITRE ATT&CK mapping

Rules and pre-registered mappings: `docs/MITRE_MAPPING.md`
(T1083, T1046 aggregate, T1110 / T1110.001, narrow T1082). For the final
report: list the mappings that actually fired on observed data, with
their per-technique totals from `reports/summary.json`, each with
evidence, confidence, alternatives, limitations — and nothing that no
observed request supports. Names verified on attack.mitre.org *(pending
— verification date to be recorded; site unreachable at build time)*.

## 16. Limitations

- One host, one provider, one 96-hour sample: no representativeness
  claims.
- Scanners can lie (User-Agent, XFF, path noise); telemetry records
  provider-observed facts only.
- Free-plan sleep/restarts may fragment the exposure window; recorded
  honestly in the event log.
- Classification threshold (≥3 repeated probes) is a defensible
  convention, not a universal truth.
- The honeypot observes only what reaches it; absence of probes on a
  route doesn't mean "nobody scans it".
- Countries unavailable unless a documented GeoIP provider is enabled
  and licensed.

## 17. Conclusion

*(pending — write after results exist.)*

## 18. References

- MITRE ATT&CK Enterprise techniques: T1083, T1046, T1110 (+ .001),
  T1082 — https://attack.mitre.org/techniques/<id>/
  *(verify each before submission; see docs/MITRE_MAPPING.md header)*
- Werkzeug ProxyFix documentation —
  https://werkzeug.palletsprojects.com/en/stable/middleware/proxy_fix/
- Gunicorn documentation — https://docs.gunicorn.org/
- Flask documentation — https://flask.palletsprojects.com/
- Render documentation — https://render.com/docs
- GeoLite2 / MaxMind licensing — https://www.maxmind.com/

## 19. Appendices and evidence

- A. Project tree: `evidence/` per `docs/EVIDENCE_COLLECTION.md`
- B. Test run outputs (67 passing)
- C. Deployment screenshots (build, live URL, logs)
- D. Observation log (`docs/OBSERVATION_PLAN.md` §C)
- E. Analysis outputs (`reports/tables/`, `reports/figures/`,
  `reports/summary.json`)
- F. Code excerpts: client-ip resolver, classification rules, MITRE
  mapping module
