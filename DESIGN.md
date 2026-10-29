# DESIGN.md — decisions and why

This records the important engineering decisions so they can be
defended (or contested) in the report. Originals are preserved in
`backup/original/`.

## 1. Framework and server

**Flask + Gunicorn.** Flask was already the prototype's framework and
fits the scope: routing, templating, and testability in one small
package. Gunicorn is production standard WSGI for Render; binds
`0.0.0.0:$PORT`. Flask's dev server stays for local Windows use only,
with `debug` opt-in via `python app.py --debug`.

## 2. Storage: SQLite → PostgreSQL behind one store class

JSONL (the prototype's storage) is fragile for concurrent writers and
has no indexes. But a managed database was not yet configured, so
`TelemetryStore` uses **SQLite on local disk by default** and switches
to **PostgreSQL when `DATABASE_URL` is set**. Same schema, same API —
the difference is isolated to placeholder style and two date
functions. JSONL remains an *export/import* format: the prototype's
`telemetry.jsonl` can be migrated with `import_jsonl()` without
modifying the source file (documented in docs/TROUBLESHOOTING.md).

Indexes exist on the filter/sort columns used by the dashboard
(timestamp, source IP, path, classification, synthetic).

## 3. Telemetry capture in `after_request`

Capturing *after* the response exists lets us record the actual status
code and response size, and lets failures in telemetry never affect the
served response. Observer-owned paths (`/health`, `/dashboard*`,
`/export*`, `/static/*`, favicon) are excluded so the researcher's own
dashboard checks don't pollute the data.

## 4. Client IP: sockets first, verified proxies second

`PROXY_TRUSTED_HOPS` (default **0**) gates whether forwarded headers
are consulted at all. Werkzeug `ProxyFix` performs the adjustment when
configured, and `honeypot/clientip.py` documents/tests the same
semantics purely. Malformed headers fall back to the socket peer. The
Render hop count is documented as "verify, then set" — never guessed.

## 5. Classification: facts vs inference, by design

`route_category()` is a *fact* (which route was hit).
`classify()` is an *inference* with a confidence level. The two are
recorded in separate columns deliberately, so analysis can always
return to the observed facts. The "repeated authentication probing"
upgrade requires frequency evidence (≥ 3 recent login probes from the
source) — a single request cannot earn it.

## 6. MITRE mapping: qualified, per-mapping metadata

Each mapping carries evidence, rationale, confidence, alternatives,
limitations — stored per event (`mitre_*` columns) so the exported
dataset is self-describing. The aggregate T1046 rule lives in the
analysis stage only (`analyze.py`), with an explicit "candidate only"
note.

## 7. Dashboard honesty

Every number is a live database query in the request; there is no
hardcoded statistic anywhere. The default view is *observed only*
(non-synthetic), so local/testing routes never inflate public numbers.
Empty states are explicit. Jinja2 autoescaping protects all untrusted
values; there is no `|safe` usage anywhere.

## 8. Synthetic data separation

`MARK_LOCAL_SYNTHETIC=1` (default) flags loopback/private sources as
`synthetic = 1` at insert time — local developer traffic and functional
tests can never blend into observed Internet statistics. Exports and
the analysis default to excluding them; `--include-synthetic` exists
for transparency, not for results.

## 9. Analysis pipeline reproducibility

`analyze.py` writes everything a report needs from one command against
one input file: CSV tables, PNG charts, a JSON summary, including data
quality accounting (malformed lines, duplicates, missing fields,
synthetic count). Charts skip rather than invent when a dimension has
no data. `matplotlib` uses the `Agg` backend (no GUI).

## 10. GeoIP optional

No key, no baked-in provider. If `GEOIP_DB_PATH` + `geoip2` exist,
countries come from a licensed MMDB; otherwise dashboard says
enrichment is disabled and every country stays "unknown" — and the
code never guesses.

## 11. Security defaults

- Debug off unless explicitly requested; tracebacks never reach HTTP.
- Security headers on every response.
- No credential values, cookies, tokens, or authorization data stored
  (tests assert this).
- Import/exports use parameterised queries only.
- `.gitignore` keeps `.env`, DBs, exports, backups, venvs out of git.
