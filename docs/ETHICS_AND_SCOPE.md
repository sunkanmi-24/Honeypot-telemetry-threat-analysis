# Ethics and Scope

## 1. Scope of collection

Telemetry is collected **only** on infrastructure the researcher
controls and deploys for this assignment. Nothing is collected from
networks, devices, hosts, or services that belong to anyone else. No
active probing, scanning, exploitation, or "recon against" any
third-party system is performed by this project, ever.

## 2. What visitors know

The public landing page (`/`) describes the service as a defensive
research honeypot. No hidden visitors tracking; request-scoped data is
metadata-only and is retained only for the duration of the academic
study.

## 3. Data minimisation (privacy-by-construction)

- Only standard HTTP headers/routes/response sizes needed for analysis
  are stored. **Field values of any credential-like input are never
  stored** — only the boolean flag that such a field was present.
- No cookies, tokens, authorization headers, or JSON bodies are stored.
- Field lengths are truncated (path/query/UA/referrer ≤ 512; host
  ≤ 255).
- Source IPs are the least-complete reasonable identifier: derived as
  documented (docs/DEPLOYMENT.md) and never enriched beyond optional
  country data when a documented provider is enabled.

## 4. No fabrication, ever

- No synthetic telemetry is presented as observed traffic. Synthetic and
  local test events carry `synthetic = 1` in the database and exports
  default to excluding them.
- No fictional numbers, countries, or attack narratives appear in the
  dashboard, exports, reports, or charts. Empty/missing data is
  explicitly labelled "unknown"/"pending".
- Countries are never guessed from IPs — with no provider configured,
  the field stays "unknown".

## 5. Attribution limits (in-force rule)

- An IP address identifies an endpoint at a moment, not a person or an
  organisation. No "botnet" or actor claims are made from IP data alone.
- Classification outputs are inferences with stated confidence,
  alternatives, and limitations; they are never presented as facts or
  proof of compromise.

## 6. Legal context

- Fingerprinting or profiling individuals is out of scope; no CAPTCHA,
  no tracking cookies are set.
- Relevant considerations for the report (data protection coursework):
  describe retention (the observation window plus until submission),
  access (single researcher account, private repository, no public
  telemetry), and deletion (exports deleted after marking).
- A `robots.txt` disallowing `/admin/` is served; the honeypot does not
  deceive third parties into unintended actions (no `Referer`-based
  games, no drive-by exploitation).

## 7. Prohibited uses of this project

- Deploying decoys against systems you do not own.
- Modifying the honeypot to actually collect passwords, run commands,
  upload payloads, or serve exploit content.
- Fabricating telemetry to inflate results.
