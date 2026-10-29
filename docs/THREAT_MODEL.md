# Threat Model

This document defines what the system protects, what it tolerates, and
the boundaries of any claims made about observed behaviour.

## 1. Assets

| Asset | Sensitivity | Protection |
|---|---|---|
| Telemetry database | personal data (IP addresses, ~metadata) | DB credentials via env only; exports treated as sensitive; no secrets column exists |
| Honeypot host | the platform being defended | decoys only; no real service logic runs |
| Credential values (if submitted by a scanner) | third-party secrets | **never stored or logged**; only field-name presence flags |
| Research integrity | the assignment itself | figures derive only from stored data; synthetic traffic separable |

## 2. Attack surfaces the honeypot exposes deliberately

- Static decoy login pages (`/admin`, `/wp-login.php`, …) that never
  authenticate anything. POSTs get `403 Authentication is disabled`.
- 404-style endings for configuration/backup probes; no files served.
- Static fake XML-RPC fault, phpinfo, actuator, server-status pages.
- Nothing executes, uploads, downloads, or writes from request input.
  Templates autoescape untrusted values; the database layer uses
  parameterised statements only.

## 3. Explicit non-goals

- Wasting attackers' time at scale (no slowloris traps, no SSH shell
  emulation) — this is a *low-interaction* HTTP honeypot for research.
- Attribution of any request to a person or organisation. IP addresses
  identify *network endpoints*, not people; no claims beyond that.
- Passing off scanner traffic as "attacks against us". Every
  classification is an inference with evidence and confidence.

## 4. Trust assumptions and boundaries

| Assumption | Boundary |
|---|---|
| The platform (Render) proxy is trusted for hop-level IP resolution | Only after the hop count is verified (docs/DEPLOYMENT.md §6); unverified ⇒ headers not trusted |
| The telemetry DB is trusted | access restricted to this service; no query endpoints on the public app except paginated dashboard/exports |
| JSONL imports | read-only against the source file; malformed lines skipped |
| Config derived from env vars | invalid values fail startup with a clear message rather than defaulting silently |

## 5. Failure modes and their handling

- Telemetry insert fails → HTTP response unaffected; failure recorded to
  stderr; tests cover failure both ways.
- Dashboard query errors → Flask's global 500 handler returns a generic
  JSON error without a traceback; the Render log carries details.
- Client caches a broken export → exports are generated fresh per
  request; no cache headers are set on dynamic pages.

## 6. What this research *can and cannot* claim

Can claim (when evidence exists): which routes were probed, by which
source IPs, at what times, in what frequencies, and that these
behaviours are **consistent with** specific MITRE ATT&CK techniques.

Cannot claim: that any source is malicious, is part of a botnet, or is
an adversary; that any technique succeeded; that traffic attributes
(User-Agent, IP) are truthful; that the absence of a route in the data
means "nobody probes it" (our sample is one endpoint, one platform).
