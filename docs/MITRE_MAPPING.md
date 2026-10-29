# MITRE ATT&CK Mapping — Rules, Evidence, and Limitations

> **Verification status:** the identifiers below were written from the
> published ATT&CK Enterprise matrix (as most recently confirmed by the
> author at implementation time, October 2026). The `attack.mitre.org`
> website could not be reached from this offline development machine
> during the final build, so **before submitting the report, open each
> reference link below and confirm the technique name/description**. This
> checklist item also appears in `docs/EVIDENCE_COLLECTION.md`. The
> application code stores only IDs and names, so a renaming would not
> break the data.

---

## 1. How mapping works

Mapping happens in `honeypot/mitre.py` and is **rule-based and
evidence-driven**. It is *never* automatic per-request labelling: a rule
fires only when a specific observed classification exists, and every
mapping records evidence, rationale, confidence, alternatives, and
limitations alongside it. Four things are deliberately prevented:

1. A single request is never claimed to prove a scanning campaign or a
   compromise.
2. No source is labelled a "botnet", threat actor, or organisation based
   on IP address alone.
3. An HTTP request alone never proves a technique *succeeded* — only
   that behaviour *consistent with* a technique was observed.
4. The aggregate rule (T1046) requires breadth evidence (≥ 3 distinct
   route categories from one source) and is evaluated only per-IP across
   the whole observation window, never per-request.

## 2. Mappings implemented

### T1083 — File and Directory Discovery
- **Trigger classification(s):** Configuration file probing
  (`/.env`, `/config.php`, …), Repository metadata probing
  (`/.git/config`), Backup and database file discovery
  (`/backup.zip`, `/database.sql`, …).
- **Confidence:** moderate.
- **Rationale:** requests for hidden configuration, repository metadata,
  or backup files are consistent with an adversary enumerating
  well-known file locations to find credentials or sensitive data.
- **Alternative explanations:** automated vulnerability scanners probe
  these paths routinely; the source may be a scanning tool rather than a
  targeted actor.
- **Limitations:** the honeypot controls these endpoints — no file was
  ever returned, so no real discovery succeeded.
- **Reference:** https://attack.mitre.org/techniques/T1083/

### T1110 — Brute Force
- **Trigger:** Login endpoint probing (single events) and CMS endpoint
  discovery; *Repeated authentication probing* without credential-like
  fields.
- **Confidence:** low.
- **Rationale:** requests to login endpoints are consistent with
  credential checking against the (decoy) authentication surface.
- **Alternatives:** a single login request may be a link preview, a
  mistyped URL, or routine scanner coverage.
- **Limitations:** the decoy has no real authentication — no credentials
  existed to guess. Field values are never stored.
- **Reference:** https://attack.mitre.org/techniques/T1110/

### T1110.001 — Brute Force: Password Guessing
- **Trigger:** *Repeated authentication probing* (≥ 3 login-endpoint
  requests from the same source inside the recent window) **and**
  credential-like fields present in the last request.
- **Confidence:** moderate.
- **Rationale:** repeated login attempts with credential-like fields
  from the same source are consistent with repeated password guessing
  attempts.
- **Alternatives:** automated tooling re-checking endpoints (uptime
  monitors, misconfigured clients) also repeats login requests.
- **Limitations:** frequency evidence demonstrates repetition, not a
  successful authentication or a human adversary.
- **Reference:** https://attack.mitre.org/techniques/T1110/001/

### T1082 — System Information Discovery *(extension beyond the required candidates, applied narrowly)*
- **Trigger:** Server information discovery (`/server-status`,
  `/server-info`, `/phpinfo.php`) and Service console discovery
  (`/console`, `/debug`, `/actuator*`).
- **Confidence:** low.
- **Rationale:** probing such pages may indicate interest in system
  information, since serving them would reveal system configuration.
- **Alternatives:** monitoring tools request phpinfo as a health probe;
  benign administrators trigger these pages too.
- **Limitations:** the honeypot returns controlled, non-revealing
  responses, so no actual system information was ever disclosed.
- **Reference:** https://attack.mitre.org/techniques/T1082/

### T1046 — Network Service Discovery *(aggregate-only)*
- **Trigger:** the *analysis stage* rule: one source IP probed ≥ 3
  **distinct route categories** during the observation period
  (`analyze.py` computes this; the dashboard never applies it).
- **Confidence:** low.
- **Rationale:** broad HTTP probing across many unrelated route
  categories is consistent with service/endpoint scanning.
- **Alternatives:** internet-wide scanners and search crawlers sweep
  millions of addresses daily; breadth alone is not targeting.
- **Limitations:** candidate only — reported as `mitre_aggregate` in
  `reports/summary.json` with a note that it does not prove intent.
- **Reference:** https://attack.mitre.org/techniques/T1046/

## 3._NOT_ mapped (deliberate)

| Classification | Why no mapping |
|---|---|
| Normal application request | benign behaviour; no technique applies |
| API discovery | generic enumeration without file/credential focus |
| Administrative interface discovery | too ambiguous on its own (could be curious human, health probe, scanner); mapping it would over-claim |
| Unclassified suspicious request | unknown purpose by definition — mapping would be pure speculation |

If a course rubric requires `/admin` to map to something, prefer
describing it in prose as "behaviour consistent with management-interface
enumeration" rather than assigning a technique — that keeps the claim
within what the evidence supports.

## 4. Confidence vocabulary

| Term | Meaning in this project |
|---|---|
| `high` | the behaviour is directly and unambiguously observable (route-category facts) |
| `medium` | behaviour consistent with the technique, with plausible benign alternatives noted |
| `low` | weak consistency; requires aggregate evidence; candidate only |

## 5. Reproducibility

- Classification + mapping are pure functions with `lru_cache`; the same
  inputs always yield the same outputs (`tests/test_classify_ip_mitre.py`).
- Mappings are stored per event (`mitre_technique`,
  `mitre_rationale`, `mitre_confidence` columns) so the exported dataset
  can be re-analysed independently of the running service.
- The aggregate rule is deterministic given the exported dataset.
