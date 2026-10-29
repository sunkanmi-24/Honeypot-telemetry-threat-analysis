# Coding Agent Instructions

You are helping finish an existing defensive, low-interaction HTTP honeypot for an academic telemetry and threat-analysis assignment.

## Start by preserving the existing project
- Inspect `app.py`, `analyze.py`, `requirement.txt`/`requirements.txt`, and the current static CSS before editing.
- Do not rewrite the entire app without explaining why.
- Work one phase at a time and run tests after each change.
- Give beginner-friendly Windows CMD instructions.
- Prefer complete replacement files when code changes are needed.

## First task
1. Check the existing code and confirm it runs.
2. Fix the dependency filename by using `requirements.txt` for deployment (keep dependencies minimal).
3. Add a small pytest suite for `/health` and existing routes.
4. Add safe deceptive routes with fake responses only.
5. Do not implement deployment until local behavior and tests are stable.
6. Stop and report the files changed, commands run, test results, and next step.

## Security and evidence rules
- Never scan or exploit third-party systems.
- Never expose real credentials or configuration.
- Never store plaintext passwords.
- Never trust arbitrary forwarded IP headers; trust only configured platform proxies.
- Do not fabricate telemetry, IPs, countries, timestamps, or report findings.
- Clearly label synthetic/local test traffic and exclude it from real Internet observation statistics.
- Do not call an IP a botnet merely because its requests look suspicious.
