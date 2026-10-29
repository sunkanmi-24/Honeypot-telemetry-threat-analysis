# reports/

This folder contains generated analysis outputs and the final report.

| Path | What it is | Generates when |
|---|---|---|
| `final-report.md` | the assignment report (results currently **pending** until real observation data exists) | maintained by you |
| `tables/*.csv` | summary tables | `python analyze.py --input exports\…` |
| `figures/*.png` | charts | `python analyze.py --input exports\…` |
| `summary.json` | machine-readable summary consumed by the report's results section | `python analyze.py …` |

Notes:

- Currently empty by design: **no observation has run yet**, and no
  sample/demo outputs are kept here so nothing can be mistaken for real
  results (see `docs/ETHICS_AND_SCOPE.md` §4).
- Outputs are derived only from the dataset you pass with `--input`
  (or the local development database). Synthetic (local/test) traffic
  is excluded unless you explicitly pass `--include-synthetic`.
- Safe to regenerate at any time; the raw telemetry is never modified
  by the analysis.
