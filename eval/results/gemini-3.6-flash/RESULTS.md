# Evaluation results — `gemini-3.6-flash` (effort: medium)

Generated 2026-09-30 21:16 over 5 test manifests.

| Metric | Result |
|---|---|
| Recall vs. OSV ground truth | **100.0%** (37/37) |
| Recall on hand-labelled must-find CVEs | **100.0%** (18/18) |
| False alarms (vulns not affecting that version) | **0** |
| Unsupported claims submitted by the model | **0** of 222 (0.0%) |
| Unsupported claims in the final report | **0** (removed by the checker) |
| Claims honestly marked unknown | 0 (of which evidence existed: 0) |
| Actively exploited (KEV) items ranked P1 | 2/2 |
| Priority agreement with rubric | 100.0% |
| Upgrade recommendations confirmed by OSV | 12/12 |
| Runs that errored | 0 |
| Total cost / avg time per manifest | $0.00 / 70.1s |

## Per case

| Case | Deps | Truth | Found | Must-find | False alarms | Claims | Unsupported | Unknown | KEV→P1 | Rubric agree | Fixes OK | Cost | Error |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| npm01_lodash | 1 | 8 | 8 | 4/4 | 0 | 48 | 0 | 0 | 0/0 | 8/8 | 1/1 | $0.000 |  |
| npm02_jquery_kev | 2 | 4 | 4 | 4/4 | 0 | 24 | 0 | 0 | 1/1 | 4/4 | 2/2 | $0.000 |  |
| npm03_express | 3 | 5 | 5 | 3/3 | 0 | 30 | 0 | 0 | 0/0 | 5/5 | 3/3 | $0.000 |  |
| npm04_utils | 4 | 8 | 8 | 5/5 | 0 | 48 | 0 | 0 | 0/0 | 8/8 | 4/4 | $0.000 |  |
| npm05_sysinfo_kev | 2 | 12 | 12 | 2/2 | 0 | 72 | 0 | 0 | 1/1 | 12/12 | 2/2 | $0.000 |  |
