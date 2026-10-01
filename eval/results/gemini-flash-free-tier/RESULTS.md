# Evaluation results — `gemini-3.5-flash-lite`, `gemini-3.6-flash`, `gemini-3.7-flash`, `gemini-3.8-flash`

Generated 2026-09-30 21:42 over 18 test manifests.

| Metric | Result |
|---|---|
| Recall vs. OSV ground truth | **100.0%** (171/171) |
| Recall on hand-labelled must-find CVEs | **100.0%** (45/45) |
| False alarms (vulns not affecting that version) | **0** |
| Unsupported claims submitted by the model | **1** of 1026 (0.1%) |
| Unsupported claims in the final report | **0** (removed by the checker) |
| Claims honestly marked unknown | 46 (of which evidence existed: 2) |
| Actively exploited (KEV) items ranked P1 | 7/7 |
| Priority agreement with rubric | 87.5% |
| Upgrade recommendations confirmed by OSV | 28/30 |
| Runs that errored | 0 |
| Total cost / avg time per manifest | $0.00 / 74.0s |

## Per case

| Case | Model | Deps | Truth | Found | Must-find | False alarms | Claims | Unsupported | Unknown | KEV→P1 | Rubric agree | Fixes OK | Time | Error |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| npm01_lodash | gemini-3.6-flash | 1 | 8 | 8 | 4/4 | 0 | 48 | 0 | 0 | 0/0 | 8/8 | 1/1 | 46s |  |
| npm02_jquery_kev | gemini-3.6-flash | 2 | 4 | 4 | 4/4 | 0 | 24 | 0 | 0 | 1/1 | 4/4 | 2/2 | 172s |  |
| npm03_express | gemini-3.6-flash | 3 | 5 | 5 | 3/3 | 0 | 30 | 0 | 0 | 0/0 | 5/5 | 3/3 | 27s |  |
| npm04_utils | gemini-3.6-flash | 4 | 8 | 8 | 5/5 | 0 | 48 | 0 | 0 | 0/0 | 8/8 | 4/4 | 61s |  |
| npm05_sysinfo_kev | gemini-3.6-flash | 2 | 12 | 12 | 2/2 | 0 | 72 | 0 | 0 | 1/1 | 12/12 | 2/2 | 45s |  |
| npm06_mongo_express_kev | gemini-3.8-flash | 2 | 21 | 21 | 2/2 | 0 | 126 | 0 | 24 | 1/1 | 4/15 | 1/2 | 422s |  |
| npm07_ranges | gemini-3.7-flash | 4 | 4 | 4 | 2/2 | 0 | 24 | 0 | 0 | 0/0 | 4/4 | 1/1 | 271s |  |
| npm08_clean | gemini-3.7-flash | 3 | 0 | 0 | 0/0 | 0 | 0 | 0 | 0 | 0/0 | 0/0 | 0/0 | 127s |  |
| py01_web_basics | gemini-3.5-flash-lite | 2 | 11 | 11 | 4/4 | 0 | 66 | 0 | 0 | 0/0 | 11/11 | 2/2 | 23s |  |
| py02_urllib3 | gemini-3.5-flash-lite | 1 | 13 | 13 | 4/4 | 0 | 78 | 0 | 1 | 0/0 | 8/13 | 1/1 | 16s |  |
| py03_flask_app | gemini-3.5-flash-lite | 3 | 9 | 9 | 4/4 | 0 | 54 | 0 | 0 | 0/0 | 9/9 | 3/3 | 11s |  |
| py04_ray_kev | gemini-3.5-flash-lite | 2 | 7 | 7 | 1/1 | 0 | 42 | 0 | 5 | 1/1 | 6/6 | 1/1 | 9s |  |
| py05_ssh_crypto | gemini-3.5-flash-lite | 2 | 17 | 17 | 2/2 | 0 | 102 | 0 | 16 | 0/0 | 11/13 | 1/2 | 19s |  |
| py06_werkzeug_setuptools | gemini-3.5-flash-lite | 2 | 13 | 13 | 4/4 | 0 | 78 | 1 | 0 | 0/0 | 12/13 | 2/2 | 15s |  |
| py07_clean | gemini-3.5-flash-lite | 4 | 0 | 0 | 0/0 | 0 | 0 | 0 | 0 | 0/0 | 0/0 | 0/0 | 2s |  |
| py08_unpinned_mix | gemini-3.5-flash-lite | 4 | 4 | 4 | 1/1 | 0 | 24 | 0 | 0 | 0/0 | 4/4 | 2/2 | 6s |  |
| py09_fake_package | gemini-3.5-flash-lite | 2 | 4 | 4 | 1/1 | 0 | 24 | 0 | 0 | 0/0 | 3/4 | 1/1 | 6s |  |
| py10_salt_stress | gemini-3.5-flash-lite | 1 | 31 | 31 | 2/2 | 0 | 186 | 0 | 0 | 3/3 | 31/31 | 1/1 | 55s |  |
