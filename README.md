# Grounded Vulnerability Triage Agent

Give it a `requirements.txt` or `package.json`. An LLM agent finds the known vulnerabilities in your dependencies, judges how urgent each one is, and writes a prioritized fix report.

**No source, no value.** Every claim in the report must cite the record it came from, and an automated checker verifies each claim against what the tools actually returned. A claim with no source, a source that was never fetched, or a value that doesn't match its source is removed, and the item goes to human review instead of being guessed at.

![demo](docs/demo.gif)

## Why this exists

LLMs are good at the judgment part of vulnerability triage, like "this is actively exploited, fix it first". But they also confidently invent CVE numbers, CVSS scores and fixed versions. In security, a made-up "fixed in 2.4.1" is worse than no answer. This project keeps the model's judgment and checks every fact it states.

## How it works

```
manifest ──► parser ──► agent (LLM + tools) ──► submit_report ──► grounding checker ──► report
                         │                                            ▲
                         ▼                                            │
              OSV · NVD · CISA KEV · EPSS ──► evidence ledger ────────┘
```

| Source | Used for | Key |
|---|---|---|
| [OSV.dev](https://osv.dev) | Which vulnerabilities affect `package@version`, fixed versions | none |
| [NVD](https://nvd.nist.gov) | CVSS base score and severity | optional (raises the rate limit) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Is it being exploited in the wild? | none |
| [FIRST EPSS](https://www.first.org/epss/) | Probability of exploitation in the next 30 days | none |

1. **Parser** (`triage/parsers.py`) turns the manifest into `(ecosystem, name, version)`. Unpinned or range specs (`flask>=2.0`, `"express": "*"`) aren't guessed. They go straight to the review list.
2. **Agent** (`triage/agent.py`, `triage/gemini_agent.py`) gets six tools: `osv_lookup`, `nvd_lookup`, `kev_lookup`, `epss_lookup`, `check_upgrade`, `submit_report`. The model decides what to call. Every result includes the URL it came from. The report is a strict JSON schema (Pydantic), and malformed reports go back to the model as tool errors.
3. **Evidence ledger** (`triage/evidence.py`) records every fact any tool returned during the scan, keyed by source URL and subject.
4. **Grounding checker** (`triage/checker.py`), the core of the project, assigns each claim one of these statuses:
   - `verified`: the cited URL was fetched in this scan, it's about *this* vulnerability, and the value matches
   - `unknown`: the model said it couldn't find the value (allowed; goes to review)
   - `unsourced` / `ungrounded` / `mismatch`: **removed** from the report

   It also **rejects findings** for vulnerabilities OSV never returned for that version (hallucinated or wrong-version CVEs). It **re-adds anything OSV returned that the agent skipped**, and **re-queries OSV** to confirm each recommended upgrade really clears the issues.
5. **Baseline** (`triage/baseline.py`) is the same pipeline with no AI. It's the ground truth for the eval and a fallback mode in the UI.

Priority uses a published rubric (`triage/rubric.py`). The agent may deviate with a written reason, and the eval measures how often it agrees:

| | Rule |
|---|---|
| **P1** fix now | in CISA KEV, or EPSS ≥ 0.50, or CVSS ≥ 9.0 and EPSS ≥ 0.10 |
| **P2** this sprint | CVSS ≥ 7.0, or EPSS ≥ 0.10 |
| **P3** plan a fix | CVSS ≥ 4.0 |
| **P4** low | CVSS < 4.0 |

## Results

Evaluated on 18 dependency files in [`eval/cases`](eval/cases) (10 PyPI, 8 npm). They include old versions with known CVEs, 4 files with actively exploited (KEV) vulnerabilities, 2 fully up-to-date files where any finding is a false alarm, a made-up package name, files with unpinned versions, and a 31-vulnerability stress test. Ground truth comes from the no-AI baseline, plus a hand-labeled list of well-known CVEs each file must surface ([`eval/labels.json`](eval/labels.json)).

<!-- RESULTS:START -->
Models: `gemini-3.5-flash-lite`, `gemini-3.6-flash`, `gemini-3.7-flash`, `gemini-3.8-flash` (Google Gemini free tier, $0 total).

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

Per-case breakdown: [`eval/results/gemini-flash-free-tier/RESULTS.md`](eval/results/gemini-flash-free-tier/RESULTS.md). Full agent traces and checked reports: [`eval/results/gemini-flash-free-tier/runs/`](eval/results/gemini-flash-free-tier/runs/).
<!-- RESULTS:END -->

### What the results show

- **Finding vulnerabilities is the easy part.** 171/171 vulnerabilities and 45/45 hand-labeled CVEs were found, with zero false alarms. That includes the made-up package and the two fully up-to-date files.
- **The model still makes things up, and the checker catches it.** In `py06`, the model said a setuptools vulnerability (CVE-2026-59890) was fixed in **3.1.5**, apparently borrowing a Werkzeug version number. The OSV record it cited says **83.0.0**. The checker removed the value and sent the finding to review. That's 1 unsupported claim in 1,026 submitted, and **0 reached the final report**.
- **"Unknown" is an honest answer, not a failure.** 46 claims were marked unknown, mostly GHSA-only advisories with no CVE id, which NVD, KEV, and EPSS can't look up. Only 2 of those had evidence the model could have found.
- **Every actively exploited (KEV) vulnerability was ranked P1** (7/7).
- **Judgment is where models differ.** Rubric agreement was 87.5%, and the disagreements fall into two groups. In `npm06`, the model deliberately downgraded `handlebars` because it's a devDependency that doesn't ship to production, a reasonable call that it explained in each rationale. In `py02`, the smaller `flash-lite` model mislabeled CVSS 6.1–6.5 items as P2 instead of P3. The checker now sends **every** departure from the rubric to human review, with the rubric's answer next to the model's.
- **Upgrade advice is verified, not trusted.** In 2 of 30 recommendations, OSV showed the suggested version still had a known issue. Those were marked "partial" instead of "fixed".

The model doesn't have to be perfect, because nothing unchecked reaches the reader.

_Note on models: Gemini's free tier allows ~20 requests per model per day, so the 18 cases were spread across four Gemini Flash models (shown per case in the breakdown). `eval/run_eval.py --models a b c` falls back to the next model when one's daily quota runs out, and `--resume` skips finished cases._

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env        # add GEMINI_API_KEY (free tier) or ANTHROPIC_API_KEY

# no AI, no key needed
python -m triage.cli baseline examples/requirements.txt

# the agent
python -m triage.cli scan examples/package.json --out report.md

# web UI + API on http://localhost:8000
(cd web && npm install && npm run build)
uvicorn triage.server:app

# tests (offline, no API calls) and the eval
pytest
python -m eval.run_eval --resume
```

Or with Docker:

```bash
docker compose up --build    # http://localhost:8000
```

### Models

The agent runs on **Claude** (`ANTHROPIC_API_KEY`, default `claude-opus-5-5`, with adaptive thinking, strict tool schemas, prompt caching, and server-side refusal fallback) or **Google Gemini** (`GEMINI_API_KEY`, default `gemini-3.5-flash`, which works on the free tier). Both share the same tools, prompt, ledger, and checker. Set `TRIAGE_PROVIDER` to choose when both keys are present.

Gemini's free tier allows about 20 requests per model per day, and one file takes about 3. `eval/run_eval.py --resume` saves each finished case, and `--models` falls back across models, so a full run costs nothing.

## Tests

`pytest` runs 26 offline tests, no network or API calls. They include adversarial checker tests that submit fabricated reports (wrong CVSS, URLs never fetched, a real URL about a *different* CVE, invented CVE ids, wrong installed version, fake fixed versions, unfixable upgrade recommendations, priorities that ignore the rubric) and confirm that each is caught. The agent loop is tested with a scripted fake model client.

## Project layout

```
triage/        parsers, data sources, evidence ledger, checker, agents, API server
eval/          18 test manifests, hand labels, eval runner, results
tests/         offline unit tests
web/           React (Vite) front end
```

## Limitations

- npm range specs (`^4.17.1`) are checked at the lowest allowed version. A lock file would give the exact installed version.
- Vulnerabilities without a CVE id (some GHSA-only advisories) can't be looked up in NVD/KEV/EPSS, so they're always flagged for review.
- The checker verifies facts, not judgment: a priority can be well sourced and still debatable. That's why rubric agreement is reported separately.
