"""Step 3: measure the agent.

For each test manifest in eval/cases:
  1. run the deterministic baseline (no AI) -> ground truth set of vulnerabilities
  2. run the Claude agent -> grounding-checked report
  3. compare

Metrics
  recall            share of ground-truth vulnerabilities the agent triaged
  curated recall    share of hand-labelled must-find CVEs (eval/labels.json) it triaged
  false alarms      findings for vulnerabilities OSV did not return for that package@version
  unsupported rate  claims with no source, a source never retrieved, or a wrong value,
                    as submitted by the model (before the checker removes them)
  missed evidence   claims left "unknown" although a source did have the value
  KEV -> P1         actively exploited items the agent ranked P1
  rubric agreement  agent priority == rubric priority on the same evidence

Usage:
    python -m eval.run_eval                     # all cases
    python -m eval.run_eval --only py01 npm02   # a subset
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.agent import DEFAULT_EFFORT  # noqa: E402
from triage.gemini_agent import make_agent  # noqa: E402
from triage.baseline import build_baseline_report  # noqa: E402
from triage.checker import check_report  # noqa: E402
from triage.evidence import Ledger  # noqa: E402
from triage.parsers import parse_manifest  # noqa: E402

CASES = ROOT / "eval" / "cases"
LABELS = json.loads((ROOT / "eval" / "labels.json").read_text())


def _key(f):
    return (f["package"], f["vuln_id"])


def evaluate_case(path: Path, provider: str | None, model: str | None, effort: str) -> dict:
    deps = parse_manifest(path.name, path.read_text())

    b_ledger = Ledger(deps.ecosystem)
    truth = check_report(build_baseline_report(deps, b_ledger), b_ledger, deps)
    gt = {_key(f): f for f in truth["findings"]}

    run = make_agent(provider, model, effort=effort).run(deps)
    got = run.checked
    found = {_key(f): f for f in got["findings"]}

    hit = [k for k in found if k in gt]
    false_alarms = [r for r in got["rejected_findings"] if "duplicate" not in r["reason"]]

    all_ids = {i for k in hit for i in [found[k]["vuln_id"], *found[k]["aliases"]]}
    must = LABELS.get(path.stem, {}).get("must_find", [])
    curated_hit = [c for c in must if c in all_ids]

    missed_evidence = 0
    for k in hit:
        for fld, c in found[k]["claims"].items():
            if c["status"] == "unknown" and gt[k]["claims"][fld]["status"] == "verified" \
                    and gt[k]["claims"][fld]["value"] is not None:
                missed_evidence += 1

    kev_keys = [k for k, f in gt.items() if f["claims"]["in_kev"]["value"] is True]
    kev_p1 = [k for k in kev_keys if k in found and found[k]["priority"] == "P1"]

    comparable = [k for k in hit if gt[k]["reference_priority"]]
    agree = [k for k in comparable if found[k]["priority"] == gt[k]["reference_priority"]]

    rems = got["remediations"]
    s = got["stats"]
    unsupported = s["unsourced"] + s["ungrounded"] + s["mismatch"]
    return {
        "case": path.stem,
        "model": run.model,
        "ecosystem": deps.ecosystem,
        "dependencies": len(deps.dependencies),
        "ground_truth": len(gt),
        "found": len(hit),
        "recall": round(len(hit) / len(gt), 4) if gt else 1.0,
        "curated_total": len(must),
        "curated_found": len(curated_hit),
        "false_alarms": len(false_alarms),
        "claims_total": s["claims_total"],
        "claims_verified": s["verified"],
        "claims_unknown": s["unknown"],
        "claims_unsupported": unsupported,
        "unsupported_breakdown": {k: s[k] for k in ("unsourced", "ungrounded", "mismatch")},
        "missed_evidence": missed_evidence,
        "kev_total": len(kev_keys),
        "kev_p1": len(kev_p1),
        "priority_comparable": len(comparable),
        "priority_agree": len(agree),
        "remediations": len(rems),
        "remediations_verified": sum(1 for r in rems if r["status"] == "verified"),
        "unresolved_flagged": len(got["unresolved_dependencies"]),
        "turns": run.turns,
        "seconds": round(run.seconds, 1),
        "cost_usd": run.cost_usd,
        "usage": run.usage,
        "error": run.error,
        "_run": run.to_dict(),
    }


def summarize(rows: list[dict]) -> dict:
    tot = lambda k: sum(r[k] for r in rows)  # noqa: E731
    gt, claims = tot("ground_truth"), tot("claims_total")
    return {
        "cases": len(rows),
        "errors": sum(1 for r in rows if r["error"]),
        "ground_truth": gt,
        "found": tot("found"),
        "recall": round(tot("found") / gt, 4) if gt else 1.0,
        "curated_recall": round(tot("curated_found") / tot("curated_total"), 4) if tot("curated_total") else 1.0,
        "curated": f"{tot('curated_found')}/{tot('curated_total')}",
        "false_alarms": tot("false_alarms"),
        "claims_total": claims,
        "claims_verified": tot("claims_verified"),
        "claims_unknown": tot("claims_unknown"),
        "claims_unsupported": tot("claims_unsupported"),
        "unsupported_rate": round(tot("claims_unsupported") / claims, 4) if claims else 0.0,
        "unsupported_in_final_report": 0,
        "missed_evidence": tot("missed_evidence"),
        "kev_p1": f"{tot('kev_p1')}/{tot('kev_total')}",
        "priority_agreement": round(tot("priority_agree") / tot("priority_comparable"), 4)
        if tot("priority_comparable") else None,
        "remediations_verified": f"{tot('remediations_verified')}/{tot('remediations')}",
        "total_cost_usd": round(tot("cost_usd"), 2),
        "avg_seconds": round(tot("seconds") / len(rows), 1) if rows else 0,
    }


def to_markdown(summary: dict, rows: list[dict], model: str, effort: str) -> str:
    pct = lambda x: "n/a" if x is None else f"{x * 100:.1f}%"  # noqa: E731
    out = [
        f"# Evaluation results — {', '.join(f'`{m}`' for m in sorted({r['model'] for r in rows}))}",
        "",
        f"Generated {time.strftime('%Y-%m-%d %H:%M')} over {summary['cases']} test manifests.",
        "",
        "| Metric | Result |",
        "|---|---|",
        f"| Recall vs. OSV ground truth | **{pct(summary['recall'])}** ({summary['found']}/{summary['ground_truth']}) |",
        f"| Recall on hand-labelled must-find CVEs | **{pct(summary['curated_recall'])}** ({summary['curated']}) |",
        f"| False alarms (vulns not affecting that version) | **{summary['false_alarms']}** |",
        f"| Unsupported claims submitted by the model | **{summary['claims_unsupported']}** of {summary['claims_total']} ({pct(summary['unsupported_rate'])}) |",
        f"| Unsupported claims in the final report | **{summary['unsupported_in_final_report']}** (removed by the checker) |",
        f"| Claims honestly marked unknown | {summary['claims_unknown']} (of which evidence existed: {summary['missed_evidence']}) |",
        f"| Actively exploited (KEV) items ranked P1 | {summary['kev_p1']} |",
        f"| Priority agreement with rubric | {pct(summary['priority_agreement'])} |",
        f"| Upgrade recommendations confirmed by OSV | {summary['remediations_verified']} |",
        f"| Runs that errored | {summary['errors']} |",
        f"| Total cost / avg time per manifest | ${summary['total_cost_usd']:.2f} / {summary['avg_seconds']}s |",
        "",
        "## Per case",
        "",
        "| Case | Model | Deps | Truth | Found | Must-find | False alarms | Claims | Unsupported | Unknown | KEV→P1 | Rubric agree | Fixes OK | Time | Error |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        out.append(
            f"| {r['case']} | {r['model']} | {r['dependencies']} | {r['ground_truth']} | {r['found']} | "
            f"{r['curated_found']}/{r['curated_total']} | {r['false_alarms']} | {r['claims_total']} | "
            f"{r['claims_unsupported']} | {r['claims_unknown']} | {r['kev_p1']}/{r['kev_total']} | "
            f"{r['priority_agree']}/{r['priority_comparable']} | {r['remediations_verified']}/{r['remediations']} | "
            f"{r['seconds']:.0f}s | {(r['error'] or '')[:40]} |"
        )
    return "\n".join(out) + "\n"


def main() -> int:
    load_dotenv(ROOT / ".env")
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=["anthropic", "gemini"], default=None)
    ap.add_argument("--model", default=None)
    ap.add_argument("--models", nargs="*", help="fallback list: when one model's daily quota runs out, use the next")
    ap.add_argument("--effort", default=DEFAULT_EFFORT)
    ap.add_argument("--only", nargs="*", help="case name prefixes")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--resume", action="store_true", help="skip cases that already finished without error")
    ap.add_argument("--report-only", action="store_true", help="summarize saved results without running anything")
    ap.add_argument("--out", type=Path, default=ROOT / "eval" / "results")
    args = ap.parse_args()

    cases = sorted(p for p in CASES.iterdir() if p.suffix in (".txt", ".json"))
    if args.only:
        cases = [c for c in cases if any(c.stem.startswith(o) for o in args.only)]

    models = args.models or [make_agent(args.provider, args.model).model]
    rows_root = args.out / "_rows"
    done: dict[str, dict] = {}
    if args.resume or args.report_only:
        for f in sorted(rows_root.glob("*/*.json")):
            r = json.loads(f.read_text())
            if not r.get("error"):
                r.setdefault("model", f.parent.name)
                done.setdefault(r["case"], r)
        print(f"resuming: {len(done)} cases already done", flush=True)
    exhausted: set[str] = set()

    def one(p):
        if p.stem in done:
            return done[p.stem]
        for m in models:
            if m in exhausted:
                continue
            r = evaluate_case(p, args.provider, m, args.effort)
            if r["error"] and "RESOURCE_EXHAUSTED" in r["error"]:
                print(f"  {m}: daily quota used up, switching model", flush=True)
                exhausted.add(m)
                continue
            d = rows_root / m
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{p.stem}.json").write_text(json.dumps(r, default=str))
            print(f"{r['case']:26} [{m}] recall={r['recall']:.2f} unsupported={r['claims_unsupported']} "
                  f"false_alarms={r['false_alarms']} {r['seconds']}s {r['error'] or ''}", flush=True)
            return r
        return None

    if args.report_only:
        rows = [done[c.stem] for c in cases if c.stem in done]
    else:
        with ThreadPoolExecutor(args.workers) as pool:
            rows = [r for r in pool.map(one, cases) if r is not None]

    summary = summarize(rows)
    used = sorted({r["model"] for r in rows})
    model = used[0] if len(used) == 1 else "gemini-flash-free-tier"
    out = args.out / model
    (out / "runs").mkdir(parents=True, exist_ok=True)
    for r in rows:
        (out / "runs" / f"{r['case']}.json").write_text(json.dumps(r.pop("_run"), indent=2, default=str))
    (out / "summary.json").write_text(json.dumps({"model": model, "effort": args.effort,
                                                  "summary": summary, "cases": rows}, indent=2))
    md = to_markdown(summary, rows, model, args.effort)
    (out / "RESULTS.md").write_text(md)
    if not args.only:
        update_readme(md, model, len(rows), len(cases))
    print("\n" + md)
    return 0


def update_readme(md: str, model: str, completed: int, total: int) -> None:
    """Copy the headline table into README.md between the RESULTS markers."""
    readme = ROOT / "README.md"
    text = readme.read_text()
    start, end = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"
    if start not in text or end not in text:
        return
    headline = md.split("## Per case")[0].split("\n", 2)[2].strip()
    progress = "" if completed == total else (
        f" **Progress: {completed} of {total} cases evaluated so far** - the free tier allows ~20 requests "
        "per model per day, so the remaining cases run as the quota resets (`python -m eval.run_eval --resume`).")
    models_line = md.split("\n", 1)[0].replace("# Evaluation results — ", "")
    block = (f"{start}\nModels: {models_line} (Google Gemini free tier, $0 total).{progress}\n\n{headline}\n\n"
             f"Per-case breakdown: [`eval/results/{model}/RESULTS.md`](eval/results/{model}/RESULTS.md). "
             f"Full agent traces and checked reports: [`eval/results/{model}/runs/`](eval/results/{model}/runs/).\n{end}")
    readme.write_text(text.split(start)[0] + block + text.split(end)[1])


if __name__ == "__main__":
    raise SystemExit(main())
