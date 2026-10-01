"""Command line entry point.

    python -m triage.cli baseline examples/requirements.txt
    python -m triage.cli scan examples/package.json --out report.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

from .baseline import build_baseline_report
from .checker import check_report
from .evidence import Ledger
from .parsers import parse_manifest
from .report import render_markdown


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    p = argparse.ArgumentParser(prog="triage", description="Grounded vulnerability triage")
    p.add_argument("mode", choices=["baseline", "scan"], help="baseline = no AI; scan = Claude agent")
    p.add_argument("file", type=Path, help="requirements.txt or package.json")
    p.add_argument("--out", type=Path, help="write the Markdown report here")
    p.add_argument("--json", type=Path, help="write the full JSON result here")
    p.add_argument("--provider", choices=["anthropic", "gemini"], default=None)
    p.add_argument("--model", default=None)
    args = p.parse_args(argv)

    deps = parse_manifest(args.file.name, args.file.read_text())
    print(f"Parsed {len(deps.dependencies)} {deps.ecosystem} dependencies "
          f"({len(deps.unresolved)} without an exact version)", file=sys.stderr)

    if args.mode == "baseline":
        ledger = Ledger(deps.ecosystem)
        checked = check_report(build_baseline_report(deps, ledger), ledger, deps)
        result = {"mode": "baseline", "checked": checked}
    else:
        from .gemini_agent import make_agent

        def log(e):
            if e["type"] == "tool_call":
                print(f"  -> {e['tool']} {e['input']}", file=sys.stderr)
            elif e["type"] == "error":
                print(f"  !! {e['error']}", file=sys.stderr)

        run = make_agent(args.provider, args.model, on_event=log).run(deps)
        checked = run.checked
        result = {"mode": "agent", **run.to_dict()}
        print(f"Agent: {run.turns} turns, {run.seconds:.0f}s, ${run.cost_usd:.3f}", file=sys.stderr)

    md = render_markdown(checked)
    if args.out:
        args.out.write_text(md)
    else:
        print(md)
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
