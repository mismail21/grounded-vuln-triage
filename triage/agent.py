"""Step 2: the triage agent.

Claude gets the parsed dependency list and a set of tools (OSV, NVD, KEV,
EPSS, upgrade check). It decides which tools to call, then submits a
structured report through ``submit_report``. Every tool result carries the URL
it came from, every call is recorded in the evidence ledger, and the report is
then run through the grounding checker.
"""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

import anthropic
from pydantic import ValidationError

from .checker import check_report
from .evidence import Ledger
from .parsers import ParseResult
from .rubric import RUBRIC_TEXT
from .schema import Report, report_json_schema

DEFAULT_MODEL = os.environ.get("TRIAGE_MODEL", "claude-opus-5-5")
DEFAULT_EFFORT = os.environ.get("TRIAGE_EFFORT", "medium")
MAX_TURNS = int(os.environ.get("TRIAGE_MAX_TURNS", "16"))

# USD per million tokens: input, output, cache read, cache write (5-minute TTL).
PRICES = {
    "claude-opus-5-5": (4.00, 20.00, 0.20, 5.00),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20, 2.50),
    "claude-haiku-4-5": (1.00, 5.00, 0.10, 1.25),
}

SYSTEM_PROMPT = f"""\
You are a vulnerability triage analyst. You are given the dependencies of a software \
project. Find their known vulnerabilities, judge how urgent each one is, and submit a \
prioritized fix report with the submit_report tool.

The rule for this job is "no source, no value". The report is checked automatically \
against the tool results from this session:
- Every value you report must come from a tool result in this session, and its \
source_url must be copied exactly from that same tool result. Claims that don't match \
their source are deleted from the report.
- If a tool did not give you a value (for example NVD has no CVSS score, or the \
vulnerability has no CVE id so NVD/KEV/EPSS cannot be queried), set value to null \
and source_url to null, and mention it in review_notes. Never estimate, recall from \
memory, or infer a number.
- Look up NVD, KEV and EPSS using the vulnerability's CVE id. Cite the URL returned \
for that CVE.
- Report every vulnerability osv_lookup returns for the installed versions, one \
finding each, using the exact vuln_id osv_lookup gave you. Do not add any others.
- For each vulnerable package, choose an upgrade from the fixed versions OSV lists, \
confirm it with check_upgrade, and add a remediation. If none clears every issue, \
say so in the note.

Prioritize with this rubric. You may deviate when the evidence justifies it (for \
example a devDependency), and if you do, explain why in the rationale:
{RUBRIC_TEXT}

Work efficiently: tools accept lists, so batch lookups and make independent calls in \
parallel. An efficient run takes three turns: (1) osv_lookup for all packages at once; \
(2) nvd_lookup, kev_lookup and epss_lookup for all CVEs plus check_upgrade for each \
vulnerable package, all in the same turn; (3) submit_report."""


def _tool(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    }


_CVE_LIST = {"cve_ids": {"type": "array", "items": {"type": "string"}, "description": "CVE ids, e.g. CVE-2019-10906"}}

TOOLS = [
    _tool(
        "osv_lookup",
        "Query OSV.dev for known vulnerabilities affecting each package at its installed version. "
        "Returns one entry per vulnerability (aliases already merged) with CVE ids, summary, "
        "fixed versions and the source URL.",
        {
            "packages": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}, "version": {"type": "string"}},
                    "required": ["name", "version"],
                    "additionalProperties": False,
                },
            }
        },
        ["packages"],
    ),
    _tool("nvd_lookup", "Get the CVSS base score and severity for CVEs from the US National Vulnerability "
          "Database. Slow (rate-limited), so only ask for CVEs you need.", _CVE_LIST, ["cve_ids"]),
    _tool("kev_lookup", "Check whether CVEs are in the CISA Known Exploited Vulnerabilities catalog "
          "(actively exploited in the wild).", _CVE_LIST, ["cve_ids"]),
    _tool("epss_lookup", "Get EPSS scores: the probability each CVE is exploited in the next 30 days.",
          _CVE_LIST, ["cve_ids"]),
    _tool(
        "check_upgrade",
        "Check which known vulnerabilities (per OSV) still affect a candidate upgrade version.",
        {"package": {"type": "string"}, "version": {"type": "string"}},
        ["package", "version"],
    ),
    {
        "name": "submit_report",
        "description": "Submit the final triage report. Call exactly once, at the end.",
        "input_schema": report_json_schema(),
    },
]


@dataclass
class AgentRun:
    report: dict[str, Any] | None = None
    checked: dict[str, Any] | None = None
    trace: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int] = field(
        default_factory=lambda: {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    )
    turns: int = 0
    seconds: float = 0.0
    model: str = DEFAULT_MODEL
    error: str | None = None

    @property
    def cost_usd(self) -> float:
        p = PRICES.get(self.model)
        if not p:
            return 0.0
        u = self.usage
        return round(
            (u["input"] * p[0] + u["output"] * p[1] + u["cache_read"] * p[2] + u["cache_write"] * p[3]) / 1e6, 4
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "turns": self.turns,
            "seconds": round(self.seconds, 1),
            "usage": self.usage,
            "cost_usd": self.cost_usd,
            "trace": self.trace,
            "error": self.error,
            "raw_report": self.report,
            "checked": self.checked,
        }


class TriageAgent:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        effort: str = DEFAULT_EFFORT,
        client: anthropic.Anthropic | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.model = model
        self.effort = effort
        self.client = client or anthropic.Anthropic()
        self.on_event = on_event or (lambda e: None)
        # Server-side refusal fallback: supported on the current Opus / Sonnet models.
        self.use_fallbacks = os.environ.get("TRIAGE_FALLBACKS", "1") == "1" and model in (
            "claude-opus-5-5",
            "claude-sonnet-5-5",
        )

    # ------------------------------------------------------------------ tools

    def _run_tool(self, name: str, args: dict[str, Any], ledger: Ledger) -> Any:
        if name == "osv_lookup":
            pkgs = args["packages"]
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda p: ledger.osv(p["name"], p["version"]), pkgs))
            return [
                {
                    "package": p["name"],
                    "version": p["version"],
                    "vulnerabilities": [
                        {**c.to_dict(), "summary": c.summary[:240], "source_url": c.osv_urls[0]}
                        for c in clusters
                    ],
                }
                for p, clusters in zip(pkgs, results)
            ]
        if name == "nvd_lookup":
            return [ledger.nvd(c) for c in _dedupe(args["cve_ids"])]
        if name == "kev_lookup":
            return [ledger.kev(c) for c in _dedupe(args["cve_ids"])]
        if name == "epss_lookup":
            return list(ledger.epss(_dedupe(args["cve_ids"])).values())
        if name == "check_upgrade":
            clusters = ledger.check_upgrade(args["package"], args["version"])
            return {
                "package": args["package"],
                "version": args["version"],
                "still_affected_by": [{"id": c.canonical_id, "aliases": sorted(c.all_ids)} for c in clusters],
            }
        raise ValueError(f"unknown tool {name}")

    # ------------------------------------------------------------------ loop

    def run(self, deps: ParseResult) -> AgentRun:
        run = AgentRun(model=self.model)
        start = time.time()
        ledger = Ledger(deps.ecosystem)
        messages: list[dict[str, Any]] = [{"role": "user", "content": _user_prompt(deps)}]
        nudges = 0
        try:
            for _ in range(MAX_TURNS):
                run.turns += 1
                self.on_event({"type": "turn", "turn": run.turns})
                resp = self._call(messages)
                u = resp.usage
                run.usage["input"] += u.input_tokens or 0
                run.usage["output"] += u.output_tokens or 0
                run.usage["cache_read"] += u.cache_read_input_tokens or 0
                run.usage["cache_write"] += u.cache_creation_input_tokens or 0

                if resp.stop_reason == "refusal":
                    raise RuntimeError(f"model declined the request: {getattr(resp, 'stop_details', None)}")
                messages.append({"role": "assistant", "content": resp.content})
                tool_uses = [b for b in resp.content if b.type == "tool_use"]
                if not tool_uses:
                    if resp.stop_reason == "max_tokens":
                        raise RuntimeError("response hit max_tokens before a report was submitted")
                    if nudges >= 2:
                        raise RuntimeError("model stopped without submitting a report")
                    nudges += 1
                    messages.append({"role": "user", "content": "Please submit your report with submit_report."})
                    continue

                results = []
                for tu in tool_uses:
                    results.append(self._handle(tu, ledger, run))
                messages.append({"role": "user", "content": results})
                if run.report is not None:
                    break
            else:
                raise RuntimeError(f"no report after {MAX_TURNS} turns")
        except (anthropic.APIError, RuntimeError) as e:
            run.error = f"{type(e).__name__}: {e}"
            self.on_event({"type": "error", "error": run.error})

        # Even a failed run gets checked: everything OSV found goes to the review list.
        run.checked = check_report(run.report or {"findings": [], "remediations": []}, ledger, deps)
        run.seconds = time.time() - start
        self.on_event({"type": "done"})
        return run

    def _call(self, messages: list[dict[str, Any]]):
        kwargs: dict[str, Any] = dict(
            model=self.model,
            max_tokens=64000,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort},
            cache_control={"type": "ephemeral"},
        )
        if self.use_fallbacks:
            kwargs.update(betas=["server-side-fallback-2026-07-01"], fallbacks="default")
        # Streaming keeps a long report under the HTTP timeout.
        with self.client.beta.messages.stream(**kwargs) as stream:
            return stream.get_final_message()

    def _handle(self, tu, ledger: Ledger, run: AgentRun) -> dict[str, Any]:
        result, is_error = self._execute(tu.name, tu.input, ledger, run)
        content = result if isinstance(result, str) else json.dumps(result)
        return {"type": "tool_result", "tool_use_id": tu.id, "content": content, "is_error": is_error}

    def _execute(self, name: str, args: dict[str, Any], ledger: Ledger, run: AgentRun) -> tuple[Any, bool]:
        """Run one tool call (provider-independent). Returns (result, is_error)."""
        t0 = time.time()
        entry: dict[str, Any] = {"tool": name, "input": args}
        self.on_event({"type": "tool_call", "tool": name, "input": _short(args)})
        try:
            if name == "submit_report":
                report = Report.model_validate(args).model_dump()
                run.report = report
                result, is_error = "Report received.", False
                entry["input"] = {"findings": len(report["findings"]), "remediations": len(report["remediations"])}
            else:
                result, is_error = self._run_tool(name, args, ledger), False
        except ValidationError as e:
            result, is_error = f"Report failed validation, fix and resubmit:\n{e}", True
        except Exception as e:  # data-source failure: tell the model, it should mark values unknown
            ledger.errors.append(f"{name}: {e}")
            result, is_error = f"Tool failed: {e}. Treat values from this tool as unknown.", True
        entry.update(seconds=round(time.time() - t0, 2), is_error=is_error)
        run.trace.append(entry)
        return result, is_error


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(i.strip() for i in items if i.strip()))


def _short(obj: Any, limit: int = 200) -> str:
    s = json.dumps(obj)
    return s if len(s) <= limit else s[:limit] + "..."


def _user_prompt(deps: ParseResult) -> str:
    lines = [f"Ecosystem: {deps.ecosystem}", "", "Dependencies (name, installed version):"]
    for d in deps.resolved:
        lines.append(f"- {d.name} {d.version}" + (" (devDependency)" if d.dev else "") + (f"  [{d.note}]" if d.note else ""))
    if deps.unresolved:
        lines += ["", "These could not be resolved to an exact version; they are already flagged for human review:"]
        lines += [f"- {d.raw}  [{d.note}]" for d in deps.unresolved]
    if not deps.resolved:
        lines += ["", "(No dependency has an exact version. Submit an empty report.)"]
    return "\n".join(lines)
