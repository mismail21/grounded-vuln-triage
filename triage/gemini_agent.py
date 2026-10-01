"""The same triage agent, driven by Google Gemini (free tier friendly).

Tools, system prompt, evidence ledger and grounding checker are shared with
the Claude agent in ``agent.py``; only the model API differs.
"""

from __future__ import annotations

import copy
import os
import re
import time
from typing import Any, Callable

from .agent import MAX_TURNS, SYSTEM_PROMPT, TOOLS, AgentRun, TriageAgent, _user_prompt
from .checker import check_report
from .evidence import Ledger
from .parsers import ParseResult

DEFAULT_GEMINI_MODEL = os.environ.get("TRIAGE_GEMINI_MODEL", "gemini-3.5-flash")


def _inline_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Replace $ref/$defs with inline copies - the most portable schema form."""
    defs = schema.get("$defs", {})

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                return walk(copy.deepcopy(defs[node["$ref"].split("/")[-1]]))
            return {k: walk(v) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    return _collapse_nullable(walk(schema))


def _collapse_nullable(node: Any) -> Any:
    """anyOf[X, null] -> X with a nullable type list; Gemini handles this far more reliably."""
    if isinstance(node, list):
        return [_collapse_nullable(v) for v in node]
    if not isinstance(node, dict):
        return node
    node = {k: _collapse_nullable(v) for k, v in node.items()}
    opts = node.get("anyOf")
    if isinstance(opts, list) and len(opts) == 2 and {"type": "null"} in opts:
        other = next(o for o in opts if o != {"type": "null"})
        merged = {**{k: v for k, v in node.items() if k != "anyOf"}, **other}
        if isinstance(merged.get("type"), str):
            merged["type"] = [merged["type"], "null"]
        return merged
    return node


class GeminiTriageAgent(TriageAgent):
    def __init__(
        self,
        model: str = DEFAULT_GEMINI_MODEL,
        client: Any = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        **_: Any,
    ):
        from google import genai
        from google.genai import types

        self.types = types
        self.model = model
        self.client = client or genai.Client(
            api_key=os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"),
            http_options=types.HttpOptions(timeout=120_000),
        )
        self.on_event = on_event or (lambda e: None)
        self.config = types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0,
            tools=[
                types.Tool(
                    function_declarations=[
                        types.FunctionDeclaration(
                            name=t["name"],
                            description=t["description"],
                            parameters_json_schema=_inline_refs(t["input_schema"]),
                        )
                        for t in TOOLS
                    ]
                )
            ],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )

    def _generate(self, contents):
        """Call Gemini, waiting out free-tier rate limits (HTTP 429) instead of failing."""
        from google.genai import errors

        transport_errors: tuple[type[BaseException], ...] = (ConnectionError, TimeoutError)
        for mod in ("httpx", "httpx2"):
            try:
                transport_errors += (__import__(mod).TransportError,)
            except (ImportError, AttributeError):
                pass

        for attempt in range(8):
            try:
                return self.client.models.generate_content(model=self.model, contents=contents, config=self.config)
            except transport_errors as e:  # timeouts, dropped connections, TLS resets
                if attempt == 7:
                    raise
                wait = 5 * (attempt + 1)
                self.on_event({"type": "network_retry", "error": type(e).__name__})
            except errors.APIError as e:
                if e.code not in (429, 500, 503) or attempt == 7:
                    raise
                m = re.search(r"retry in ([\d.]+)s", str(e))
                wait = float(m.group(1)) + 1 if m else 15 * (attempt + 1)
                self.on_event({"type": "rate_limited", "wait": round(wait)})
                time.sleep(min(wait, 90))

    def run(self, deps: ParseResult) -> AgentRun:
        types = self.types
        run = AgentRun(model=self.model)
        start = time.time()
        ledger = Ledger(deps.ecosystem)
        contents = [types.Content(role="user", parts=[types.Part.from_text(text=_user_prompt(deps))])]
        nudges = malformed = 0
        try:
            for _ in range(MAX_TURNS):
                run.turns += 1
                self.on_event({"type": "turn", "turn": run.turns})
                resp = self._generate(contents)
                um = resp.usage_metadata
                if um:
                    run.usage["input"] += um.prompt_token_count or 0
                    run.usage["output"] += (um.candidates_token_count or 0) + (um.thoughts_token_count or 0)
                    run.usage["cache_read"] += um.cached_content_token_count or 0
                cand = resp.candidates[0] if resp.candidates else None
                if cand is None or cand.content is None or not cand.content.parts:
                    reason = str(getattr(cand, "finish_reason", None))
                    if "MALFORMED_FUNCTION_CALL" in reason and malformed < 3:
                        # Known Gemini failure mode: the call didn't parse. Retry the same turn.
                        malformed += 1
                        run.trace.append({"tool": "(malformed call, retried)", "input": {}, "is_error": True})
                        continue
                    raise RuntimeError(f"empty response (finish_reason={reason})")
                contents.append(cand.content)
                calls = resp.function_calls or []
                if not calls:
                    if nudges >= 2:
                        raise RuntimeError("model stopped without submitting a report")
                    nudges += 1
                    contents.append(types.Content(role="user", parts=[types.Part.from_text(
                        text="Please submit your report by calling submit_report.")]))
                    continue
                parts = []
                for fc in calls:
                    result, is_error = self._execute(fc.name, dict(fc.args or {}), ledger, run)
                    payload = {"error": result} if is_error else {"result": result}
                    parts.append(types.Part.from_function_response(name=fc.name, response=payload))
                contents.append(types.Content(role="user", parts=parts))
                if run.report is not None:
                    break
            else:
                raise RuntimeError(f"no report after {MAX_TURNS} turns")
        except Exception as e:  # API or model failure; still produce a checked report
            run.error = f"{type(e).__name__}: {str(e)[:300]}"
            self.on_event({"type": "error", "error": run.error})

        run.checked = check_report(run.report or {"findings": [], "remediations": []}, ledger, deps)
        run.seconds = time.time() - start
        self.on_event({"type": "done"})
        return run


def make_agent(provider: str | None = None, model: str | None = None, **kw: Any) -> TriageAgent:
    """Pick the provider from TRIAGE_PROVIDER, or from whichever API key is set."""
    provider = provider or os.environ.get("TRIAGE_PROVIDER")
    if not provider:
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
            provider = "gemini"
        else:
            raise RuntimeError("No model API key found: set ANTHROPIC_API_KEY or GEMINI_API_KEY in .env")
    if provider == "gemini":
        return GeminiTriageAgent(model=model or DEFAULT_GEMINI_MODEL, **kw)
    if provider == "anthropic":
        from .agent import DEFAULT_MODEL

        return TriageAgent(model=model or DEFAULT_MODEL, **kw)
    raise ValueError(f"unknown provider {provider!r}")
