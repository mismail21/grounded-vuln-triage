"""FastAPI backend: scan a manifest with the agent or the no-AI baseline.

    uvicorn triage.server:app --reload
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .baseline import build_baseline_report
from .checker import check_report
from .evidence import Ledger
from .parsers import parse_manifest
from .report import render_markdown

load_dotenv()

app = FastAPI(title="Grounded Vulnerability Triage", version="0.1.0")
WEB_DIST = Path(os.environ.get("TRIAGE_WEB_DIST", Path(__file__).resolve().parent.parent / "web" / "dist"))
MAX_BYTES = 200_000


class ScanRequest(BaseModel):
    filename: str = Field(examples=["requirements.txt"])
    content: str = Field(max_length=MAX_BYTES)
    mode: Literal["agent", "baseline"] = "agent"


def _has_model_key() -> bool:
    return any(os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"))


@app.get("/api/health")
def health():
    return {"status": "ok", "agent_available": _has_model_key()}


@app.post("/api/scan")
async def scan(req: ScanRequest):
    try:
        deps = parse_manifest(req.filename, req.content)
    except ValueError as e:
        raise HTTPException(400, f"Could not parse manifest: {e}")
    if not deps.dependencies:
        raise HTTPException(400, "No dependencies found in that file.")
    if len(deps.dependencies) > 60:
        raise HTTPException(400, "Too many dependencies for the demo (max 60).")

    def work():
        if req.mode == "baseline":
            ledger = Ledger(deps.ecosystem)
            checked = check_report(build_baseline_report(deps, ledger), ledger, deps)
            return {"mode": "baseline", "checked": checked, "trace": [], "model": None}
        if not _has_model_key():
            raise HTTPException(503, "No model API key configured on the server; use baseline mode.")
        from .gemini_agent import make_agent

        run = make_agent().run(deps)
        return {"mode": "agent", **run.to_dict()}

    result = await run_in_threadpool(work)
    result["ecosystem"] = deps.ecosystem
    result["markdown"] = render_markdown(result["checked"])
    result.pop("raw_report", None)
    return result


if WEB_DIST.exists():
    app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        return FileResponse(WEB_DIST / "index.html")
