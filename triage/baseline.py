"""Step 1: the deterministic pipeline, with no AI involved.

Parse the manifest, query OSV for every dependency, enrich each vulnerability
with NVD, KEV and EPSS, and rank with the fixed rubric. The output uses the
same report shape the agent submits, so it goes through the same grounding
checker. It is the ground truth the agent is evaluated against.
"""

from __future__ import annotations

from typing import Any

from .evidence import Ledger
from .parsers import ParseResult
from .rubric import reference_priority
from .versions import is_newer, version_key


def build_baseline_report(deps: ParseResult, ledger: Ledger, enrich: bool = True) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []

    for d in deps.resolved:
        clusters = ledger.osv(d.name, d.version)
        for c in clusters:
            claims: dict[str, Any] = {
                "summary": {"value": c.summary or None, "source_url": c.osv_urls[0]},
                "fixed_versions": {"value": c.fixed_versions, "source_url": c.osv_urls[0]},
                "cvss_score": {"value": None, "source_url": None},
                "cvss_severity": {"value": None, "source_url": None},
                "in_kev": {"value": None, "source_url": None},
                "epss": {"value": None, "source_url": None},
            }
            cve = c.cves[0] if c.cves else None
            if enrich and cve:
                nvd = ledger.nvd(cve)
                if nvd["cvss_score"] is not None:
                    claims["cvss_score"] = {"value": nvd["cvss_score"], "source_url": nvd["source_url"]}
                    claims["cvss_severity"] = {"value": nvd["cvss_severity"], "source_url": nvd["source_url"]}
                kev = ledger.kev(cve)
                claims["in_kev"] = {"value": kev["in_kev"], "source_url": kev["source_url"]}
                ep = ledger.epss([cve])[cve]
                if ep["epss"] is not None:
                    claims["epss"] = {"value": ep["epss"], "source_url": ep["source_url"]}
            prio = reference_priority(
                claims["cvss_score"]["value"], claims["in_kev"]["value"], claims["epss"]["value"]
            )
            findings.append(
                {
                    "package": d.name,
                    "installed_version": d.version,
                    "vuln_id": c.canonical_id,
                    "claims": claims,
                    "priority": prio or "P3",
                    "priority_basis": ["in_kev", "cvss_score", "epss"],
                    "rationale": "Ranked by the fixed rubric (no AI)."
                    + ("" if prio else " Not enough evidence to rank; defaulted to P3."),
                }
            )
        if clusters:
            remediations.append(_pick_upgrade(d.name, d.version, clusters, ledger))

    return {"findings": findings, "remediations": remediations, "review_notes": []}


def _pick_upgrade(name: str, current: str, clusters, ledger: Ledger) -> dict[str, Any]:
    """Smallest advisory-named fixed version that OSV says clears every issue.

    Tries candidates in ascending order and stops at the first that works; falls
    back to the highest named fixed version.
    """
    candidates = sorted(
        {v for c in clusters for v in c.fixed_versions if is_newer(v, current)}, key=version_key
    )
    ids = [c.canonical_id for c in clusters]
    if not candidates:
        return {"package": name, "current_version": current, "recommended_version": None,
                "resolves": [], "note": "No fixed version is published for at least one issue."}
    # Checking every candidate costs one OSV query each; try the top few plus the max.
    for cand in candidates[-4:]:
        remaining = ledger.check_upgrade(name, cand)
        remaining_ids = set().union(*(c.all_ids for c in remaining)) if remaining else set()
        if not any(i in remaining_ids for i in ids):
            return {"package": name, "current_version": current, "recommended_version": cand,
                    "resolves": ids, "note": ""}
    return {"package": name, "current_version": current, "recommended_version": candidates[-1],
            "resolves": ids, "note": "Highest advisory-named fix; some issues may remain."}
