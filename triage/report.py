"""Render a checked report as Markdown. Every number links to its source."""

from __future__ import annotations

from typing import Any


def _cell(claim: dict[str, Any], fmt: str = "{}") -> str:
    if claim["status"] != "verified":
        return "⚠ review"
    v = claim["value"]
    if isinstance(v, list):
        v = ", ".join(v) if v else "none"
    elif isinstance(v, bool):
        v = "YES" if v else "no"
    else:
        v = fmt.format(v)
    return f"[{v}]({claim['source_url']})"


def render_markdown(checked: dict[str, Any], title: str = "Vulnerability triage report") -> str:
    s = checked["stats"]
    out = [f"# {title}", ""]
    out.append(
        f"**{s['findings_accepted']} findings** · {s['findings_needing_review']} need human review · "
        f"{s['omitted']} omitted by the agent (added for review) · "
        f"{s['findings_rejected']} rejected as unsupported"
    )
    out.append(
        f"\nGrounding: {s['verified']}/{s['claims_total']} claims verified against their sources; "
        f"{s['unsourced'] + s['ungrounded'] + s['mismatch']} unsupported claims removed. "
        "Every value below links to the record it came from.\n"
    )

    if checked["findings"]:
        out += [
            "## Findings",
            "",
            "| Priority | Package | Vulnerability | CVSS | KEV | EPSS | Fixed in | Status |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for f in checked["findings"]:
            c = f["claims"]
            status = "✅ verified" if f["status"] == "verified" else "⚠ needs review"
            out.append(
                f"| **{f['priority']}** | {f['package']} {f['installed_version']} | {f['vuln_id']} | "
                f"{_cell(c['cvss_score'])} | {_cell(c['in_kev'])} | {_cell(c['epss'], '{:.3f}')} | "
                f"{_cell(c['fixed_versions'])} | {status} |"
            )
        out.append("")
        out.append("### Details")
        for f in checked["findings"]:
            summ = f["claims"]["summary"]
            text = f"[{summ['value']}]({summ['source_url']})" if summ["status"] == "verified" else "(summary needs review)"
            out.append(f"- **{f['priority']} {f['vuln_id']}** ({f['package']}): {text}. _{f['rationale']}_")
            for r in f["review_reasons"]:
                out.append(f"  - ⚠ {r}")
        out.append("")

    if checked["remediations"]:
        out += ["## Fix plan", "", "| Package | Current | Upgrade to | Check |", "|---|---|---|---|"]
        for r in checked["remediations"]:
            check = {"verified": "✅ OSV confirms", "partial": "⚠ partial", "needs_review": "⚠ review"}[r["status"]]
            reason = f" – {r['reason']}" if r["reason"] else ""
            out.append(
                f"| {r['package']} | {r['current_version']} | {r.get('recommended_version') or '—'} | {check}{reason} |"
            )
        out.append("")

    review = []
    for o in checked["omitted"]:
        review.append(f"- {o['package']} {o['installed_version']} **{o['vuln_id']}**: {o['summary']} ({o['reason']}) {o['source_urls'][0]}")
    for r in checked["rejected_findings"]:
        review.append(f"- Rejected: {r.get('package')} {r.get('vuln_id')} – {r['reason']}")
    for u in checked["unresolved_dependencies"]:
        review.append(f"- `{u['dependency']}` – {u['note']}")
    for n in checked["review_notes"]:
        review.append(f"- Agent note: {n}")
    for e in checked["errors"]:
        review.append(f"- Data source error: {e}")
    if review:
        out += ["## Needs human review", "", *review, ""]
    return "\n".join(out)
