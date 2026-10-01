"""The grounding checker: "no source, no value".

Takes the report the model submitted and checks every claim in it against the
evidence ledger. For each claim:

  verified    the cited URL was actually retrieved in this scan, it is about
              this vulnerability, and the value matches what the source says
  unknown     the model said it could not determine the value (value = null);
              the item is sent for human review. This is allowed, not a failure.
  unsourced   a value with no source URL                 -> claim removed
  ungrounded  a source URL that was never retrieved, or  -> claim removed
              is not about this vulnerability
  mismatch    the value disagrees with the cited source  -> claim removed

Findings about vulnerabilities that OSV never returned for that package and
version are rejected outright. Vulnerabilities that OSV did return but the
model left out are added back to a review list, so nothing is silently lost.
"""

from __future__ import annotations

from typing import Any

from .evidence import Ledger
from .parsers import ParseResult
from .rubric import reference_priority
from .sources import VulnCluster

CLAIM_SOURCES = {
    "summary": "osv",
    "fixed_versions": "osv",
    "cvss_score": "nvd",
    "cvss_severity": "nvd",
    "in_kev": "kev",
    "epss": "epss",
}
CLAIM_FIELDS = tuple(CLAIM_SOURCES)
VIOLATIONS = ("unsourced", "ungrounded", "mismatch")


def _subjects(field: str, cluster: VulnCluster) -> set[str]:
    return {cluster.canonical_id} if CLAIM_SOURCES[field] == "osv" else set(cluster.cves)


def _values_match(field: str, claimed: Any, fact: dict[str, Any]) -> tuple[bool, str]:
    if field == "summary":
        ok = isinstance(claimed, str) and bool(claimed.strip())
        return ok, "" if ok else "empty summary"
    if field == "fixed_versions":
        actual = fact.get("fixed_versions") or []
        if not isinstance(claimed, list):
            return False, "fixed_versions must be a list"
        if not actual:
            return (not claimed), f"source lists no fixed version, claim says {claimed}"
        extra = [v for v in claimed if v not in actual]
        if extra or not claimed:
            return False, f"source lists fixed versions {actual}, claim says {claimed}"
        return True, ""
    if field == "cvss_score":
        actual = fact.get("cvss_score")
        ok = actual is not None and isinstance(claimed, (int, float)) and abs(float(claimed) - actual) <= 0.05
        return ok, "" if ok else f"NVD says {actual}, claim says {claimed}"
    if field == "cvss_severity":
        actual = fact.get("cvss_severity")
        ok = actual is not None and str(claimed).upper() == str(actual).upper()
        return ok, "" if ok else f"NVD says {actual}, claim says {claimed}"
    if field == "in_kev":
        actual = fact.get("in_kev")
        ok = isinstance(claimed, bool) and claimed == actual
        return ok, "" if ok else f"KEV says {actual}, claim says {claimed}"
    if field == "epss":
        actual = fact.get("epss")
        ok = actual is not None and isinstance(claimed, (int, float)) and abs(float(claimed) - actual) <= 0.001
        return ok, "" if ok else f"EPSS says {actual}, claim says {claimed}"
    return False, f"unknown field {field}"


def check_claim(field: str, claim: dict[str, Any] | None, cluster: VulnCluster, ledger: Ledger) -> dict[str, Any]:
    claim = claim or {}
    value = claim.get("value")
    url = (claim.get("source_url") or "").strip() or None
    out = {"value": value, "source_url": url, "status": "verified", "reason": ""}

    if value is None:
        out["status"] = "unknown"
        out["reason"] = "agent could not determine this from any source"
        return out
    if url is None:
        out.update(status="unsourced", reason="value given with no source", value=None)
        return out
    ev = ledger.find(CLAIM_SOURCES[field], url, _subjects(field, cluster))
    if ev is None:
        reason = (
            "cited URL was retrieved, but it is not about this vulnerability"
            if ledger.url_known(url)
            else "cited URL was never retrieved during this scan"
        )
        out.update(status="ungrounded", reason=reason, value=None)
        return out
    ok, why = _values_match(field, value, ev.facts)
    if not ok:
        out.update(status="mismatch", reason=why, value=None)
    return out


def _remaining_clusters(ledger: Ledger, deps: ParseResult) -> None:
    """Make sure every resolved dependency has been looked up in OSV."""
    for d in deps.resolved:
        if ledger.pkg_key(d.name, d.version) not in ledger.packages:
            try:
                ledger.osv(d.name, d.version)
            except Exception as e:  # network failure -> surfaced for review
                ledger.errors.append(f"OSV lookup failed for {d.name}@{d.version}: {e}")


def check_report(report: dict[str, Any], ledger: Ledger, deps: ParseResult) -> dict[str, Any]:
    queried_by_agent = set(ledger.packages)
    stats = {k: 0 for k in ("claims_total", "verified", "unknown", *VIOLATIONS)}
    findings: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    covered: set[tuple[str, str]] = set()  # (pkg_key, canonical_id)

    for f in report.get("findings", []):
        pkg, ver, vid = f.get("package", ""), f.get("installed_version", ""), f.get("vuln_id", "")
        cluster = ledger.cluster_for(pkg, ver, vid)
        if cluster is None:
            rejected.append({**f, "reason": f"OSV did not return {vid} for {pkg}@{ver} in this scan"})
            # Every claim attached to an invented finding is itself unsupported.
            stats["claims_total"] += len(CLAIM_FIELDS)
            stats["ungrounded"] += len(CLAIM_FIELDS)
            continue
        key = (ledger.pkg_key(pkg, ver), cluster.canonical_id)
        if key in covered:
            rejected.append({**f, "reason": "duplicate of another finding for the same vulnerability"})
            continue
        covered.add(key)

        claims = {fld: check_claim(fld, (f.get("claims") or {}).get(fld), cluster, ledger) for fld in CLAIM_FIELDS}
        review: list[str] = []
        for fld, c in claims.items():
            stats["claims_total"] += 1
            stats[c["status"]] += 1
            if c["status"] != "verified":
                review.append(f"{fld}: {c['status']} - {c['reason']}")

        basis = f.get("priority_basis") or []
        weak = [b for b in basis if b in claims and claims[b]["status"] != "verified"]
        if not basis:
            review.append("priority has no stated basis")
        elif weak:
            review.append(f"priority rests on unverified claims: {', '.join(weak)}")

        v = {k: (c["value"] if c["status"] == "verified" else None) for k, c in claims.items()}
        ref = reference_priority(v["cvss_score"], v["in_kev"], v["epss"])
        if ref and f.get("priority") != ref:
            # Judgement calls are allowed, but a human should see every departure from the rubric.
            review.append(f"priority {f.get('priority')} differs from rubric ({ref}); check the rationale")
        findings.append(
            {
                "package": ledger.pkg_key(pkg, ver).rsplit("@", 1)[0],
                "installed_version": ver,
                "vuln_id": cluster.canonical_id,
                "aliases": sorted(cluster.all_ids - {cluster.canonical_id}),
                "priority": f.get("priority"),
                "priority_basis": basis,
                "reference_priority": ref,
                "priority_agrees": ref is not None and ref == f.get("priority"),
                "rationale": f.get("rationale", ""),
                "claims": claims,
                "status": "needs_review" if review else "verified",
                "review_reasons": review,
            }
        )

    # Safety net: anything OSV knows about that the agent left out.
    _remaining_clusters(ledger, deps)
    omitted = []
    for d in deps.resolved:
        pkey = ledger.pkg_key(d.name, d.version)
        for c in ledger.packages.get(pkey, []):
            if (pkey, c.canonical_id) not in covered:
                omitted.append(
                    {
                        "package": pkey.rsplit("@", 1)[0],
                        "installed_version": d.version,
                        "vuln_id": c.canonical_id,
                        "summary": c.summary,
                        "source_urls": c.osv_urls,
                        "reason": "returned by OSV but not triaged by the agent",
                    }
                )

    remediations = [_check_remediation(r, ledger, findings) for r in report.get("remediations", [])]

    unqueried = [
        f"{d.name}@{d.version}" for d in deps.resolved if ledger.pkg_key(d.name, d.version) not in queried_by_agent
    ]
    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    findings.sort(key=lambda x: (order.get(x["priority"], 9), -(x["claims"]["cvss_score"]["value"] or 0)))

    violations = sum(stats[k] for k in VIOLATIONS)
    return {
        "findings": findings,
        "rejected_findings": rejected,
        "omitted": omitted,
        "remediations": remediations,
        "unresolved_dependencies": [{"dependency": d.raw, "note": d.note} for d in deps.unresolved],
        "unqueried_dependencies": unqueried,
        "review_notes": report.get("review_notes", []),
        "errors": list(ledger.errors),
        "stats": {
            **stats,
            "findings_reported": len(report.get("findings", [])),
            "findings_accepted": len(findings),
            "findings_rejected": len(rejected),
            "findings_needing_review": sum(1 for x in findings if x["status"] == "needs_review"),
            "omitted": len(omitted),
            "unsupported_claim_rate": round(violations / stats["claims_total"], 4) if stats["claims_total"] else 0.0,
            "unsupported_claims_in_final_report": 0,  # removed above, by construction
        },
    }


def _canonical(vid: str, clusters: list[VulnCluster]) -> str:
    return next((c.canonical_id for c in clusters if vid in c.all_ids), vid)


def _check_remediation(r: dict[str, Any], ledger: Ledger, findings: list[dict[str, Any]]) -> dict[str, Any]:
    pkg, cur, rec = r.get("package", ""), r.get("current_version", ""), r.get("recommended_version")
    out = {**r, "status": "verified", "reason": "", "still_affected_by": []}
    if not rec:
        out.update(status="needs_review", reason="no fixed version recommended")
        return out
    advisories = ledger.packages.get(ledger.pkg_key(pkg, cur), [])
    named = {v for c in advisories for v in c.fixed_versions}
    if rec not in named:
        out.update(
            status="needs_review",
            reason=f"{rec} is not a fixed version named by any advisory for {pkg}@{cur}",
        )
        return out
    try:
        remaining = ledger.check_upgrade(pkg, rec)
    except Exception as e:
        out.update(status="needs_review", reason=f"could not verify with OSV: {e}")
        return out
    remaining_ids = set().union(*(c.all_ids for c in remaining)) if remaining else set()
    # Every known issue in the installed version should be gone, not just the ones the agent listed.
    claimed = set(r.get("resolves") or []) | {c.canonical_id for c in advisories}
    still = sorted({_canonical(i, advisories) for i in claimed if i in remaining_ids})
    out["still_affected_by"] = still
    out["remaining_known_vulns"] = sorted(c.canonical_id for c in remaining)
    out["verification_url"] = f"https://osv.dev/list?ecosystem={ledger.ecosystem}&q={pkg}"
    if still:
        out.update(status="partial", reason=f"OSV says {pkg}@{rec} is still affected by {', '.join(still)}")
    return out
