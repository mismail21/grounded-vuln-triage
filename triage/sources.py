"""Clients for the four public vulnerability data sources.

Every function returns plain data plus the URL a human can open to check it.
Nothing here decides anything: these are the facts the agent and the checker
are both held to.

  * OSV.dev  - which vulnerabilities affect a package@version, and fixed versions
  * NVD      - CVSS base score / severity for a CVE
  * CISA KEV - whether a CVE is known to be exploited in the wild
  * EPSS     - probability of exploitation in the next 30 days
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from .http import FetchError, fetch_json

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_HUMAN_URL = "https://osv.dev/vulnerability/{id}"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
NVD_HUMAN_URL = "https://nvd.nist.gov/vuln/detail/{cve}"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={cves}"
EPSS_HUMAN_URL = "https://api.first.org/data/v1/epss?cve={cve}"


# --------------------------------------------------------------------------- OSV


@dataclass
class VulnCluster:
    """One real-world vulnerability, merged across its OSV aliases.

    OSV often has several records for the same issue (e.g. a GHSA and a PYSEC
    entry that both alias the same CVE). We merge them so a single bug is
    counted once.
    """

    canonical_id: str
    ids: list[str]
    aliases: list[str]
    summary: str
    fixed_versions: list[str]
    osv_urls: list[str]
    severity_vectors: list[str] = field(default_factory=list)

    @property
    def cves(self) -> list[str]:
        return sorted({a for a in self.all_ids if a.startswith("CVE-")})

    @property
    def all_ids(self) -> set[str]:
        return set(self.ids) | set(self.aliases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.canonical_id,
            "osv_ids": self.ids,
            "aliases": sorted(set(self.aliases) - set(self.ids)),
            "cves": self.cves,
            "summary": self.summary,
            "fixed_versions": self.fixed_versions,
            "source_urls": self.osv_urls,
        }


def _canonical_id(ids: set[str]) -> str:
    for prefix in ("CVE-", "GHSA-"):
        matches = sorted(i for i in ids if i.startswith(prefix))
        if matches:
            return matches[0]
    return sorted(ids)[0]


def _norm_pkg(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        from .parsers import normalize_pypi_name

        return normalize_pypi_name(name)
    return name


def _fixed_versions(vuln: dict, ecosystem: str, name: str) -> list[str]:
    out: list[str] = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != ecosystem or _norm_pkg(ecosystem, pkg.get("name", "")) != _norm_pkg(
            ecosystem, name
        ):
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for ev in rng.get("events", []):
                if "fixed" in ev and ev["fixed"] not in out:
                    out.append(ev["fixed"])
    return out


def osv_raw_query(ecosystem: str, name: str, version: str) -> list[dict]:
    """Return the raw OSV records affecting ``name@version``."""
    vulns: list[dict] = []
    body: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    while True:
        data = fetch_json(OSV_QUERY_URL, method="POST", body=body) or {}
        vulns.extend(data.get("vulns", []))
        token = data.get("next_page_token")
        if not token:
            return vulns
        body = {**body, "page_token": token}


def cluster_vulns(raw: list[dict], ecosystem: str, name: str) -> list[VulnCluster]:
    """Merge OSV records that alias each other into one cluster per real issue."""
    # Withdrawn advisories are not real vulnerabilities any more.
    raw = [v for v in raw if not v.get("withdrawn")]
    groups: list[tuple[set[str], list[dict]]] = []
    for v in raw:
        ids = {v["id"], *v.get("aliases", [])}
        merged_ids, merged_recs = set(ids), [v]
        remaining = []
        for g_ids, g_recs in groups:
            if g_ids & merged_ids:
                merged_ids |= g_ids
                merged_recs += g_recs
            else:
                remaining.append((g_ids, g_recs))
        groups = remaining + [(merged_ids, merged_recs)]

    clusters: list[VulnCluster] = []
    for all_ids, recs in groups:
        rec_ids = sorted(r["id"] for r in recs)
        fixed: list[str] = []
        for r in recs:
            for f in _fixed_versions(r, ecosystem, name):
                if f not in fixed:
                    fixed.append(f)
        summary = next((r.get("summary") for r in recs if r.get("summary")), "") or next(
            (r.get("details", "")[:200] for r in recs if r.get("details")), ""
        )
        vectors = [s.get("score") for r in recs for s in r.get("severity", []) if s.get("score")]
        clusters.append(
            VulnCluster(
                canonical_id=_canonical_id(all_ids),
                ids=rec_ids,
                aliases=sorted(all_ids),
                summary=summary.strip(),
                fixed_versions=fixed,
                osv_urls=[OSV_HUMAN_URL.format(id=i) for i in rec_ids],
                severity_vectors=sorted(set(vectors)),
            )
        )
    clusters.sort(key=lambda c: c.canonical_id)
    return clusters


def osv_lookup(ecosystem: str, name: str, version: str) -> list[VulnCluster]:
    return cluster_vulns(osv_raw_query(ecosystem, name, version), ecosystem, name)


# --------------------------------------------------------------------------- NVD


def _nvd_headers() -> dict[str, str] | None:
    key = os.environ.get("NVD_API_KEY")
    return {"apiKey": key} if key else None


def nvd_lookup(cve: str) -> dict[str, Any]:
    """Return CVSS data for a CVE from NVD.

    ``cvss_score`` is None when NVD has not scored the CVE (or it is unknown).
    """
    data = fetch_json(NVD_API_URL.format(cve=cve), headers=_nvd_headers()) or {}
    vulns = data.get("vulnerabilities") or []
    result: dict[str, Any] = {
        "cve": cve,
        "found": bool(vulns),
        "cvss_score": None,
        "cvss_severity": None,
        "cvss_version": None,
        "cvss_vector": None,
        "source_url": NVD_HUMAN_URL.format(cve=cve),
    }
    if not vulns:
        return result
    metrics = vulns[0].get("cve", {}).get("metrics", {})
    for key, version in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss = entry.get("cvssData", {})
        result.update(
            cvss_score=cvss.get("baseScore"),
            cvss_severity=(cvss.get("baseSeverity") or entry.get("baseSeverity") or "").upper() or None,
            cvss_version=version,
            cvss_vector=cvss.get("vectorString"),
        )
        break
    return result


# --------------------------------------------------------------------------- KEV

_kev_index: dict[str, dict] | None = None
_kev_meta: dict[str, Any] = {}


def _load_kev() -> dict[str, dict]:
    global _kev_index
    if _kev_index is None:
        data = fetch_json(KEV_FEED_URL, ttl=12 * 3600) or {}
        _kev_meta.update(
            catalog_version=data.get("catalogVersion"), date_released=data.get("dateReleased")
        )
        _kev_index = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    return _kev_index


def kev_lookup(cve: str) -> dict[str, Any]:
    entry = _load_kev().get(cve)
    return {
        "cve": cve,
        "in_kev": entry is not None,
        "date_added": entry.get("dateAdded") if entry else None,
        "known_ransomware_use": entry.get("knownRansomwareCampaignUse") if entry else None,
        "catalog_version": _kev_meta.get("catalog_version"),
        "source_url": KEV_FEED_URL,
    }


# --------------------------------------------------------------------------- EPSS


def epss_lookup(cves: list[str]) -> dict[str, dict[str, Any]]:
    """Return EPSS scores for up to ~100 CVEs per request."""
    out: dict[str, dict[str, Any]] = {}
    cves = sorted(set(cves))
    for i in range(0, len(cves), 50):
        chunk = cves[i : i + 50]
        data = fetch_json(EPSS_API_URL.format(cves=",".join(chunk))) or {}
        rows = {r["cve"]: r for r in data.get("data", [])}
        for cve in chunk:
            row = rows.get(cve)
            out[cve] = {
                "cve": cve,
                "epss": float(row["epss"]) if row else None,
                "percentile": float(row["percentile"]) if row else None,
                "date": row.get("date") if row else None,
                "source_url": EPSS_HUMAN_URL.format(cve=cve),
            }
    return out


__all__ = [
    "FetchError",
    "VulnCluster",
    "cluster_vulns",
    "epss_lookup",
    "kev_lookup",
    "nvd_lookup",
    "osv_lookup",
    "osv_raw_query",
]
