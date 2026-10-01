"""Offline fixtures: fake data sources so tests never touch the network."""

from __future__ import annotations

import pytest

from triage import sources
from triage.sources import VulnCluster

OSV = "https://osv.dev/vulnerability/"
NVD = "https://nvd.nist.gov/vuln/detail/"
EPSS = "https://api.first.org/data/v1/epss?cve="


def _cluster(cid, ids, summary, fixed):
    return VulnCluster(
        canonical_id=cid,
        ids=ids,
        aliases=sorted({cid, *ids}),
        summary=summary,
        fixed_versions=fixed,
        osv_urls=[OSV + i for i in ids],
    )


FAKE_OSV = {
    ("PyPI", "demo", "1.0"): [
        _cluster("CVE-2020-0001", ["GHSA-aaaa-aaaa-aaaa", "PYSEC-2020-1"], "Remote code execution", ["1.1"]),
        _cluster("CVE-2021-0002", ["GHSA-bbbb-bbbb-bbbb"], "Denial of service", ["1.2"]),
    ],
    ("PyPI", "demo", "1.1"): [
        _cluster("CVE-2021-0002", ["GHSA-bbbb-bbbb-bbbb"], "Denial of service", ["1.2"]),
    ],
    ("PyPI", "demo", "1.2"): [],
    ("PyPI", "safe", "2.0"): [],
}
FAKE_NVD = {
    "CVE-2020-0001": (9.8, "CRITICAL"),
    "CVE-2021-0002": (5.3, "MEDIUM"),
}
FAKE_KEV = {"CVE-2020-0001"}
FAKE_EPSS = {"CVE-2020-0001": 0.91234, "CVE-2021-0002": 0.00412}


@pytest.fixture
def fake_sources(monkeypatch):
    calls = {"osv": 0, "nvd": 0}

    def osv_lookup(eco, name, version):
        calls["osv"] += 1
        return FAKE_OSV.get((eco, name, version), [])

    def nvd_lookup(cve):
        calls["nvd"] += 1
        score, sev = FAKE_NVD.get(cve, (None, None))
        return {"cve": cve, "found": cve in FAKE_NVD, "cvss_score": score, "cvss_severity": sev,
                "cvss_version": "3.1", "cvss_vector": None, "source_url": NVD + cve}

    def kev_lookup(cve):
        return {"cve": cve, "in_kev": cve in FAKE_KEV, "date_added": None, "known_ransomware_use": None,
                "catalog_version": "test", "source_url": sources.KEV_FEED_URL}

    def epss_lookup(cves):
        return {c: {"cve": c, "epss": FAKE_EPSS.get(c), "percentile": 0.5, "date": "2026-01-01",
                    "source_url": EPSS + c} for c in cves}

    monkeypatch.setattr(sources, "osv_lookup", osv_lookup)
    monkeypatch.setattr(sources, "nvd_lookup", nvd_lookup)
    monkeypatch.setattr(sources, "kev_lookup", kev_lookup)
    monkeypatch.setattr(sources, "epss_lookup", epss_lookup)
    return calls


def good_finding(vid="CVE-2020-0001", osv_id="GHSA-aaaa-aaaa-aaaa", **overrides):
    """A finding exactly as a well-behaved agent would write it."""
    score, sev = FAKE_NVD[vid]
    f = {
        "package": "demo",
        "installed_version": "1.0",
        "vuln_id": vid,
        "claims": {
            "summary": {"value": "Remote code execution", "source_url": OSV + osv_id},
            "fixed_versions": {"value": ["1.1"] if vid == "CVE-2020-0001" else ["1.2"], "source_url": OSV + osv_id},
            "cvss_score": {"value": score, "source_url": NVD + vid},
            "cvss_severity": {"value": sev, "source_url": NVD + vid},
            "in_kev": {"value": vid in FAKE_KEV, "source_url": sources.KEV_FEED_URL},
            "epss": {"value": round(FAKE_EPSS[vid], 3), "source_url": EPSS + vid},
        },
        "priority": "P1",
        "priority_basis": ["in_kev", "cvss_score"],
        "rationale": "Actively exploited.",
    }
    f.update(overrides)
    return f
