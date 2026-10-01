"""The evidence ledger: a record of every fact retrieved during one scan.

All data-source access goes through a ``Ledger``. The agent's tools write to
it, and the grounding checker reads from it. A claim in the final report is
only accepted if it matches evidence that is actually in the ledger, so the
model cannot cite a URL it never fetched or a number it made up.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from . import sources
from .parsers import normalize_pypi_name
from .sources import VulnCluster


@dataclass
class Evidence:
    source: str  # "osv" | "nvd" | "kev" | "epss" | "osv-upgrade"
    url: str
    subject: str  # the vuln id / CVE / package@version the facts are about
    facts: dict[str, Any]
    retrieved_at: float = field(default_factory=time.time)


class Ledger:
    def __init__(self, ecosystem: str):
        self.ecosystem = ecosystem
        self.evidence: list[Evidence] = []
        self.packages: dict[str, list[VulnCluster]] = {}  # "name@version" -> clusters
        self.errors: list[str] = []

    # ------------------------------------------------------------------ helpers

    def pkg_key(self, name: str, version: str) -> str:
        if self.ecosystem == "PyPI":
            name = normalize_pypi_name(name)
        return f"{name}@{version}"

    def _add(self, source: str, url: str, subject: str, facts: dict[str, Any]) -> None:
        self.evidence.append(Evidence(source, url, subject, facts))

    # ------------------------------------------------------------------ lookups

    def osv(self, name: str, version: str) -> list[VulnCluster]:
        key = self.pkg_key(name, version)
        if key in self.packages:
            return self.packages[key]
        clusters = sources.osv_lookup(self.ecosystem, name, version)
        self.packages[key] = clusters
        for c in clusters:
            facts = {
                "package": key,
                "ids": c.all_ids,
                "summary": c.summary,
                "fixed_versions": c.fixed_versions,
            }
            for url in c.osv_urls:
                self._add("osv", url, c.canonical_id, facts)
        return clusters

    def nvd(self, cve: str) -> dict[str, Any]:
        cached = self._find_one("nvd", cve)
        if cached:
            return cached.facts
        facts = sources.nvd_lookup(cve)
        self._add("nvd", facts["source_url"], cve, facts)
        return facts

    def kev(self, cve: str) -> dict[str, Any]:
        cached = self._find_one("kev", cve)
        if cached:
            return cached.facts
        facts = sources.kev_lookup(cve)
        self._add("kev", facts["source_url"], cve, facts)
        return facts

    def epss(self, cves: list[str]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        todo = []
        for cve in cves:
            cached = self._find_one("epss", cve)
            if cached:
                out[cve] = cached.facts
            else:
                todo.append(cve)
        if todo:
            for cve, facts in sources.epss_lookup(todo).items():
                self._add("epss", facts["source_url"], cve, facts)
                out[cve] = facts
        return out

    def check_upgrade(self, name: str, version: str) -> list[VulnCluster]:
        """Which known vulnerabilities still affect ``name@version``?"""
        key = self.pkg_key(name, version)
        cached = self._find_one("osv-upgrade", key)
        if cached:
            return cached.facts["clusters"]
        clusters = sources.osv_lookup(self.ecosystem, name, version)
        ids = set().union(*(c.all_ids for c in clusters)) if clusters else set()
        url = f"https://osv.dev/list?ecosystem={self.ecosystem}&q={name}"
        self._add("osv-upgrade", url, key, {"remaining_ids": ids, "clusters": clusters})
        return clusters

    # ------------------------------------------------------------------ queries

    def _find_one(self, source: str, subject: str) -> Evidence | None:
        for ev in self.evidence:
            if ev.source == source and ev.subject == subject:
                return ev
        return None

    def find(self, source: str, url: str | None, subjects: set[str]) -> Evidence | None:
        """Evidence from ``source`` at exactly ``url`` about any of ``subjects``."""
        if not url:
            return None
        url = url.strip()
        for ev in self.evidence:
            if ev.source == source and ev.url == url and ev.subject in subjects:
                return ev
        return None

    def url_known(self, url: str | None) -> bool:
        return bool(url) and any(ev.url == url.strip() for ev in self.evidence)

    def cluster_for(self, package: str, version: str, vuln_id: str) -> VulnCluster | None:
        """The OSV cluster for ``vuln_id`` that was returned for package@version."""
        for c in self.packages.get(self.pkg_key(package, version), []):
            if vuln_id in c.all_ids:
                return c
        return None

    def all_clusters(self) -> dict[str, list[VulnCluster]]:
        return self.packages
