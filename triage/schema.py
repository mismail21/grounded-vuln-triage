"""The report the agent must submit, as Pydantic models.

The same models generate the JSON schema for the ``submit_report`` tool and
validate what the model sends back, so a malformed report is returned to the
model as a tool error it can fix.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Priority = Literal["P1", "P2", "P3", "P4"]
ClaimField = Literal["summary", "fixed_versions", "cvss_score", "cvss_severity", "in_kev", "epss"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class StrClaim(_Strict):
    value: str | None
    source_url: str | None


class NumClaim(_Strict):
    value: float | None
    source_url: str | None


class BoolClaim(_Strict):
    value: bool | None
    source_url: str | None


class ListClaim(_Strict):
    value: list[str] | None
    source_url: str | None


class Claims(_Strict):
    summary: StrClaim = Field(description="One-line description of the issue. Source: the OSV URL.")
    fixed_versions: ListClaim = Field(description="Versions that fix it, exactly as OSV lists them. Source: the OSV URL.")
    cvss_score: NumClaim = Field(description="CVSS base score from NVD. Source: the NVD URL.")
    cvss_severity: StrClaim = Field(description="CVSS severity (LOW/MEDIUM/HIGH/CRITICAL) from NVD. Source: the NVD URL.")
    in_kev: BoolClaim = Field(description="Whether the CVE is in CISA KEV. Source: the KEV URL.")
    epss: NumClaim = Field(description="EPSS probability (0-1). Source: the EPSS URL.")


class Finding(_Strict):
    package: str
    installed_version: str
    vuln_id: str = Field(description="The vulnerability id exactly as returned by osv_lookup.")
    claims: Claims
    priority: Priority
    priority_basis: list[ClaimField] = Field(description="Which claims the priority is based on.")
    rationale: str = Field(description="One or two sentences explaining the priority.")


class Remediation(_Strict):
    package: str
    current_version: str
    recommended_version: str | None = Field(
        description="A fixed version named by OSV that check_upgrade confirmed; null if none exists."
    )
    resolves: list[str] = Field(description="vuln_ids this upgrade fixes.")
    note: str


class Report(_Strict):
    findings: list[Finding]
    remediations: list[Remediation]
    review_notes: list[str] = Field(description="Anything you could not determine and a human should check.")


def _clean(node: Any) -> Any:
    """Strip Pydantic's cosmetic keys so the schema is small and strict-mode friendly."""
    if isinstance(node, dict):
        return {k: _clean(v) for k, v in node.items() if k not in ("title", "default")}
    if isinstance(node, list):
        return [_clean(v) for v in node]
    return node


def report_json_schema() -> dict[str, Any]:
    return _clean(Report.model_json_schema())
