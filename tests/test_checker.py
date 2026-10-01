"""The grounding checker is the core of the project, so it gets adversarial tests:
each one feeds it a report containing a specific kind of made-up claim."""

import copy

from conftest import NVD, OSV, good_finding

from triage.baseline import build_baseline_report
from triage.checker import check_report
from triage.evidence import Ledger
from triage.parsers import parse_requirements
from triage.rubric import reference_priority


def _setup(reqs="demo==1.0\n", enrich=True):
    deps = parse_requirements(reqs)
    ledger = Ledger("PyPI")
    for d in deps.resolved:
        for c in ledger.osv(d.name, d.version):
            if enrich:
                for cve in c.cves:
                    ledger.nvd(cve)
                    ledger.kev(cve)
                    ledger.epss([cve])
    return deps, ledger


def _both_findings():
    second = good_finding("CVE-2021-0002", "GHSA-bbbb-bbbb-bbbb", priority="P3",
                          priority_basis=["cvss_score"], rationale="Medium.")
    second["claims"]["summary"]["value"] = "Denial of service"
    return [good_finding(), second]


def _statuses(out):
    return {f["vuln_id"]: {k: c["status"] for k, c in f["claims"].items()} for f in out["findings"]}


def test_honest_report_is_fully_verified(fake_sources):
    deps, ledger = _setup()
    out = check_report({"findings": _both_findings(), "remediations": []}, ledger, deps)
    s = out["stats"]
    assert s["claims_total"] == 12 and s["verified"] == 12
    assert s["unsupported_claim_rate"] == 0.0
    assert all(f["status"] == "verified" for f in out["findings"])
    assert out["omitted"] == [] and out["rejected_findings"] == []
    # Sorted by priority, and the KEV item agrees with the rubric.
    assert out["findings"][0]["vuln_id"] == "CVE-2020-0001"
    assert out["findings"][0]["priority_agrees"] is True


def test_priority_deviation_goes_to_review(fake_sources):
    deps, ledger = _setup()
    f = good_finding(priority="P3", rationale="Only used in a test fixture.")  # rubric says P1 (KEV)
    out = check_report({"findings": [f], "remediations": []}, ledger, deps)
    fd = out["findings"][0]
    assert fd["status"] == "needs_review" and fd["priority_agrees"] is False
    assert "differs from rubric (P1)" in fd["review_reasons"][-1]
    assert out["stats"]["verified"] == 6  # the facts themselves are still fine


def test_osv_alias_can_be_used_as_vuln_id(fake_sources):
    deps, ledger = _setup()
    f = good_finding(vuln_id="PYSEC-2020-1")
    out = check_report({"findings": [f], "remediations": []}, ledger, deps)
    assert out["findings"][0]["vuln_id"] == "CVE-2020-0001"  # normalised to the canonical id
    assert out["stats"]["verified"] == 6


def test_wrong_number_is_a_mismatch_and_removed(fake_sources):
    deps, ledger = _setup()
    f = good_finding()
    f["claims"]["cvss_score"]["value"] = 7.5  # NVD says 9.8
    f["claims"]["epss"]["value"] = 0.2  # EPSS says 0.912
    out = check_report({"findings": [f], "remediations": []}, ledger, deps)
    st = _statuses(out)["CVE-2020-0001"]
    assert st["cvss_score"] == "mismatch" and st["epss"] == "mismatch"
    assert out["findings"][0]["claims"]["cvss_score"]["value"] is None  # stripped from the report
    assert out["findings"][0]["status"] == "needs_review"
    assert "priority rests on unverified claims: cvss_score" in out["findings"][0]["review_reasons"]


def test_url_never_fetched_is_ungrounded(fake_sources):
    deps, ledger = _setup()
    f = good_finding()
    f["claims"]["cvss_score"]["source_url"] = "https://example.com/looks-legit"
    f["claims"]["summary"]["source_url"] = OSV + "GHSA-zzzz-zzzz-zzzz"
    out = check_report({"findings": [f], "remediations": []}, ledger, deps)
    st = _statuses(out)["CVE-2020-0001"]
    assert st["cvss_score"] == "ungrounded" and st["summary"] == "ungrounded"


def test_real_url_about_a_different_vuln_is_ungrounded(fake_sources):
    deps, ledger = _setup()
    f = good_finding()
    # Cite the NVD page of the *other* CVE, which was fetched in this scan.
    f["claims"]["cvss_score"] = {"value": 5.3, "source_url": NVD + "CVE-2021-0002"}
    out = check_report({"findings": [f], "remediations": []}, ledger, deps)
    c = out["findings"][0]["claims"]["cvss_score"]
    assert c["status"] == "ungrounded" and "not about this vulnerability" in c["reason"]


def test_value_without_source_is_unsourced(fake_sources):
    deps, ledger = _setup()
    f = good_finding()
    f["claims"]["in_kev"]["source_url"] = None
    out = check_report({"findings": [f], "remediations": []}, ledger, deps)
    assert _statuses(out)["CVE-2020-0001"]["in_kev"] == "unsourced"


def test_null_value_means_unknown_and_goes_to_review(fake_sources):
    deps, ledger = _setup(enrich=False)  # agent never called NVD
    f = good_finding()
    f["claims"]["cvss_score"] = {"value": None, "source_url": None}
    f["claims"]["cvss_severity"] = {"value": None, "source_url": None}
    f["claims"]["in_kev"] = {"value": None, "source_url": None}
    f["claims"]["epss"] = {"value": None, "source_url": None}
    f["priority_basis"] = ["summary"]
    out = check_report({"findings": [f], "remediations": []}, ledger, deps)
    s = out["stats"]
    assert s["unknown"] == 4 and s["unsourced"] == s["ungrounded"] == s["mismatch"] == 0
    assert out["findings"][0]["status"] == "needs_review"
    assert out["findings"][0]["reference_priority"] is None


def test_invented_vulnerability_is_rejected(fake_sources):
    deps, ledger = _setup()
    fake = good_finding(vuln_id="CVE-2099-9999")
    out = check_report({"findings": [fake], "remediations": []}, ledger, deps)
    assert out["findings"] == []
    assert len(out["rejected_findings"]) == 1
    assert out["stats"]["ungrounded"] == 6
    # ...and the real issues it failed to report come back as omitted.
    assert {o["vuln_id"] for o in out["omitted"]} == {"CVE-2020-0001", "CVE-2021-0002"}


def test_wrong_installed_version_is_rejected(fake_sources):
    deps, ledger = _setup()
    f = good_finding(installed_version="1.1")  # 1.1 is not what is installed / queried
    out = check_report({"findings": [f], "remediations": []}, ledger, deps)
    assert out["stats"]["findings_rejected"] == 1


def test_duplicate_finding_is_rejected(fake_sources):
    deps, ledger = _setup()
    out = check_report({"findings": [good_finding(), copy.deepcopy(good_finding())], "remediations": []}, ledger, deps)
    assert out["stats"]["findings_accepted"] == 1
    assert "duplicate" in out["rejected_findings"][0]["reason"]


def test_unqueried_dependency_is_looked_up_and_reported(fake_sources):
    deps = parse_requirements("demo==1.0\n")
    ledger = Ledger("PyPI")  # agent queried nothing
    out = check_report({"findings": [], "remediations": []}, ledger, deps)
    assert out["unqueried_dependencies"] == ["demo@1.0"]
    assert len(out["omitted"]) == 2


def test_fixed_versions_must_match_osv(fake_sources):
    deps, ledger = _setup()
    f = good_finding()
    f["claims"]["fixed_versions"]["value"] = ["1.0.5"]
    out = check_report({"findings": [f], "remediations": []}, ledger, deps)
    assert _statuses(out)["CVE-2020-0001"]["fixed_versions"] == "mismatch"


def test_remediation_checks(fake_sources):
    deps, ledger = _setup()
    rems = [
        {"package": "demo", "current_version": "1.0", "recommended_version": "1.2",
         "resolves": ["CVE-2020-0001", "CVE-2021-0002"], "note": ""},
        {"package": "demo", "current_version": "1.0", "recommended_version": "1.1",
         "resolves": ["CVE-2020-0001", "CVE-2021-0002"], "note": ""},
        {"package": "demo", "current_version": "1.0", "recommended_version": "9.9.9",
         "resolves": ["CVE-2020-0001"], "note": ""},
        {"package": "demo", "current_version": "1.0", "recommended_version": None, "resolves": [], "note": ""},
    ]
    out = check_report({"findings": _both_findings(), "remediations": rems}, ledger, deps)
    st = [r["status"] for r in out["remediations"]]
    assert st == ["verified", "partial", "needs_review", "needs_review"]
    assert out["remediations"][1]["still_affected_by"] == ["CVE-2021-0002"]
    assert "not a fixed version named" in out["remediations"][2]["reason"]


def test_baseline_passes_its_own_checker(fake_sources):
    deps = parse_requirements("demo==1.0\nsafe==2.0\nloose>=1\n")
    ledger = Ledger("PyPI")
    out = check_report(build_baseline_report(deps, ledger), ledger, deps)
    assert out["stats"]["verified"] == out["stats"]["claims_total"] == 12
    assert out["remediations"][0]["recommended_version"] == "1.2"
    assert out["remediations"][0]["status"] == "verified"
    assert out["unresolved_dependencies"][0]["dependency"] == "loose>=1"
    assert [f["priority"] for f in out["findings"]] == ["P1", "P3"]


def test_rubric():
    assert reference_priority(5.0, True, 0.0) == "P1"
    assert reference_priority(9.8, False, 0.2) == "P1"
    assert reference_priority(9.8, False, 0.01) == "P2"
    assert reference_priority(None, False, 0.3) == "P2"
    assert reference_priority(6.1, False, 0.99) == "P1"  # very likely exploited
    assert reference_priority(5.5, False, 0.01) == "P3"
    assert reference_priority(2.0, False, None) == "P4"
    assert reference_priority(None, False, 0.01) is None
