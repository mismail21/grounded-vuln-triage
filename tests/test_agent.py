"""Agent loop tests with a scripted fake Claude client (no API calls)."""

from types import SimpleNamespace

from conftest import good_finding

from triage.agent import TOOLS, TriageAgent
from triage.parsers import parse_requirements


def _msg(blocks, stop="tool_use"):
    return SimpleNamespace(
        content=blocks,
        stop_reason=stop,
        usage=SimpleNamespace(input_tokens=100, output_tokens=50, cache_read_input_tokens=0,
                              cache_creation_input_tokens=0),
    )


def _tool(i, name, inp):
    return SimpleNamespace(type="tool_use", id=f"tu_{i}", name=name, input=inp)


class FakeClient:
    """Replays a fixed script of assistant turns and records what it was sent."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))

    def _stream(self, **kwargs):
        self.requests.append({**kwargs, "messages": list(kwargs["messages"])})  # snapshot
        msg = self.script.pop(0)

        class _Ctx:
            def __enter__(s):
                return SimpleNamespace(get_final_message=lambda: msg)

            def __exit__(s, *a):
                return False

        return _Ctx()


def _report(findings, remediations=None):
    return {"findings": findings, "remediations": remediations or [], "review_notes": []}


def test_agent_happy_path(fake_sources):
    deps = parse_requirements("demo==1.0\n")
    client = FakeClient([
        _msg([_tool(1, "osv_lookup", {"packages": [{"name": "demo", "version": "1.0"}]})]),
        _msg([
            _tool(2, "nvd_lookup", {"cve_ids": ["CVE-2020-0001"]}),
            _tool(3, "kev_lookup", {"cve_ids": ["CVE-2020-0001"]}),
            _tool(4, "epss_lookup", {"cve_ids": ["CVE-2020-0001"]}),
            _tool(5, "check_upgrade", {"package": "demo", "version": "1.1"}),
        ]),
        _msg([_tool(6, "submit_report", _report(
            [good_finding()],
            [{"package": "demo", "current_version": "1.0", "recommended_version": "1.1",
              "resolves": ["CVE-2020-0001"], "note": ""}],
        ))]),
    ])
    run = TriageAgent(client=client).run(deps)
    assert run.error is None
    assert run.turns == 3
    assert [t["tool"] for t in run.trace] == [
        "osv_lookup", "nvd_lookup", "kev_lookup", "epss_lookup", "check_upgrade", "submit_report"]
    s = run.checked["stats"]
    assert s["verified"] == 6 and s["unsupported_claim_rate"] == 0
    # The agent skipped CVE-2021-0002; the checker puts it back for review.
    assert [o["vuln_id"] for o in run.checked["omitted"]] == ["CVE-2021-0002"]
    # 1.1 still has CVE-2021-0002, so the upgrade is only a partial fix.
    assert run.checked["remediations"][0]["status"] == "partial"
    assert run.checked["remediations"][0]["still_affected_by"] == ["CVE-2021-0002"]
    # Request shape: adaptive thinking, effort, strict tools, fallbacks.
    req = client.requests[0]
    assert req["thinking"] == {"type": "adaptive"}
    assert req["fallbacks"] == "default"
    assert all(t.get("strict") for t in req["tools"] if t["name"] != "submit_report")
    # Tool results go back in a single user message, in order.
    second = client.requests[2]["messages"][4]
    assert second["role"] == "user" and len(second["content"]) == 4
    assert run.cost_usd > 0


def test_invalid_report_is_bounced_back_to_the_model(fake_sources):
    deps = parse_requirements("demo==1.0\n")
    bad = _report([{**good_finding(), "priority": "URGENT"}])
    client = FakeClient([
        _msg([_tool(1, "osv_lookup", {"packages": [{"name": "demo", "version": "1.0"}]})]),
        _msg([_tool(2, "submit_report", bad)]),
        _msg([_tool(3, "submit_report", _report([]))]),
    ])
    run = TriageAgent(client=client).run(deps)
    assert run.error is None
    last_results = client.requests[2]["messages"][-1]["content"]
    assert last_results[0]["is_error"] is True and "validation" in last_results[0]["content"]
    assert run.report == _report([])


def test_nudge_then_give_up(fake_sources):
    deps = parse_requirements("demo==1.0\n")
    text = SimpleNamespace(type="text", text="I think we are done.")
    client = FakeClient([_msg([text], "end_turn")] * 3)
    run = TriageAgent(client=client).run(deps)
    assert "without submitting" in run.error
    # Even when the agent fails, nothing is lost: OSV results are in the review list.
    assert len(run.checked["omitted"]) == 2


def test_refusal_is_reported(fake_sources):
    deps = parse_requirements("demo==1.0\n")
    msg = _msg([], "refusal")
    msg.stop_details = {"category": "cyber"}
    run = TriageAgent(client=FakeClient([msg])).run(deps)
    assert "declined" in run.error


def test_tool_failure_is_returned_as_error(fake_sources, monkeypatch):
    from triage import sources

    def boom(cve):
        raise RuntimeError("NVD down")

    monkeypatch.setattr(sources, "nvd_lookup", boom)
    deps = parse_requirements("demo==1.0\n")
    client = FakeClient([
        _msg([_tool(1, "nvd_lookup", {"cve_ids": ["CVE-2020-0001"]})]),
        _msg([_tool(2, "submit_report", _report([]))]),
    ])
    run = TriageAgent(client=client).run(deps)
    result = client.requests[1]["messages"][-1]["content"][0]
    assert result["is_error"] and "unknown" in result["content"]
    assert any("NVD down" in e for e in run.checked["errors"])


def test_submit_report_schema_is_closed():
    schema = next(t for t in TOOLS if t["name"] == "submit_report")["input_schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"findings", "remediations", "review_notes"}
