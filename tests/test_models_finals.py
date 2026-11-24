"""본선 확장 구조가 직렬화·역직렬화되고 기존 기본값을 깨지 않는지 확인."""
from triage.models import Component, Evidence, Finding, Verdict, Vulnerability, WorkRequest, TriageBundle


def test_component_defaults_keep_scanner_path():
    c = Component(id="pkg:npm/a@1.0.0", name="a", version="1.0.0")
    assert c.kind == "library" and c.deployed == "unknown" and c.evidence_ids == []


def test_finding_with_verdict_roundtrip():
    c = Component(id="pkg:maven/x/y@1", name="y", version="1", deployed="yes", evidence_ids=["E1"])
    v = Vulnerability(id="CVE-0000-0001")
    f = Finding(key=Finding.make_key(v.id, c.id, None), component=c, vulnerability=v,
                verdict=Verdict(state="undetermined", decided_by="model:test",
                                work_request=WorkRequest(to_team="인프라", title="t", body="b", branches=["A면 영향 없음"])))
    b = TriageBundle(components=[c], findings=[f], evidence=[Evidence(id="E1", kind="lockfile", file="pom.xml", line_start=3)])
    again = TriageBundle.model_validate_json(b.model_dump_json())
    assert again.findings[0].verdict.work_request.to_team == "인프라"
    assert again.evidence[0].line_start == 3
