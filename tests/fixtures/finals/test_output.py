import json
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import ValidationError

from triage.models import Finding, PriorityResult, Remediation, TriageBundle, Verdict, Vulnerability
from triage.output import RunLog, render_pdf, validate_cyclonedx, write_cyclonedx


@pytest.fixture
def bundle():
    bundle = TriageBundle.model_validate_json(
        Path(__file__).with_name("output_bundle.json").read_text(encoding="utf-8")
    )
    for index, state in enumerate(("affected", "not_affected", "undetermined")):
        component = bundle.components[1 if state == "not_affected" else 0]
        finding = Finding(
            key=f"finding-{index}", component=component, vulnerability=Vulnerability(
                id=f"FIXTURE-{index}", severity="high", cvss_score=7.5, cvss_source="fixture-db",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                references=["https://example.com/advisories/fixture", "javascript:bad"],
                affected_ranges=["<1.2"], fixed_versions=["1.2"],
            ),
            verdict=Verdict(
                state=state,
                justification="code_not_reachable" if state == "not_affected" else "",
                rationale_ko="설정에서 실행 조건을 확인했습니다.",
                item_results=[{"item_key": "config", "status": "met", "evidence_ids": ["evidence-0001"]}],
                work_request={
                    "to_team": "운영팀", "title": "배포 범위 확인",
                    "body": "운영 설정을 확인해 주세요. password=sensitive-fixture",
                    "branches": ["활성화 상태에 따라 재판정합니다."],
                } if state == "undetermined" else None,
            ),
        )
        bundle.findings.append(finding)
    bundle.results.append(PriorityResult(finding_key="finding-0", tier="P1", score=9.0))
    bundle.remediations.append(Remediation(
        finding_key="finding-0", target_version="1.2", verified=True, steps=["잠금 파일을 갱신합니다."],
        verify_notes=["공개 권고문과 수정 버전을 대조했습니다."],
    ))
    return bundle


def test_cyclonedx_writes_valid_bom_and_vex(bundle, tmp_path):
    out = tmp_path / "result" / "sbom.json"
    evidence = write_cyclonedx(bundle, {"name": "예제 프로젝트", "version": "0.1"}, out)
    document = json.loads(out.read_text(encoding="utf-8"))
    validate_cyclonedx(document)
    assert [item.id for item in evidence] == ["cyclonedx-0001"]
    assert document["specVersion"] == "1.6"
    root = document["metadata"]["component"]
    assert root["name"] == "예제 프로젝트"
    assert root["version"] == "0.1"
    assert document["metadata"]["tools"]["components"][0]["name"] == "triage"
    first, second = document["components"]
    assert first["purl"] == bundle.components[0].purl
    assert first["scope"] == "required"
    assert second["scope"] == "excluded"
    assert {"name": "triage:module", "value": "fixtures"} in second["properties"]
    assert {"name": "triage:evidence_location", "value": "collect-0001 requirements-fixture.txt:1-2"} in first["properties"]
    graph = {edge["ref"]: edge["dependsOn"] for edge in document["dependencies"]}
    assert graph == {root["bom-ref"]: [first["bom-ref"]], first["bom-ref"]: [second["bom-ref"]], second["bom-ref"]: []}
    affected, excluded, unknown = document["vulnerabilities"]
    assert [item["analysis"]["state"] for item in (affected, excluded, unknown)] == [
        "exploitable", "not_affected", "in_triage",
    ]
    assert excluded["analysis"]["justification"] == "code_not_reachable"
    assert "evidence-0001" in affected["analysis"]["detail"]
    assert excluded["affects"] == [{"ref": second["bom-ref"]}]
    assert affected["ratings"][0]["score"] == 7.5
    assert affected["ratings"][0]["method"] == "CVSSv31"
    assert affected["advisories"] == [{"url": "https://example.com/advisories/fixture"}]


def test_schema_checks_official_spdx_ref_and_invalid_output(bundle, tmp_path):
    out = tmp_path / "sbom.json"
    write_cyclonedx(bundle, {}, out)
    document = json.loads(out.read_text(encoding="utf-8"))
    document["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]
    validate_cyclonedx(document)
    document["components"][0]["licenses"] = [{"license": {"id": "not-an-spdx-id"}}]
    with pytest.raises(ValidationError):
        validate_cyclonedx(document)
    bundle.findings[0].verdict.justification = "non-standard"
    before = out.read_bytes()
    with pytest.raises(ValidationError):
        write_cyclonedx(bundle, {}, out)
    assert out.read_bytes() == before


def test_no_verdict_does_not_turn_a_scanner_candidate_into_an_affected_verdict(bundle, tmp_path):
    bundle.findings[0].verdict = None
    out = tmp_path / "sbom.json"
    write_cyclonedx(bundle, {}, out)
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_runlog_redacts_nested_values_and_aggregates_totals(tmp_path, monkeypatch):
    monkeypatch.setenv("FIXTURE_API_KEY", "fixture-environment-value")
    out = tmp_path / "result" / "run.jsonl"
    log = RunLog(out)
    log.emit("lookup", "retry", number=1, message="fixture-environment-value",
             request={"apiKey": "cleartext-fixture", "headers": {"Authorization": "Bearer fixture-header"}})
    log.emit("judge", "decided", decided_at="2026-01-01T00:00:00Z",
             command="GET https://some-user:some-pass@example.com/?token=query-value")
    log.add_usage(prompt_tokens=10, completion_tokens=5, reasoning_tokens=2)
    log.add_usage({"total_tokens": 3})
    assert [item.id for item in log.close()] == ["runlog-0001"]
    log.close()
    with pytest.raises(ValueError):
        log.emit("lookup", "result")
    raw = out.read_text(encoding="utf-8")
    for value in ("fixture-environment-value", "cleartext-fixture", "fixture-header", "some-pass", "query-value"):
        assert value not in raw
    retry, decision, summary = (json.loads(line) for line in raw.splitlines())
    assert (retry["stage"], retry["event"], retry["data"]["number"]) == ("lookup", "retry", 1)
    assert decision["data"]["decided_at"] == "2026-01-01T00:00:00Z"
    assert (summary["stage"], summary["event"]) == ("run", "end")
    assert summary["data"]["total_tokens"] == 18
    assert summary["data"]["reported_reasoning_tokens"] == 2
    assert summary["data"]["total_seconds"] >= 0


@pytest.mark.parametrize("usage", [[], [7, None]])
def test_runlog_explains_unavailable_tokens(usage, tmp_path):
    out = tmp_path / "run.jsonl"
    with RunLog(out) as log:
        for value in usage:
            log.add_usage(value)
    summary = json.loads(out.read_text(encoding="utf-8").splitlines()[-1])
    assert summary["data"]["total_tokens"] == "측정 불가"
    assert summary["data"]["total_tokens_reason"]


def _pdf_text(bundle, out):
    pdftotext = shutil.which("pdftotext")
    if not pdftotext:
        pytest.skip("pdftotext가 설치되어 있지 않습니다.")
    try:
        import weasyprint  # noqa: F401
    except OSError as error:
        pytest.skip(f"WeasyPrint 네이티브 라이브러리를 불러올 수 없습니다. {error}")
    assert [item.id for item in render_pdf(bundle, {"name": "한글 예제 프로젝트"}, out)] == ["pdf-0001"]
    text = subprocess.check_output([pdftotext, "-enc", "UTF-8", str(out), "-"], encoding="utf-8")
    return " ".join(text.split())


def test_pdf_extracts_korean_report_and_work_request(bundle, tmp_path):
    text = _pdf_text(bundle, tmp_path / "report.pdf")
    for phrase in (
        "취약점 조치 보고서", "한글 예제 프로젝트", "영향 있음", "영향 없음", "판단 유보",
        "조치 항목 및 우선순위", "검증 계획", "업무 요청 초안", "받는 팀 운영팀",
        "운영 설정을 확인해 주세요.", "잠금 파일을 갱신합니다.", "evidence-0001",
    ):
        assert phrase in text
    assert "sensitive-fixture" not in text
    assert "javascript:bad" not in text


@pytest.mark.parametrize("only_not_affected", [False, True])
def test_pdf_explicitly_describes_no_action_states(bundle, only_not_affected, tmp_path):
    bundle.findings = [bundle.findings[1]] if only_not_affected else []
    text = _pdf_text(bundle, tmp_path / "report.pdf")
    assert "이번 점검에서 확인된 조치 대상이 없습니다." in text
    expected = "모두 영향 없음으로 판정했습니다." if only_not_affected else "취약점 후보가 0건입니다."
    assert expected in text
