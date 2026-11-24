import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest
from jsonschema import ValidationError

from triage.models import Anomaly, Finding, PriorityResult, Remediation, TriageBundle, Verdict, Vulnerability
from triage.output import RunLog, render_pdf, validate_cyclonedx, write_cyclonedx
from triage.output._common import write_artifact
from triage.output.report_pdf import _context, _engines


@pytest.fixture
def bundle():
    bundle = TriageBundle.model_validate_json(
        (Path(__file__).parent / "fixtures" / "finals" / "output_bundle.json").read_text(encoding="utf-8")
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
            hints={"evidence_ids": ["lookup-0001"]},
            verdict=Verdict(
                state=state,
                justification="code_not_reachable" if state == "not_affected" else "",
                rationale_ko="설정에서 실행 조건을 확인했습니다.",
                item_results=[{
                    "item_key": "config", "status": "met", "evidence_ids": ["evidence-0001", "lookup-0002"],
                }],
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


@pytest.mark.skipif(os.name != "posix", reason="POSIX 파일 권한 검사")
@pytest.mark.parametrize(("mask", "mode"), [(0, 0o644), (0o027, 0o640)])
def test_atomic_artifact_respects_umask_on_replace(tmp_path, mask, mode):
    out = tmp_path / "artifact"
    out.write_bytes(b"before")
    out.chmod(0o600)
    previous = os.umask(mask)
    try:
        write_artifact(out, b"after")
    finally:
        os.umask(previous)
    assert out.read_bytes() == b"after"
    assert stat.S_IMODE(out.stat().st_mode) == mode


def _pdf_text(bundle, out, **meta):
    pdftotext = shutil.which("pdftotext")
    if not pdftotext:
        pytest.skip("pdftotext가 설치되어 있지 않습니다.")
    try:
        import weasyprint  # noqa: F401
    except OSError as error:
        pytest.skip(f"WeasyPrint 네이티브 라이브러리를 불러올 수 없습니다. {error}")
    evidence = render_pdf(bundle, {"name": "한글 예제 프로젝트", **meta}, out)
    assert [item.id for item in evidence] == ["pdf-0001"]
    return subprocess.check_output([pdftotext, "-enc", "UTF-8", str(out), "-"], encoding="utf-8")


@pytest.fixture
def missing_weasyprint(monkeypatch):
    def unavailable(_page):
        raise OSError("Pango DLL unavailable")

    monkeypatch.setattr(_engines, "_render_weasyprint", unavailable)


@pytest.mark.parametrize(("configured_timeout", "timeout"), [(None, 240), ("45", 45)])
def test_pdf_uses_chromium_with_temporary_profile(
    bundle, tmp_path, monkeypatch, missing_weasyprint, configured_timeout, timeout,
):
    browser = tmp_path / "example browser" / "example-chromium.exe"
    scratch_parent = tmp_path / "system-temp"
    scratch_parent.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch_parent))
    if configured_timeout is None:
        monkeypatch.delenv("SBOMTRIAGE_PDF_TIMEOUT", raising=False)
    else:
        monkeypatch.setenv("SBOMTRIAGE_PDF_TIMEOUT", configured_timeout)
    times = iter((10.0, 10.125, 12.5))
    monkeypatch.setattr(_engines, "perf_counter", lambda: next(times))
    monkeypatch.setenv("SBOMTRIAGE_PDF_BROWSER", str(browser))
    monkeypatch.setattr(_engines.shutil, "which", lambda name: str(browser) if name == str(browser) else None)
    out = tmp_path / "output" / "result.pdf"
    content = b"%PDF-1.7\n"
    events = []
    scratch = []

    def run(arguments, **options):
        assert arguments[0] == str(browser)
        assert "--headless=new" in arguments
        assert "--no-pdf-header-footer" in arguments
        assert options["timeout"] == timeout
        pdf = Path(next(value for value in arguments if value.startswith("--print-to-pdf=")).split("=", 1)[1])
        profile = Path(next(value for value in arguments if value.startswith("--user-data-dir=")).split("=", 1)[1])
        assert profile.parent == pdf.parent
        assert pdf.parent.parent == scratch_parent
        scratch.append(pdf.parent)
        html = pdf.with_suffix(".html")
        assert arguments[-1] == html.as_uri()
        assert "NotoSansKR.ttf" in html.read_text(encoding="utf-8")
        pdf.write_bytes(content)

    def event(stage, name, **data):
        events.append((stage, name, data))

    monkeypatch.setattr(_engines.subprocess, "run", run)
    evidence, = render_pdf(bundle, {}, out, log=event)
    assert out.read_bytes() == content
    assert scratch and not scratch[0].exists()
    assert evidence.id == "pdf-0001"
    assert "chromium:example-chromium.exe" in evidence.note
    assert str(browser.parent) not in evidence.note
    assert events == [("pdf", "engine", {
        "engine": "chromium:example-chromium.exe", "weasyprint_seconds": 0.125, "browser_seconds": 2.375,
    })]


def test_chromium_returns_pdf_when_profile_cleanup_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    original_unlink = os.unlink
    failed = []
    content = b"%PDF-1.7\n"

    def run(arguments, **options):
        profile = Path(next(value for value in arguments if value.startswith("--user-data-dir=")).split("=", 1)[1])
        profile.mkdir()
        (profile / "locked-profile-file").write_bytes(b"locked")
        (profile.parent / "report.pdf").write_bytes(content)

    def locked_unlink(path, *args, **kwargs):
        if Path(path).name == "locked-profile-file":
            failed.append(path)
            raise PermissionError("프로필 파일 사용 중")
        return original_unlink(path, *args, **kwargs)

    with monkeypatch.context() as mocks:
        mocks.setattr(_engines.subprocess, "run", run)
        mocks.setattr(os, "unlink", locked_unlink)
        assert _engines._print_chromium("<html></html>", tmp_path / "example.exe") == content
    assert failed


@pytest.mark.parametrize("browser_exists", [False, True])
def test_pdf_reports_unavailable_engines(bundle, tmp_path, monkeypatch, missing_weasyprint, browser_exists):
    browser = tmp_path / "example-chromium.exe" if browser_exists else None
    monkeypatch.setattr(_engines, "_find_browser", lambda: browser)

    def timeout(*args):
        raise subprocess.TimeoutExpired(str(browser), 240)

    monkeypatch.setattr(_engines, "_print_chromium", timeout)
    out = tmp_path / "report.pdf"
    with pytest.raises(OSError, match="WeasyPrint 라이브러리와 Edge/Chrome을 찾지 못함") as error:
        render_pdf(bundle, {}, out)
    assert str(tmp_path) not in str(error.value)
    assert ("TimeoutExpired" if browser_exists else "(OSError)") in str(error.value)
    assert not out.exists()


def test_chromium_pdf_extracts_korean_and_evidence_location(bundle, tmp_path, missing_weasyprint):
    browser = _engines._find_browser()
    pdftotext = shutil.which("pdftotext")
    if browser is None or pdftotext is None:
        pytest.skip("Chromium 계열 브라우저와 pdftotext가 필요합니다.")
    out = tmp_path / "report.pdf"
    evidence, = render_pdf(bundle, {"name": "한글 예제 프로젝트"}, out)
    assert f"chromium:{browser.name}" in evidence.note
    text = subprocess.check_output([pdftotext, "-enc", "UTF-8", str(out), "-"], encoding="utf-8")
    assert "취약점 조치 보고서" in text
    assert "한글 예제 프로젝트" in text
    assert "app-settings.json:3-5" in text


def test_pdf_groups_rule_deferred_candidates_with_shared_source_evidence(bundle):
    first = bundle.findings[2]
    first.verdict.decided_by = "rule:insufficient_evidence"
    first.verdict.item_results[0].evidence_ids = ["evidence-0001", "lookup-0001"]
    second = first.model_copy(deep=True)
    second.key = "finding-3"
    second.vulnerability.id = "FIXTURE-3"
    second.hints["evidence_ids"] = ["lookup-0002"]
    second.verdict.item_results[0].evidence_ids = ["evidence-0001", "lookup-0002"]
    bundle.findings = [first, second]

    context = _context(bundle, {})
    assert len(context["summaries"]) == 2
    detail, = context["details"]["undetermined"]
    assert detail["identifiers"] == ["FIXTURE-2", "FIXTURE-3"]
    assert detail["missing_info"][0]["where"] == "app-settings.json:3-5"
    assert {ref for item in context["decision_evidence"] for ref in item["ids"]} == {
        "evidence-0001", "lookup-0001", "lookup-0002",
    }


def test_pdf_extracts_korean_report_and_work_request(bundle, tmp_path):
    bundle.anomalies.append(Anomaly(kind="stage_failure", message="judge 단계 실패 (RuntimeError)."))
    bundle.findings[1].verdict.rationale_ko = ""
    bundle.findings[1].verdict.item_results[0].reason = "배포 설정에 해당 입력이 없습니다."
    bundle.findings[0].vulnerability.references.extend([
        "https://osv.dev/vulnerability/fixture-note",
        "https://github.com/advisories/fixture-note",
        "https://docs.example.com/additional-reference",
    ])
    extracted = _pdf_text(bundle, tmp_path / "report.pdf", lookup_sources=[
        {"name": "lookup.example.com", "retrieved_at": "2026-01-03T12:00:00Z"},
    ])
    first_page, _, following = extracted.partition("\f")
    summary = " ".join(first_page.split())
    assert "1. 점검 대상·범위" in following
    assert "1. 점검 대상·범위" not in summary
    text = " ".join(extracted.split())
    for phrase in (
        "취약점 조치 보고서", "한글 예제 프로젝트", "영향 있음", "영향 없음", "판단 유보",
        "조치 항목 및 우선순위", "검증 계획", "업무 요청 초안", "받는 팀 운영팀",
        "운영 설정을 확인해 주세요.", "잠금 파일을 갱신합니다.", "evidence-0001",
    ):
        assert phrase in text
    assert "sensitive-fixture" not in text
    assert "javascript:bad" not in text
    main, _, appendix = text.partition("부록 · 판정 근거 목록")
    assert "app-settings.json:3-5" in main
    assert "fixture_mode = true fixture_checks = true" in main
    assert "fixture_extra" not in text
    assert "requirements-fixture.txt:1-2" in main
    assert "https://lookup.example.com/fixture-note" in main
    citations = appendix.split("부록 · 추가 참고 링크", 1)[0]
    assert "app-settings.json:3-5 [evidence-0001]" in citations
    assert "https://lookup.example.com/fixture-note [lookup-0002]" in citations
    for unrelated in ("collect-0001", "collect-0002", "scope-0001", "lookup-0001", "pdf-0001"):
        assert unrelated not in citations
    assert "unreferenced.fixture" not in text

    assert "오늘 할 일 1개 · 영향 있음 1 · 확인 필요 1 · 영향 없음 1" in summary
    assert "fixture-parser@1.0 업그레이드 · 관련 취약점 2건" in summary
    assert "목표 버전 1.2 · P1" in summary
    for phrase in ("무엇을", "왜", "어떻게", "확인", "잠금 파일을 갱신합니다.", "재점검 전", "uv run triage scan"):
        assert phrase in summary
    assert "FIXTURE-1" not in summary
    assert "FIXTURE-2" not in summary
    assert "점검 일부 실패: judge" in summary
    assert "stage_failure · judge 단계 실패 (RuntimeError)." in main
    assert "lock_mismatch · 총 3건 · 대표 사례 첫 번째 고정 버전이 다릅니다. requirements-fixture.txt:1-2" in main
    assert "lock_mismatch · 두 번째 고정 버전이 다릅니다." in main
    assert "missing_metadata · 구성요소 식별 정보가 없습니다." in main
    assert "점검 대상·범위" in main
    assert "생태계 pypi · 구성요소 2개" in main
    assert "배포 폴더 요약" in main
    assert "배포됨 1개 파일 / 미배포 0개" in main
    assert "배포됨 0개 파일 / 미배포 1개" in main
    assert "Containerfile.fixture:8" in main
    assert "확인 위치 app-settings.json:3-5" in main
    assert "https://osv.dev/vulnerability/fixture-note" in main
    assert "https://github.com/advisories/fixture-note" in main
    assert "docs.example.com" not in main
    assert "docs.example.com" in appendix
    assert "영향 없음 상세" not in main
    assert "배포 설정에 해당 입력이 없습니다." in main
    for phrase in ("test · entry_check.py", "legacy · entry.py", "script · local.py",
                   "generated · model.py", "vendored_bundle · fixture.min.js"):
        assert phrase in appendix
    for phrase in ("lookup.example.com", "2026-01-03T12:00:00Z", "2026-01-02"):
        assert phrase in main


@pytest.mark.parametrize("only_not_affected", [False, True])
def test_pdf_explicitly_describes_no_action_states(bundle, only_not_affected, tmp_path):
    bundle.findings = [bundle.findings[1]] if only_not_affected else []
    text = " ".join(_pdf_text(bundle, tmp_path / "report.pdf").split())
    assert "먼저 확인할 것" in text
    assert "오늘 할 일 0개 · 영향 있음 0" in text
    assert "이번 점검에서 확인된 조치 대상이 없습니다." in text
    expected = "모두 영향 없음으로 판정했습니다." if only_not_affected else "취약점 후보가 0건입니다."
    assert expected in text


def test_pdf_uses_same_actions_in_summary_plan_and_verification(tmp_path):
    from triage.actions import build_actions

    fixture = Path(__file__).parent / "fixtures/finals/action_bundle.json"
    bundle = TriageBundle.model_validate_json(fixture.read_text(encoding="utf-8"))
    # 네 번째 카드는 3·4절에는 있고 첫머리에는 없어야 한다.
    extra = bundle.findings[2].model_copy(deep=True)
    extra.key = "separate-component"
    extra.component.id = "pkg:pypi/another@1"
    extra.component.name = "another"
    extra.vulnerability.id = "FIXTURE-EXTRA"
    bundle.findings.append(extra)
    actions = build_actions(bundle)
    assert len(actions) == 4
    extracted = _pdf_text(bundle, tmp_path / "report.pdf")
    top = " ".join(extracted.split("\f", 1)[0].split())
    assert "먼저 고칠 것 3개" in top
    assert "오늘 할 일 4개" in top
    assert "다시 실행" in top and "uv run triage scan" in top
    text = " ".join(extracted.split())
    decisions, rest = text.split("2. 취약점 후보별 판정 및 근거", 1)[1].split("3. 조치 항목 및 우선순위", 1)
    plan, verification = rest.split("4. 검증 계획", 1)
    verification = verification.split("5. 점검 한계", 1)[0]
    assert all(f.vulnerability.id in decisions for f in bundle.findings)
    assert actions[-1].title not in top
    for section in (top, plan, verification):
        expected = actions[:3] if section == top else actions
        positions = [section.index(a.title) for a in expected]
        assert positions == sorted(positions)
    for section in (plan, verification):
        assert section.count("할 일 ") == len(actions)
        for idx, action in enumerate(actions, 1):
            card = section.split(f"할 일 {idx} · ", 1)[1].split("할 일 ", 1)[0]
            for key in action.findings:
                assert bundle.finding(key).vulnerability.id in card
            if action.target:
                assert f"목표 버전 후보 {action.target} (확인 필요)" in card
            assert all(ref in card for ref in action.evidence_ids)
    assert "활성 옵션 · 확인 위치 배포 설정" in verification


def test_pdf_marks_assumption_conditions_as_premise(bundle, tmp_path, monkeypatch):
    import triage.output.report_pdf as report
    from triage.models import ItemResult

    pages = []
    monkeypatch.setattr(report, "render_with_engine", lambda page: (pages.append(page), b"%PDF-1.4", "fake", {})[1:])
    bundle.findings[0].verdict.item_results.append(
        ItemResult(item_key="attacker_network_position", status="assumed", reason="운영 환경 전제"))
    render_pdf(bundle, {}, tmp_path / "report.pdf")
    assert "attacker_network_position · 전제" in pages[0]
def test_summary_uses_matching_edits_and_scan_wide_check(tmp_path):
    fixture = Path(__file__).parent / "fixtures/finals/action_bundle.json"
    bundle = TriageBundle.model_validate_json(fixture.read_text(encoding="utf-8"))
    component = bundle.components[0].id
    bundle.meta.update(
        fix_plan=[
            {"component": component, "target": "1.8", "findings": ["finding-1", "finding-2"],
             "kind": "change", "file": "deps.toml", "line": 7, "before": 'lib = "<1.1"',
             "after": 'lib = "1.8"', "evidence_ids": ["E1"]},
            {"component": bundle.components[1].id, "target": "4.8.10", "findings": ["finding-4"],
             "kind": "change", "file": "container/Dockerfile", "line": 2,
             "before": "FROM old-image  # " + "긴 원본 주석 " * 20,
             "after": "FROM new-image  # " + "긴 원본 주석 " * 20, "evidence_ids": ["E2"]},
            {"component": component, "target": "", "findings": ["finding-3"], "kind": "manual",
             "reason": "상위 패키지 선언을 먼저 확인하세요."},
        ],
        fix_check={"status": "ok", "reason": None, "before_candidates": 7, "after_candidates": 6,
                   "resolved": ["finding-1", "finding-2"], "remaining": list("abcde"), "new": ["f"]},
    )
    pages = _pdf_text(bundle, tmp_path / "report.pdf", label="sample", scan_source="src dir",
                      scan_offline=True).split("\f")
    cover = " ".join(pages[0].split())
    first, rest = cover.split("2. 기반 이미지")
    assert 'deps.toml:7 lib = "<1.1" → lib = "1.8"' in first
    assert "deps.toml" not in rest
    assert "변경안 목표 1.8" in first
    assert "3절 할 일 2의 변경 원문 참조" in rest
    assert "FROM old-image" in " ".join(pages[1:])
    assert "FROM new-image" in " ".join(pages[1:])
    assert "수동 확인 · 상위 패키지 선언을 먼저 확인하세요." in rest
    assert "전체 후보 · 해소 2건 · 남음 5건 · 새로 생김 1건" in cover
    assert cover.count("uv run triage scan --offline -- sample 'src dir' out/recheck") == 3
    assert "입력 이상" in pages[1]


@pytest.mark.parametrize("status", ["skipped", "unavailable"])
def test_unavailable_fix_check_does_not_claim_zero_candidates(bundle, status):
    bundle.meta["fix_check"] = {"status": status, "reason": "대상 버전 미확인",
                                "resolved": [], "remaining": [], "new": []}
    assert _context(bundle, {})["check_summary"] == "대상 버전 미확인"
