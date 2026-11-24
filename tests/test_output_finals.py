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
    except (ImportError, OSError):
        if _engines._find_browser() is None:
            pytest.skip("PDF 인쇄 엔진이 필요합니다.")
    evidence = render_pdf(bundle, {"name": "한글 예제 프로젝트", **meta}, out)
    assert [item.id for item in evidence] == ["pdf-0001"]
    return subprocess.check_output([pdftotext, "-raw", "-enc", "UTF-8", str(out), "-"], encoding="utf-8")


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


def packed(text):
    # 인쇄 엔진마다 글리프 사이 공백과 한글 줄바꿈이 다르다.
    return "".join(text.split())


def test_deferred_table_has_one_row_per_candidate_and_preserves_refs(bundle, tmp_path, monkeypatch):
    import triage.output.report_pdf as report

    first = bundle.findings[2]
    second = first.model_copy(deep=True)
    second.key, second.vulnerability.id = "finding-3", "FIXTURE-3"
    second.verdict.item_results[0].evidence_ids = ["lookup-0001"]
    bundle.findings = [first, second]
    pages = []
    monkeypatch.setattr(report, "render_with_engine", lambda page: (pages.append(page) or b"%PDF-1.4", "mock", {}))
    render_pdf(bundle, {}, tmp_path / "report.pdf")
    table = pages[0].split('id="pending-list"', 1)[1].split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert table.count("<tr>") == len(bundle.findings)
    assert all(table.count(f.vulnerability.id) == 1 for f in bundle.findings)
    ctx = _context(bundle, {})
    for row in ctx["summaries"]:
        assert row["sources"] == sorted({ctx["ref_numbers"][ref] for ref in row["refs"]})
    assert len(set(ctx["ref_numbers"].values())) == len(ctx["ref_numbers"])
    assert "조건별 목록" not in table and "<pre" not in table


def test_pdf_cover_required_sections_and_traceability(bundle, tmp_path):
    bundle.anomalies.append(Anomaly(kind="stage_failure", message="judge 단계 실패 (RuntimeError)."))
    bundle.findings[1].verdict.rationale_ko = ""
    bundle.findings[1].verdict.item_results[0].reason = "배포 설정에 해당 입력이 없습니다."
    bundle.findings[0].vulnerability.references.append("https://osv.dev/vulnerability/fixture-note")
    bundle.meta["fix_plan"] = [dict(kind="change", findings=["finding-0"], file="deps.txt", line=2,
                                   target="1.2", before="lib==1", after="lib==1.2", evidence_ids=["collect-0001"])]
    bundle.meta["fix_check"] = dict(status="ok", resolved=["finding-0"], remaining=["finding-1"], new=[])
    pages = [packed(p) for p in _pdf_text(bundle, tmp_path / "report.pdf", patch_name="fix-demo.patch",
                                          lookup_sources=[dict(name="공개 조회", retrieved_at="2026-01-03")]).split("\f") if p.strip()]
    assert len(pages) >= 5
    for phrase in ("한글 예제 프로젝트", "deps.txt 2행을 수정하세요. lib==1 → lib==1.2",
                   "오늘 할 일", "조치 보드", "연락할 부서", "다음 행동",
                   "지금 할 일", "git apply fix-demo.patch", "uv run triage scan", "후보 2건 → 1건", "점검 일부 실패"):
        assert packed(phrase) in pages[0]
    for phrase in ("바로 고칠 것", "왜 위험한가", "app-settings.json:3-5", "fixture_mode = true",
                   "FIXTURE-0", "영향 버전 범위", "<1.2", "lib==1 → lib==1.2"):
        assert packed(phrase) in pages[1]
    assert all(packed(s) in pages[2] for s in ("연락할 부서별 확인 요청", "운영팀", "운영 설정을 확인해 주세요.",
                                               "활성화 상태에 따라 재판정합니다."))
    assert all(packed(s) in pages[3] for s in ("적용·검증 계획", "적용 방법", "확인 방법", "재점검 명령", "회귀 테스트"))
    appendix = "".join(pages[4:])
    sections = ("여기부터는 판정 근거 확인용입니다", "부록 A · 점검 대상·범위", "부록 B · 전체 후보 판정표",
                "부록 C · 판단 유보 확인 목록", "부록 D · 영향 있음 판정 상세", "부록 E · 근거 목록과 배포 파일 목록")
    positions = [appendix.index(packed(section)) for section in sections]
    assert positions == sorted(positions)
    candidates = appendix[positions[2]:positions[3]]
    assert candidates.index("FIXTURE-0") < candidates.index("FIXTURE-2") < candidates.index("FIXTURE-1")
    assert all(packed(v) in appendix for v in ("배포 설정에 해당 입력이 없습니다.", "공개 조회", "2026-01-03",
                                              "Containerfile.fixture:8", "entry_check.py", "fixture.min.js",
                                              "두 번째 고정 버전이 다릅니다.", "구성요소 식별 정보가 없습니다."))
    evidence = appendix[positions[-1]:]
    assert all(ref in evidence for ref in ("[evidence-0001]", "[lookup-0001]", "[lookup-0002]", "[collect-0001]"))
    assert "fixture_mode" not in evidence and "unreferenced.fixture" not in appendix
    assert all(secret not in "".join(pages) for secret in ("sensitive-fixture", "javascript:bad"))


@pytest.mark.parametrize(("verified", "edit_target", "line", "expected"), [
    (False, "1.2", 8, "수정 버전을 먼저 확인하세요"),
    (True, "1.1", 8, "적용할 위치를 확인하세요"),
    (True, None, 8, "적용할 위치를 확인하세요"),
    (True, "1.2", None, "적용할 위치를 확인하세요"),
])
def test_pdf_cover_requires_a_verified_matching_edit(bundle, verified, edit_target, line, expected):
    bundle.remediations[0].verified = verified
    bundle.meta["fix_plan"] = [dict(kind="change", findings=["finding-0"], file="deps.txt", line=line,
                                    target=edit_target, before="old", after="new")]
    cover = _context(bundle, {})["conclusion"]
    assert expected in cover and "old → new" not in cover


def test_pdf_cover_for_pending_finding_starts_with_confirmation(bundle):
    finding = bundle.findings[2]
    bundle.findings = [finding]
    assert _context(bundle, {})["conclusion"] == "운영팀에 확인을 요청하세요. 배포 범위 확인"
    finding.verdict.work_request = None
    assert finding.component.display in _context(bundle, {})["conclusion"]


@pytest.mark.parametrize("only_not_affected", [False, True])
def test_pdf_explicitly_describes_no_action_states(bundle, only_not_affected, tmp_path):
    bundle.findings = [bundle.findings[1]] if only_not_affected else []
    pages = _pdf_text(bundle, tmp_path / "report.pdf").split("\f")
    expected = "모두 영향 없음으로 판정했습니다." if only_not_affected else "취약점 후보가 0건입니다."
    assert packed(expected) in packed(pages[0])
    assert packed("이번 점검에서 확인된 조치 대상이 없습니다.") in packed(pages[0])
    assert packed("바로 고칠 것 없음") in packed(pages[1])


def test_developer_section_stays_four_pages_with_long_inputs(bundle, tmp_path):
    from triage.models import WorkRequest

    base = bundle.findings[0]
    bundle.findings = []
    for i in range(24):
        f = base.model_copy(deep=True)
        f.key = f.component.id = f"component-{i}"
        f.component.name = "아주긴구성요소" * 40 + str(i)
        f.vulnerability.id = f"FIXTURE-{i}"
        f.verdict.work_request = WorkRequest(to_team=f"부서 {i}", title="확인 요청", body="조건을 확인해 주세요. " * 40,
                                             branches=["해당하면 버전을 변경합니다. " * 20] * 3)
        bundle.findings.append(f)
    pages = _pdf_text(bundle, tmp_path / "report.pdf", label="긴 이름" * 30, scan_source="긴 경로" * 50).split("\f")
    assert packed("지금 할 일") in packed(pages[0])
    assert packed("외 16개는 부록 A") in packed(pages[0])
    assert packed("바로 고칠 것") in packed(pages[1])
    assert packed("연락할 부서별 확인 요청") in packed(pages[2])
    assert packed("테스트 확인 항목") in packed(pages[3])
    assert packed("여기부터는 판정 근거 확인용입니다") in packed(pages[4])
    assert len(_context(bundle, {})["board"]) == 24


def test_pdf_marks_assumption_conditions_as_premise(bundle):
    from triage.models import ItemResult
    bundle.findings[0].verdict.item_results.append(ItemResult(item_key="environment", status="assumed", reason="운영 전제"))
    ctx = _context(bundle, {})
    condition = ctx["groups"]["affected"][0]["conditions"][-1]
    assert condition["item_key"] == "environment" and ctx["conditions"][condition["status"]] == "전제"


@pytest.mark.parametrize("status", ["skipped", "unavailable"])
def test_unavailable_fix_check_does_not_claim_zero_candidates(bundle, status):
    bundle.meta["fix_check"] = {"status": status, "reason": "대상 버전 미확인", "resolved": [], "remaining": [], "new": []}
    assert _context(bundle, {})["check_summary"] == "대상 버전 미확인"
