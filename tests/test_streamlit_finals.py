import importlib
import inspect
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from stat import S_IFLNK
from threading import Event, get_ident
from types import ModuleType, SimpleNamespace
from xml.etree import ElementTree
from zipfile import ZipFile, ZipInfo

import pytest
from streamlit.testing.v1 import AppTest

from triage.actions import build_actions
from triage.models import Anomaly, Remediation, TriageBundle


APP = Path(__file__).resolve().parents[1] / "app" / "streamlit_app.py"
SOURCE = Path(__file__).parent / "fixtures" / "finals" / "streamlit-source"


@pytest.fixture(autouse=True)
def ui(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(APP.parent.parent))
    module = importlib.import_module("app.streamlit_app")
    monkeypatch.setattr(module, "WEB_RESULTS", tmp_path / "out" / "web")
    return module


def run_app(timeout=60):
    return AppTest.from_string("from app.streamlit_app import main\nmain()", default_timeout=timeout).run()


def open_files_tab(app):
    app.session_state["result_view"] = "보고서·파일"
    app.run()


def overview_element(app):
    overview, = [item for item in app.html if 'aria-label="점검 요약"' in item.value]
    return overview


def overview_counts(app):
    overview = ElementTree.fromstring(overview_element(app).value.strip())
    return {pair.findtext("dt"): "".join(pair.find("dd").itertext())
            for pair in overview.iter() if pair.find("dt") is not None}


def archive_with(name, contents=b"demo"):
    upload = BytesIO()
    with ZipFile(upload, "w") as archive:
        archive.writestr(name, contents)
    upload.size = upload.tell()
    return upload


@pytest.mark.parametrize("name", ["../escaped", "wrapper/../../escaped", r"..\escaped",
                                  "C:/escaped", "/escaped", "a.txt:hidden", "NUL.txt"])
def test_zip_rejects_unsafe_paths(ui, tmp_path, name):
    with pytest.raises(ValueError, match="경로"):
        ui.extract_zip(archive_with(name), tmp_path / "source")
    assert not (tmp_path / "escaped").exists()


def test_zip_rejects_symlink_and_size_limits(ui, tmp_path, monkeypatch):
    link = ZipInfo("link")
    link.create_system = 3
    link.external_attr = (S_IFLNK | 0o777) << 16
    with pytest.raises(ValueError, match="특수 파일"):
        ui.extract_zip(archive_with(link), tmp_path / "source")
    monkeypatch.setattr(ui, "ZIP_EXPANDED_LIMIT", 3)
    with pytest.raises(ValueError, match="초과"):
        ui.extract_zip(archive_with("file.txt"), tmp_path / "source")
    monkeypatch.setattr(ui, "ZIP_UPLOAD_LIMIT", 1)
    with pytest.raises(ValueError, match="올릴 수"):
        ui.extract_zip(archive_with("file.txt"), tmp_path / "source")


def test_zip_uses_single_wrapper_as_scan_root(ui, tmp_path):
    root = ui.extract_zip(archive_with("wrapper/file.txt"), tmp_path / "source")
    assert root == tmp_path / "source" / "wrapper"
    assert (root / "file.txt").read_bytes() == b"demo"


def submit_server_path(app, root, *, offline=False):
    app.text_input[0].set_value("테스트 서비스")
    app.text_input[1].set_value(str(root))
    app.tabs[0].checkbox[0].set_value(offline)
    app.button[0].click().run()


def real_backend():
    try:
        return importlib.import_module("triage.finals")
    except ModuleNotFoundError as exc:
        if exc.name != "triage.finals":
            raise
        return None


def install_backend(monkeypatch, run_scan, judge=None):
    finals = ModuleType("triage.finals")
    finals.run_scan = run_scan
    finals.default_judge = lambda: judge
    monkeypatch.setitem(sys.modules, "triage.finals", finals)


def event(stage, name, **data):
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "stage": stage, "event": name, "data": data}


def test_finals_calls_pipeline_and_keeps_downloads(monkeypatch, tmp_path):
    backend = real_backend()
    signature = inspect.signature(backend.run_scan) if backend else None
    calls = []
    judge_provider = object()
    warning = "판정 모델이 설정되지 않아 1건 전부 판단 유보로 처리됨"

    def scan(label, root, out_dir, offline=False, run_no=1, judge=None, on_event=None):
        if signature is not None and "on_event" in signature.parameters:
            signature.bind(label, root, out_dir, offline=offline, run_no=run_no, judge=judge, on_event=on_event)
        calls.append((label, root, out_dir, offline, judge))
        on_event(event("collect", "end", components=0))
        on_event(event("judge", "end", verdicts={"affected": 1, "not_affected": 2, "undetermined": 3}))
        on_event(event("cyclonedx", "end", files=1))
        on_event(event("pdf", "end", files=1))
        paths = {}
        for kind, name in (("report", "report.pdf"), ("sbom", "sbom.json"), ("log", "log.jsonl")):
            path = out_dir / name
            path.write_bytes(b"test download")
            paths[kind] = path
        bundle = TriageBundle(anomalies=[Anomaly(kind="judge_degraded", message=warning)])
        return SimpleNamespace(bundle=bundle, paths=paths, failures={})

    install_backend(monkeypatch, scan, judge=judge_provider)
    app = run_app()
    assert [tab.label for tab in app.tabs] == ["본선 소스 점검", "기존 스캔 결과 분석"]
    assert app.tabs[0].checkbox[0].value is False
    submit_server_path(app, tmp_path, offline=True)
    assert not app.exception
    assert app.error.values == [warning]
    assert warning not in app.text.values
    elements = list(app.main)
    overview = overview_element(app)
    assert elements.index(app.error[0]) < elements.index(overview)
    assert any("먼저 확인할 것" in value for value in app.markdown.values)
    assert calls[0][:2] == ("테스트 서비스", tmp_path.resolve())
    assert calls[0][3:] == (True, judge_provider)
    assert not calls[0][2].exists()
    assert any("구성요소 0건" in item.value for item in app.text)
    assert any("판정 6건" in item.value for item in app.text)
    assert any("PDF 보고서 생성 — 완료" in item.value for item in app.text)
    buttons = app.get("download_button")
    assert [button.label for button in buttons] == ["PDF 내보내기"]
    assert buttons[0].proto.type == "primary"
    conclusion = next(line for line in app.markdown if "먼저 확인할 것" in line.value)
    assert elements.index(buttons[0]) < elements.index(overview) < elements.index(conclusion)
    assert elements.index(conclusion) < elements.index(app.text_input(key="finding_query"))
    open_files_tab(app)
    assert len(calls) == 1
    assert [b.label for b in app.get("download_button")] == [
        "PDF 내보내기", "구성요소 목록 (SBOM JSON)", "실행 기록 (JSONL)",
    ]


def test_missing_backend_shows_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "triage.finals", None)
    app = run_app()
    assert not app.exception
    assert app.error[0].value == "점검 실행기를 찾을 수 없습니다"
    assert not app.get("download_button")


def test_saved_result_reopens_in_new_session_without_scan(ui, monkeypatch, tmp_path):
    bundle = TriageBundle.model_validate_json((SOURCE.parent / "action_bundle.json").read_bytes())
    downloads = {"sbom": ("서비스 목록.json", b"{}")}
    failures = {"pdf": "글꼴 없음"}
    command = ui.scan_command("테스트 서비스", str(tmp_path))
    rendered = []

    def scan(label, root, out, **kwargs):
        name, data = downloads["sbom"]
        (out / name).write_bytes(data)
        return SimpleNamespace(bundle=bundle, paths={"sbom": name}, failures=failures)

    install_backend(monkeypatch, scan)
    monkeypatch.setattr(ui, "show_results", lambda b, d, f, command: rendered.append((b, d, f, command)))
    app = run_app()
    submit_server_path(app, tmp_path)
    assert not app.exception
    assert rendered == [(bundle, downloads, failures, command)]
    directory, = ui.saved_results()
    assert directory.parent.name == "테스트 서비스"
    datetime.strptime(directory.name, "%Y%m%d-%H%M%S")
    assert {file.name for file in directory.iterdir()} == {"meta.json", "bundle.json", "서비스 목록.json"}

    older = ui.WEB_RESULTS / "이전 서비스" / "20000101-000000"
    older.mkdir(parents=True)
    monkeypatch.setattr(ui, "load_scan", lambda: None)
    fresh = run_app()
    picker = fresh.selectbox[0]
    assert picker.options[1:] == [ui.history_label(directory), "이전 서비스 · 2000-01-01 00:00:00"]
    assert picker.value == directory
    assert not fresh.exception and not fresh.error
    assert rendered == [(bundle, downloads, failures, command)] * 2
    assert rendered[-1][0] is not bundle


def test_saved_result_rejects_outside_paths(ui, tmp_path):
    directory = ui.save_result("서비스", TriageBundle(), {}, {}, "점검")
    with pytest.raises(ValueError, match="경로"):
        ui.load_result(tmp_path)
    (tmp_path / "outside.pdf").write_bytes(b"outside")
    meta = directory / "meta.json"
    contents = json.loads(meta.read_text(encoding="utf-8"))
    contents["downloads"] = {"report": "../../../../outside.pdf"}
    meta.write_text(json.dumps(contents), encoding="utf-8")
    with pytest.raises(ValueError, match="경로"):
        ui.load_result(directory)
    app = run_app()
    app.selectbox[0].select(directory).run()
    assert not app.exception
    assert app.warning.values == ["저장된 점검 결과를 읽을 수 없습니다."]
    assert not app.get("download_button")


def test_overview_and_pdf_follow_selected_result(ui, monkeypatch):
    from streamlit.delta_generator import DeltaGenerator
    from triage.output.report_pdf import saved

    bundle = TriageBundle.model_validate_json((SOURCE.parent / "action_bundle.json").read_bytes())
    directory = ui.save_result("저장 서비스", bundle, {"report": ("old.pdf", b"stored-pdf")}, {}, "")
    other = ui.save_result("다른 서비스", TriageBundle(), {"report": ("lost.pdf", b"old")}, {}, "")
    (other / "lost.pdf").unlink()
    downloads = {}
    calls = []
    native = DeltaGenerator.download_button

    def download(self, label, data, file_name, *args, **kwargs):
        downloads[kwargs["key"]] = file_name, data
        return native(self, label, data, file_name, *args, **kwargs)

    def render(source, out):
        calls.append(source)
        out.write_bytes(source.read_bytes())
        log = out.with_suffix(".report.jsonl")
        log.write_text('{"stage":"report"}\n', encoding="utf-8")
        return log

    monkeypatch.setattr(DeltaGenerator, "download_button", download)
    monkeypatch.setattr(ui.st, "download_button", download.__get__(ui.st.download_button.__self__))
    monkeypatch.setattr(saved, "render_saved_report", render)
    page = run_app()
    page.selectbox(key="finals_history").select(directory).run()
    assert page.selectbox(key="finals_history").value == directory
    totals = overview_counts(page)
    assert totals == {"처리할 일": "3개", "수정할 일": "1", "확인할 일": "2", "취약점 후보": "7건",
                      "영향 있음": "1", "확인 필요": "4", "영향 없음": "2"}
    page.segmented_control[0].set_value("확인 필요").run()
    assert page.radio(key="queue_desktop").value == page.selectbox(key="queue_mobile").value == 2
    assert len(page.radio(key="queue_desktop").options) == 2
    page.selectbox(key="queue_mobile").select(3).run()
    assert page.radio(key="queue_desktop").value == 3
    assert overview_counts(page) == totals and not calls
    assert "export_log" not in downloads
    open_files_tab(page)
    assert overview_counts(page) == totals and not calls
    assert downloads["archived_report"] == ("old.pdf", b"stored-pdf")
    name, pdf = downloads["finals_top_report"]
    assert name == "report-저장 서비스.pdf"
    with ThreadPoolExecutor(max_workers=2) as pool:
        report = pool.submit(pdf)
        log = pool.submit(downloads["export_log"][1])
    assert report.result() == (directory / "bundle.json").read_bytes()
    assert json.loads(log.result()) == {"stage": "report"}
    page.run()
    assert downloads["finals_top_report"][1]() == report.result()
    assert calls == [directory / "bundle.json"] and (directory / "old.pdf").read_bytes() == b"stored-pdf"
    page.selectbox(key="finals_history").select(other).run()
    assert not page.exception and overview_counts(page)["처리할 일"] == "0개"
    open_files_tab(page)
    assert not any(b.key == "archived_report" for b in page.get("download_button"))
    assert downloads["finals_top_report"][0] == "report-다른 서비스.pdf"
    assert downloads["finals_top_report"][1]() == (other / "bundle.json").read_bytes()
    assert pdf() == report.result() and calls == [directory / "bundle.json", other / "bundle.json"]


def test_pdf_export_retries_live_snapshot_if_first_render_fails(ui, monkeypatch):
    from triage.output.report_pdf import saved

    bundle = TriageBundle(meta={"label": "현재 서비스"})
    command = ui.scan_command("현재 서비스", "./source")
    sides = []

    def render(source, out):
        assert TriageBundle.model_validate_json(source.read_bytes()) == bundle
        sidecar = json.loads(source.with_name("meta.json").read_text(encoding="utf-8"))
        sides.append(sidecar)
        if len(sides) == 1:
            raise OSError("임시 출력 실패")
        out.write_bytes(b"pdf")
        record = out.with_suffix(".jsonl")
        record.write_bytes(b"log")
        return record

    monkeypatch.setattr(saved, "render_saved_report", render)
    export = ui.ReportExport(None, bundle, command, "changes.patch")
    with pytest.raises(ValueError, match="다시 시도"):
        export.pdf()
    assert export.pdf() == b"pdf" and export.log() == b"log"
    assert sides == [{"downloads": {"patch": "changes.patch"}, "failures": {}, "command": command}] * 2


def test_save_failure_keeps_current_result(ui, monkeypatch, tmp_path):
    ui.WEB_RESULTS.parent.write_bytes(b"unavailable")
    install_backend(monkeypatch, lambda *a, **kw: SimpleNamespace(bundle=TriageBundle(), paths={}, failures={}))
    app = run_app()
    submit_server_path(app, tmp_path)
    assert not app.exception
    assert app.warning.values == ["이번 점검 결과를 저장할 수 없습니다."]
    assert overview_counts(app)["취약점 후보"] == "0건"
    assert app.get("download_button")[0].label == "PDF 내보내기"


def test_partial_failure_keeps_available_downloads(monkeypatch, tmp_path):
    def scan(label, root, out_dir, *, offline, judge, on_event):
        on_event(event("pdf", "start"))
        on_event(event("pdf", "error"))
        on_event(event("pdf", "end", files=0))
        log = out_dir / "log.jsonl"
        log.write_bytes(b"test download")
        return SimpleNamespace(bundle=TriageBundle(), paths={"log": log}, failures={"pdf": "글꼴 없음"})

    install_backend(monkeypatch, scan)
    app = run_app()
    submit_server_path(app, tmp_path)
    assert not app.exception
    assert not app.error
    assert app.warning[0].value == "일부 단계 실패"
    assert any("PDF 보고서 생성 · 글꼴 없음" in item.value for item in app.markdown)
    assert any("PDF 보고서 생성 — 실패" in item.value for item in app.text)
    open_files_tab(app)
    assert [button.label for button in app.get("download_button")] == ["PDF 내보내기", "보고서 재생성 기록", "실행 기록 (JSONL)"]


def test_pipeline_exception_only_displays_type_and_stage(monkeypatch, tmp_path):
    def scan(label, root, out_dir, *, offline, judge, on_event):
        on_event(event("lookup", "start"))
        raise RuntimeError(f"private marker {root}")

    install_backend(monkeypatch, scan)
    app = run_app()
    submit_server_path(app, tmp_path)
    assert not app.exception
    assert [item.value for item in app.error] == ["조회 단계 실패 · 오류 종류 RuntimeError"]
    assert any("조회 — 실패" in item.value for item in app.text)
    assert not app.get("download_button")


def test_real_offline_scan_fills_expected_downloads(monkeypatch):
    backend = real_backend()
    if backend is None or "on_event" not in inspect.signature(backend.run_scan).parameters:
        pytest.skip("점검 실행기의 on_event 계약이 아직 반영되지 않았습니다.")

    signature = inspect.signature(backend.run_scan)
    assert list(signature.parameters) == ["label", "root", "out_dir", "offline", "run_no", "judge", "on_event"]
    monkeypatch.setattr(backend, "default_judge", lambda: None)
    app = run_app(timeout=90)
    submit_server_path(app, SOURCE, offline=True)
    assert not app.exception
    assert not app.error
    open_files_tab(app)
    assert len(app.get("download_button")) == 3  # 빈 변경안은 적용을 안내하지 않는다.
    _, downloads, failures = app.session_state["finals_result"]
    assert not failures
    assert downloads["patch"][0].endswith(".patch")
    assert downloads["report"][1].startswith(b"%PDF-")
    assert json.loads(downloads["sbom"][1])["bomFormat"] == "CycloneDX"
    log = [json.loads(line) for line in downloads["log"][1].splitlines()]
    assert {record["stage"] for record in log} >= {"collect", "scope", "lookup", "judge", "cyclonedx", "pdf"}
    assert any("수집 — 완료" in item.value for item in app.text)

def test_action_cards_search_details_and_threaded_progress(ui, monkeypatch, tmp_path):
    from streamlit.delta_generator import DeltaGenerator

    fixture = SOURCE.parent / "action_bundle.json"
    bundle = TriageBundle.model_validate_json(fixture.read_text(encoding="utf-8"))
    progress_shown = Event()
    ui_threads = []
    scan_threads = []
    original = DeltaGenerator.text

    def capture(self, body, *args, **kwargs):
        if "판정 · 3/7건" in str(body):
            ui_threads.append(get_ident())
            progress_shown.set()
        return original(self, body, *args, **kwargs)

    def scan(label, root, output, *, offline, judge, on_event):
        scan_threads.append(get_ident())
        on_event(event("judge", "progress", done=3, total=7))
        assert progress_shown.wait(15)
        on_event(event("judge", "end", verdicts={"affected": 1, "undetermined": 4, "not_affected": 2}))
        return SimpleNamespace(bundle=bundle, paths={}, failures={})

    monkeypatch.setattr(DeltaGenerator, "text", capture)
    install_backend(monkeypatch, scan)
    app = run_app()
    submit_server_path(app, tmp_path)
    assert not app.exception and not app.error
    assert ui_threads and scan_threads[0] not in ui_threads
    assert overview_counts(app) == {"처리할 일": "3개", "수정할 일": "1", "확인할 일": "2", "취약점 후보": "7건",
                                    "영향 있음": "1", "확인 필요": "4", "영향 없음": "2"}
    assert any("수정 버전을 먼저 확인하세요" in title for title in app.subheader.values)
    cards = [x for x in app.expander if "관련 취약점" in x.label]
    assert len(cards) == 1 and len(app.radio(key="queue_desktop").options) == 3
    assert any(r"근거로 쓰지 않았습니다 · container/Dockerfile\:2" in w.value for w in app.warning)
    open_files_tab(app)
    assert any("triage scan" in x.value and ui.scan_command("테스트 서비스", str(tmp_path)) == x.value for x in app.code)
    hit = next(f for f in bundle.findings if f.vulnerability.aliases)
    app.text_input(key="finding_query").set_value(hit.vulnerability.aliases[0].lower()).run()
    assert not app.exception
    assert "검색 결과 1건" in app.subheader.values
    assert any(f"{ui.md_escape(hit.vulnerability.id)} · 판단 유보" in x.value for x in app.markdown)
    app.button(key=f"hit_{hit.key}").click().run()
    assert app.session_state["active_action"] == 1 and app.session_state["result_view"] == ui.RESULT_VIEWS[0]
    app.text_input(key="finding_query").set_value(hit.component.name).run()
    assert "검색 결과 5건" in app.subheader.values
    assert any("별도 할 일 없음" in x.value for x in app.caption)
    app.session_state["details_1"] = True
    app.run()
    assert not app.exception
    assert any("문제가 생기는 조건" in x.value for x in app.markdown)
    assert len(scan_threads) == 1


@pytest.mark.parametrize("status", [None, "ok", "unavailable"])
def test_action_card_fix_metadata(ui, monkeypatch, tmp_path, status):
    bundle = TriageBundle.model_validate_json((SOURCE.parent / "action_bundle.json").read_text(encoding="utf-8"))
    upgrade, image, confirm = build_actions(bundle)
    top = next(f for f in bundle.findings if f.key == upgrade.top_finding)
    source = next(e for e in bundle.evidence if e.id in top.component.evidence_ids)
    old_step = "의존성 선언을 갱신합니다."
    bundle.remediations.append(Remediation(finding_key=top.key, target_version=upgrade.target,
                                           verified=True, steps=[old_step]))
    manual = "수정할 선언 위치를 확인하세요."
    unavailable = "재점검용 조회 결과가 없습니다."
    after = source.snippet.replace(top.component.version, upgrade.target)
    if status:
        bundle.meta["fix_plan"] = [
            dict(kind="change", findings=upgrade.findings[-1:], file=source.file, line=source.line_start,
                 before=source.snippet, after=after),
            dict(kind="manual", findings=confirm.findings, reason=manual),
        ]
        bundle.meta["fix_check"] = (dict(status=status, resolved=[top.key], remaining=confirm.findings, new=[])
                                    if status == "ok" else dict(status=status, reason=unavailable))

    def scan(label, root, output, **kwargs):
        paths = {}
        if status:
            patch = output / f"fix-{label}.patch"
            patch.write_bytes(after.encode("utf-8"))
            paths["patch"] = patch
        return SimpleNamespace(bundle=bundle, paths=paths, failures={})

    install_backend(monkeypatch, scan)
    app = run_app()
    submit_server_path(app, tmp_path)
    assert not app.exception
    cards = [x for x in app.expander if "관련 취약점" in x.label]
    assert len(cards) == 1 and app.radio(key="queue_desktop").value == 1
    open_files_tab(app)
    buttons = {button.key: button for button in app.get("download_button")}
    assert set(buttons) == {"finals_top_report", "export_log", "finals_requests"} | ({"finals_top_patch"} if status else set())
    for action in (upgrade, image, confirm):
        if action.work_request:
            assert action.work_request.title in ui.work_requests_text("svc", [upgrade, image, confirm])
    assert any(code.value.startswith("git apply ") for code in app.code) == bool(status)
    assert any(code.value.startswith("uv run triage scan") and code.value.endswith("out/recheck")
               for code in app.code)
    if status:
        assert app.session_state["finals_result"][1]["patch"][1] == after.encode("utf-8")
        assert ui.md_escape(f"{source.file} {source.line_start}행을 수정하세요") in app.subheader.values
        assert after in app.code.values
        assert any(source.snippet in html.value for html in app.html)
        if status == "ok":
            assert any(f"{len(upgrade.findings)}건 중 해소 1건" in value for value in app.caption.values)
        else:
            assert ui.md_escape(unavailable) in app.caption.values
    else:
        assert ui.md_escape(old_step) in app.markdown.values
        assert not any("**바꿀 줄**" in text for text in app.markdown.values)
    app.radio(key="queue_desktop").set_value(2).run()
    assert app.selectbox(key="queue_mobile").value == 2
    assert f"{ui.md_escape(image.team)}에 확인을 요청하세요" in app.subheader.values
    assert not any("**바꿀 줄**" in text for text in app.markdown.values)
    app.selectbox(key="queue_mobile").select(3).run()
    assert app.radio(key="queue_desktop").value == 3
    assert any(ui.md_escape(confirm.missing_info[0].what) in text for text in app.markdown.values)
    if status:
        app.session_state["details_3"] = True
        app.run()
        assert "수정 시 확인할 내용 · " + ui.md_escape(manual) in app.caption.values


def test_pending_findings_point_to_first_confirmation(ui, monkeypatch, tmp_path):
    bundle = TriageBundle.model_validate_json((SOURCE.parent / "action_bundle.json").read_text(encoding="utf-8"))
    bundle.findings = [f for f in bundle.findings if f.verdict.state == "undetermined"]
    install_backend(monkeypatch, lambda *args, **kwargs: SimpleNamespace(bundle=bundle, paths={}, failures={}))
    app = run_app()
    submit_server_path(app, tmp_path)
    assert not app.exception
    assert overview_counts(app)["영향 있음"] == overview_counts(app)["수정할 일"] == "0"
    first = build_actions(bundle)[0]
    assert f"{ui.md_escape(first.team)}에 확인을 요청하세요" in app.subheader.values
    assert any(first.work_request.body in code.value for code in app.code)
    assert not any("바꿀 줄" in line for line in app.markdown.values)


def test_unconfirmed_item_shows_question_even_when_bundle_contains_patch(ui):
    bundle = TriageBundle.model_validate_json((SOURCE.parent / "action_bundle.json").read_bytes())
    action = build_actions(bundle)[-1]
    bundle.findings = [f for f in bundle.findings if f.key in action.findings]
    bundle.meta["fix_plan"] = [dict(kind="change", findings=action.findings, file="dependency.txt", line=4,
                                    before="dependency==1", after="dependency==2")]
    ui.save_result("확인용", bundle, {"patch": ("all.patch", b"patch")}, {}, "")
    app = run_app()
    assert not app.exception
    assert not any(code.value == "dependency==2" for code in app.code)
    assert action.work_request.body in next(code.value for code in app.code if "담당자님" in code.value)
    assert any(action.missing_info[0].where in text for text in app.markdown.values)
    open_files_tab(app)
    assert any(b.key == "finals_top_patch" and b.label.startswith("전체 변경안") for b in app.get("download_button"))


def test_switching_service_and_new_scan_resets_selection(ui):
    bundle = TriageBundle.model_validate_json((SOURCE.parent / "action_bundle.json").read_bytes())
    first = ui.save_result("첫 서비스", bundle, {}, {}, "")
    other = ui.save_result("둘째 서비스", bundle, {}, {}, "")
    app = run_app()
    current = app.selectbox(key="finals_history").value
    app.radio(key="queue_desktop").set_value(3).run()
    assert app.session_state["active_action"] == 3
    app.selectbox(key="finals_history").select(other if current == first else first).run()
    assert app.radio(key="queue_desktop").value == app.selectbox(key="queue_mobile").value == 1
    app.button(key="new_scan").click().run()
    assert not app.exception and app.selectbox(key="finals_history").value is None
    assert any(t.label == "서비스 이름" for t in app.text_input)
    assert all(r.key != "queue_desktop" for r in app.radio)


def test_open_result_disappears_from_history(ui, monkeypatch):
    bundle = TriageBundle.model_validate_json((SOURCE.parent / "action_bundle.json").read_bytes())
    selected = ui.save_result("선택한 서비스", bundle, {}, {}, "")
    remaining = ui.save_result("남은 서비스", TriageBundle(), {}, {}, "")
    history = [selected, remaining]
    monkeypatch.setattr(ui, "saved_results", lambda: history)
    app = run_app()
    assert app.selectbox(key="finals_history").value == selected
    assert overview_counts(app)["취약점 후보"] == "7건"
    history.remove(selected)
    app.run()
    assert not app.exception and app.selectbox(key="finals_history").value == remaining
    assert overview_counts(app)["취약점 후보"] == "0건"
    assert app.session_state["report_export"].directory == remaining
    history.clear()
    app.run()
    assert not app.exception and app.selectbox(key="finals_history").value is None
    assert not app.get("download_button") and any(t.label == "서비스 이름" for t in app.text_input)


@pytest.mark.parametrize("only_unaffected", [True, False])
def test_empty_queue_has_an_explicit_outcome(ui, only_unaffected):
    bundle = TriageBundle.model_validate_json((SOURCE.parent / "action_bundle.json").read_bytes())
    bundle.findings = [f for f in bundle.findings if only_unaffected and f.verdict.state == "not_affected"]
    ui.save_result("빈 목록", bundle, {}, {}, "")
    app = run_app()
    assert not app.exception and "현재 수정할 항목이 없습니다" in app.subheader.values
    assert overview_counts(app) == {"처리할 일": "0개", "수정할 일": "0", "확인할 일": "0",
                                    "취약점 후보": f"{len(bundle.findings)}건", "영향 있음": "0", "확인 필요": "0",
                                    "영향 없음": str(len(bundle.findings))}
    assert all(r.key != "queue_desktop" for r in app.radio)
    assert any(("모든 후보가 영향 없음" if only_unaffected else "취약점 후보가 없어") in s for s in app.markdown.values)


def test_md_escape_preserves_each_special_character(ui):
    punctuation = r"\`*_{}[]()#+-.!|><$~"
    assert ui.md_escape("앞" + punctuation + "뒤") == "앞" + "".join("\\" + c for c in punctuation) + "뒤"


def test_external_verdict_markdown_in_cards_search_and_details(monkeypatch, tmp_path):
    bundle = TriageBundle.model_validate_json((SOURCE.parent / "action_bundle.json").read_text(encoding="utf-8"))
    sentence = "판정 ${jackson.version}, __init__.py, [링크](http://x)"
    escaped = r"판정 \$\{jackson\.version\}, \_\_init\_\_\.py, \[링크\]\(http\://x\)"
    for finding in bundle.findings:
        finding.verdict.plain_ko = sentence
        finding.verdict.rationale_ko = f"근거 · {sentence}"
    install_backend(monkeypatch, lambda *args, **kwargs: SimpleNamespace(bundle=bundle, paths={}, failures={}))
    app = run_app()
    submit_server_path(app, tmp_path)
    assert not app.exception
    assert escaped in app.markdown.values
    unaffected = next(card for card in app.expander if card.label.startswith("영향 없음"))
    assert any(line.endswith(escaped) for line in unaffected.markdown.values)

    top = build_actions(bundle)[0].top_finding
    identifier = next(f.vulnerability.id for f in bundle.findings if f.key == top)
    app.text_input(key="finding_query").set_value(identifier).run()
    assert f"근거 · {escaped}" in app.markdown.values
    assert app.button(key=f"hit_{top}").label == "조치 1 열기"
    app.session_state["details_1"] = True
    app.run()
    assert not app.exception
    detail = next(card for card in app.expander if card.label.startswith("판정 근거와 관련 취약점"))
    assert escaped in detail.markdown.values
    assert f"근거 · {escaped}" in detail.markdown.values
