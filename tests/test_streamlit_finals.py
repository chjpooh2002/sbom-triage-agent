import importlib
import inspect
import json
import sys
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from stat import S_IFLNK
from threading import Event, get_ident
from types import ModuleType, SimpleNamespace
from zipfile import ZipFile, ZipInfo

import pytest
from streamlit.testing.v1 import AppTest

from triage.models import Anomaly, TriageBundle


APP = Path(__file__).resolve().parents[1] / "app" / "streamlit_app.py"
SOURCE = Path(__file__).parent / "fixtures" / "finals" / "streamlit-source"


@pytest.fixture
def ui(monkeypatch):
    monkeypatch.syspath_prepend(str(APP.parent.parent))
    return importlib.import_module("app.streamlit_app")


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
    app = AppTest.from_file(str(APP), default_timeout=60).run()
    assert [tab.label for tab in app.tabs] == ["본선 소스 점검", "기존 스캔 결과 분석"]
    assert app.tabs[0].checkbox[0].value is False
    submit_server_path(app, tmp_path, offline=True)
    assert not app.exception
    assert app.error.values == [warning]
    assert warning not in app.text.values
    elements = list(app.main)
    conclusion = next(h for h in app.subheader if h.value.startswith("오늘 할 일"))
    assert elements.index(app.error[0]) < elements.index(conclusion)
    assert all("먼저 고칠 것" not in h.value for h in app.subheader)
    assert calls[0][:2] == ("테스트 서비스", tmp_path.resolve())
    assert calls[0][3:] == (True, judge_provider)
    assert not calls[0][2].exists()
    assert any("구성요소 0건" in item.value for item in app.text)
    assert any("판정 6건" in item.value for item in app.text)
    assert any("PDF 보고서 생성 — 완료" in item.value for item in app.text)
    assert len(app.get("download_button")) == 3
    app.run()
    assert len(calls) == 1
    assert len(app.get("download_button")) == 3


def test_missing_backend_shows_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "triage.finals", None)
    app = AppTest.from_file(str(APP), default_timeout=60).run()
    assert not app.exception
    assert app.error[0].value == "점검 실행기를 찾을 수 없습니다"
    assert not app.get("download_button")


def test_partial_failure_keeps_available_downloads(monkeypatch, tmp_path):
    def scan(label, root, out_dir, *, offline, judge, on_event):
        on_event(event("pdf", "start"))
        on_event(event("pdf", "error"))
        on_event(event("pdf", "end", files=0))
        log = out_dir / "log.jsonl"
        log.write_bytes(b"test download")
        return SimpleNamespace(bundle=TriageBundle(), paths={"log": log}, failures={"pdf": "글꼴 없음"})

    install_backend(monkeypatch, scan)
    app = AppTest.from_file(str(APP), default_timeout=60).run()
    submit_server_path(app, tmp_path)
    assert not app.exception
    assert not app.error
    assert app.warning[0].value == "일부 단계 실패"
    assert any("PDF 보고서 생성 · 글꼴 없음" in item.value for item in app.text)
    assert any("PDF 보고서 생성 — 실패" in item.value for item in app.text)
    assert len(app.get("download_button")) == 1


def test_pipeline_exception_only_displays_type_and_stage(monkeypatch, tmp_path):
    def scan(label, root, out_dir, *, offline, judge, on_event):
        on_event(event("lookup", "start"))
        raise RuntimeError(f"private marker {root}")

    install_backend(monkeypatch, scan)
    app = AppTest.from_file(str(APP), default_timeout=60).run()
    submit_server_path(app, tmp_path)
    assert not app.exception
    assert [item.value for item in app.error] == ["조회 단계 실패 · 오류 종류 RuntimeError"]
    assert any("조회 — 실패" in item.value for item in app.text)
    assert not app.get("download_button")


def test_real_offline_scan_fills_all_three_downloads(monkeypatch):
    backend = real_backend()
    if backend is None or "on_event" not in inspect.signature(backend.run_scan).parameters:
        pytest.skip("점검 실행기의 on_event 계약이 아직 반영되지 않았습니다.")

    signature = inspect.signature(backend.run_scan)
    assert list(signature.parameters) == ["label", "root", "out_dir", "offline", "run_no", "judge", "on_event"]
    monkeypatch.setattr(backend, "default_judge", lambda: None)
    app = AppTest.from_file(str(APP), default_timeout=90).run()
    submit_server_path(app, SOURCE, offline=True)
    assert not app.exception
    assert not app.error
    assert len(app.get("download_button")) == 3
    _, downloads, failures = app.session_state["finals_result"]
    assert not failures
    assert downloads["report"][1].startswith(b"%PDF-")
    assert json.loads(downloads["sbom"][1])["bomFormat"] == "CycloneDX"
    log = [json.loads(line) for line in downloads["log"][1].splitlines()]
    assert {record["stage"] for record in log} >= {"collect", "scope", "lookup", "judge", "cyclonedx", "pdf"}
    assert any("수집 — 완료" in item.value for item in app.text)

def test_action_cards_search_details_and_threaded_progress(monkeypatch, tmp_path):
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
    app = AppTest.from_file(str(APP), default_timeout=60).run()
    submit_server_path(app, tmp_path)
    assert not app.exception and not app.error
    assert ui_threads and scan_threads[0] not in ui_threads
    assert app.subheader.values.count("오늘 할 일 3개 · 영향 있음 1건 · 확인 필요 4건 · 영향 없음 2건") == 1
    cards = [x for x in app.expander if "관련 취약점" in x.label]
    assert len(cards) == 3 and all(x.proto.expanded for x in cards)
    assert any("근거로 쓰지 않았습니다 · container/Dockerfile:2" in w.value for w in app.warning)
    assert any("triage scan" in x.value and str(tmp_path) in x.value for x in app.code)
    app.text_input[2].set_value("ghsa-demo-abcd-efgh").run()
    assert not app.exception
    assert "검색 결과 1건" in app.subheader.values
    assert any("CVE-2099-1002 · 판단 유보" in x.value for x in app.text)
    assert any("(#action-1)" in x.value for x in app.markdown)
    app.text_input[2].set_value("demo-reader").run()
    assert "검색 결과 5건" in app.subheader.values
    assert any("별도 할 일 없음" in x.value for x in app.caption)
    app.session_state["details_1"] = True
    app.run()
    assert not app.exception
    assert any("문제가 생기는 조건" in x.value for x in app.markdown)
    assert len(scan_threads) == 1
