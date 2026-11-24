import importlib
import sys
from io import BytesIO
from pathlib import Path
from stat import S_IFLNK
from types import ModuleType
from zipfile import ZipFile, ZipInfo

import pytest
from streamlit.testing.v1 import AppTest

from triage.models import TriageBundle


APP = Path(__file__).resolve().parents[1] / "app" / "streamlit_app.py"


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


def submit_server_path(app, tmp_path):
    app.text_input[0].set_value("테스트 서비스")
    app.text_input[1].set_value(str(tmp_path))
    app.button[0].click().run()


def test_finals_calls_pipeline_and_keeps_downloads(monkeypatch, tmp_path):
    calls = []
    finals = ModuleType("triage.finals")

    def scan(service, root, out, *, on_event):
        calls.append((service, root, out))
        event = {"stage": "collect", "event": "end", "data": {"count": 0}}
        on_event(event)
        artifacts = {}
        for kind, name in (("pdf", "report.pdf"), ("sbom", "sbom.json"), ("log", "log.jsonl")):
            path = out / name
            path.write_bytes(b"test download")
            artifacts[kind] = path
        return TriageBundle(), artifacts, [event]

    finals.run_scan = scan
    monkeypatch.setitem(sys.modules, "triage.finals", finals)
    app = AppTest.from_file(str(APP), default_timeout=30).run()
    assert [tab.label for tab in app.tabs] == ["본선 소스 점검", "기존 스캔 결과 분석"]
    submit_server_path(app, tmp_path)
    assert not app.exception
    assert not app.error
    assert calls[0][:2] == ("테스트 서비스", tmp_path.resolve())
    assert not calls[0][2].exists()
    assert any("구성요소 0건" in item.value for item in app.text)
    assert len(app.get("download_button")) == 3
    app.run()
    assert len(calls) == 1
    assert len(app.get("download_button")) == 3


def test_preview_shows_groups_and_copyable_details(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "triage.finals", None)
    app = AppTest.from_file(str(APP), default_timeout=30).run()
    submit_server_path(app, tmp_path)
    assert not app.exception
    assert not app.error
    assert any("화면 예시 모드" in warning.value for warning in app.warning)
    assert len(app.tabs[0].expander) == 3
    assert any("예시 기능이 켜져 있나요? — 충족" in item.value for item in app.text)
    assert any("example/settings.toml:4" in item.value for item in app.text)
    assert any("받는 팀 운영팀" in item.value for item in app.code)
