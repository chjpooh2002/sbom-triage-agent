import json
import shutil
import socket
import subprocess
from datetime import date
from pathlib import Path

import pytest
from openpyxl import load_workbook
from typer.testing import CliRunner

from triage.pipeline import run
from triage.remediation import service as svc
from triage.cli import app
from triage.models import TriageBundle

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "samples" / "fixtures"
INPUTS = [str(FX / "assets.csv"), str(FX / "sbom.cdx.json"), str(FX / "grype.json"),
          f"{FX / 'trivy.json'}=SVC-001", f"{FX / 'osv.json'}=SVC-001"]


@pytest.fixture
def offline(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGE_CACHE_DIR", str(tmp_path / "cache"))           # 발췌본으로
    monkeypatch.setattr(svc, "list_versions", lambda c, offline=False: None)


def test_pipeline_end_to_end_offline_template(tmp_path, offline):
    res = run(INPUTS, tmp_path / "out", "template", as_of=date(2026, 11, 24))
    b = res.bundle
    assert b.results[0].finding_key.startswith("CVE-2021-44228|")          # Log4Shell 1위
    assert all(r.reasons for r in b.results)                               # 모든 결과에 근거
    assert {p.name for p in res.paths.values()} == {"bundle.json", "report.md", "report.xlsx"}
    md = res.paths["md"].read_text(encoding="utf-8")
    for heading in ("## 1. 요약", "## 2. 조치 계획", "## 3. 조치안 상세", "## 4. 취약점 전체 목록"):
        assert heading in md
    assert "log4j-core" in md and "CVE-2021-44228" in md
    wb = load_workbook(res.paths["xlsx"])
    assert wb.sheetnames == ["요약", "조치계획", "취약점목록", "판단근거"]
    assert wb["취약점목록"].max_row == len(b.results) + 1


def test_streamlit_app_renders(offline):
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(ROOT / "app" / "streamlit_app.py"), default_timeout=120)
    at.run()
    assert not at.exception
    legacy = at.tabs[1]
    legacy.selectbox[0].set_value("형식별 입력 샘플 (fixtures)")
    legacy.button[0].click()
    at.run()
    assert not at.exception
    assert any(m.label == "취약점" for m in at.metric)


@pytest.mark.parametrize("kind", ["snapshot", "web", "bare"])
def test_report_replays_saved_verdicts_offline(tmp_path, monkeypatch, kind):
    from triage import finals
    from triage.action_view import scan_command

    def forbidden(*args, **kwargs):
        pytest.fail("저장본 재출력에서 점검·모델·네트워크 접근")

    monkeypatch.setattr(finals, "default_judge", forbidden)
    monkeypatch.setattr(finals, "run_scan", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    bundle = TriageBundle.model_validate_json((ROOT / "tests/fixtures/finals/action_bundle.json").read_bytes())
    bundle.meta["label"] = "저장 서비스"
    path = tmp_path / ("bundle-service.json" if kind == "snapshot" else "bundle.json")
    if kind == "snapshot":
        bundle.meta["report_meta"] = dict(scan_source="source folder", scan_offline=True)
    elif kind == "web":
        (tmp_path / "meta.json").write_text(json.dumps({"command": "triage scan '저장 서비스' 'source folder' './out'",
                                                       "downloads": {"patch": "my-fix.patch"}}), encoding="utf-8")
    path.write_text(bundle.model_dump_json(), encoding="utf-8")
    original = path.read_bytes()
    out = tmp_path / "rebuilt" / "report.pdf"
    result = CliRunner().invoke(app, ["report", str(path), str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_bytes().startswith(b"%PDF-") and original == path.read_bytes()
    records = [json.loads(line) for line in out.with_suffix(".report.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [(r["stage"], r["event"]) for r in records] == [
        ("report", "start"), ("pdf", "engine"), ("report", "end"), ("run", "end"),
    ]
    assert records[-1]["data"]["total_tokens"] == 0
    if extract := shutil.which("pdftotext"):
        text = subprocess.check_output([extract, "-raw", "-enc", "UTF-8", str(out), "-"], encoding="utf-8")
        packed = "".join(text.split())
        assert "저장서비스" in packed and all(f.vulnerability.id in packed for f in bundle.findings)
        if kind != "bare":
            command = scan_command("저장 서비스", "source folder", offline=kind == "snapshot")
            assert "".join(command.split()) in packed
        assert ("gitapplymy-fix.patch" in packed) == (kind == "web")


def test_old_web_result_with_empty_patch_has_no_apply_instruction():
    from triage.output.report_pdf.saved import saved_meta

    bundle = TriageBundle(meta={"fix_plan": [], "fix_check": {"status": "skipped"}})
    assert not saved_meta(bundle, {"downloads": {"patch": "empty.patch"}}).get("patch_name")
