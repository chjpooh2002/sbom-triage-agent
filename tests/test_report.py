from datetime import date
from pathlib import Path

import pytest
from openpyxl import load_workbook

from triage.pipeline import run
from triage.remediation import service as svc

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

    at = AppTest.from_file(str(ROOT / "app" / "streamlit_app.py"), default_timeout=60)
    at.run()
    assert not at.exception
    legacy = at.tabs[1]
    legacy.selectbox[0].set_value("형식별 입력 샘플 (fixtures)")
    legacy.button[0].click()
    at.run()
    assert not at.exception
    assert any(m.label == "취약점" for m in at.metric)
