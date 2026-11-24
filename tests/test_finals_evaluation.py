import csv
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
SERVICE = "fictional-api"
COMPONENT_ALIAS = "Product Display Name=Widget"


def _vex(identifier, state, *, component="dep", **fields):
    return {"id": identifier, "affects": [{"ref": component}], "analysis": {"state": state}, **fields}


def _run(module, *args):
    return subprocess.run([sys.executable, "-m", f"eval.{module}", *map(str, args)], cwd=REPO,
                          encoding="utf-8", env={**os.environ, "PYTHONUTF8": "1"},
                          capture_output=True)


@pytest.fixture
def saved_runs(tmp_path):
    gold = tmp_path / "gold.csv"
    with gold.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("service", "vuln_id", "aliases", "component", "expected_state", "scoring_set"))
        for identifier, aliases, state, subset in (
            ("FICT-1", "ALT-1;BACKUP-1", "affected", "core"),
            ("FICT-2", "", "not_affected", "core"),
            ("FICT-3", "", "affected", "core"),
            ("FICT-4", "", "not_affected", "core"),
            ("FICT-5", "", "undetermined", "aux"),
            ("FICT-6", "", "undetermined", "aux"),
            ("FICT-7", "", "undetermined", "aux"),
        ):
            name = "Product Display Name" if identifier == "FICT-4" else "org.fake:Widget / Alternate Widget"
            writer.writerow((SERVICE, identifier, aliases, name, state, subset))
        writer.writerow(("other-service", "FICT-9", "", "Widget", "affected", "core"))

    rules = [
        _vex("alt-1", "exploitable"), _vex("FICT-2", "exploitable"),
        _vex("FICT-4", "not_affected"),
        _vex("THIRD-5", "in_triage", references=[{"id": "FICT-5", "source": {"name": "test"}}],
             properties=[{"name": "triage:missing_info", "value": '[{"what":"config","where":"deployment"}]'}]),
        _vex("FICT-6", "exploitable", properties=[{"name": "triage:missing_info", "value": "[]"}]),
        _vex("FICT-9", "exploitable"),
    ]
    model = [
        _vex("BACKUP-1", "exploitable"), _vex("FICT-2", "not_affected"), _vex("FICT-4", "not_affected"),
        _vex("FICT-5", "in_triage"), _vex("FICT-6", "exploitable"),
        _vex("FICT-10", "in_triage", component="child"),
    ]
    paths = []
    for stage, vulnerabilities in (("rules", rules), ("model", model)):
        directory = tmp_path / "saved" / stage
        directory.mkdir(parents=True)
        path = directory / "sbom-T.json"
        path.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": SERVICE}},
            "components": [{"type": "library", "bom-ref": "dep", "name": "wIDGET", "group": "other.group",
                            "components": [{"type": "library", "name": "nested", "bom-ref": "child"}]}],
            "vulnerabilities": vulnerabilities,
        }), encoding="utf-8")
        paths.append(path)
    return gold, *paths


def test_score_and_repeat_include_one_sided_candidates(tmp_path, saved_runs):
    gold, first, second = saved_runs
    out = tmp_path / "out"
    result = _run("finals_score", "T", "--gold", gold, "--sbom", first, "--run2", second, "--out", out,
                  "--component-alias", COMPONENT_ALIAS)

    assert result.returncode == 0, result.stderr
    table = (out / "score-T.md").read_text(encoding="utf-8")
    assert result.stdout == table
    assert "| core 정확 일치율 | 50.0% (2/4) |" in table
    assert "| core 영향 있음 재현율 | 50.0% (1/2) |" in table
    assert "| core 영향 있음 정밀도 | 50.0% (1/2) |" in table
    assert "| core 후보 누락 | 1 |" in table
    assert "| 정답에 없는 추가 후보 | 1 |" in table
    assert "| aux 판단 유보율 | 33.3% (1/3) |" in table
    assert "| aux missing_info 기재율 | 33.3% (1/3) |" in table
    assert "| run1·run2 판정 일치율 | 57.1% (4/7) |" in table
    assert f"## 놓친 영향 있음 (1)\n\n- {SERVICE} / FICT-3" in table
    assert f"## 오탐 (1)\n\n- {SERVICE} / FICT-2" in table
    assert f"## 추가 후보 (1)\n\n- {SERVICE} / FICT-9" in table


def test_saved_ablation_reads_only_final_totals(tmp_path, saved_runs):
    gold, first, second = saved_runs
    out = tmp_path / "out"
    for path, data in (
        (first, {"total_tokens": "측정 불가", "total_tokens_reason": "토큰 미기록", "total_seconds": 1.25}),
        (second, {"total_tokens": 132, "total_seconds": 2.5, "reported_reasoning_tokens": 45}),
    ):
        log = path.with_name("log-T-run1.jsonl")
        log.write_text(json.dumps({"stage": "model", "event": "usage", "data": {"total_tokens": 999}})
                       + "\n" + json.dumps({"stage": "run", "event": "end", "data": data}) + "\n",
                       encoding="utf-8")
    result = _run("ablation", "T", "--gold", gold, "--saved", tmp_path / "saved", "--out", out,
                  "--stage", "rules", "--stage", "model", "--component-alias", COMPONENT_ALIAS)

    assert result.returncode == 0, result.stderr
    table = (out / "ablation.md").read_text(encoding="utf-8")
    assert result.stdout == table
    assert "| 결정적 선판정 | 50.0% (2/4) | 50.0% (1/2) | 1 | 측정 불가 | 1.25 |" in table
    assert "| + 모델 판정 | 75.0% (3/4) | 50.0% (1/2) | 0 | 132 | 2.5 |" in table
    assert "토큰 미기록" in table
