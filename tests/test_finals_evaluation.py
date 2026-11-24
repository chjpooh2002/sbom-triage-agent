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


def _run(module, *args, env=None):
    return subprocess.run([sys.executable, "-m", f"eval.{module}", *map(str, args)], cwd=REPO,
                          encoding="utf-8", env={**os.environ, "PYTHONUTF8": "1", **(env or {})},
                          capture_output=True)


def _write_sbom(path, components, vulnerabilities):
    path.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "name": SERVICE}},
        "components": components,
        "vulnerabilities": vulnerabilities,
    }), encoding="utf-8")


def _runner_env(tmp_path, code):
    package = tmp_path / "triage"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from pkgutil import extend_path\n__path__ = extend_path(__path__, __name__)\n", encoding="utf-8"
    )
    (package / "finals.py").write_text(code, encoding="utf-8")
    return {"PYTHONPATH": str(tmp_path)}


def _write_advisory(cache, identifier, *, package="widget", kind="ECOSYSTEM", events=None):
    snapshot = cache / "2040-01-01"
    snapshot.mkdir(parents=True, exist_ok=True)
    doc = {
        "id": f"OSV-{identifier}", "aliases": [identifier],
        "affected": [{"package": {"ecosystem": "PyPI", "name": package},
                      "ranges": [{"type": kind, "events": events or [{"introduced": "0"}, {"fixed": "2.0"}]}]}],
    }
    (snapshot / f"osv-vuln-{identifier}.json").write_text(json.dumps(doc), encoding="utf-8")


@pytest.fixture
def saved_runs(tmp_path):
    gold = tmp_path / "gold.csv"
    with gold.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("service", "vuln_id", "aliases", "component", "expected_state", "scoring_set", "version"))
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
        _write_sbom(path, [{"type": "library", "bom-ref": "dep", "name": "wIDGET", "group": "other.group",
                            "components": [{"type": "library", "name": "nested", "bom-ref": "child"}]}],
                    vulnerabilities)
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
    assert "| core 정확 일치율 (엄격) | 50.0% (2/4) |" in table
    assert "| core 정확 일치율 (버전 제외 인정) | 50.0% (2/4) |" in table
    assert "| core 영향 있음 재현율 | 50.0% (1/2) |" in table
    assert "| core 영향 있음 정밀도 | 33.3% (1/3) |" in table
    assert "| core 후보 누락 | 1 |" in table
    assert "| 정답에 없는 추가 후보 | 1 |" in table
    assert "| aux 판단 유보율 | 33.3% (1/3) |" in table
    assert "| aux missing_info 기재율 | 33.3% (1/3) |" in table
    assert "| run1·run2 판정 일치율 | 57.1% (4/7) |" in table
    assert f"## 놓친 영향 있음 (1)\n\n- {SERVICE} / FICT-3" in table
    assert f"## 오탐 (1)\n\n- {SERVICE} / FICT-2" in table
    assert f"## 추가 후보 (1)\n\n- {SERVICE} / FICT-9 / wIDGET (affected)" in table
    assert f"## 정답지 밖 영향 있음 검토 (1)\n\n- {SERVICE} / FICT-9 / wIDGET (affected)" in table


def test_score_uses_install_version_only_for_shared_gold_key(tmp_path):
    gold = tmp_path / "gold.csv"
    with gold.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("service", "vuln_id", "aliases", "component", "expected_state", "scoring_set", "version"))
        writer.writerows([
            (SERVICE, "FICT-1", "ALT-1", "Widget", "affected", "core", "1.0 (pinned)"),
            (SERVICE, "FICT-1", "", "Widget", "undetermined", "aux", "2.0 (transitive)"),
            (SERVICE, "FICT-2", "", "Widget", "not_affected", "core", "3.0 (old metadata)"),
        ])
    first, second = (tmp_path / f"run{number}.json" for number in (1, 2))
    components = [{"type": "library", "bom-ref": version, "name": "widget", "version": version}
                  for version in ("1.0", "2.0", "4.0", "5.0")]
    vulnerabilities = [
        _vex("ALT-1", "exploitable", component="1.0"),
        _vex("FICT-1", "in_triage", component="2.0"),
        _vex("FICT-2", "not_affected", component="4.0"),
        _vex("FICT-1", "not_affected", component="5.0"),
    ]
    _write_sbom(first, components, vulnerabilities)
    _write_sbom(second, components, list(reversed(vulnerabilities)))

    result = _run("finals_score", "T", "--gold", gold, "--sbom", first, "--run2", second, "--out", tmp_path)

    assert result.returncode == 0, result.stderr
    assert "| core 정확 일치율 (엄격) | 100.0% (2/2) |" in result.stdout
    assert "| core 영향 있음 정밀도 | 100.0% (1/1) |" in result.stdout
    assert "| aux 판단 유보율 | 100.0% (1/1) |" in result.stdout
    assert "| run1·run2 판정 일치율 | 100.0% (4/4) |" in result.stdout
    assert f"## 추가 후보 (1)\n\n- {SERVICE} / FICT-1 / widget @ 5.0 (not_affected)" in result.stdout


def test_missing_candidates_need_cached_osv_range_to_count_as_excluded(tmp_path):
    gold = tmp_path / "gold.csv"
    cache = tmp_path / "cache"
    _write_advisory(cache, "FICT-FIXED")
    _write_advisory(cache, "FICT-BEFORE", events=[{"introduced": "3.0"}])
    _write_advisory(cache, "FICT-LAST", events=[{"introduced": "0"}, {"last_affected": "2.0"}])
    _write_advisory(cache, "FICT-OTHER", package="other")
    _write_advisory(cache, "FICT-UNKNOWN")
    _write_advisory(cache, "FICT-GIT", kind="GIT")
    with gold.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("service", "vuln_id", "aliases", "component", "expected_state", "scoring_set", "version"))
        for key, state, version in (
            ("FIXED", "not_affected", "2.0 (pinned)"),
            ("BEFORE", "affected", "2.0"),
            ("LAST", "not_affected", "2.0"),
            ("OTHER", "not_affected", "3.0"),
            ("UNKNOWN", "not_affected", "3.x"),
            ("GIT", "not_affected", "3.0"),
            ("NO-CACHE", "not_affected", "3.0"),
            ("PRESENT", "not_affected", "3.0"),
        ):
            writer.writerow((SERVICE, f"FICT-{key}", "", "Widget", state, "core", version))
    sbom = tmp_path / "sbom-T.json"
    _write_sbom(sbom, [{"type": "library", "bom-ref": "dep", "name": "Widget"}],
                [_vex("FICT-PRESENT", "not_affected")])

    result = _run("finals_score", "T", "--gold", gold, "--sbom", sbom, "--out", tmp_path, "--osv-cache", cache)

    assert result.returncode == 0, result.stderr
    table = result.stdout
    assert "| core 정확 일치율 (엄격) | 12.5% (1/8) |" in table
    assert "| core 정확 일치율 (버전 제외 인정) | 25.0% (2/8) |" in table
    assert "| core 후보 누락 | 5 |" in table
    assert "| 버전 범위 밖 제외 | 2 |" in table
    exclusions = table.split("## 버전 범위 밖 제외 (2)")[1].split("\n## ")[0]
    assert "FICT-FIXED / Widget @ 2.0 (pinned) (OSV OSV-FICT-FIXED)" in exclusions
    assert "FICT-BEFORE / Widget @ 2.0 (OSV OSV-FICT-BEFORE)" in exclusions


def test_saved_ablation_writes_csv_and_reads_judge_and_run_totals(tmp_path, saved_runs):
    gold, first, second = saved_runs
    out = tmp_path / "out"
    cache = tmp_path / "cache"
    _write_advisory(cache, "FICT-11")
    with gold.open("a", encoding="utf-8", newline="") as stream:
        csv.writer(stream).writerow((SERVICE, "FICT-11", "", "Widget", "not_affected", "core", "3.0"))
    for path, event, data in (
        (first, "detail.end", {"total_tokens": "측정 불가", "total_tokens_reason": "토큰 미기록", "total_seconds": 1.25}),
        (second, "end", {"total_tokens": 132, "total_seconds": 2.5, "reported_reasoning_tokens": 45}),
    ):
        log = path.with_name("log-T-run1.jsonl")
        events = [
            {"stage": "judge", "event": event, "data": {"llm_calls": 4, "total_tokens": 999}},
            {"stage": "run", "event": "end", "data": dict(data, llm_calls=999)},
        ]
        log.write_text("".join(json.dumps(record) + "\n" for record in events), encoding="utf-8")
    result = _run("ablation", "T", "--gold", gold, "--saved", tmp_path / "saved", "--out", out,
                  "--stage", "rules", "--stage", "model", "--component-alias", COMPONENT_ALIAS, "--osv-cache", cache)

    assert result.returncode == 0, result.stderr
    table = (out / "ablation.md").read_text(encoding="utf-8")
    assert result.stdout == table
    assert "| 결정적 선판정 | 40.0% (2/5) | 60.0% (3/5) | 50.0% (1/2) | 1 | 1 | 측정 불가 | 측정 불가 | 1.25 |" in table
    assert "| + 모델 판정 | 60.0% (3/5) | 80.0% (4/5) | 50.0% (1/2) | 0 | 2 | 4 | 132 | 2.5 |" in table
    assert "토큰 미기록" in table
    with (out / "ablation.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.reader(stream))
    assert rows == [line.strip("|").strip().split(" | ") for line in table.splitlines()
                    if line.startswith("|") and not line.startswith("| ---")]


@pytest.mark.parametrize(("adapter", "message"), [
    ("", "triage.finals.default_judge가 필요합니다"),
    ("def default_judge():\n    return None\n", "SBOMTRIAGE_JUDGE=on 단계에 판정기가 필요합니다"),
])
def test_live_ablation_stops_before_scanning_without_judge(tmp_path, saved_runs, adapter, message):
    gold, _, _ = saved_runs
    env = _runner_env(tmp_path, adapter + "\ndef run_scan(*args, **kwargs):\n    raise AssertionError('scan started')\n")
    env["SBOMTRIAGE_REFERENCE_MODEL"] = ""
    result = _run("ablation", "T", "--gold", gold, "--root", tmp_path, "--out", tmp_path,
                  env=env)

    assert result.returncode == 2
    assert message in result.stderr
    assert "scan started" not in result.stderr
    assert not (tmp_path / "ablation-runs").exists()


def test_live_ablation_passes_default_judge_to_scan(tmp_path, saved_runs):
    gold, _, _ = saved_runs
    env = _runner_env(tmp_path, '''\
import json
import os
import shutil

def default_judge():
    assert os.environ['SBOMTRIAGE_LLM_CACHE'] == 'off'
    return str

def run_scan(label, root, out_dir, *, offline, judge):
    assert judge is default_judge()
    assert offline is True
    flags = ('SBOMTRIAGE_JUDGE', 'SBOMTRIAGE_VERIFY', 'SBOMTRIAGE_ESCALATE')
    assert tuple(os.environ[key] for key in flags) == ('on', 'off', 'off')
    shutil.copyfile(root / 'saved' / 'rules' / f'sbom-{label}.json', out_dir / f'sbom-{label}.json')
    data = {'total_tokens': 1, 'total_seconds': 0.5}
    records = [{'stage': 'judge', 'event': 'end', 'data': {'llm_calls': 0}},
               {'stage': 'run', 'event': 'end', 'data': data}]
    (out_dir / f'log-{label}-run1.jsonl').write_text(chr(10).join(map(json.dumps, records)), encoding='utf-8')
'''
    )
    env["SBOMTRIAGE_LLM_CACHE"] = "on"
    result = _run("ablation", "T", "--gold", gold, "--root", tmp_path, "--out", tmp_path,
                  "--stage", "model", "--offline", "--component-alias", COMPONENT_ALIAS, env=env)

    assert result.returncode == 0, result.stderr
    assert "| + 모델 판정 | 50.0% (2/4) | 50.0% (2/4) | 50.0% (1/2) | 1 | 1 | 0 | 1 | 0.5 |" in result.stdout
