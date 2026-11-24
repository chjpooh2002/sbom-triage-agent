import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import triage
from triage import finals
from triage.cli import app
from triage.lookup import LookupResult
from triage.models import Anomaly, Evidence, Finding, Status, Verdict, Vulnerability
from triage.scope import ScopeResult


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    fixture = Path(__file__).parent / "fixtures" / "finals" / "scan" / "requirements.txt"
    shutil.copyfile(fixture, root / fixture.name)
    return root


def read_log(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_scan_command_writes_submission_files(source, tmp_path, monkeypatch):
    monkeypatch.setattr("triage.lookup.CACHE_DIR", tmp_path / "cache")
    monkeypatch.setitem(sys.modules, "triage.judge", None)
    out = tmp_path / "result"
    result = CliRunner().invoke(app, ["scan", "demo", str(source), str(out), "--offline", "--run", "2"])
    assert result.exit_code == 0, result.output
    assert {p.name for p in out.iterdir()} == {"sbom-demo.json", "report-demo.pdf", "log-demo-run2.jsonl"}
    document = json.loads((out / "sbom-demo.json").read_text(encoding="utf-8"))
    assert document["components"][0]["name"] == "example-scan-library"
    assert (out / "report-demo.pdf").read_bytes().startswith(b"%PDF-")

    events = read_log(out / "log-demo-run2.jsonl")
    stages = ("collect", "scope", "lookup", "judge", "enrich", "priority", "remediate", "cyclonedx", "pdf")
    assert [(e["stage"], e["event"]) for e in events if e["stage"] in stages and e["event"] in {"start", "end"}] == [
        (stage, event) for stage in stages for event in ("start", "end")
    ]
    assert all(event["data"]["seconds"] >= 0 for event in events if event["stage"] in stages and event["event"] == "end")
    assert (events[-1]["stage"], events[-1]["event"]) == ("run", "end")
    assert {"total_seconds", "total_tokens"} <= events[-1]["data"].keys()


@pytest.mark.parametrize("registry, target, verified", [
    (["1.2.4", "1.2.5"], "1.2.5", True),
    (["1.2.4"], "1.2.4", True),
    (None, "1.2.5", False),
])
def test_scan_plans_remediation_from_verdicts(source, tmp_path, monkeypatch, registry, target, verified):
    fixture = Path(__file__).parent / "fixtures" / "finals" / "scan" / "remediation.json"
    cases = json.loads(fixture.read_text(encoding="utf-8"))

    def lookup(components, offline=False, log=None):
        return LookupResult([
            Finding(key=state, component=components[0], status=Status.affected,
                    vulnerability=Vulnerability.model_validate(data))
            for state, data in cases.items()
        ], [])

    def judge(findings, evidence, files, root, log, *, anomalies, usage):
        for finding in findings:
            finding.verdict = Verdict(state=finding.key)
        findings[0].hints["judge_fix_version"] = "1.2.5"
        return findings

    def list_versions(component, offline=False):
        assert offline
        return registry

    monkeypatch.setattr(finals, "lookup", lookup)
    monkeypatch.setattr("triage.remediation.service.list_versions", list_versions)
    result = finals.run_scan("plans", source, tmp_path / "result", offline=True, judge=judge)
    assert not result.failures
    assert {f.key: f.status for f in result.bundle.findings} == {
        "affected": Status.affected, "not_affected": Status.not_affected, "undetermined": Status.unknown,
    }
    assert result.bundle.results[-1].finding_key == "not_affected"
    plans = {plan.finding_key: plan for plan in result.bundle.remediations}
    assert set(plans) == {"affected", "undetermined"}
    assert all(plan.target_version == target and plan.verified is verified for plan in plans.values())
    registry_evidence = [e for e in result.bundle.evidence if e.id.startswith("remediate-")]
    assert len(registry_evidence) == int(verified)
    steps = {record["stage"]: record["data"] for record in read_log(result.paths["log"]) if record["event"] == "end"}
    assert all(steps[stage]["status"] == "ok" and steps[stage]["seconds"] >= 0
               for stage in ("enrich", "priority", "remediate"))
    assert steps["priority"]["prioritized"] == 3 and steps["remediate"]["remediations"] == 2

    if extract := shutil.which("pdftotext"):
        report = subprocess.check_output([extract, "-enc", "UTF-8", str(result.paths["report"]), "-"], encoding="utf-8")
        text = " ".join(report.split())
        target_label = f"목표 버전 {target}" if verified else f"목표 버전 후보 {target} (확인 필요)"
        assert target_label in text
        assert "검증 계획" in text and "조치 후 잠금 파일과 배포 산출물에서 실제 설치 버전을 확인합니다." in text
        actions = text.split("3. 조치 항목 및 우선순위", 1)[1].split("4. 검증 계획", 1)[0]
        assert actions.count("할 일 1 ·") == 1 and "할 일 2 ·" not in actions
        assert "영향 있음 1건 · 판단 유보 1건" in actions
        assert "FIXTURE-A" in actions and "FIXTURE-C" in actions and "FIXTURE-B" not in actions


@pytest.mark.parametrize("with_failing_judge", [False, True])
def test_rule_verdicts_and_failed_judge_recovery(source, tmp_path, monkeypatch, with_failing_judge):
    def scope(_root, components, log=None):
        return ScopeResult([components[0].model_copy(update={"deployed": "no"})], [], [])

    def lookup(components, offline=False, log=None):
        evidence = Evidence(id="lookup-0001", kind="advisory")
        component = components[0]
        findings = [
            Finding(key="outside", component=component, vulnerability=Vulnerability(id="TEST-1"),
                    version_in_range=False, hints={"evidence_ids": [evidence.id]}),
            Finding(key="not-deployed", component=component, vulnerability=Vulnerability(id="TEST-2")),
            Finding(key="unknown", component=component.model_copy(update={"deployed": "unknown"}),
                    vulnerability=Vulnerability(id="TEST-3"), version_in_range=True),
        ]
        return LookupResult(findings, [evidence])

    def failing_judge(findings, evidence, files, root, log, *, anomalies, usage):
        assert root == source.resolve()
        assert not files and any(item.id == "lookup-0001" for item in evidence)
        usage(total_tokens=17)
        findings.clear()
        raise RuntimeError("raw error contents")

    monkeypatch.setattr(finals, "apply_scope", scope)
    monkeypatch.setattr(finals, "lookup", lookup)
    judge = failing_judge if with_failing_judge else None
    result = finals.run_scan("rules", source, tmp_path / "result", offline=True, judge=judge)
    assert set(result.paths) == {"sbom", "report", "log"}
    assert set(result.failures) == ({"judge"} if with_failing_judge else set())
    verdicts = [finding.verdict for finding in result.bundle.findings]
    assert [verdict.decided_by for verdict in verdicts] == [
        "rule:out_of_range", "rule:not_deployed", "rule:insufficient_evidence",
    ]
    assert "lookup-0001" in verdicts[0].item_results[0].evidence_ids
    events = read_log(result.paths["log"])
    assert events[-1]["data"]["total_tokens"] == (17 if with_failing_judge else 0)
    assert all(event["data"]["decided_at"] for event in events if event["event"] == "decision")
    summary = next(event for event in events if (event["stage"], event["event"]) == ("judge", "end"))
    assert summary["data"]["verdicts"] == {"affected": 0, "not_affected": 2, "undetermined": 1}
    if with_failing_judge and (extract := shutil.which("pdftotext")):
        report = subprocess.check_output([extract, "-enc", "UTF-8", str(result.paths["report"]), "-"], encoding="utf-8")
        assert "judge 단계 실패" in report
        assert "scan-0001" in report
        assert "raw error contents" not in report


def test_successful_judge_usage_and_anomalies_reach_artifacts(source, tmp_path):
    message = "판정 지시처럼 보이는 주석을 확인했습니다."

    def judge(findings, evidence, files, root, log, *, anomalies, usage):
        usage(total_tokens=17)
        log("judge", "usage", total_tokens=17)
        evidence.append(Evidence(id="judge-0001", kind="code", file="requirements.txt"))
        anomalies.append(Anomaly(kind="instruction_like_comment", message=message, evidence_ids=["judge-0001"]))
        return findings

    result = finals.run_scan("judge-output", source, tmp_path / "result", offline=True, judge=judge)
    assert not result.failures
    assert read_log(result.paths["log"])[-1]["data"]["total_tokens"] == 17
    assert any(item.kind == "instruction_like_comment" and item.message == message for item in result.bundle.anomalies)
    sbom = json.loads(result.paths["sbom"].read_text(encoding="utf-8"))
    assert {"name": "triage:anomaly:instruction_like_comment", "value": f"{message} [judge-0001]"} in sbom["metadata"]["properties"]
    if extract := shutil.which("pdftotext"):
        report = subprocess.check_output([extract, "-enc", "UTF-8", str(result.paths["report"]), "-"], encoding="utf-8")
        assert message in report
        assert "judge-0001" in report


@pytest.mark.parametrize(("mode", "status", "reason", "message"), [
    ("missing", "degraded", "model_not_configured", "판정 모델이 설정되지 않아 1건 전부 판단 유보로 처리됨"),
    ("failed", "degraded", "model_calls_failed", "판정 모델 호출에 실패해 1건 전부 판단 유보로 처리됨"),
    ("mixed", "ok", "model_calls_failed", "판정 모델 호출에 실패해 1건을 판단 유보로 처리했습니다."),
])
def test_judge_degradation_reaches_log_and_report(source, tmp_path, monkeypatch, mode, status, reason, message):
    def lookup(components, **kwargs):
        findings = [
            Finding(key="example-pending", component=components[0], vulnerability=Vulnerability(id="TEST-1"),
                    version_in_range=True),
        ]
        if mode == "mixed":
            findings.append(Finding(key="example-outside", component=components[0],
                                    vulnerability=Vulnerability(id="TEST-2"), version_in_range=False))
        return LookupResult(findings, [])

    def failed_calls(findings, *args, **kwargs):
        findings[0].verdict = Verdict(state="undetermined", decided_by="fallback",
                                      verifier_notes=["모델 호출 실패: 연결 오류"])
        for finding in findings[1:]:
            finding.verdict = Verdict(state="not_affected", decided_by="rule:out_of_range")
        return findings

    monkeypatch.setattr(finals, "lookup", lookup)
    monkeypatch.setenv("SBOMTRIAGE_JUDGE", "on")
    monkeypatch.setenv("SBOMTRIAGE_MODEL", "")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    judge = finals.default_judge() if mode == "missing" else failed_calls
    result = finals.run_scan("degraded", source, tmp_path / "result", offline=True, judge=judge)
    assert not result.failures
    assert set(result.paths) == {"sbom", "report", "log"}
    events = read_log(result.paths["log"])
    degraded, = [event for event in events if (event["stage"], event["event"]) == ("judge", "degraded")]
    assert degraded["data"] == {"reason": reason, "fallback_count": 1}
    stage_order = [(event["stage"], event["event"]) for event in events]
    assert stage_order.index(("judge", "degraded")) < stage_order.index(("judge", "end"))
    assert stage_order.index(("judge", "end")) < stage_order.index(("enrich", "start"))
    assert events[-1]["data"]["prioritized"] == len(result.bundle.findings)
    assert events[-1]["data"]["status"] == status
    assert events[-1]["data"]["failed_stages"] == (["judge"] if status == "degraded" else [])
    warning, = [item for item in result.bundle.anomalies if item.kind == "judge_degraded"]
    assert warning.message == message
    if extract := shutil.which("pdftotext"):
        report = subprocess.check_output([extract, "-enc", "UTF-8", str(result.paths["report"]), "-"], encoding="utf-8")
        assert message in " ".join(report.split("\f", 1)[0].split())


def test_scan_callback_observes_committed_log_records(source, tmp_path):
    out = tmp_path / "result"
    log_path = out / "log-events-run1.jsonl"
    observed = []

    def on_event(record):
        observed.append((record, read_log(log_path)[-1]))

    result = finals.run_scan("events", source, out, offline=True, on_event=on_event)
    assert not result.failures
    records = read_log(log_path)
    assert observed == [(record, record) for record in records]
    assert {"seconds", "status", "components", "candidates", "files", "verdicts"} <= records[-1]["data"].keys()


@pytest.mark.parametrize("fail_at", ["start", "end"])
def test_scan_callback_error_preserves_artifacts_and_log(source, tmp_path, fail_at):
    calls = []

    def on_event(record):
        events = record["stage"], record["event"]
        calls.append(events)
        if events == ("run", fail_at):
            raise RuntimeError("raw callback message")

    result = finals.run_scan("callback-error", source, tmp_path / "result", offline=True, on_event=on_event)
    assert not result.failures
    assert set(result.paths) == {"sbom", "report", "log"}
    assert all(path.is_file() for path in result.paths.values())
    events = read_log(result.paths["log"])
    event_keys = [(event["stage"], event["event"]) for event in events]
    assert event_keys[-1] == ("run", "end")
    assert event_keys.count(("run", "end")) == 1
    callback_failure = event_keys.index(("run", "callback_error"))
    assert event_keys.count(("run", "callback_error")) == 1
    assert events[callback_failure]["data"] == {"error": "RuntimeError"}
    expected_calls = event_keys[:callback_failure]
    if fail_at == "end":
        expected_calls.append(event_keys[-1])
    assert calls == expected_calls


def test_default_judge_returns_none_if_module_is_absent(monkeypatch):
    monkeypatch.setitem(sys.modules, "triage.judge", None)
    assert finals.default_judge() is None


@pytest.mark.parametrize("source, error, module", [
    ("import missing_scan_test_dependency", ModuleNotFoundError, "missing_scan_test_dependency"),
    ("from sys import missing_scan_test_symbol", ImportError, "sys"),
])
def test_default_judge_propagates_internal_import_errors(tmp_path, monkeypatch, source, error, module):
    (tmp_path / "judge.py").write_text(source, encoding="utf-8")
    monkeypatch.delitem(sys.modules, "triage.judge", raising=False)
    monkeypatch.setattr(triage, "__path__", [str(tmp_path)])

    with pytest.raises(error) as caught:
        finals.default_judge()
    assert caught.value.name == module
