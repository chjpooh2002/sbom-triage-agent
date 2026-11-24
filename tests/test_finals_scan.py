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
from triage.models import Evidence, Finding, Vulnerability
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
    stages = ("collect", "scope", "lookup", "judge", "cyclonedx", "pdf")
    assert [(e["stage"], e["event"]) for e in events if e["stage"] in stages and e["event"] in {"start", "end"}] == [
        (stage, event) for stage in stages for event in ("start", "end")
    ]
    assert all(event["data"]["seconds"] >= 0 for event in events if event["stage"] in stages and event["event"] == "end")
    assert (events[-1]["stage"], events[-1]["event"]) == ("run", "end")
    assert {"total_seconds", "total_tokens"} <= events[-1]["data"].keys()


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

    def failing_judge(findings, evidence, files, root, log):
        assert root == source.resolve()
        assert not files and any(item.id == "lookup-0001" for item in evidence)
        log("judge", "usage", total_tokens=17)
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
