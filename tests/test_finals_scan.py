import json
import shutil
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from triage import finals
from triage.cli import app
from triage.lookup import LookupResult
from triage.models import Evidence, Finding, Vulnerability
from triage.scope import ScopeResult


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "requirements.txt").write_text("example-scan-library==1.2.3\n", encoding="utf-8")
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
