import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from triage import finals
from triage.cli import app
from triage.collect import collect
from triage.fixplan import build_fix_plan, prepare_patch
from triage.lookup import LookupResult
from triage.models import Finding, Remediation, TriageBundle, Verdict, Vulnerability


FIXTURE = Path(__file__).parent / "fixtures" / "finals" / "fixplan"


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root)
    return root


def candidate(component, identifier, state="affected", aliases=()):
    return Finding(key=Finding.make_key(identifier, component.id, None), component=component,
                   vulnerability=Vulnerability(id=identifier, aliases=list(aliases)), verdict=Verdict(state=state))


def test_plan_edits_only_cited_declarations(project, tmp_path):
    collected = collect(project, offline=True)
    by_version = {(component.name, component.version): component for component in collected.components}
    overridden = next(component for component in collected.components if component.version_source == "property_override")
    by_version[overridden.name, overridden.version] = overridden
    cases = [
        (("demo-lock-pin", "1.2.3"), "1.3.0", "requirements.txt", "demo-lock-pin==1.3.0  # example pin"),
        (("python", "3.11.4-slim"), "3.11.9-slim", "Dockerfile", "FROM python:3.11.9-slim AS final"),
        (("demo-toml-pin", "2.1.0"), "2.2.0", "pyproject.toml", "demo-toml-pin[cli]==2.2.0; python_version < '4'"),
        (("demo-poetry-pin", "2.3.0"), "2.4.0", "pyproject.toml", 'demo-poetry-pin = "2.4.0"'),
        (("demo-node-pin", "3.0.0"), "3.1.0", "package.json", '"demo-node-pin": "3.1.0"'),
        (("demo-maven-pin", "4.1.0"), "4.2.0", "child/pom.xml", "<fixture.version>4.2.0</fixture.version>"),
        (("demo-direct-pin", "5.0.0"), "5.1.0", "child/pom.xml", "<version>5.1.0</version>"),
    ]
    findings = [candidate(by_version[key], f"TEST-{i}") for i, (key, *_) in enumerate(cases)]
    transitive = findings[0].component.model_copy(update={"id": "indirect", "direct": False, "evidence_ids": []})
    findings.append(candidate(transitive, "TEST-TRANSITIVE", state="undetermined"))
    unverified = transitive.model_copy(update={"id": "unverified"})
    findings.append(candidate(unverified, "TEST-UNVERIFIED"))
    versions = [case[1] for case in cases] + ["1.3.0", "1.3.0"]
    bundle = TriageBundle(findings=findings, evidence=collected.evidence, remediations=[
        Remediation(finding_key=finding.key, target_version=target, verified=finding.component.id != "unverified")
        for finding, target in zip(findings, versions)
    ])

    plan = build_fix_plan(bundle, project)
    for row, (_, target, file, expected) in zip(plan, cases):
        assert row["kind"] == "change" and row["target"] == target and row["file"] == file
        assert expected in row["after"]
        assert row["before"] == (project / file).read_text(encoding="utf-8").splitlines()[row["line"] - 1]
        assert row["evidence_ids"]
    assert plan[-2]["kind"] == "manual" and "전이 의존성" in plan[-2]["reason"]
    assert plan[-1]["kind"] == "manual" and plan[-1]["reason"] == "목표 버전 확인 필요"
    patch, files = prepare_patch(project, plan)
    assert "-demo-lock-pin==1.2.3" in patch and "+demo-lock-pin==1.3.0" in patch
    assert "-FROM python:3.11.4-slim" in patch and "+FROM python:3.11.9-slim" in patch
    assert "pom.xml" not in files
    if git := shutil.which("git"):
        patch_file = tmp_path / "test.patch"
        patch_file.write_bytes(patch.encode("utf-8"))
        subprocess.run([git, "apply", "--check", str(patch_file)], cwd=project, check=True, capture_output=True)


@pytest.mark.parametrize("lookup_result", ["complete", "cache_miss", "unexpected_error"])
def test_scan_applies_same_patch_and_compares_candidates(tmp_path, monkeypatch, lookup_result):
    root = tmp_path / "project"
    root.mkdir()
    shutil.copyfile(FIXTURE / "requirements.txt", root / "requirements.txt")
    source = root / "requirements.txt"
    before = source.read_bytes()
    calls = []
    judge_calls = []

    def lookup(components, offline=False, log=None):
        assert offline
        component, = components
        calls.append(component.version)
        if component.version == "1.2.3":
            return LookupResult([candidate(component, "TEST-GONE"), candidate(component, "TEST-STAYS")], [])
        assert component.version == "1.3.0" and source.read_bytes() == before
        if lookup_result == "cache_miss":
            log("lookup", "cache_miss", source="test")
        elif lookup_result == "unexpected_error":
            raise ValueError("unexpected fixture error")
        return LookupResult([candidate(component, "TEST-NOW-PRIMARY", aliases=["TEST-STAYS"]),
                             candidate(component, "TEST-NEW")], [])

    def remediate(bundle, *args, **kwargs):
        bundle.remediations = [Remediation(finding_key=item.key, target_version="1.3.0", verified=True)
                               for item in bundle.findings]

    def judge(findings, evidence, files, source_root, log, *, anomalies, usage):
        judge_calls.append(source_root)
        return findings

    monkeypatch.setattr(finals, "lookup", lookup)
    monkeypatch.setattr(finals, "remediate", remediate)
    monkeypatch.setattr(finals, "default_judge", lambda: judge)
    run_scan = finals.run_scan
    scan_results = []

    def capture_scan(*args, **kwargs):
        result = run_scan(*args, **kwargs)
        scan_results.append(result)
        return result

    monkeypatch.setattr(finals, "run_scan", capture_scan)
    cli_result = CliRunner().invoke(app, ["scan", "demo", str(root), str(root / "out"), "--offline"])
    assert cli_result.exit_code == int(lookup_result == "unexpected_error"), cli_result.output
    result, = scan_results

    assert source.read_bytes() == before and calls == ["1.2.3", "1.3.0"]
    assert judge_calls == [root]
    assert set(result.paths) == {"patch", "sbom", "report", "log"}
    assert "+demo-lock-pin==1.3.0" in result.paths["patch"].read_text(encoding="utf-8")
    records = [json.loads(line) for line in result.paths["log"].read_text(encoding="utf-8").splitlines()]
    change = next(event["data"] for event in records if (event["stage"], event["event"]) == ("fixplan", "change"))
    assert change["file"] == "requirements.txt" and change["line"] == 1
    assert "==1.2.3" in change["before"] and "==1.3.0" in change["after"]
    check = result.bundle.meta["fix_check"]
    logged_check = next(event["data"] for event in records if (event["stage"], event["event"]) == ("fixplan", "check"))
    if lookup_result != "complete":
        failed = lookup_result == "unexpected_error"
        assert ("fixplan" in result.failures) == failed
        assert check["status"] == logged_check["status"] == "unavailable"
        assert "재점검 불가" in check["reason"] and check["after_candidates"] is None
        assert not check["resolved"]
        assert any(a.kind == "stage_failure" for a in result.bundle.anomalies) == failed
        assert records[-1]["data"]["status"] == ("partial" if failed else "ok")
    else:
        assert not result.failures and check["status"] == "ok"
        assert check["before_candidates"] == 2 and check["after_candidates"] == 2
        assert [key.split("|")[0] for key in check["resolved"]] == ["TEST-GONE"]
        assert [key.split("|")[0] for key in check["remaining"]] == ["TEST-STAYS"]
        assert [key.split("|")[0] for key in check["new"]] == ["TEST-NEW"]
        assert logged_check["resolved"] == logged_check["remaining"] == logged_check["new"] == 1
        assert logged_check["new_findings"] == check["new"]
    assert logged_check["seconds"] >= 0
