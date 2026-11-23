from pathlib import Path

import pytest

from triage.ingest import ingest_paths, parse_file
from triage.models import Status

FX = Path(__file__).resolve().parents[1] / "samples" / "fixtures"
LOG4SHELL = "CVE-2021-44228"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


@pytest.mark.parametrize("name,conv,kind", [
    ("sbom.cdx.json", "cyclonedx", "sbom"), ("sbom.spdx.json", "spdx", "sbom"),
    ("grype.json", "grype", "scan"), ("trivy.json", "trivy", "scan"),
    ("osv.json", "osv-scanner", "scan"), ("assets.csv", "assets-table", "assets"),
])
def test_autodetect(name, conv, kind):
    p = parse_file(FX / name)
    assert (p.converter, p.kind) == (conv, kind)


@pytest.mark.parametrize("name", ["grype.json", "trivy.json", "osv.json"])
def test_scanner_finds_log4shell_with_cve_primary(name):
    p = parse_file(FX / name)
    hits = [f for f in p.findings if f.vulnerability.id == LOG4SHELL]
    assert len(hits) == 1
    f = hits[0]
    assert f.component.id == LOG4J
    assert f.vulnerability.cvss_score == 10.0
    assert "2.15.0" in f.vulnerability.fixed_versions
    assert any(a.startswith("GHSA-") for a in f.vulnerability.aliases)


def test_sbom_components_and_direct_flag():
    for name in ("sbom.cdx.json", "sbom.spdx.json"):
        p = parse_file(FX / name)
        ids = {c.id for c in p.components}
        assert LOG4J in ids
        log4j = next(c for c in p.components if c.id == LOG4J)
        assert log4j.direct is True and log4j.dependency_paths


def test_assets_korean_headers():
    p = parse_file(FX / "assets.csv")
    a = {x.asset_id: x for x in p.assets}
    assert a["SVC-001"].service_name == "주문 API"
    assert a["SVC-001"].internet_exposed is True and a["SVC-001"].criticality == 4
    assert a["SVC-002"].internet_exposed is False and a["SVC-002"].criticality == 3
    assert a["SVC-001"].match == ["target"]


def test_merge_three_scanners_into_one_finding():
    specs = [str(FX / "assets.csv"), str(FX / "sbom.cdx.json")] + [
        f"{FX / n}=SVC-001" for n in ("grype.json", "trivy.json", "osv.json")]
    b = ingest_paths(specs)
    hits = [f for f in b.findings if f.vulnerability.id == LOG4SHELL]
    assert len(hits) == 1
    f = hits[0]
    assert f.scanners == ["grype", "osv-scanner", "trivy"]
    assert f.asset_id == "SVC-001" and f.status == Status.affected
    assert f.key == f"{LOG4SHELL}|{LOG4J}|SVC-001"
    assert f.hints["kev"]["date_added"] == "2021-12-10"      # grype 가 준 보조 지표 보존
    # 한 자산 안에서 (취약점, 구성요소) 키는 유일해야 한다
    assert len({x.key for x in b.findings}) == len(b.findings)


def test_unknown_file_in_directory_is_skipped_with_warning():
    b = ingest_paths([str(FX)])
    assert any("README.md" in w for w in b.meta["warnings"])


def test_cyclonedx_vex_not_affected(tmp_path):
    import json
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": "app", "name": "app"}},
        "components": [{"bom-ref": "c1", "type": "library", "name": "log4j-core", "group": "org.apache.logging.log4j",
                        "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
        "dependencies": [{"ref": "app", "dependsOn": ["c1"]}],
        "vulnerabilities": [{"id": LOG4SHELL, "affects": [{"ref": "c1"}],
                             "analysis": {"state": "not_affected", "justification": "code_not_reachable"}}],
    }
    p = tmp_path / "vex.cdx.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    grype = f"{FX / 'grype.json'}=app"
    b = ingest_paths([f"{p}=app", grype])
    f = next(x for x in b.findings if x.vulnerability.id == LOG4SHELL)
    assert f.status == Status.not_affected and "code_not_reachable" in f.status_note


def test_trivy_jar_scan_without_package_ids_links_to_right_component(tmp_path):
    """trivy 의 jar 스캔은 Packages[].ID 가 비어 있다. 이때 취약점이 엉뚱한 패키지에 붙으면 안 된다."""
    import json
    doc = {"SchemaVersion": 2, "ArtifactName": "app.jar", "Results": [{
        "Target": "Java", "Class": "lang-pkgs", "Type": "jar",
        "Packages": [
            {"Name": "org.apache.logging.log4j:log4j-core", "Version": "2.14.1",
             "Identifier": {"PURL": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "UID": "u1"}},
            {"Name": "org.yaml:snakeyaml", "Version": "1.29",
             "Identifier": {"PURL": "pkg:maven/org.yaml/snakeyaml@1.29", "UID": "u2"}}],
        "Vulnerabilities": [{"VulnerabilityID": LOG4SHELL, "PkgName": "org.apache.logging.log4j:log4j-core",
                             "InstalledVersion": "2.14.1", "FixedVersion": "2.15.0",
                             "PkgIdentifier": {"PURL": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "UID": "u1"}}]}]}
    p = tmp_path / "t.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    f = parse_file(p).findings[0]
    assert f.component.id == LOG4J


def test_demo_app_log4j_only_on_log4j_core():
    demo = Path(__file__).resolve().parents[1] / "samples" / "demo-app" / "scan"
    b = ingest_paths([str(demo)])
    comps = {f.component.name for f in b.findings if f.vulnerability.id == LOG4SHELL}
    assert comps == {"log4j-core"}
    log4j = next(c for c in b.components if c.id == LOG4J)
    assert log4j.direct is False and log4j.dependency_paths      # 전이 의존성으로 들어옴(Gradle SBOM)
