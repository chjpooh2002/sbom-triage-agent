"""C2 공개 API의 정적 배포 판정과 근거 연결을 검증한다."""
from pathlib import Path

from triage.models import Component
from triage.scope import apply_scope

FIXTURES = Path(__file__).parent / "fixtures" / "finals"


def _assert_evidence(result):
    refs = {item.id for item in result.evidence}
    assert [item.id for item in result.evidence] == [f"scope-{index:04d}" for index in range(1, len(refs) + 1)]
    for item in [*result.files, *result.components]:
        scope_refs = {ref for ref in item.evidence_ids if ref.startswith("scope-")}
        assert scope_refs and scope_refs <= refs


def test_final_copy_ignore_classification_and_install_tools():
    components = [
        Component(id="npm:core", ecosystem="npm", name="orbit-core", version="1.0.0", sources=["package-lock.json"]),
        Component(id="npm:checker#node_modules/pixel-check", ecosystem="npm", name="pixel-check", version="2.0.0",
                  scope="dev", sources=["package-lock.json"], evidence_ids=["collect-0001"]),
        Component(id="npm:checker#node_modules/orbit-core/node_modules/pixel-check", ecosystem="npm",
                  name="pixel-check", version="2.0.0", sources=["package-lock.json"]),
        Component(id="pypi:demo", ecosystem="pypi", name="pep-demo", version="1.2"),
        Component(id="pypi:constraint", ecosystem="pypi", name="constraint-demo", version="1.0"),
        Component(id="pypi:marker", ecosystem="pypi", name="marker-demo", version="2.0"),
        Component(id="vendored:chart", name="chart", version_source="vendored", sources=["app/chart.min.js"]),
        Component(id="runtime:python", name="python", version="3.11", kind="runtime", version_source="dockerfile"),
    ]
    events = []
    result = apply_scope(FIXTURES / "scope-node", components, lambda stage, event, **data: events.append((stage, event, data)))
    assert [item.deployed for item in result.components] == ["yes", "no", "yes", "yes", "unknown", "unknown", "yes", "yes"]
    assert result.components[1].evidence_ids[0] == "collect-0001"
    assert all(item.deployed == "unknown" for item in components)
    files = {item.path: (item.deployed, item.category) for item in result.files}
    assert files["app/main.py"] == ("yes", "app")
    assert files["app/tests/discard.py"] == ("no", "test")
    assert files["app/tests/keep.py"] == ("yes", "test")
    assert files["tools/bootstrap.sh"] == ("no", "script")
    assert files["app/snapshot.js"] == ("yes", "generated")
    assert files["app/generated/index.js"] == ("yes", "generated")
    assert files["app/chart.min.js"] == ("yes", "vendored_bundle")
    assert files["app/legacy/v1.py"] == ("yes", "legacy")
    assert files["settings/service.cfg"] == ("yes", "config")
    assert files["settings/drop.cfg"] == ("no", "config")
    assert files["package-lock.json"] == ("no", "config")
    assert events[0][:2] == ("scope", "complete")
    _assert_evidence(result)


def test_maven_selected_project_and_reactor_dependencies():
    components = [Component(id=f"maven:{name}", name=name, module=module, ecosystem="maven", scope=scope)
                  for name, module, scope in [("network", "entry", "runtime"), ("codec", "shared", "runtime"),
                                              ("formatter", "unused", "runtime"), ("checker", "entry", "test"),
                                              ("other", "outside", "runtime")]]
    result = apply_scope(FIXTURES / "scope-maven", components)
    assert [item.deployed for item in result.components] == ["yes", "yes", "no", "no", "unknown"]
    refs = {item.id: item for item in result.evidence}
    assert any("--also-make" in refs[ref].snippet for ref in result.components[1].evidence_ids)
    assert {refs[ref].file for ref in result.components[1].evidence_ids} >= {"entry/pom.xml", "shared/pom.xml"}
    _assert_evidence(result)


def test_inherited_stage_preserves_npm_production_install():
    component = Component(id="npm:lint", name="lint-unit", version="1.0", ecosystem="npm", scope="dev",
                          sources=["package-lock.json"])
    result = apply_scope(FIXTURES / "scope-inherit", [component])
    assert result.components[0].deployed == "no"
    assert {item.path: item.deployed for item in result.files}["package-lock.json"] == "yes"
    _assert_evidence(result)


def test_absent_dockerfile_keeps_classification_and_marks_everything_unknown():
    component = Component(id="example", name="example", deployed="yes")
    result = apply_scope(FIXTURES / "scope-node" / "app", [component])
    assert result.components[0].deployed == "unknown"
    assert "Dockerfile" in result.components[0].deployed_reason
    assert {item.deployed for item in result.files} == {"unknown"}
    assert {item.category for item in result.files} >= {"test", "legacy", "generated", "vendored_bundle"}
    _assert_evidence(result)


def test_unresolved_build_paths_are_unknown():
    result = apply_scope(FIXTURES / "scope-uncertain", [])
    files = {item.path: item for item in result.files}
    assert files["example.py"].deployed == "unknown"
    _assert_evidence(result)
