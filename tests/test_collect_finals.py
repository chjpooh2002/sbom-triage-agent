import json
from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace
from zipfile import ZipFile

from triage.collect import CollectResult, collect, maven, syft

FIX = Path(__file__).parent / "fixtures/finals/collect"


def verify(result, root):
    assert isinstance(result, CollectResult)
    refs = {e.id: e for e in result.evidence}
    assert list(refs) == [f"collect-{i:04d}" for i in range(1, len(refs) + 1)]
    for item in [*result.components, *result.anomalies]:
        assert item.evidence_ids and set(item.evidence_ids) <= refs.keys()
    for item in result.components:
        assert item.version_source
    for e in result.evidence:
        if e.line_start and not e.url and "!/" not in e.file and e.kind != "tool":
            assert (root / e.file).read_text(encoding="utf-8").splitlines()[e.line_start - 1][:600] == e.snippet
    return refs


def test_npm_nested_scope_graph_and_drift():
    root = FIX / "npm"
    events = []
    result = collect(root, log=lambda stage, event, **data: events.append((stage, event)))
    refs = verify(result, root)
    assert result == collect(root)
    assert events[0] == ("collect", "adapter.start") and events[-1] == ("collect", "end")
    top, nested = [c for c in result.components if c.name == "copper-rim"]
    assert (top.direct, top.version, top.declared_spec) == (True, "3.0.1", "^4.0.0")
    assert (nested.direct, nested.version) == (False, "1.2.0")
    assert nested.id.endswith("#node_modules/arc-dial/node_modules/copper-rim")
    assert next(c for c in result.components if c.name == "arc-dial").depends_on == [nested.id]
    for c, line in ((top, 13), (nested, 16)):
        assert any(refs[r].line_start == line and refs[r].kind == "lockfile" for r in c.evidence_ids)
    assert next(c for c in result.components if c.name == "ink-probe").scope == "dev"
    assert len(result.anomalies) == 2
    for anomaly in result.anomalies:
        assert anomaly.kind == "lock_mismatch"
        assert {refs[r].kind for r in anomaly.evidence_ids} == {"manifest", "lockfile"}


def test_npm_missing_lock(tmp_path):
    copyfile(FIX / "npm/package.json", tmp_path / "package.json")
    result = collect(tmp_path)
    verify(result, tmp_path)
    assert len(result.components) == len(result.anomalies) == 3
    assert all(not c.version and c.version_source == "manifest_range" for c in result.components)


def test_npm_v2_without_manifest_keeps_directness_unknown(tmp_path):
    path = tmp_path / "package-lock.json"
    tree = json.loads((FIX / "npm" / path.name).read_text(encoding="utf-8"))
    tree["lockfileVersion"] = 2
    path.write_text(json.dumps(tree, indent=2), encoding="utf-8")
    result = collect(tmp_path)
    verify(result, tmp_path)
    assert len(result.components) == 4 and all(c.direct is None for c in result.components)


def test_invalid_npm_lock_preserves_declarations(tmp_path):
    copyfile(FIX / "npm/package.json", tmp_path / "package.json")
    (tmp_path / "package-lock.json").write_text("{", encoding="utf-8")
    result = collect(tmp_path)
    assert len(result.components) == 3 and all(not c.version for c in result.components)
    assert any(a.kind == "unsupported_lockfile" for a in result.anomalies)


def test_python_directness_ranges_and_lock_disagreement():
    root = FIX / "python"
    result = collect(root)
    verify(result, root)
    comps = {c.name: c for c in result.components}
    assert len(comps) == len(result.components) == 6
    assert comps["vial-meter"].version == "3.3.0" and comps["vial-meter"].declared_spec == "==3.2.1"
    assert comps["amber-kite"].version == "0.8.2" and comps["amber-kite"].version_source == "manifest_pinned"
    assert comps["plain-ring"].version == "" and comps["plain-ring"].direct is None
    assert comps["thin-lens"].direct is True and comps["thin-lens"].version == "4.1.0"
    assert comps["blue-spline"].direct is None
    assert comps["blue-spline"].scope == comps["wax-finch"].scope == "dev"
    assert comps["wax-finch"].direct is True
    assert [a.kind for a in result.anomalies] == ["lock_mismatch"]


def test_maven_remote_parent_bom_cache_and_property_override(tmp_path, monkeypatch):
    urls = []
    def download(url):
        urls.append(url)
        name = url.split("/")[-3]
        return (FIX / "central" / (name + ".pom")).read_text(encoding="utf-8")

    monkeypatch.setattr(maven, "CACHE", tmp_path)
    monkeypatch.setattr(maven, "download", download)
    root = FIX / "maven"
    result = collect(root)
    refs = verify(result, root)
    assert result.anomalies == []
    assert len(urls) == len(list(tmp_path.rglob("*.pom"))) == 2
    deps = {(c.module, c.name): c for c in result.components}
    assert len(deps) == 4
    wheel = deps["wheel", "bearing"]
    assert (wheel.version, wheel.scope, wheel.version_source) == ("2.7.0", "test", "property_override")
    assert any("2.7.0" in refs[r].snippet and refs[r].file == "wheel/pom.xml" for r in wheel.evidence_ids)
    assert deps["axle", "bearing"].version == "2.4.0"
    sleeve = deps["wheel", "sleeve"]
    assert (sleeve.version, sleeve.version_source, sleeve.declared_spec) == ("1.7.1", "managed", "")
    assert any(refs[r].url.endswith("metal-bom-2.0.pom") and "1.7.1" in refs[r].snippet for r in sleeve.evidence_ids)
    assert deps["axle", "unnumbered"].version == ""
    monkeypatch.setattr(maven, "download", lambda _: (_ for _ in ()).throw(AssertionError("캐시를 사용해야 함")))
    assert collect(root) == result


def test_maven_unavailable_leaves_version_unknown(tmp_path, monkeypatch):
    def unavailable(_url):
        raise OSError("offline")
    monkeypatch.setattr(maven, "CACHE", tmp_path)
    monkeypatch.setattr(maven, "download", unavailable)
    result = collect(FIX / "maven")
    assert {a.kind for a in result.anomalies} == {"unresolved_pom"}
    assert all(not c.version and c.version_source == "unknown" for c in result.components)


def test_docker_stages_and_floating_release_lines():
    root = FIX / "images"
    result = collect(root)
    refs = verify(result, root)
    assert {(c.kind, c.name, c.version) for c in result.components} == {
        ("base-image", "eclipse-temurin", "11-jre"), ("runtime", "jre", "11"),
        ("base-image", "registry.invalid:5000/work/unknown", ""),
        ("base-image", "nginx", "1.27-alpine"), ("runtime", "nginx", "1.27"),
    }
    jre = next(c for c in result.components if c.name == "jre")
    assert {refs[r].line_start for r in jre.evidence_ids} == {1, 2}
    assert all(c.version_source == "dockerfile" and c.deployed == "unknown" for c in result.components)


def test_bundles_and_jar_metadata(tmp_path):
    from shutil import copytree
    copytree(FIX / "bundles/vendor", tmp_path / "vendor")
    with ZipFile(tmp_path / "opaque.jar", "w") as jar:
        jar.write(FIX / "bundles/pom.properties", "META-INF/maven/org.fixture/pressed-wheel/pom.properties")
    result = collect(tmp_path)
    verify(result, tmp_path)
    assert {(c.name, c.version) for c in result.components} == {("pressed-wheel", "2.3.1"), ("rotary-dial", "2.3.4")}
    assert sorted(a.kind for a in result.anomalies) == ["undeclared_bundle", "undeclared_bundle", "unidentified_bundle"]


def test_syft_only_without_matching_adapter(monkeypatch):
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        assert kwargs["cwd"] != FIX / "unknown"
        return SimpleNamespace(stdout=(FIX / "syft-output.json").read_text(encoding="utf-8"))

    monkeypatch.setattr(syft.shutil, "which", lambda _: str(FIX / "syft.exe"))
    monkeypatch.setattr(syft.subprocess, "run", run)
    assert collect(FIX / "images").components and not calls
    result = collect(FIX / "syft")
    verify(result, FIX / "syft")
    assert len(calls) == 1
    assert result.components[0].version_source == "tool"
    assert result.components[0].sources == ["opaque_wheel-8.0.1.dist-info/METADATA"]
    assert any(e.file.endswith("/METADATA") and e.line_start == 3 for e in result.evidence)
    monkeypatch.setattr(syft.shutil, "which", lambda _: None)
    assert collect(FIX / "unknown").anomalies[0].kind == "syft_unavailable"
