import json
from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace
from zipfile import ZipFile

import httpx
import pytest

from triage import maven_repos
from triage.collect import CollectResult, collect, maven, syft
from triage.collect.core import Collection, Document

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
    anomaly, = result.anomalies
    assert anomaly.kind == "lock_mismatch" and "총 2건" in anomaly.message
    assert {refs[r].kind for r in anomaly.evidence_ids} == {"manifest", "lockfile"}


def test_npm_missing_lock(tmp_path):
    copyfile(FIX / "npm/package.json", tmp_path / "package.json")
    result = collect(tmp_path)
    verify(result, tmp_path)
    assert len(result.components) == 3
    anomaly, = result.anomalies
    assert anomaly.kind == "missing_lockfile" and "총 3건" in anomaly.message
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
    assert comps["plain-ring"].version == "" and comps["plain-ring"].direct is True
    assert comps["amber-kite"].direct is True and comps["vial-meter"].direct is True
    assert comps["thin-lens"].direct is True and comps["thin-lens"].version == "4.1.0"
    assert comps["blue-spline"].direct is None
    assert comps["blue-spline"].scope == comps["wax-finch"].scope == "dev"
    assert comps["wax-finch"].direct is True
    assert [a.kind for a in result.anomalies] == ["lock_mismatch"]


@pytest.fixture
def central(tmp_path, monkeypatch):
    urls = []

    def download(url):
        urls.append(url)
        name, version = url.split("/")[-3:-1]
        assert url == f"{maven_repos.DEFAULT_REPOS[0]}/org/fixture/{name}/{version}/{name}-{version}.pom"
        if name in {"bearing", "sleeve", "released", "flat", "lathe"}:
            text = (FIX / "central/leaf.pom").read_text(encoding="utf-8")
            text = text.replace("ARTIFACT", name).replace("VERSION", version)
        else:
            fixture = "metal-bom-2.1" if (name, version) == ("metal-bom", "2.1") else name
            text = (FIX / "central" / (fixture + ".pom")).read_text(encoding="utf-8")
        return httpx.Response(200, text=text)

    monkeypatch.delenv("SBOMTRIAGE_MAVEN_REPOS", raising=False)
    monkeypatch.setattr(maven, "CACHE", tmp_path)
    monkeypatch.setattr(maven, "download", download)
    return urls


def test_maven_remote_parent_bom_cache_and_property_override(tmp_path, monkeypatch, central):
    root = FIX / "maven"
    result = collect(root)
    refs = verify(result, root)
    assert [a.kind for a in result.anomalies] == ["unresolved_dependency"]
    assert len(central) == len(list(tmp_path.rglob("*.pom"))) == 5
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
    assert {a.kind for a in result.anomalies} == {"unresolved_pom", "unresolved_dependency"}
    assert all(not c.version and c.version_source == "unknown" for c in result.components)


def test_maven_offline_cache_miss_skips_repository_fetch(tmp_path, monkeypatch):
    monkeypatch.setattr(maven, "CACHE", tmp_path)
    monkeypatch.setattr(maven.MavenRepositories, "fetch", lambda *_: pytest.fail("오프라인 저장소 조회"))
    root = FIX / "maven"
    result = collect(root, offline=True)
    refs = verify(result, root)
    missing = next(a for a in result.anomalies if a.kind == "unresolved_pom")
    assert "오프라인 캐시" in missing.message
    assert any(refs[r].note == "오프라인 모드에 필요한 POM 캐시 없음" for r in missing.evidence_ids)
    assert not list(tmp_path.iterdir())


def test_maven_managed_transitives_and_nearest_winner(central, monkeypatch):
    root = FIX / "maven-graph"
    result = collect(root)
    refs = verify(result, root)
    assert not result.anomalies
    for module, bearing_version in (("gearbox", "2.4.0"), ("adjusted", "2.9.0")):
        deps = {c.name: c for c in result.components if c.module == module}
        direct_names = {"rotor", "shaft", "lathe"} if module == "adjusted" else {"rotor", "shaft"}
        assert {c.name for c in deps.values() if c.direct} == direct_names
        assert all(c.direct is False for c in deps.values() if c.name not in direct_names)
        sleeve = deps["sleeve"]
        expected = ("1.8.0", "property_override", "2.1") if module == "adjusted" else ("1.7.1", "managed", "2.0")
        version, source, bom_version = expected
        assert (sleeve.version, sleeve.version_source, sleeve.declared_spec) == (version, source, "0.1")
        assert any(refs[r].url.endswith(f"/metal-bom-{bom_version}.pom") for r in sleeve.evidence_ids)
        assert any(refs[r].url.endswith("/rotor-1.0.pom") for r in sleeve.evidence_ids)
        bearing = deps["bearing"]
        assert bearing.version == bearing_version
        assert deps["rotor"].depends_on == [sleeve.id, bearing.id, deps["bridge"].id]
        if module == "adjusted":
            assert bearing.version_source == "property_override"
            assert any(refs[r].file == "adjusted/pom.xml" and "2.9.0" in refs[r].snippet for r in bearing.evidence_ids)
            assert any(refs[r].file == "adjusted/pom.xml" and "<bom.version>2.1" in refs[r].snippet
                       for r in sleeve.evidence_ids)
            assert (deps["lathe"].version, deps["lathe"].version_source) == ("3.2.0", "property_override")
        assert deps["flat"].version == "4.0"
        assert deps["flat"].id in deps["shaft"].depends_on and deps["flat"].id in deps["bridge"].depends_on
        assert deps["released"].id in deps["bridge"].depends_on
        assert {"blind", "accessory", "gauge"}.isdisjoint(deps)
    assert len(set(central)) == len(central)
    assert not any(url.endswith(("flat-8.0.pom", "sleeve-0.1.pom", "bearing-1.3.pom")) for url in central)
    monkeypatch.setattr(maven, "download", lambda _: pytest.fail("오프라인 재실행에서 네트워크 호출"))
    assert collect(root, offline=True) == result


def test_maven_equal_depth_loser_does_not_reopen_excluded_children(central, monkeypatch):
    download = maven.download

    def alternate_version(url):
        response = download(url)
        if url.endswith("/shaft-1.0.pom"):
            text = response.text.replace("<artifactId>bridge</artifactId><version>1.0",
                                         "<artifactId>bridge</artifactId><version>2.0")
            return httpx.Response(200, text=text)
        return response

    monkeypatch.setattr(maven, "download", alternate_version)
    result = collect(FIX / "maven-graph")
    assert not result.anomalies
    components = {c.name: c for c in result.components if c.module == "gearbox"}
    bridge = components["bridge"]
    assert bridge.version == "1.0" and bridge.id in components["shaft"].depends_on
    assert "released" not in components
    assert not any(url.endswith("/bridge-2.0.pom") for url in central)


@pytest.mark.parametrize("limits", [maven.Limits(1, 100, 100), maven.Limits(8, 1, 100), maven.Limits(8, 100, 2)])
def test_maven_limits_preserve_direct_inventory(central, monkeypatch, limits):
    monkeypatch.setattr(maven, "load_limits", lambda: limits)
    root = FIX / "maven-graph"
    result = collect(root)
    verify(result, root)
    assert {c.name for c in result.components} == {"rotor", "shaft", "lathe"}
    assert len(central) <= limits.max_poms
    assert any(a.kind == "maven_limit" for a in result.anomalies)


def test_maven_unavailable_descriptor_records_url_and_preserves_siblings(central, monkeypatch):
    download = maven.download

    def unavailable(url):
        if url.endswith("rotor-1.0.pom"):
            raise OSError("offline")
        return download(url)

    monkeypatch.setattr(maven, "download", unavailable)
    root = FIX / "maven-graph"
    result = collect(root)
    refs = verify(result, root)
    failure = next(a for a in result.anomalies if a.kind == "unresolved_pom")
    assert any(refs[r].url.endswith("rotor-1.0.pom") for r in failure.evidence_ids)
    assert any(c.name == "flat" and c.direct is False for c in result.components)


def test_repeated_pom_failures_keep_three_examples_and_all_url_evidence(tmp_path, monkeypatch):
    def unavailable(_url):
        raise OSError("offline")

    monkeypatch.setattr(maven, "CACHE", tmp_path)
    monkeypatch.setattr(maven, "download", unavailable)
    root = FIX / "maven-graph"
    result = collect(root)
    refs = verify(result, root)
    failures = [a for a in result.anomalies if a.kind == "unresolved_pom"]
    failure, = failures
    assert "총 5건" in failure.message
    assert failure.message.count("org.fixture:") == 3
    urls = [refs[r].url for r in failure.evidence_ids if refs[r].url]
    assert len(urls) == 5
    assert any(url.endswith("/metal-bom-2.1.pom") for url in urls)


@pytest.fixture
def pom_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr(maven, "CACHE", tmp_path)
    monkeypatch.delenv("SBOMTRIAGE_MAVEN_REPOS", raising=False)
    events = []
    context = Collection(tmp_path, lambda stage, event, **data: events.append((stage, event, data)))
    ref = context.evidence(Document("pom.xml", "<project/>", "manifest"))
    coordinate = ("org.fixture", "metal-bom", "2.0")

    def lookup():
        return maven.Repository(context, []).lookup(coordinate, ref)

    return lookup, context, events


def bom_response():
    return httpx.Response(200, text=(FIX / "central/metal-bom.pom").read_text(encoding="utf-8"))


@pytest.mark.parametrize("blocked", [
    httpx.Response(404, text=" ", headers={"Content-Type": "application/xml"}),
    httpx.Response(404, text="denied", headers={"Content-Type": "text/plain"}),
    httpx.Response(403), httpx.Response(429),
])
def test_maven_blocked_pom_uses_next_mirror_and_preserves_cached_source(pom_lookup, monkeypatch, blocked):
    lookup, context, events = pom_lookup
    responses = iter([blocked, bom_response()])
    monkeypatch.setattr(maven, "download", lambda _url: next(responses))
    pom = lookup()
    assert pom.doc.url.startswith(maven_repos.DEFAULT_REPOS[1] + "/")
    errors = [data for _, event, data in events if event == "maven.fetch_error"]
    assert [(data["attempt"], data["blocked"]) for data in errors] == [(1, True)]
    evidence = context.evidence(pom.doc, 2)

    monkeypatch.setenv("SBOMTRIAGE_MAVEN_REPOS", "https://other.invalid/maven2")
    monkeypatch.setattr(maven, "download", lambda _: pytest.fail("캐시 적중 시 네트워크 호출"))
    cached = lookup()
    assert (cached.doc.text, cached.doc.url) == (pom.doc.text, pom.doc.url)
    assert context.evidence(cached.doc, 2) == evidence


def test_maven_timeout_twice_then_success(pom_lookup, monkeypatch):
    lookup, _, events = pom_lookup
    attempts, delays = [], []

    def request(url):
        attempts.append(url)
        if len(attempts) <= 2:
            raise httpx.ReadTimeout("sensitive detail")
        return bom_response()

    monkeypatch.setattr(maven, "download", request)
    monkeypatch.setattr(maven_repos, "sleep", delays.append)
    monkeypatch.setattr(maven_repos, "uniform", lambda *_: 0)
    assert lookup() and len(attempts) == 3 and len(set(attempts)) == 1
    assert delays == [0.5, 1.0]
    errors = [data for _, event, data in events if event == "maven.fetch_error"]
    assert [(data["attempt"], data["error_type"]) for data in errors] == [(1, "ReadTimeout"), (2, "ReadTimeout")]
    assert "sensitive detail" not in str(events)


def test_maven_all_missing_records_each_repository_in_configured_order(pom_lookup, monkeypatch):
    lookup, context, events = pom_lookup
    repositories = ["https://z.invalid/maven2", "https://a.invalid/maven2"]
    monkeypatch.setenv("SBOMTRIAGE_MAVEN_REPOS", ", ".join(repositories))
    missing = httpx.Response(404, text="<error/>", headers={"Content-Type": "application/xml"})
    monkeypatch.setattr(maven, "download", lambda _: missing)
    assert lookup() is None
    errors = [data for _, event, data in events if event == "maven.fetch_error"]
    assert [(data["repository"], data["status_code"], data["blocked"]) for data in errors] == [
        (repo, 404, False) for repo in repositories]
    anomaly, = context.result.anomalies
    summary = " / ".join(f"{repo} HTTP 404" for repo in repositories)
    assert anomaly.kind == "unresolved_pom" and anomaly.message.endswith(summary)
    assert any(e.note == summary and e.id in anomaly.evidence_ids for e in context.result.evidence)


def test_maven_three_blocks_demote_repository_for_rest_of_run(monkeypatch):
    monkeypatch.delenv("SBOMTRIAGE_MAVEN_REPOS", raising=False)
    repos = maven_repos.MavenRepositories()
    calls = []

    def request(url):
        calls.append(url)
        if url.startswith(repos.repos[0] + "/"):
            return httpx.Response(429)
        return bom_response()

    for path in ("one", "two", "three", "four"):
        repos.fetch(path, request, lambda _text, url: url)
    assert len(calls) == 7 and calls[-1] == f"{repos.repos[1]}/four"


def test_maven_invalid_xml_uses_next_mirror(pom_lookup, monkeypatch):
    lookup, context, events = pom_lookup
    responses = iter([httpx.Response(200, text="<project"), bom_response()])
    monkeypatch.setattr(maven, "download", lambda _url: next(responses))
    assert lookup().doc.url.startswith(maven_repos.DEFAULT_REPOS[1] + "/")
    assert not context.result.anomalies
    assert any(data["error_type"] == "ExpatError" for _, event, data in events if event == "maven.fetch_error")


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
    assert sorted(a.kind for a in result.anomalies) == ["undeclared_bundle", "unidentified_bundle"]


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
