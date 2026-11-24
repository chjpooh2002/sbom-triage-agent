from pathlib import Path
import re

import pytest

from triage.evidence import (
    EvidenceStore, build_import_graph, find_callers, read_lines, resolve_config, search_symbol,
)
from triage.models import Evidence, SourceFileScope


ROOT = Path(__file__).parent / "fixtures/finals/c4"


def scope(*names, category="app"):
    return [SourceFileScope(path=n, category=category) for n in names]


def check(result, root=ROOT):
    payload, evidence = result
    store = EvidenceStore(root)
    store.merge(evidence)
    assert all(store.verify(e.id) and re.fullmatch(r"[\w-]+-\d{4}", e.id) for e in evidence)
    return payload


def test_store_merge_and_original_lines(tmp_path):
    path = tmp_path / "text"
    path.write_bytes("둘\r\n  셋\r\n".encode())
    store = EvidenceStore(tmp_path)
    e = store.add("collect", kind="code", file="text", line_start=1, line_end=2, snippet="둘\n  셋")
    assert e.id == "collect-0001" and store.verify(e)
    store.merge([e, e])
    foreign = Evidence(id="lookup-0042", kind="advisory", url="https://example.org")
    with pytest.raises(ValueError):
        store.merge([foreign, e.model_copy(update={"snippet": "변경"})])
    with pytest.raises(KeyError):
        store.get(foreign.id)
    store.merge([foreign])
    assert store.add("lookup", kind="tool").id == "lookup-0043"
    assert not store.verify(foreign.id)
    assert not store.verify(e.model_copy(update={"line_end": 3}))
    assert not store.verify(e.model_copy(update={"snippet": "둘"}))
    path.write_text("둘\n셋", encoding="utf-8")
    assert not store.verify(e.id)


def test_read_and_search_limits_and_scope(tmp_path):
    lines = [str(n) for n in range(80)]
    for n in range(10, 21):
        lines[n] = "emit(arg)"
    (tmp_path / "a").write_text("\n".join(lines), encoding="utf-8")
    files = scope("a")
    hits, evidence = search_symbol(tmp_path, files, "emit")
    assert len(hits) == 8 and (evidence[0].line_start, evidence[0].line_end) == (8, 14)
    assert hits == check((hits, evidence), tmp_path)
    seen = []
    result = read_lines(tmp_path, files, "a", 2, 80, log=lambda *a, **kw: seen.append(a))
    assert check(result, tmp_path)["lines"] == lines[1:61]
    assert seen == [("read", "start"), ("read", "end")]
    assert read_lines(tmp_path, [], "a")[0]["lines"] == []
    assert read_lines(tmp_path, scope("../a"), "../a")[1] == []


@pytest.mark.parametrize("category", ["generated", "vendored_bundle"])
def test_all_tools_exclude_categories(category):
    files = scope("routes.py", "application.yml", category=category)
    for tool, args in [(read_lines, ("routes.py",)), (search_symbol, ("emit",)),
                       (find_callers, ("emit",)), (resolve_config, ("paper.format",)),
                       (build_import_graph, ())]:
        assert tool(ROOT, files, *args)[1] == []
        assert tool(ROOT, files, *args, include_excluded=True)[1]


def test_imports_and_sources():
    graph = check(build_import_graph(ROOT, scope("routes.py", "routes.js", "Notes.java")))
    assert set(graph) == {"flask", "paperkit", "@paper/kit", "folio", "lab.paper"}
    assert list(graph["@paper/kit"]) == ["routes.js"]


@pytest.mark.parametrize(("file", "framework", "states"), [
    ("routes.py", "flask", ["yes", "yes", "no", "unknown", "no"]),
    ("routes.js", "express", ["yes", "no", "yes"]),
    ("Notes.java", "spring", ["yes", "unknown"]),
])
def test_argument_flow(file, framework, states):
    calls = check(find_callers(ROOT, scope(file), "emit"))
    assert [c["request_input"] for c in calls] == states
    assert calls[0]["framework"] == framework
    if framework == "flask":
        assert calls[-1]["framework"] is None
    assert len(calls[0]["evidence_ids"]) >= 3


def test_explicit_scan_store_and_standalone_ids():
    files = scope("routes.py")
    store = EvidenceStore(ROOT)
    a = search_symbol(ROOT, files, "emit", store=store)[1]
    b = search_symbol(ROOT, files, "emit", store=store)[1]
    assert a[0].id == "search-0001"
    assert store.verify(b[-1].id)
    e = search_symbol(ROOT, files, "phrase")[1] + search_symbol(ROOT, files, "name")[1]
    assert len({item.id for item in e}) == len(e)


def test_spring_precedence_and_profile():
    files = scope("application.yml", "application.properties", "application-night.yml")
    for active, expected in [([], "flat"), (["day"], "flat"), (["night"], "rolled")]:
        result = check(resolve_config(ROOT, files, "paper.format", active_profiles=active))
        assert result["status"] == "resolved" and result["value"] == expected
    result = check(resolve_config(ROOT, files, "paper.format"))
    assert result["status"] == "unknown" and result["active_profiles"] == {".": None}
    assert {m["value"] for m in result["matches"]} == {"flat", "rolled"}
    result = check(resolve_config(ROOT, scope("active/application.yml",
                                             "active/application-night.properties"), "paper.format"))
    assert result["value"] == "bound" and len(result["evidence_ids"]) == 2


@pytest.mark.parametrize(("file", "key", "value"), [
    ("notation.yml", "page.title", "초안"), ("notation.json", "page.count", "12"),
    (".env.example", "EDITION", "paper copy"), ("edge.conf", "resolver", "127.0.0.1"),
    ("edge.conf", "proxy_pass", "http://archive"),
])
def test_configuration_source_lines(file, key, value):
    result = check(resolve_config(ROOT, scope(file), key))
    assert result["status"] == "resolved" and result["value"] == value


def test_nginx_servers_have_independent_values():
    result = check(resolve_config(ROOT, scope("edge.conf"), "nginx.http2"))
    assert result["status"] == "unknown" and result["value"] is None
    assert [m["value"] for m in result["matches"]] == ["on", "off"]
    assert len({m["context"] for m in result["matches"]}) == 2


def test_nginx_server_overrides_inherited_http2():
    result = check(resolve_config(ROOT, scope("inherit.conf"), "http2"))
    assert result["status"] == "resolved" and result["value"] == "off"


def test_express_concise_arrows_and_local_boundaries():
    calls = check(find_callers(ROOT, scope("short.js"), "emit"))
    assert [(c["framework"], c["request_input"]) for c in calls] == [
        ("express", "yes"), ("express", "yes"), (None, "unknown"), (None, "unknown"),
    ]


def test_spring_servlet_request():
    calls = check(find_callers(ROOT, scope("raw.java"), "emit"))
    assert [(c["framework"], c["request_input"]) for c in calls] == [("spring", "yes")]


def test_constant_reassignment_has_assignment_evidence():
    calls, evidence = find_callers(ROOT, scope("routes.py"), "emit")
    literal = next(c for c in calls if c["framework"] and c["request_input"] == "no")
    assert any(e.snippet.strip() == 'phrase = "fixed"' for e in evidence
               if e.id in literal["evidence_ids"])
