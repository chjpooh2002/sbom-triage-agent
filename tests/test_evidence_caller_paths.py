from pathlib import Path

import pytest

from triage.evidence import EvidenceStore, find_callers
from triage.models import SourceFileScope


ROOT = Path(__file__).parent / "fixtures/finals/c4/hop"


def trace(names, exclude=(), **options):
    files = [SourceFileScope(path=n, category="generated" if n in exclude else "app") for n in names]
    hits, evidence = find_callers(ROOT, files, "emit", **options)
    store = EvidenceStore(ROOT)
    store.merge(evidence)
    assert all(store.verify(e.id) for e in evidence)
    for hit in hits:
        for path in hit["caller_paths"]:
            assert set(path["evidence_ids"]) <= set(hit["evidence_ids"])
            refs = [store.get(eid) for eid in path["evidence_ids"]]
            for location in (hit, path["handler"], path["method"]):
                assert any(ref.file == location["file"] and ref.line_start <= location["line"] <= ref.line_end
                           for ref in refs)
            assert any(ref.file == path["handler"]["file"] and
                       any(mark in ref.snippet for mark in ("route(", "router.", "Mapping(")) for ref in refs)
    return hits, {e.id: e for e in evidence}


def test_flask_imports_shadowing_and_one_hop_boundary():
    hits, refs = trace(["views.py", "paper.py", "other.py"])
    linked = [h for h in hits if h["caller_paths"]]
    assert [(h["file"], h["handler"]) for h in linked] == [("paper.py", "write"), ("paper.py", "fold")]
    hit, instance = linked
    path, = instance["caller_paths"]
    assert path["method"]["name"] == "Binder.fold"
    assert any("binder = Binder()" in refs[e].snippet for e in path["evidence_ids"])
    assert hit["request_input"] == "unknown"
    paths = hit["caller_paths"]
    assert [(p["handler"]["handler"], p["handler"]["request_input"]) for p in paths] == [
        ("note", "yes"), ("fixed", "no")]
    assert any("import relay, write as put" in refs[e].snippet for e in paths[0]["evidence_ids"])
    assert all(p["method"]["name"] == "write" for p in paths)


def test_express_exports_and_nested_callback_boundary():
    hits, refs = trace(["web.js", "edition.js", "shelf.js"])
    paths = [p for h in hits for p in h["caller_paths"]]
    assert [(p["method"]["file"], p["method"]["name"]) for p in paths] == [
        ("edition.js", "write"), ("shelf.js", "insert"), ("shelf.js", "fold")]
    assert all(p["handler"]["framework"] == "express" for p in paths)
    assert paths[1]["handler"]["callee"] == "shelf.write"
    assert any("write: insert" in refs[e].snippet for e in paths[1]["evidence_ids"])
    assert any("module.exports" in refs[e].snippet for e in paths[-1]["evidence_ids"])


def test_spring_field_binding_overloads_and_shadowing():
    hits, refs = trace(["Pages.java", "Folio.java"])
    assert [[p["handler"]["handler"] for p in h["caller_paths"]] for h in hits] == [
        ["entry"], ["literal"], [], []]
    for hit in hits[:2]:
        path, = hit["caller_paths"]
        snippets = [refs[e].snippet for e in path["evidence_ids"]]
        assert any("import copy.domain.Folio" in s for s in snippets)
        assert any("private Folio book" in s for s in snippets)
        assert path["handler"]["framework"] == "spring"


@pytest.mark.parametrize("excluded", ["views.py", "paper.py"])
def test_scope_applies_to_both_ends(excluded):
    files = ["paper.py", "views.py"]
    hits, _ = trace(files, [excluded])
    assert not any(h["caller_paths"] for h in hits)
    hits, _ = trace(files, [excluded], include_excluded=True)
    assert any(h["caller_paths"] for h in hits)
