"""SPDX 2.x JSON → 구성요소."""
from __future__ import annotations

from pathlib import Path

from ..models import Component
from . import graph
from .common import component_id, parse_purl
from .registry import ParsedInput, register


def _purl(pkg: dict) -> str:
    for r in pkg.get("externalRefs") or []:
        if r.get("referenceType") == "purl":
            return r.get("referenceLocator", "")
    return ""


@register("spdx", kind="sbom",
          sniff=lambda p, d: isinstance(d, dict) and str(d.get("spdxVersion", "")).startswith("SPDX-"))
def parse(path: Path, data: dict) -> ParsedInput:
    src = str(path)
    by_ref: dict[str, Component] = {}
    for pkg in data.get("packages") or []:
        purl = _purl(pkg)
        pp = parse_purl(purl)
        lic = pkg.get("licenseConcluded") or pkg.get("licenseDeclared") or ""
        by_ref[pkg["SPDXID"]] = Component(
            id=component_id(purl, pp.get("type", ""), pkg.get("name", ""), pkg.get("versionInfo", "")),
            name=pp.get("name") or pkg.get("name", ""), group=pp.get("group", ""),
            version=pkg.get("versionInfo") or pp.get("version", ""), ecosystem=pp.get("type", ""), purl=purl,
            licenses=[lic] if lic and lic != "NOASSERTION" else [], sources=[src])
    edges: dict[str, list[str]] = {}
    described: list[str] = list(data.get("documentDescribes") or [])
    for r in data.get("relationships") or []:
        a, b, t = r.get("spdxElementId"), r.get("relatedSpdxElement"), r.get("relationshipType", "")
        if t == "DESCRIBES" and a == data.get("SPDXID"):
            described.append(b)
        elif t in ("DEPENDS_ON", "CONTAINS"):
            edges.setdefault(a, []).append(b)
        elif t == "DEPENDENCY_OF":
            edges.setdefault(b, []).append(a)
    roots = [d for d in dict.fromkeys(described) if d in edges]
    if not roots and edges:
        children = {c for v in edges.values() for c in v}
        roots = [r for r in edges if r not in children and r in by_ref]
    graph.annotate(by_ref, edges, roots)
    # 루트(대상 앱 자신)와 purl 없는 파일·디렉터리 노드는 구성요소에서 뺀다
    comps = [c for r, c in by_ref.items() if r not in roots and c.purl]
    target = by_ref[roots[0]].name if roots and roots[0] in by_ref else data.get("name", "")
    return ParsedInput(source=src, converter="spdx", kind="sbom", components=comps, target=target)
