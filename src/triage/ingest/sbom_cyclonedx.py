"""CycloneDX JSON → 구성요소(+ vulnerabilities 구간이 있으면 취약점·VEX 상태)."""
from __future__ import annotations

from pathlib import Path

from ..models import Component, Finding, Status, Vulnerability
from . import graph
from .common import component_id, normalize_severity, parse_purl, pick_primary_id, score_from_vector, to_float
from .registry import ParsedInput, register

# CycloneDX VEX analysis.state → 내부 상태
VEX_STATE = {"not_affected": Status.not_affected, "false_positive": Status.not_affected,
             "resolved": Status.not_affected, "resolved_with_pedigree": Status.not_affected,
             "exploitable": Status.affected, "in_triage": Status.unknown}


def _walk(items, out):
    for c in items or []:
        out.append(c)
        _walk(c.get("components"), out)


def _component(c: dict, source: str) -> Component:
    purl = c.get("purl", "")
    pp = parse_purl(purl)
    lic = []
    for item in c.get("licenses") or []:
        x = item.get("license") or {}
        lic.append(x.get("id") or x.get("name") or item.get("expression") or "")
    return Component(
        id=component_id(purl, pp.get("type", c.get("type", "")), c.get("name", ""), c.get("version", "")),
        name=c.get("name") or pp.get("name", ""), group=c.get("group") or pp.get("group", ""),
        version=c.get("version") or pp.get("version", ""), ecosystem=pp.get("type", ""), purl=purl,
        licenses=[x for x in lic if x], sources=[source],
    )


def _rating_score(r: dict) -> float:
    return to_float(r.get("score")) or score_from_vector(r.get("vector", "")) or 0.0


@register("cyclonedx", kind="sbom",
          sniff=lambda p, d: isinstance(d, dict) and d.get("bomFormat") == "CycloneDX")
def parse(path: Path, data: dict) -> ParsedInput:
    src = str(path)
    meta = data.get("metadata") or {}
    root = meta.get("component") or {}
    flat: list[dict] = []
    _walk(data.get("components"), flat)
    by_ref: dict[str, Component] = {}
    for c in flat:
        if c.get("type") in ("file", "operating-system") and not c.get("purl"):
            continue
        by_ref[c.get("bom-ref") or c.get("purl") or c.get("name")] = _component(c, src)
    edges = {d["ref"]: d.get("dependsOn") or [] for d in data.get("dependencies") or [] if "ref" in d}
    roots = [root.get("bom-ref")] if root.get("bom-ref") in edges else []
    if not roots and edges:   # syft 처럼 대상 앱이 components 안에 있으면: 아무도 의존하지 않는 노드가 루트
        children = {c for v in edges.values() for c in v}
        roots = [r for r in edges if r not in children]
    graph.annotate(by_ref, edges, roots)
    comps = [c for r, c in by_ref.items() if r not in roots]
    target = root.get("name", "")
    if roots and roots[0] in by_ref:
        target = target or by_ref[roots[0]].name

    findings = []
    for v in data.get("vulnerabilities") or []:
        ids = [v.get("id", "")] + [r.get("id", "") for r in v.get("references") or []]
        primary, aliases = pick_primary_id(ids)
        ratings = v.get("ratings") or []
        best = max(ratings, key=_rating_score, default={})
        score = _rating_score(best) or None
        analysis = v.get("analysis") or {}
        status = VEX_STATE.get(analysis.get("state", ""), Status.affected)
        fixed = [x.get("version") for a in v.get("affects") or [] for x in a.get("versions") or []
                 if x.get("status") == "unaffected" and x.get("version")]
        vuln = Vulnerability(
            id=primary, aliases=aliases, description=(v.get("description") or "")[:1500],
            severity=normalize_severity(best.get("severity")), cvss_score=score,
            cvss_vector=best.get("vector", ""), cvss_source=(best.get("source") or {}).get("name", ""),
            fixed_versions=fixed, references=[a.get("url") for a in v.get("advisories") or [] if a.get("url")],
            published=v.get("published", ""))
        for a in v.get("affects") or []:
            comp = by_ref.get(a.get("ref"))
            if comp is None:
                continue
            note = " ".join(x for x in [analysis.get("justification", ""), analysis.get("detail", "")] if x)
            findings.append(Finding(
                key=Finding.make_key(primary, comp.id, None), component=comp, vulnerability=vuln,
                scanners=["cyclonedx-vex" if analysis else "cyclonedx"], status=status, status_note=note))
    return ParsedInput(source=src, converter="cyclonedx", kind="sbom", components=comps, findings=findings,
                       target=target)
