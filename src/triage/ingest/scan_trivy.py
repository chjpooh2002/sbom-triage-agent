"""Trivy JSON(SchemaVersion 2) → 구성요소 + 취약점."""
from __future__ import annotations

from pathlib import Path

from ..models import Component, Finding, Status, Vulnerability
from .common import component_id, make_purl, normalize_severity, parse_purl, pick_primary_id, split_versions
from .registry import ParsedInput, register

# 같은 취약점에 여러 출처 점수가 있을 때 고르는 순서
CVSS_SOURCE_ORDER = ["nvd", "ghsa", "redhat"]
NOT_AFFECTED = {"not_affected"}

# Trivy Result.Type → OSV 생태계 이름(purl 을 못 받았을 때 직접 만들기 위함)
TYPE_TO_ECOSYSTEM = {"pom": "Maven", "jar": "Maven", "gradle": "Maven", "npm": "npm", "yarn": "npm",
                     "pnpm": "npm", "pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "gomod": "Go",
                     "gobinary": "Go", "cargo": "crates.io", "nuget": "NuGet", "composer": "Packagist"}


def _cvss(v: dict) -> tuple[float | None, str, str]:
    table = v.get("CVSS") or {}
    order = CVSS_SOURCE_ORDER + sorted(k for k in table if k not in CVSS_SOURCE_ORDER)
    for src in order:
        c = table.get(src)
        if not c:
            continue
        if c.get("V3Score") is not None:
            return float(c["V3Score"]), c.get("V3Vector", ""), src
        if c.get("V40Score") is not None:
            return float(c["V40Score"]), c.get("V40Vector", ""), src
        if c.get("V2Score") is not None:
            return float(c["V2Score"]), c.get("V2Vector", ""), src
    return None, "", ""


def _component(name: str, version: str, purl: str, rtype: str, src: str) -> Component:
    purl = purl or make_purl(TYPE_TO_ECOSYSTEM.get(rtype, ""), name, version)
    pp = parse_purl(purl)
    return Component(id=component_id(purl, rtype, name, version), name=pp.get("name") or name,
                     group=pp.get("group", ""), version=version, ecosystem=pp.get("type", rtype), purl=purl,
                     sources=[src])


@register("trivy", kind="scan",
          sniff=lambda p, d: isinstance(d, dict) and "SchemaVersion" in d and "Results" in d)
def parse(path: Path, data: dict) -> ParsedInput:
    src = str(path)
    comps: dict[str, Component] = {}
    findings: dict[str, Finding] = {}
    for r in data.get("Results") or []:
        rtype = r.get("Type", "")
        pkg_by_id = {}
        for p in r.get("Packages") or []:
            c = _component(p.get("Name", ""), p.get("Version", ""), (p.get("Identifier") or {}).get("PURL", ""),
                           rtype, src)
            rel = p.get("Relationship")
            if rel == "root":
                continue
            c.direct = True if rel == "direct" else False if rel == "indirect" else None
            c.direct_evidence = 3 if c.direct is not None else 0   # 빌드 도구가 알려 준 관계는 그래프 근거로 본다
            comps[c.id] = c
            # jar 스캔 결과는 ID 가 비어 있다(None). 비어 있는 키로 묶으면 모든 취약점이 마지막 패키지에 붙으므로
            # 값이 있는 식별자(UID, ID)만 키로 쓴다
            for k in ((p.get("Identifier") or {}).get("UID"), p.get("ID")):
                if k:
                    pkg_by_id[k] = c
        for v in r.get("Vulnerabilities") or []:
            ref = (v.get("PkgIdentifier") or {}).get("UID") or v.get("PkgID")
            comp = (pkg_by_id.get(ref) if ref else None) or _component(
                v.get("PkgName", ""), v.get("InstalledVersion", ""), (v.get("PkgIdentifier") or {}).get("PURL", ""),
                rtype, src)
            comps.setdefault(comp.id, comp)
            primary, aliases = pick_primary_id([v.get("VulnerabilityID", ""), *(v.get("VendorIDs") or [])])
            score, vector, csrc = _cvss(v)
            key = Finding.make_key(primary, comp.id, None)
            st = v.get("Status", "")
            findings[key] = Finding(
                key=key, component=comp, scanners=["trivy"],
                status=Status.not_affected if st in NOT_AFFECTED else Status.affected,
                status_note=f"trivy status={st}" if st and st != "fixed" else "",
                vulnerability=Vulnerability(
                    id=primary, aliases=aliases, title=v.get("Title", ""),
                    description=(v.get("Description") or "")[:1500], severity=normalize_severity(v.get("Severity")),
                    cvss_score=score, cvss_vector=vector, cvss_source=csrc,
                    fixed_versions=split_versions(v.get("FixedVersion", "")),
                    references=(v.get("References") or [])[:10], published=v.get("PublishedDate", "")))
    return ParsedInput(source=src, converter="trivy", kind="scan", components=list(comps.values()),
                       findings=list(findings.values()), target=data.get("ArtifactName", ""))
