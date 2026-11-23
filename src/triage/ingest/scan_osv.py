"""OSV-Scanner JSON(v1·v2) → 구성요소 + 취약점. 같은 그룹(별칭으로 묶인 항목)은 한 건으로 만든다."""
from __future__ import annotations

from pathlib import Path

from ..models import Component, Finding, Vulnerability
from .common import component_id, make_purl, parse_purl, pick_primary_id, score_from_vector, to_float
from .registry import ParsedInput, register


def _severity_from_score(s: float | None) -> str:
    if s is None:
        return "unknown"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "unknown"


def _fixed_and_ranges(vuln: dict, pkg_name: str) -> tuple[list[str], list[str]]:
    fixed, ranges = [], []
    for a in vuln.get("affected") or []:
        if (a.get("package") or {}).get("name") != pkg_name:
            continue
        for rg in a.get("ranges") or []:
            intro = None
            for ev in rg.get("events") or []:
                if "introduced" in ev:
                    intro = ev["introduced"]
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
                    ranges.append(f">={intro or '0'},<{ev['fixed']}")
                    intro = None
                if "last_affected" in ev:
                    ranges.append(f">={intro or '0'},<={ev['last_affected']}")
                    intro = None
            if intro is not None:
                ranges.append(f">={intro}")
    return list(dict.fromkeys(fixed)), list(dict.fromkeys(ranges))


@register("osv-scanner", kind="scan",
          sniff=lambda p, d: isinstance(d, dict) and isinstance(d.get("results"), list)
          and all("packages" in r or "source" in r for r in d["results"]))
def parse(path: Path, data: dict) -> ParsedInput:
    src = str(path)
    comps: dict[str, Component] = {}
    findings: dict[str, Finding] = {}
    targets = []
    for res in data.get("results") or []:
        targets.append((res.get("source") or {}).get("path", ""))
        for p in res.get("packages") or []:
            info = p.get("package") or {}
            name, ver, eco = info.get("name", ""), info.get("version", ""), info.get("ecosystem", "")
            purl = info.get("purl") or make_purl(eco, name, ver)
            pp = parse_purl(purl)
            comp = Component(id=component_id(purl, eco, name, ver), name=pp.get("name") or name,
                             group=pp.get("group", ""), version=ver, ecosystem=pp.get("type", eco.lower()),
                             purl=purl, sources=[src])
            comps.setdefault(comp.id, comp)
            vulns = {v["id"]: v for v in p.get("vulnerabilities") or []}
            groups = p.get("groups") or [{"ids": [i], "aliases": vulns[i].get("aliases", [])} for i in vulns]
            for g in groups:
                members = [vulns[i] for i in g.get("ids", []) if i in vulns]
                ids = list(g.get("ids", [])) + list(g.get("aliases", []))
                for m in members:
                    ids += m.get("aliases") or []
                primary, aliases = pick_primary_id(ids)
                best_score, best_vec = None, ""
                fixed, ranges, refs, summary, details, published = [], [], [], "", "", ""
                for m in members:
                    for s in m.get("severity") or []:
                        sc = score_from_vector(s.get("score", ""))
                        # v3 점수를 우선(다른 스캐너와 기준을 맞추기 위해), 없으면 v4·v2
                        if sc is not None and (best_score is None or s.get("type") == "CVSS_V3"):
                            if best_vec.startswith("CVSS:3") and s.get("type") != "CVSS_V3":
                                continue
                            best_score, best_vec = sc, s.get("score", "")
                    f, r = _fixed_and_ranges(m, name)
                    fixed += f
                    ranges += r
                    refs += [x.get("url") for x in m.get("references") or [] if x.get("url")]
                    summary = summary or m.get("summary", "")
                    details = details or m.get("details", "")
                    published = published or m.get("published", "")
                if best_score is None:
                    best_score = to_float(g.get("max_severity"))
                key = Finding.make_key(primary, comp.id, None)
                findings[key] = Finding(
                    key=key, component=comp, scanners=["osv-scanner"],
                    vulnerability=Vulnerability(
                        id=primary, aliases=aliases, title=summary, description=details[:1500],
                        severity=_severity_from_score(best_score), cvss_score=best_score, cvss_vector=best_vec,
                        cvss_source="osv" if best_vec else "", fixed_versions=list(dict.fromkeys(fixed)),
                        affected_ranges=list(dict.fromkeys(ranges)), references=refs[:10], published=published))
    return ParsedInput(source=src, converter="osv-scanner", kind="scan", components=list(comps.values()),
                       findings=list(findings.values()), target=targets[0] if targets else "")
