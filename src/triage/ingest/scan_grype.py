"""Grype JSON → 취약점. (예선 시제품 load.py 의 별칭 병합·CVE 우선·최고 CVSS 방식을 이어받음)"""
from __future__ import annotations

from pathlib import Path

from ..models import Component, Finding, Status, Vulnerability
from .common import component_id, normalize_severity, parse_purl, pick_primary_id, to_float
from .registry import ParsedInput, register


def _best_cvss(entries: list[dict]) -> tuple[float | None, str, str]:
    """(점수, 벡터, 출처)."""
    best = None
    for vul in entries:
        for c in vul.get("cvss") or []:
            s = to_float((c.get("metrics") or {}).get("baseScore"))
            if s is None:
                continue
            ver = to_float(c.get("version")) or 0
            # 스캐너 간 기준을 맞추려고 v3.x > v4 > v2 순으로 고르고, 같은 버전대에서는 높은 점수
            pref = 3 if 3 <= ver < 4 else 2 if ver >= 4 else 1
            cand = (pref, s, c.get("vector", ""), c.get("source") or vul.get("namespace", ""))
            if best is None or cand[:2] > best[:2]:
                best = cand
    return (best[1], best[2], best[3]) if best else (None, "", "")


def _target(data: dict) -> str:
    t = (data.get("source") or {}).get("target")
    if isinstance(t, dict):
        return t.get("userInput") or t.get("name") or ""
    return t or ""


@register("grype", kind="scan",
          sniff=lambda p, d: isinstance(d, dict) and "matches" in d and "descriptor" in d)
def parse(path: Path, data: dict) -> ParsedInput:
    src = str(path)
    out: dict[str, Finding] = {}
    for m in data.get("matches") or []:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        related = m.get("relatedVulnerabilities") or []
        primary, aliases = pick_primary_id([v.get("id", "")] + [r.get("id", "") for r in related])
        score, vector, cvss_src = _best_cvss([v, *related])
        purl = a.get("purl", "")
        pp = parse_purl(purl)
        comp = Component(
            id=component_id(purl, a.get("type", ""), a.get("name", ""), a.get("version", "")),
            name=a.get("name", ""), group=pp.get("group", ""), version=a.get("version", ""),
            ecosystem=pp.get("type", ""), purl=purl, sources=[src])
        key = Finding.make_key(primary, comp.id, None)
        if key in out:  # 같은 구성요소가 여러 위치에서 잡히면 한 건
            continue
        fix = v.get("fix") or {}
        ranges = [d.get("found", {}).get("versionConstraint", "") for d in m.get("matchDetails") or []]
        desc = v.get("description") or next((r.get("description") for r in related if r.get("description")), "")
        hints = {}
        if v.get("knownExploited"):
            k = v["knownExploited"][0]
            hints["kev"] = {"date_added": k.get("dateAdded", ""), "due_date": k.get("dueDate", ""),
                            "ransomware": k.get("knownRansomwareCampaignUse") == "known"}
        if v.get("epss"):
            e = max(v["epss"], key=lambda x: x.get("epss", 0))
            hints["epss"] = {"epss": e.get("epss"), "percentile": e.get("percentile"), "date": e.get("date", "")}
        out[key] = Finding(
            key=key, component=comp, scanners=["grype"], hints=hints,
            status=Status.not_affected if fix.get("state") == "not-affected" else Status.affected,
            vulnerability=Vulnerability(
                id=primary, aliases=aliases, description=(desc or "")[:1500],
                severity=normalize_severity(v.get("severity")), cvss_score=score, cvss_vector=vector,
                cvss_source=cvss_src, fixed_versions=fix.get("versions") or [],
                affected_ranges=[r.replace(" (unknown)", "") for r in ranges if r],
                references=(v.get("urls") or [])[:10]))
    return ParsedInput(source=src, converter="grype", kind="scan", findings=list(out.values()), target=_target(data))
