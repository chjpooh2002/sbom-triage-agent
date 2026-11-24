"""SBOM 구성요소를 공개 권고문과 대조한다."""
from __future__ import annotations

import re
from collections import defaultdict
from contextlib import nullcontext
from dataclasses import dataclass

import httpx

from ..config import ROOT
from ..ingest.common import pick_primary_id
from ..intel.enrich import enrich
from ..models import Component, Evidence, Finding, Status, TriageBundle, Vulnerability
from . import _nvd, _osv
from ._advisory import Advisory, EvidenceList, any_match
from ._http import Log, Responses

__all__ = ["LookupResult", "lookup"]

CACHE_DIR = ROOT / "data" / "cache" / "lookup"
CVE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


@dataclass
class LookupResult:
    findings: list[Finding]
    evidence: list[Evidence]


def _alias_groups(records: list[tuple[Component, Advisory, str]]) -> dict[str, tuple[str, list[str]]]:
    edges = defaultdict(set)
    for _, item, _ in records:
        identifier = _normalize_id(item.vulnerability.id)
        for alias in item.vulnerability.all_ids:
            alias = _normalize_id(alias)
            if not alias:
                continue
            edges[identifier].add(alias)
            edges[alias].add(identifier)
    groups = {}
    for identifier in sorted(edges):
        if identifier in groups:
            continue
        connected = set()
        pending = [identifier]
        while pending:
            current = pending.pop()
            if current not in connected:
                connected.add(current)
                pending.extend(edges[current] - connected)
        identity = pick_primary_id(sorted(connected))
        groups.update(dict.fromkeys(connected, identity))
    return groups


def _normalize_id(identifier: str) -> str:
    identifier = identifier.strip()
    return identifier.upper() if CVE.fullmatch(identifier) else identifier


def _merge(primary: str, aliases: list[str], items: list[Advisory]) -> Vulnerability:
    vulns = [item.vulnerability for item in items]
    scored = (v for v in vulns if v.cvss_score is not None)
    best = max(scored, key=lambda v: (v.cvss_vector.startswith("CVSS:3"), v.cvss_score), default=vulns[0])
    return Vulnerability(
        id=primary, aliases=aliases,
        title=next((v.title for v in vulns if v.title), ""),
        description=next((v.description for v in vulns if v.description), ""),
        published=min((v.published for v in vulns if v.published), default=""),
        severity=next((v.severity for v in [best, *vulns] if v.severity not in ("", "unknown")), "unknown"),
        cvss_score=best.cvss_score, cvss_vector=best.cvss_vector, cvss_source=best.cvss_source,
        references=list(dict.fromkeys(ref for v in vulns for ref in v.references)),
        affected_ranges=list(dict.fromkeys(expr for v in vulns for expr in v.affected_ranges)),
        fixed_versions=list(dict.fromkeys(version for v in vulns for version in v.fixed_versions)),
    )


def _findings(records: list[tuple[Component, Advisory, str]], evidence: EvidenceList) -> list[Finding]:
    aliases = _alias_groups(records)
    candidates = defaultdict(list)
    alias_evidence = defaultdict(list)
    for component, advisory, query_id in records:
        primary, _ = aliases[_normalize_id(advisory.vulnerability.id)]
        if advisory.vulnerability.aliases:
            alias_evidence[primary].append(advisory.evidence_id)
        candidates[Finding.make_key(primary, component.id, None)].append((component, advisory, query_id))

    findings = []
    for key, matches in sorted(candidates.items()):
        component = matches[0][0]
        items = [advisory for _, advisory, _ in matches]
        primary, other_ids = aliases[_normalize_id(items[0].vulnerability.id)]
        vulnerability = _merge(primary, other_ids, items)
        in_range = any_match([item.in_range for item in items])
        source_ids = list(dict.fromkeys(i for _, item, query_id in matches for i in (query_id, item.evidence_id)))
        inputs = list(dict.fromkeys([*component.evidence_ids, *source_ids]))
        result = {True: "범위 안", False: "범위 밖", None: "판단 유보"}[in_range]
        note = f"{primary}에 대한 {component.display} 버전 재판정: {result} (근거 {', '.join(inputs)})"
        verdict_evidence = evidence.add("tool", note=note)
        evidence_ids = list(dict.fromkeys([*source_ids, *alias_evidence[primary], verdict_evidence]))
        findings.append(Finding(
            key=key, component=component, vulnerability=vulnerability,
            scanners=sorted({item.source for item in items}), status=Status.unknown,
            version_in_range=in_range, hints={"evidence_ids": evidence_ids},
        ))
    return findings


def _enrich(findings: list[Finding], evidence: EvidenceList) -> list[Finding]:
    bundle = enrich(TriageBundle(findings=findings))
    sources = {}
    for finding in bundle.findings:
        for source, url in (
            (finding.signals.kev.source, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
            (finding.signals.epss_source, "https://www.first.org/epss/data_stats"),
        ):
            if source:
                if source not in sources:
                    sources[source] = evidence.add("advisory", url=url, note=f"조회에 사용한 인텔리전스 출처 {source}")
                finding.hints["evidence_ids"].append(sources[source])
    return bundle.findings


def lookup(components: list[Component], offline: bool = False, log: Log | None = None) -> LookupResult:
    """후보와 조회 근거를 반환한다. offline에서는 디스크 스냅샷만 읽는다.

    후보별 근거의 ID는 ``Finding.hints["evidence_ids"]``에 있다. 설치 버전의
    범위 결과는 ``version_in_range``이고 최종 영향 판정은 이후 단계에서 한다.
    """
    evidence = EvidenceList()
    if not components:
        return LookupResult([], evidence)
    libraries = [component for component in components if component.kind == "library"]
    runtimes = [component for component in components if component.kind in _nvd.KINDS]
    for component in components:
        if component.kind != "library" and component.kind not in _nvd.KINDS:
            evidence.add("tool", note=f"{component.id}: 조회 규칙이 없는 유형 {component.kind}")

    with (nullcontext() if offline else httpx.Client(timeout=20)) as client:
        responses = Responses(CACHE_DIR, client, log)
        records = [*_osv.lookup(libraries, responses, evidence), *_nvd.lookup(runtimes, responses, evidence)]
    findings = _nvd.limit_candidates(_findings(records, evidence), responses, evidence)
    if findings:
        findings = _enrich(findings, evidence)
    return LookupResult(findings, evidence)
