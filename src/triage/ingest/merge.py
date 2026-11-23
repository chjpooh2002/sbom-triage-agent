"""여러 입력을 하나의 TriageBundle 로 합친다.

1) 입력마다 자산을 정한다: 명시 지정(path=ASSET) > 자산표 match 열 > 입력 대상 이름과 서비스명 일치 > 미지정
2) 구성요소를 정규화 purl 로 합친다(SBOM 의 직접 의존·경로 정보가 스캐너 결과에도 붙도록).
3) 같은 (자산, 구성요소)에서 식별자(CVE·GHSA 별칭)가 하나라도 겹치면 같은 취약점으로 합친다.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..models import AssetContext, Component, Finding, Status, TriageBundle, Vulnerability
from .common import pick_primary_id
from .registry import ParsedInput


def resolve_asset(p: ParsedInput, assets: list[AssetContext], explicit: Optional[str]) -> tuple[Optional[str], str]:
    if explicit:
        return explicit, "명시 지정"
    hay = f"{Path(p.source).name} {p.target}".lower()
    for a in assets:
        for m in a.match:
            if m.lower() in hay:
                return a.asset_id, f"match '{m}'"
    for a in assets:
        for n in (a.service_name, a.asset_id):
            if n and n.lower() in hay:
                return a.asset_id, f"이름 '{n}'"
    return None, "미지정"


def _merge_component(base: Component, other: Component) -> Component:
    base.sources = list(dict.fromkeys(base.sources + other.sources))
    # 직접/전이: 더 깊은 의존 그래프에서 나온 판단을 믿는다(평평한 jar 목록보다 빌드 도구 그래프).
    # 깊이가 같으면 '직접'을 남긴다(하나라도 직접 선언이면 직접 조치 대상)
    if other.direct is not None:
        if base.direct is None or other.direct_evidence > base.direct_evidence:
            base.direct, base.direct_evidence = other.direct, other.direct_evidence
            if other.dependency_paths:
                base.dependency_paths = list(other.dependency_paths)
        elif other.direct_evidence == base.direct_evidence and other.direct:
            base.direct = True
    for path in other.dependency_paths:
        if path not in base.dependency_paths and len(base.dependency_paths) < 3:
            base.dependency_paths.append(path)
    base.licenses = list(dict.fromkeys(base.licenses + other.licenses))
    for f in ("group", "purl", "ecosystem", "version"):
        if not getattr(base, f) and getattr(other, f):
            setattr(base, f, getattr(other, f))
    return base


def _merge_vulns(vs: list[Vulnerability]) -> Vulnerability:
    primary, aliases = pick_primary_id([i for v in vs for i in v.all_ids])
    # 점수: v3 벡터가 있는 것 우선, 그중 가장 높은 값(보수적으로)
    scored = [v for v in vs if v.cvss_score is not None]
    best = max(scored, key=lambda v: (v.cvss_vector.startswith("CVSS:3"), v.cvss_score), default=None)
    uniq = lambda xs: list(dict.fromkeys(x for x in xs if x))  # noqa: E731
    sev_order = ["critical", "high", "medium", "low", "unknown"]
    return Vulnerability(
        id=primary, aliases=aliases,
        title=next((v.title for v in vs if v.title), ""),
        description=max((v.description for v in vs), key=len, default=""),
        severity=min((v.severity or "unknown" for v in vs), key=lambda s: sev_order.index(s) if s in sev_order else 9),
        cvss_score=best.cvss_score if best else None, cvss_vector=best.cvss_vector if best else "",
        cvss_source=best.cvss_source if best else "",
        fixed_versions=uniq(x for v in vs for x in v.fixed_versions),
        affected_ranges=uniq(x for v in vs for x in v.affected_ranges),
        references=uniq(x for v in vs for x in v.references)[:10],
        published=next((v.published for v in vs if v.published), ""))


def _merge_status(fs: list[Finding]) -> tuple[Status, str]:
    vex = [f for f in fs if "cyclonedx-vex" in f.scanners and f.status == Status.not_affected]
    if vex:
        return Status.not_affected, f"VEX: {vex[0].status_note}".strip()
    if fs and all(f.status == Status.not_affected for f in fs):
        return Status.not_affected, "; ".join(dict.fromkeys(f.status_note for f in fs if f.status_note))
    if any(f.status == Status.affected for f in fs):
        return Status.affected, ""
    return Status.unknown, ""


def merge(parsed: list[ParsedInput], explicit_assets: Optional[dict[str, str]] = None) -> TriageBundle:
    explicit_assets = explicit_assets or {}
    assets: dict[str, AssetContext] = {}
    warnings: list[str] = []
    for p in parsed:
        warnings += p.warnings
        for a in p.assets:
            if a.asset_id in assets:
                warnings.append(f"자산 id 중복: {a.asset_id} (뒤의 행으로 덮어씀)")
            assets[a.asset_id] = a
    asset_list = list(assets.values())

    comps: dict[str, Component] = {}
    # (asset_id, component_id) → 그 안의 취약점 묶음 목록. 묶음 = (식별자 집합, [Finding])
    groups: dict[tuple, list[tuple[set, list[Finding]]]] = {}
    inputs_meta = []
    for p in parsed:
        if p.kind == "assets":
            inputs_meta.append({"source": p.source, "converter": p.converter, "kind": p.kind, "assets": len(p.assets)})
            continue
        asset_id, how = resolve_asset(p, asset_list, explicit_assets.get(p.source))
        if asset_id is None and asset_list:
            warnings.append(f"{Path(p.source).name}: 자산을 찾지 못함(대상 '{p.target}') → 자산 맥락 없이 처리")
        if asset_id and asset_id not in assets:
            assets[asset_id] = AssetContext(asset_id=asset_id, service_name=asset_id)
        inputs_meta.append({"source": p.source, "converter": p.converter, "kind": p.kind, "target": p.target,
                            "asset_id": asset_id, "asset_match": how,
                            "components": len(p.components), "findings": len(p.findings)})
        for c in p.components:
            comps[c.id] = _merge_component(comps[c.id], c) if c.id in comps else c.model_copy(deep=True)
        for f in p.findings:
            comps[f.component.id] = (_merge_component(comps[f.component.id], f.component)
                                     if f.component.id in comps else f.component.model_copy(deep=True))
            ids = set(f.vulnerability.all_ids)
            bucket = groups.setdefault((asset_id, f.component.id), [])
            hit = [g for g in bucket if g[0] & ids]
            if not hit:
                bucket.append((ids, [f]))
                continue
            # 여러 묶음과 겹치면 하나로 합친다(별칭 사슬)
            first = hit[0]
            first[0].update(ids)
            first[1].append(f)
            for g in hit[1:]:
                first[0].update(g[0])
                first[1].extend(g[1])
                bucket.remove(g)

    findings: list[Finding] = []
    for (asset_id, cid), bucket in groups.items():
        for _, fs in bucket:
            vuln = _merge_vulns([f.vulnerability for f in fs])
            status, note = _merge_status(fs)
            hints: dict = {}
            for f in fs:
                for k, v in f.hints.items():
                    hints.setdefault(k, v)
            findings.append(Finding(
                key=Finding.make_key(vuln.id, cid, asset_id), component=comps[cid], vulnerability=vuln,
                asset_id=asset_id, scanners=sorted({s for f in fs for s in f.scanners}),
                status=status, status_note=note, hints=hints))
    findings.sort(key=lambda f: f.key)
    return TriageBundle(components=sorted(comps.values(), key=lambda c: c.id), findings=findings,
                        assets=list(assets.values()), meta={"inputs": inputs_meta, "warnings": warnings})
