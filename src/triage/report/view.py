"""보고서·화면이 함께 쓰는 표 데이터. 마크다운·엑셀·스트림릿은 이 행들을 그리기만 한다."""
from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import date
from typing import Optional

from ..models import Finding, PriorityResult, Remediation, Tier, TriageBundle


@dataclass
class ActionGroup:
    """조치 단위: (자산, 구성요소). 이 구성요소를 올리면 함께 해결되는 취약점 묶음."""

    order: int
    service: str
    asset_id: Optional[str]
    component: str
    ecosystem: str
    installed: str
    direct: Optional[bool]
    target: Optional[str]
    verified: bool
    tier: Tier
    due_date: Optional[str]
    kev_ids: list[str]
    vuln_ids: list[str]
    remediation: Optional[Remediation]
    findings: list[tuple[PriorityResult, Finding]] = field(default_factory=list)


def service_name(b: TriageBundle, asset_id: Optional[str]) -> str:
    a = b.asset(asset_id)
    return (a.service_name or a.asset_id) if a else "(자산 미지정)"


def ranked(b: TriageBundle) -> list[tuple[PriorityResult, Finding]]:
    by_key = {f.key: f for f in b.findings}
    return [(r, by_key[r.finding_key]) for r in b.results if r.finding_key in by_key]


def action_groups(b: TriageBundle) -> list[ActionGroup]:
    rem = {r.finding_key: r for r in b.remediations}
    groups: "OrderedDict[tuple, list]" = OrderedDict()
    for r, f in ranked(b):
        groups.setdefault((f.asset_id, f.component.id), []).append((r, f))
    out = []
    for i, ((asset_id, _), items) in enumerate(groups.items(), 1):
        r0, f0 = items[0]
        rm = rem.get(f0.key)
        dues = [r.due_date for r, _ in items if r.due_date]
        out.append(ActionGroup(
            order=i, service=service_name(b, asset_id), asset_id=asset_id, component=f0.component.display.rsplit("@", 1)[0],
            ecosystem=f0.component.ecosystem, installed=f0.component.version, direct=f0.component.direct,
            target=rm.target_version if rm else None, verified=bool(rm and rm.verified),
            tier=min((r.tier for r, _ in items), key=lambda t: t.rank), due_date=min(dues) if dues else None,
            kev_ids=[f.vulnerability.id for _, f in items if f.signals.kev.listed],
            vuln_ids=[f.vulnerability.id for _, f in items], remediation=rm, findings=items))
    return out


def summary(b: TriageBundle, as_of: Optional[date] = None) -> dict:
    as_of = as_of or date.fromisoformat(b.meta.get("policy", {}).get("as_of", date.today().isoformat()))
    rs = ranked(b)
    tiers = Counter(r.tier.value for r, _ in rs)
    soon = sum(1 for r, _ in rs if r.due_days is not None and r.due_days <= 7)
    groups = action_groups(b)
    return {
        "findings": len(rs), "tiers": {t: tiers.get(t, 0) for t in ("P1", "P2", "P3", "P4")},
        "kev": sum(1 for _, f in rs if f.signals.kev.listed), "due_within_7": soon,
        "groups": len(groups), "groups_verified": sum(g.verified for g in groups),
        "services": dict(Counter(service_name(b, f.asset_id) for _, f in rs)),
        "components": len({f.component.id for _, f in rs}),
        "as_of": as_of.isoformat(),
    }


def path_text(f: Finding) -> str:
    if f.component.direct is True:
        return "직접"
    if f.component.direct is False:
        p = f.component.dependency_paths[0] if f.component.dependency_paths else []
        names = [x.rsplit("/", 1)[-1].split("@")[0] for x in p]
        return "전이" + (f" ({' → '.join(names)})" if names else "")
    return "모름"


def finding_row(r: PriorityResult, f: Finding, b: TriageBundle) -> dict:
    return {
        "순위": r.rank, "등급": r.tier.value, "기한": r.due_date or "-", "취약점": f.vulnerability.id,
        "CVSS": f.vulnerability.cvss_score, "EPSS": None if f.signals.epss is None else round(f.signals.epss, 4),
        "KEV": "예" if f.signals.kev.listed else "", "서비스": service_name(b, f.asset_id),
        "구성요소": f.component.display, "의존 경로": path_text(f), "점수": r.score, "결정 계층": r.layer,
        "스캐너": ", ".join(f.scanners), "상태": f.status.value,
    }


def reasons_text(r: PriorityResult) -> list[str]:
    return [f"[{x.signal}] {x.value} → {x.effect}" for x in r.reasons]
