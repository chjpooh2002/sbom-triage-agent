"""결정적 우선순위 엔진. 같은 입력·같은 정책이면 항상 같은 순위와 근거를 낸다(언어 모델 사용 안 함)."""
from __future__ import annotations

import math
from datetime import date, timedelta
from typing import Optional

from ..models import AssetContext, Finding, PriorityResult, Reason, Status, Tier, TriageBundle
from .policy import Override, Policy


def interp(x: float, table: list[tuple[float, float]]) -> float:
    """구간 선형 보간."""
    x = min(max(x, table[0][0]), table[-1][0])
    for (x0, y0), (x1, y1) in zip(table, table[1:]):
        if x0 <= x <= x1:
            return y0 if x1 == x0 else y0 + (y1 - y0) * (x - x0) / (x1 - x0)
    return table[-1][1]


def _fmt(x: Optional[float], nd: int = 3) -> str:
    return "없음" if x is None else f"{x:.{nd}f}".rstrip("0").rstrip(".")


def normalized_signals(f: Finding, asset: Optional[AssetContext], pol: Policy) -> dict[str, tuple[float, str]]:
    """신호별 (0~1 정규화값, 근거 문장). 결측이면 어떻게 가정했는지 근거에 쓴다."""
    m = pol.missing
    out: dict[str, tuple[float, str]] = {}

    e = f.signals.epss
    if e is None:
        out["epss"] = (m.epss, f"EPSS 값 없음 → {m.epss} 가정")
    else:
        pct = f.signals.epss_percentile
        extra = f", 백분위 {pct * 100:.1f}%" if pct is not None else ""
        out["epss"] = (interp(e, pol.score.epss_scale), f"EPSS {_fmt(e, 4)}{extra}")

    c = f.vulnerability.cvss_score
    if c is None:
        sev = f.vulnerability.severity or "unknown"
        c = m.cvss_by_severity.get(sev, m.cvss_by_severity.get("unknown", 5.0))
        out["cvss"] = (c / 10, f"CVSS 없음 → 심각도 '{sev}' 기준 {c} 가정")
    else:
        src = f" ({f.vulnerability.cvss_source})" if f.vulnerability.cvss_source else ""
        out["cvss"] = (c / 10, f"CVSS {c}{src}")

    exp = asset.internet_exposed if asset else None
    if exp is None:
        out["exposure"] = (m.exposure, f"외부 노출 여부 모름 → {m.exposure} 가정")
    else:
        out["exposure"] = (1.0 if exp else 0.0, "외부 노출" if exp else "내부망")

    crit = asset.criticality if asset else None
    if crit is None:
        out["criticality"] = (m.criticality, f"자산 중요도 모름 → {m.criticality} 가정")
    else:
        out["criticality"] = ((crit - 1) / 4, f"자산 중요도 {crit}/5")
    return out


def _matches(o: Override, f: Finding, asset: Optional[AssetContext]) -> bool:
    w = o.when
    exp = asset.internet_exposed if asset else None
    crit = asset.criticality if asset else None
    checks = {
        "epss_gte": lambda v: f.signals.epss is not None and f.signals.epss >= v,
        "cvss_gte": lambda v: f.vulnerability.cvss_score is not None and f.vulnerability.cvss_score >= v,
        "internet_exposed": lambda v: exp is not None and exp == bool(v),
        "criticality_gte": lambda v: crit is not None and crit >= v,
        "criticality_lte": lambda v: crit is not None and crit <= v,
        "direct": lambda v: f.component.direct is not None and f.component.direct == bool(v),
        "has_fix": lambda v: bool(f.vulnerability.fixed_versions) == bool(v),
    }
    return all(checks[k](v) for k, v in w.items())


def due(tier: Tier, asset: Optional[AssetContext], pol: Policy, as_of: date) -> tuple[Optional[int], Optional[str], str]:
    days = pol.due_days.get(tier)
    if days is None:
        return None, None, f"{tier.value} 은 기한 없음"
    note = f"{tier.value} 기본 {days}일"
    if asset and asset.internet_exposed and pol.exposed_due_factor != 1.0:
        days = max(1, math.ceil(days * pol.exposed_due_factor))
        note += f" × 외부 노출 {pol.exposed_due_factor} = {days}일"
    return days, (as_of + timedelta(days=days)).isoformat(), note


def evaluate(f: Finding, asset: Optional[AssetContext], pol: Policy, as_of: date) -> PriorityResult:
    reasons: list[Reason] = []
    sig = normalized_signals(f, asset, pol)
    w = pol.score.weights
    total_w = sum(w.values())
    score = sum(w.get(k, 0) * v for k, (v, _) in sig.items()) / total_w
    layer, tier = "score", None

    if pol.layers.not_affected.enabled and f.status == Status.not_affected:
        layer, tier = "not_affected", pol.layers.not_affected.tier
        reasons.append(Reason(signal="status", value="not_affected", effect=f"{tier.value} 확정 (영향 없음 계층)",
                              source=f.status_note or "스캐너/VEX"))
    elif pol.layers.kev.enabled and f.signals.kev.listed:
        layer, tier = "kev", pol.layers.kev.tier
        k = f.signals.kev
        val = f"{k.date_added} 등재" + (", 랜섬웨어 악용 확인" if k.ransomware else "")
        reasons.append(Reason(signal="kev", value=val, effect=f"{tier.value} 확정 (KEV 계층: 실제 악용 확인)",
                              source=k.source or "CISA KEV"))

    # 점수와 신호별 기여는 어느 계층이든 기록한다(같은 등급 안의 순서, 설명에 쓰임)
    for k, (v, text) in sig.items():
        reasons.append(Reason(signal=k, value=text, effect=f"{v:.2f} × 가중치 {w.get(k, 0)} → +{w.get(k, 0) * v / total_w:.3f}",
                              source=f"정책 {pol.fingerprint}"))

    if tier is None:
        tier = Tier.P4
        for t in sorted(pol.score.thresholds, key=lambda t: t.rank):
            if score >= pol.score.thresholds[t]:
                tier = t
                break
        th = pol.score.thresholds.get(tier)
        reasons.append(Reason(signal="score", value=round(score, 3),
                              effect=f"{tier.value} (기준 {th} 이상)" if th is not None else "P4 (모든 기준 미만)"))
        for o in pol.overrides:
            if not _matches(o, f, asset):
                continue
            before = tier
            if o.min_tier and tier.rank > o.min_tier.rank:
                tier = o.min_tier
            if o.max_tier and tier.rank < o.max_tier.rank:
                tier = o.max_tier
            if tier != before:
                reasons.append(Reason(signal="override", value=o.name, effect=f"{before.value} → {tier.value}"))

    days, due_date, note = due(tier, asset, pol, as_of)
    reasons.append(Reason(signal="due", value=due_date or "-", effect=note))
    return PriorityResult(finding_key=f.key, tier=tier, score=round(score, 4), layer=layer, due_days=days,
                          due_date=due_date, reasons=reasons, policy_version=pol.fingerprint)


def sort_key(r: PriorityResult, f: Finding):
    """동점 처리 고정: 등급 → KEV → 점수 → EPSS → CVSS → 키."""
    return (r.tier.rank, not f.signals.kev.listed, -r.score, -(f.signals.epss or 0),
            -(f.vulnerability.cvss_score or 0), f.key)


def prioritize(bundle: TriageBundle, pol: Policy, as_of: Optional[date] = None) -> TriageBundle:
    as_of = as_of or date.today()
    results = []
    for f in bundle.findings:
        results.append((evaluate(f, bundle.asset(f.asset_id), pol, as_of), f))
    results.sort(key=lambda rf: sort_key(*rf))
    for i, (r, _) in enumerate(results, 1):
        r.rank = i
    bundle.results = [r for r, _ in results]
    bundle.meta["policy"] = {"name": pol.name, "version": pol.fingerprint, "as_of": as_of.isoformat()}
    return bundle


def cvss_only_tier(f: Finding) -> Tier:
    """비교 기준선: 심각도 점수만 보는 흔한 방식."""
    s = f.vulnerability.cvss_score or 0
    return Tier.P1 if s >= 9 else Tier.P2 if s >= 7 else Tier.P3 if s >= 4 else Tier.P4
