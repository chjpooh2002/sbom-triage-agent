"""목표 버전 재검증(규칙). 언어 모델이 고른 버전을 그대로 믿지 않는다.

같은 (자산, 구성요소)에 걸린 취약점 전부를 한 묶음으로 보고:
  ① 실제 배포된 버전인가(레지스트리, 모르면 스캐너 수정 버전 목록)
  ② 설치 버전보다 높은가
  ③ 묶음의 모든 취약점 영향 범위를 벗어나는가
  ④ 메이저 버전이 바뀌는가(경고만)
를 확인하고, 실패하면 규칙이 고른 안전한 최소 버전으로 바꾼다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..models import Finding
from .versions import V, cmp, is_affected, is_prerelease, major, variant


@dataclass
class Check:
    ok: bool
    target: Optional[str]
    notes: list[str] = field(default_factory=list)
    still_affected: list[str] = field(default_factory=list)   # 이 버전으로도 남는 취약점
    major_change: bool = False


def _eco(group: list[Finding]) -> str:
    return group[0].component.ecosystem


def remaining(version: str, group: list[Finding]) -> list[str]:
    eco, inst = _eco(group), group[0].component.version
    return [f.vulnerability.id for f in group
            if is_affected(version, inst, f.vulnerability.affected_ranges, f.vulnerability.fixed_versions, eco)]


def candidate_versions(group: list[Finding], available: Optional[list[str]]) -> list[str]:
    """설치 버전보다 높은 정식 버전 후보(오름차순). 레지스트리 목록이 없으면 스캐너 수정 버전으로."""
    eco, inst = _eco(group), group[0].component.version
    pool = available if available else [v for f in group for v in f.vulnerability.fixed_versions]
    pool = [v for v in dict.fromkeys(pool) if v and not is_prerelease(v) and cmp(v, inst, eco) > 0]
    # 설치 버전과 같은 변형(-jre, .RELEASE 등)이 있으면 그것만 남긴다(guava -jre 를 -android 로 바꾸지 않게)
    same_variant = [v for v in pool if variant(v) == variant(inst)]
    if variant(inst) and same_variant:
        pool = same_variant
    return sorted(pool, key=lambda v: V(v, eco))


def rule_pick(group: list[Finding], available: Optional[list[str]]) -> tuple[Optional[str], list[str]]:
    """묶음의 취약점을 모두 해결하는 가장 작은 버전. 같은 메이저 안에서 먼저 찾는다."""
    inst = group[0].component.version
    cands = candidate_versions(group, available)
    clean = [v for v in cands if not remaining(v, group)]
    same = [v for v in clean if major(v) == major(inst)]
    if same:
        return same[0], [f"같은 메이저({major(inst)}.x) 안에서 모든 취약점을 해결하는 최소 버전"]
    if clean:
        return clean[0], [f"같은 메이저에는 해결 버전이 없어 메이저 버전 변경({major(inst)} → {major(clean[0])}) 필요"]
    if cands:   # 전부는 못 고친다: 가장 많이 줄이는 버전
        best = min(cands, key=lambda v: (len(remaining(v, group)), V(v, _eco(group))))
        return best, [f"모든 취약점을 해결하는 버전 없음 → 남는 취약점이 가장 적은 {best} 선택"]
    return None, ["수정 버전 정보 없음 → 버전 업그레이드로 해결 불가, 완화책 필요"]


def verify(target: Optional[str], group: list[Finding], available: Optional[list[str]]) -> Check:
    eco, inst = _eco(group), group[0].component.version
    notes: list[str] = []
    if not target:
        return Check(False, None, ["목표 버전 없음"])
    target = target.strip().lstrip("=")
    if available is not None:
        if target not in available:
            return Check(False, target, [f"{target} 은 레지스트리에 없는 버전"])
        notes.append("레지스트리에 존재 확인")
    else:
        known = {v for f in group for v in f.vulnerability.fixed_versions}
        if target not in known:
            return Check(False, target, [f"레지스트리 확인 불가(오프라인)이고 스캐너 수정 버전 목록에도 없음: {target}"])
        notes.append("레지스트리 확인 불가 → 스캐너 수정 버전 목록에서 확인")
    if cmp(target, inst, eco) <= 0:
        return Check(False, target, notes + [f"설치 버전 {inst} 보다 높지 않음"])
    if is_prerelease(target):
        return Check(False, target, notes + ["정식 버전이 아님(rc·beta 등)"])
    left = remaining(target, group)
    if left:
        return Check(False, target, notes + [f"이 버전으로도 남는 취약점: {', '.join(left)}"], still_affected=left)
    notes.append(f"묶음의 취약점 {len(group)}건 모두 영향 범위 밖")
    if variant(inst) and variant(target) != variant(inst):
        notes.append(f"변형이 다름({variant(inst)} → {variant(target) or '없음'}): 의도한 것인지 확인 필요")
    mc = major(target) != major(inst)
    if mc:
        notes.append(f"메이저 버전 변경({major(inst)} → {major(target)}): 호환성 확인 필요")
    return Check(True, target, notes, major_change=mc)
