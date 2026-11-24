"""판정과 근거를 보존하면서 개발자가 함께 처리할 후보를 묶는다."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Literal

from univers.versions import Version

from .models import Component, Finding, MissingInfo, TriageBundle, WorkRequest
from .output._common import finding_evidence, finding_state
from .remediation.versions import V, cmp, in_range

_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_MINOR = re.compile(r"^v?(\d+)\.(\d+)(?=[.\-+]|$)")


@dataclass
class Action:
    kind: Literal["upgrade", "base_image", "confirm"]
    title: str
    component: str
    target: str
    findings: list[str]
    counts: dict[str, int]
    top_finding: str
    priority: tuple
    team: str
    work_request: WorkRequest | None
    evidence_ids: list[str]
    missing_info: list[MissingInfo]


def _concrete(value: str, eco: str) -> bool:
    # 숫자 조각만으로 비교하는 대체 파서는 범위·태그를 수정 버전으로 인정하면 안 된다.
    if not re.fullmatch(r"v?\d[0-9A-Za-z.!+_~:-]*", value) or re.search(r"(?:^|\.)x(?:\.|$)", value, re.I):
        return False
    return bool(re.fullmatch(r"v?\d+(?:\.\d+)*", value) or isinstance(V(value, eco), Version))


def _highest(versions, eco: str) -> str:
    candidates = sorted({v for v in versions if v and _concrete(v, eco)})
    return max(candidates, key=cmp_to_key(lambda a, b: cmp(a, b, eco)), default="")


def _covered(finding: Finding, target: str) -> bool:
    eco, installed = finding.component.ecosystem, finding.component.version
    vuln = finding.vulnerability
    if not target or not _concrete(installed, eco) or cmp(target, installed, eco) <= 0:
        return False
    if any(in_range(target, expr, eco) for expr in vuln.affected_ranges):
        return False
    # 이전 유지보수 줄의 수정 버전만으로 현재 줄이 해소된다고 결론 내리지 않는다.
    return any(_concrete(fix, eco) and cmp(installed, fix, eco) < 0 and cmp(fix, target, eco) <= 0
               for fix in vuln.fixed_versions)


def _image_source(component: Component, evidence) -> str:
    for ref in component.evidence_ids:
        item = evidence.get(ref)
        if item and item.file and item.kind == "build":
            return item.file
    return next(iter(component.sources), component.id)


def _image_target(findings: list[Finding]) -> str:
    # 한 Dockerfile의 서로 다른 이미지에 같은 목표 태그를 제시하지 않는다.
    images = {f.component.declared_spec or f.component.display for f in findings}
    if len(images) != 1:
        return "같은 줄 최신 패치"
    fixes = []
    for finding in findings:
        current = finding.component.version
        line = _MINOR.match(current)
        for fix in finding.vulnerability.fixed_versions:
            fixed_line = _MINOR.match(fix)
            if (line and fixed_line and line.groups() == fixed_line.groups()
                    and cmp(fix, current.split("-")[0], "runtime") > 0):
                fixes.append(fix)
    return _highest(fixes, "runtime") or "같은 줄 최신 패치"


def build_actions(bundle: TriageBundle) -> list[Action]:
    priorities = {p.finding_key: p for p in bundle.results}
    plans = {r.finding_key: r for r in bundle.remediations}
    evidence = {e.id: e for e in bundle.evidence}
    images = defaultdict(list)
    packages = defaultdict(list)
    for finding in bundle.findings:
        if finding_state(finding) == "not_affected":
            continue
        component = finding.component
        if component.kind in {"base-image", "runtime"}:
            images[_image_source(component, evidence)].append(finding)
        else:
            packages[component.id].append(finding)

    def severity(f):
        return -_SEVERITY.get(f.vulnerability.severity.lower(), 0)

    def order(f):
        p = priorities.get(f.key)
        fallback = (severity(f), -int(f.signals.kev.listed),
                    -(f.signals.epss if f.signals.epss is not None else -1), f.key)
        if p:
            return (0, p.tier.rank, p.rank or float("inf"), -p.score, *fallback)
        return (1, *fallback)

    def action(kind, members, target=""):
        members = sorted(members, key=order)
        top = members[0]
        component = top.component
        keys = [f.key for f in members]
        affected = sum(finding_state(f) == "affected" for f in members)
        counts = {"affected": affected, "undetermined": len(keys) - affected}
        request = top.verdict.work_request if top.verdict else None
        refs = finding_evidence(top)
        # 카드 첫 근거에서 실제 코드나 선언 위치를 바로 볼 수 있게 한다.
        refs.sort(key=lambda r: not (r in evidence and evidence[r].file and evidence[r].snippet))
        missing = {(m.what, m.where): m for f in members if f.verdict for m in f.verdict.missing_info}
        if kind == "base_image":
            name = ", ".join(dict.fromkeys(f.component.declared_spec or f.component.display for f in members))
            title = f"기반 이미지 {name} 패치 버전으로 교체"
        elif kind == "upgrade":
            title = f"{component.display} 업그레이드"
        else:
            title = f"{component.display} 영향 조건 확인"
        group_order = 0 if affected else (1 if kind == "base_image" else 2)
        highest_severity = min(map(severity, members))
        priority = (group_order, highest_severity if kind == "confirm" else 0, order(top))
        return Action(
            kind=kind, title=f"{title} · 관련 취약점 {len(keys)}건", component=component.display,
            target=target, findings=keys, counts=counts, top_finding=top.key, priority=priority,
            team=request.to_team if request else "", work_request=request, evidence_ids=refs[:2],
            missing_info=list(missing.values()),
        )

    actions = [action("base_image", members, _image_target(members)) for members in images.values()]
    for members in packages.values():
        affected = [f for f in members if finding_state(f) == "affected"]
        pending = [f for f in members if finding_state(f) == "undetermined"]
        if affected:
            eco = affected[0].component.ecosystem
            targets = [plans[f.key].target_version for f in affected if f.key in plans and plans[f.key].target_version]
            target = _highest(targets or [v for f in affected for v in f.vulnerability.fixed_versions], eco)
            covered = [f for f in pending if _covered(f, target)]
            actions.append(action("upgrade", [*affected, *covered], target))
            covered_keys = {f.key for f in covered}
            pending = [f for f in pending if f.key not in covered_keys]
        if pending:
            actions.append(action("confirm", pending))
    return sorted(actions, key=lambda a: a.priority)
