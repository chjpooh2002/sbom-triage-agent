"""채점: 등급 일치, 놓침(과소 평가), 과잉 경보, 순위 상관. 규칙 엔진과 CVSS 단독 기준선을 같은 표로 낸다."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Callable, Optional

from ..models import Tier
from ..priority.engine import cvss_only_tier, evaluate, sort_key
from ..priority.policy import Policy
from .gold import GoldCase


def kendall_tau_b(x: list[float], y: list[float]) -> Optional[float]:
    """동점을 보정한 켄달 타우-b. 표본이 2개 미만이거나 한쪽이 전부 같으면 None."""
    n = len(x)
    if n < 2:
        return None
    conc = disc = tx = ty = 0
    for i in range(n):
        for j in range(i + 1, n):
            dx, dy = x[i] - x[j], y[i] - y[j]
            if dx == 0 and dy == 0:
                continue
            if dx == 0:
                tx += 1
            elif dy == 0:
                ty += 1
            elif (dx > 0) == (dy > 0):
                conc += 1
            else:
                disc += 1
    denom = ((conc + disc + tx) * (conc + disc + ty)) ** 0.5
    return None if denom == 0 else (conc - disc) / denom


@dataclass
class MethodScore:
    name: str
    n: int
    exact: float
    within_one: float
    p1_expected: int
    p1_recall: Optional[float]        # 정답 P1 중 P1 로 맞춘 비율
    false_p1: int                     # 정답이 P1 이 아닌데 P1 로 올린 수(불필요 긴급 경보)
    under: int                        # 정답보다 덜 급하게 매긴 수(놓침 위험)
    over: int                         # 정답보다 더 급하게 매긴 수
    tau: Optional[float]
    confusion: dict[str, dict[str, int]]
    preds: dict[str, Tier]


def score_method(name: str, cases: list[GoldCase], preds: dict[str, Tier], order: dict[str, float]) -> MethodScore:
    n = len(cases)
    exact = sum(preds[c.case_id] == c.expected_tier for c in cases)
    within = sum(abs(preds[c.case_id].rank - c.expected_tier.rank) <= 1 for c in cases)
    p1 = [c for c in cases if c.expected_tier == Tier.P1]
    hit = sum(preds[c.case_id] == Tier.P1 for c in p1)
    false_p1 = sum(preds[c.case_id] == Tier.P1 and c.expected_tier != Tier.P1 for c in cases)
    under = sum(preds[c.case_id].rank > c.expected_tier.rank for c in cases)
    over = sum(preds[c.case_id].rank < c.expected_tier.rank for c in cases)
    # 순위 상관: 정답 순서 묶음(없으면 정답 등급)과 예측 순서
    exp_order = [float(c.expected_order_group if c.expected_order_group is not None else c.expected_tier.rank)
                 for c in cases]
    tau = kendall_tau_b(exp_order, [order[c.case_id] for c in cases])
    conf = {e.value: {p.value: 0 for p in Tier} for e in Tier}
    for c in cases:
        conf[c.expected_tier.value][preds[c.case_id].value] += 1
    return MethodScore(name, n, exact / n, within / n, len(p1), (hit / len(p1)) if p1 else None,
                       false_p1, under, over, tau, conf, preds)


def run_eval(cases: list[GoldCase], pol: Policy, as_of: Optional[date] = None,
             extra_methods: Optional[dict[str, Callable[[GoldCase], Tier]]] = None) -> tuple[list[MethodScore], dict]:
    as_of = as_of or date(2026, 11, 24)
    results = {c.case_id: evaluate(c.finding, c.asset, pol, as_of) for c in cases}
    ranked = sorted(cases, key=lambda c: sort_key(results[c.case_id], c.finding))
    rule_order = {c.case_id: float(i) for i, c in enumerate(ranked)}
    rule_preds = {cid: r.tier for cid, r in results.items()}
    cvss_preds = {c.case_id: cvss_only_tier(c.finding) for c in cases}
    cvss_order = {c.case_id: -(c.finding.vulnerability.cvss_score or 0) for c in cases}
    scores = [score_method("CVSS 단독(기준선)", cases, cvss_preds, cvss_order),
              score_method(f"규칙 엔진({pol.fingerprint})", cases, rule_preds, rule_order)]
    for name, fn in (extra_methods or {}).items():
        preds = {c.case_id: fn(c) for c in cases}
        scores.append(score_method(name, cases, preds, {k: float(v.rank) for k, v in preds.items()}))
    return scores, results


def _pct(x: Optional[float]) -> str:
    return "-" if x is None else f"{x * 100:.0f}%"


def render_markdown(gold_path: str, cases: list[GoldCase], scores: list[MethodScore], results: dict,
                    pol: Policy) -> str:
    reviewed = sum(c.reviewed for c in cases)
    lines = [f"# 정확도 측정 결과", "",
             f"- 정답 파일: `{gold_path}` ({len(cases)}건, 사람 검증 완료 {reviewed}건)",
             f"- 정책: {pol.name} `{pol.fingerprint}`", ""]
    if reviewed < len(cases):
        lines += [f"> 주의: 검증되지 않은 사례가 {len(cases) - reviewed}건 있다. 확정 수치로 쓰지 않는다.", ""]
    lines += ["| 방식 | 정확 일치 | 한 단계 이내 | P1 재현율 | 불필요 P1 | 과소 평가(놓침 위험) | 과대 평가 | 순위 상관 τ |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for s in scores:
        rec = f"{_pct(s.p1_recall)} ({round((s.p1_recall or 0) * s.p1_expected)}/{s.p1_expected})"
        tau = "-" if s.tau is None else f"{s.tau:.2f}"
        lines.append(f"| {s.name} | {_pct(s.exact)} | {_pct(s.within_one)} | {rec} | {s.false_p1} | {s.under} | {s.over} | {tau} |")
    rule = scores[1]
    lines += ["", "## 규칙 엔진 혼동 행렬 (행: 정답, 열: 예측)", "", "| 정답＼예측 | P1 | P2 | P3 | P4 |", "| --- | --- | --- | --- | --- |"]
    for e, row in rule.confusion.items():
        lines.append(f"| {e} | " + " | ".join(str(row[p]) for p in ("P1", "P2", "P3", "P4")) + " |")
    wrong = [c for c in cases if rule.preds[c.case_id] != c.expected_tier]
    lines += ["", f"## 규칙 엔진이 틀린 사례 ({len(wrong)}건)", ""]
    if wrong:
        lines += ["| 사례 | 취약점 | 정답 | 예측 | 점수 | 결정 계층 | 정답 근거 |", "| --- | --- | --- | --- | --- | --- | --- |"]
        for c in wrong:
            r = results[c.case_id]
            lines.append(f"| {c.case_id} | {c.finding.vulnerability.id} | {c.expected_tier.value} | {r.tier.value} | "
                         f"{r.score:.3f} | {r.layer} | {c.rationale.replace('|', '/')} |")
    lines += ["", "틀린 사례를 고칠 때는 그 사례에 맞추지 말고, 다른 데이터에서도 통할 일반 원칙인지 먼저 따진다(AGENTS.md)."]
    return "\n".join(lines) + "\n"
