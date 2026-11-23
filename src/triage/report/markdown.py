"""현업 담당자용 한국어 조치 보고서(마크다운)."""
from __future__ import annotations

from datetime import datetime

from ..models import Tier, TriageBundle
from ..priority.policy import Policy
from .view import action_groups, finding_row, reasons_text, summary

DETAIL_TIERS = {Tier.P1, Tier.P2}


def _cell(v) -> str:
    return "-" if v is None or v == "" else str(v).replace("|", "/").replace("\n", " ")


def _table(rows: list[dict]) -> list[str]:
    if not rows:
        return ["(해당 없음)"]
    cols = list(rows[0])
    return ["| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"] + \
        ["| " + " | ".join(_cell(r[c]) for c in cols) + " |" for r in rows]


def render(b: TriageBundle, pol: Policy) -> str:
    s = summary(b)
    groups = action_groups(b)
    intel = b.meta.get("intel", {})
    rem = b.meta.get("remediation", {})
    L = ["# SW 공급망 취약점 조치 보고서", "",
         f"- 작성: {datetime.now().strftime('%Y-%m-%d %H:%M')} · 기한 기준일 {s['as_of']}",
         f"- 판단 정책: {pol.name} `{pol.fingerprint}` (가중치·기한은 config/policy.yaml)",
         f"- 위협 정보: CISA KEV {intel.get('kev', {}).get('date') or intel.get('kev', {}).get('origin', '-')}, "
         f"EPSS {intel.get('epss', {}).get('date') or intel.get('epss', {}).get('origin', '-')}",
         f"- 조치안 생성: {rem.get('provider', '-')} ({rem.get('model', '-')}), 목표 버전은 규칙으로 재검증", "",
         "## 1. 요약", "",
         f"- 취약점 **{s['findings']}건** (구성요소 {s['components']}개, 서비스별 " +
         ", ".join(f"{k} {v}건" for k, v in s["services"].items()) + ")",
         f"- 등급: **P1 {s['tiers']['P1']}** / P2 {s['tiers']['P2']} / P3 {s['tiers']['P3']} / P4 {s['tiers']['P4']}"
         f" · 실제 악용 확인(KEV) **{s['kev']}건** · 7일 이내 기한 {s['due_within_7']}건",
         f"- 조치 단위 **{s['groups']}개**: 구성요소 {s['groups']}개를 올리면 위 취약점이 해결된다"
         f" (목표 버전 검증 완료 {s['groups_verified']}개)", ""]
    for name, a in [("P1", pol.action(Tier.P1)), ("P2", pol.action(Tier.P2)), ("P3", pol.action(Tier.P3)), ("P4", pol.action(Tier.P4))]:
        days = pol.due_days.get(Tier(name))
        L.append(f"  - {name} {pol.label(Tier(name))}: {a}" + (f" (기본 {days}일, 외부 노출 자산은 ×{pol.exposed_due_factor})" if days else ""))

    L += ["", "## 2. 조치 계획 (구성요소 단위, 급한 순)", ""]
    L += _table([{
        "순서": g.order, "등급": g.tier.value, "기한": g.due_date, "서비스": g.service, "구성요소": g.component,
        "현재": g.installed, "목표": g.target, "검증": "✔" if g.verified else "✘",
        "의존": "직접" if g.direct else "전이" if g.direct is False else "모름",
        "해결 건수": len(g.vuln_ids), "KEV": ", ".join(g.kev_ids)} for g in groups])

    L += ["", "## 3. 조치안 상세 (P1·P2)", ""]
    detailed = [g for g in groups if g.tier in DETAIL_TIERS]
    if not detailed:
        L.append("(P1·P2 없음)")
    for g in detailed:
        rm = g.remediation
        L += [f"### {g.order}. {g.component} {g.installed} → {g.target or '수정 버전 없음'} ({g.service}, {g.tier.value}, 기한 {g.due_date or '-'})", ""]
        if rm:
            L += [rm.summary_ko, "", "**조치 단계**", ""] + [f"{i}. {x}" for i, x in enumerate(rm.steps, 1)]
            L += ["", f"**임시 완화책**: {rm.workaround}", "",
                  f"**목표 버전 검증**: {'통과' if rm.verified else '미통과'} — " + "; ".join(rm.verify_notes), "",
                  f"<sub>작성: {rm.provider}{' (모델 실패로 대체)' if rm.fallback_used else ''}</sub>", ""]
        L += ["**포함된 취약점과 판단 근거**", ""]
        for r, f in g.findings:
            L.append(f"- **{f.vulnerability.id}** {r.tier.value} (점수 {r.score:.3f}, {r.layer} 계층) "
                     f"{f.vulnerability.title or f.vulnerability.description[:120]}")
            L += [f"  - {x}" for x in reasons_text(r)]
        L.append("")

    L += ["## 4. 취약점 전체 목록", ""]
    rows = [finding_row(r, f, b) for g in groups for r, f in g.findings]
    rows.sort(key=lambda x: x["순위"])
    L += _table([{k: r[k] for k in ("순위", "등급", "기한", "취약점", "CVSS", "EPSS", "KEV", "서비스", "구성요소", "의존 경로", "점수")} for r in rows])

    warns = b.meta.get("warnings", []) + intel.get("warnings", []) + rem.get("warnings", [])
    L += ["", "## 5. 참고", "",
          "- 등급은 규칙(결정적)으로 정해지며 같은 입력·같은 정책이면 항상 같은 결과가 나온다. 언어 모델은 설명과 조치 단계만 작성한다.",
          "- 계층: ① 영향 없음(VEX) → P4 ② KEV 등재 → P1 ③ EPSS·CVSS·외부 노출·자산 중요도 가중 점수 → 보정 규칙."]
    if warns:
        L += ["", "**입력·처리 경고**", ""] + [f"- {w}" for w in warns]
    L += ["", "**입력 파일**", ""] + [f"- [{i['converter']}] {i['source']}" + (f" → 자산 {i.get('asset_id')}" if i.get("kind") != "assets" else "")
                                    for i in b.meta.get("inputs", [])]
    return "\n".join(L) + "\n"
