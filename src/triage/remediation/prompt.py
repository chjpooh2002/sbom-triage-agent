"""조치안 생성 입력(사실 묶음)과 지시문, 구조화 출력 스키마. 모든 공급자가 같은 입력·같은 스키마를 쓴다."""
from __future__ import annotations

import json
from typing import Optional

from pydantic import BaseModel, Field

from ..models import AssetContext, Finding, PriorityResult

SYSTEM = """\
너는 기업 인프라 보안팀의 오픈소스 취약점 조치 담당자다. 현업 개발자가 바로 따라 할 수 있는 한국어 조치안을 쓴다.

규칙
1. 입력 JSON 에 있는 사실만 쓴다. 입력에 없는 CVE 번호, 버전, 날짜, 공격 사례를 지어내지 않는다.
2. target_version 은 반드시 candidate_versions 목록 안에서 고른다. 고를 수 없으면 null 로 둔다.
   rule_suggestion 이 있으면 특별한 이유가 없는 한 그것을 고른다. 다른 것을 고르면 이유를 summary_ko 에 쓴다.
3. 우선순위·등급·기한은 이미 규칙으로 정해졌다. 바꾸거나 다시 평가하지 말고 그 이유를 쉽게 풀어 설명만 한다.
4. 전이 의존성(direct=false)이면 직접 선언이 아니라는 점과, 버전을 강제하는 방법(예: Gradle constraints,
   Maven dependencyManagement, npm overrides)을 단계에 포함한다.
5. 업그레이드가 당장 어려울 때 쓸 수 있는 임시 완화책을 workaround 에 쓴다. 모르면 '벤더 권고 확인'이라고만 쓴다.
6. steps 는 3~6개, 각 한 문장. summary_ko 는 2~3문장.
"""


class RemediationDraft(BaseModel):
    target_version: Optional[str] = Field(description="candidate_versions 중 하나, 없으면 null")
    summary_ko: str = Field(description="무엇이 왜 위험하고 무엇을 하면 되는지 2~3문장")
    steps: list[str] = Field(description="조치 단계 3~6개")
    workaround: str = Field(description="업그레이드 전 임시 완화책")


def draft_schema() -> dict:
    """structured output 용 JSON 스키마(모든 필드 required, additionalProperties false)."""
    return {
        "type": "object",
        "properties": {
            "target_version": {"type": ["string", "null"]},
            "summary_ko": {"type": "string"},
            "steps": {"type": "array", "items": {"type": "string"}},
            "workaround": {"type": "string"},
        },
        "required": ["target_version", "summary_ko", "steps", "workaround"],
        "additionalProperties": False,
    }


def build_context(group: list[Finding], results: dict[str, PriorityResult], asset: Optional[AssetContext],
                  candidates: list[str], rule_suggestion: Optional[str], rule_notes: list[str]) -> dict:
    c = group[0].component
    vulns = []
    for f in sorted(group, key=lambda x: results[x.key].rank):
        r = results[f.key]
        vulns.append({
            "id": f.vulnerability.id, "title": f.vulnerability.title or f.vulnerability.description[:200],
            "cvss": f.vulnerability.cvss_score, "kev": f.signals.kev.listed, "epss": f.signals.epss,
            "fixed_versions": f.vulnerability.fixed_versions[:8], "tier": r.tier.value, "due_date": r.due_date,
            "priority_reasons": [f"{x.signal}: {x.value} ({x.effect})" for x in r.reasons
                                 if x.signal in ("kev", "status", "override", "score")],
        })
    return {
        "component": {"name": c.display, "ecosystem": c.ecosystem, "installed_version": c.version,
                      "direct": c.direct, "dependency_paths": c.dependency_paths[:2]},
        "asset": None if asset is None else {"service": asset.service_name or asset.asset_id,
                                             "internet_exposed": asset.internet_exposed,
                                             "criticality": asset.criticality, "environment": asset.environment},
        "vulnerabilities": vulns,
        "candidate_versions": candidates[:30],
        "rule_suggestion": rule_suggestion,
        "rule_notes": rule_notes,
    }


def user_message(ctx: dict) -> str:
    return "다음 구성요소의 조치안을 작성하라.\n```json\n" + json.dumps(ctx, ensure_ascii=False, indent=1) + "\n```"
