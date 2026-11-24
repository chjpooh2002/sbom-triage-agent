"""판단 유보이면서 증거가 충분할 때만 승급 모델(SBOMTRIAGE_ESCALATE_MODEL)로 1회 다시 판정한다.

'증거 충분'은 결정적으로 정한다: 배포되는 앱 파일에서 주석이 아닌 코드 근거를 일정 수 이상 모았는가.
증거 자체가 없어서 유보한 건은 더 강한 모델도 추측밖에 못 하므로 올리지 않는다.
"""
from __future__ import annotations

import json

from triage.models import Verdict

from .client import LLMClient, ModelError, Prompt
from .decide import Outcome, step_schema
from .settings import Settings
from .workspace import Workspace


def eligible(verdict: Verdict, ws: Workspace, settings: Settings, client: LLMClient | None) -> tuple[bool, str]:
    if not settings.escalate:
        return False, "승급 단계 꺼짐(SBOMTRIAGE_ESCALATE=off)"
    if verdict.state != "undetermined":
        return False, "판단 유보 아님"
    if client is None:
        return False, "승급 모델 미설정"
    n = ws.deployed_code_evidence()
    if n < settings.min_deployed_code_evidence:
        return False, f"증거 부족(배포 앱 코드 근거 {n}건)"
    return True, f"배포 앱 코드 근거 {n}건"


def run(outcome: Outcome, verdict: Verdict, client: LLMClient, prompt: Prompt, case: str, subject: str) -> Outcome:
    base = outcome.messages or [{"role": "system", "content": prompt.text}, {"role": "user", "content": case}]
    why = "; ".join([verdict.rationale_ko[:300], *verdict.verifier_notes[:3]]) or "사유 없음"
    messages = [*base, {"role": "user", "content":
                        "## 승급 판정\n앞선 판정은 판단 유보였다(사유: " + why + "). 위 자료와 도구 결과만으로 다시 판정하라. "
                        "도구는 더 쓸 수 없다(action=final). 규칙은 그대로다: 근거 ID·원문 인용 필수, 모르면 undetermined."}]
    try:
        reply = client.complete(purpose="escalate", prompt_version=prompt.version, messages=messages,
                                schema=step_schema(True), schema_name="decision", subject=subject)
    except ModelError as e:
        return Outcome(None, client.model, messages, error=str(e))
    if reply.refused or reply.data is None:
        return Outcome(None, client.model, messages, refused=True, error=reply.refusal or "모델 거절")
    messages.append({"role": "assistant", "content": json.dumps(reply.data, ensure_ascii=False)})
    return Outcome(reply.data["verdict"], client.model, messages, submissions=1)
