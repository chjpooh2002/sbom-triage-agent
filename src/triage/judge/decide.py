"""점검표 항목별 증거를 먼저 결정적으로 모아 주고, 부족하면 모델이 도구를 최대 N회 호출한 뒤 판정한다.

판정은 json_schema 응답으로만 받는다. 도구 요청도 같은 스키마의 action 칸으로 받는다
(공급자·프록시마다 다른 함수 호출 기능에 기대지 않기 위해).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from triage.models import Checklist, Finding, ItemResult, MissingInfo, Verdict

from .client import LLMClient, ModelError, Prompt
from .settings import Settings
from .workspace import Workspace

STATES = ["affected", "not_affected", "undetermined"]
JUSTIFICATIONS = ["", "code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
                  "requires_environment", "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter",
                  "protected_by_mitigating_control"]
TOOLS = ["search_symbol", "find_callers", "read_lines", "resolve_config"]


def _obj(props: dict) -> dict:
    return {"type": "object", "additionalProperties": False, "properties": props, "required": list(props)}


_S = {"type": "string"}


def verdict_schema() -> dict:
    citation = _obj({"evidence_id": _S, "quote": _S})
    item = _obj({"key": _S, "status": {"type": "string", "enum": ["met", "not_met", "unknown"]},
                 "citations": {"type": "array", "items": citation}, "reason": _S})
    return _obj({
        "state": {"type": "string", "enum": STATES},
        "justification": {"type": "string", "enum": JUSTIFICATIONS},
        "items": {"type": "array", "items": item},
        "rationale_ko": _S, "plain_ko": _S, "fix_version": _S,
        "missing_info": {"type": "array", "items": _obj({"what": _S, "where": _S})},
        "suspicious_comments": {"type": "array", "items": _obj({"evidence_id": _S, "text": _S})},
    })


def step_schema(final_only: bool) -> dict:
    request = _obj({"tool": {"type": "string", "enum": TOOLS}, "symbol": _S, "path": _S,
                    "start": {"type": "integer"}, "end": {"type": "integer"}, "key": _S, "why": _S})
    return _obj({"action": {"type": "string", "enum": ["final"] if final_only else ["tool", "final"]},
                 "tool_requests": {"type": "array", "items": request},
                 "verdict": verdict_schema()})


def checklist_text(checklist: Checklist) -> str:
    rows = []
    for n, item in enumerate(checklist.items, 1):
        extra = []
        if item.symbols:
            extra.append("검색어: " + ", ".join(item.symbols))
        if item.config_keys:
            extra.append("설정 키: " + ", ".join(item.config_keys))
        rows.append(f"{n}. `{item.key}` ({item.kind}, {'필수' if item.required else '선택'}) {item.question}"
                    + (f"\n   {' / '.join(extra)}" if extra else ""))
    entry = ", ".join(checklist.vulnerable_entry_points) or "(권고문에 없음)"
    return f"취약 진입점: {entry}\n" + "\n".join(rows)


def case_text(finding: Finding, checklist: Checklist, ws: Workspace, gathered: str, remaining: int) -> str:
    return "\n\n".join([
        "## 후보(조회·수집 단계가 정한 사실 — 바꾸지 않는다)", ws.facts(finding),
        "## 권고문 요약", f"{finding.vulnerability.title}\n{finding.vulnerability.description[:ws.settings.max_description_chars]}",
        "## 발생 조건 점검표", checklist_text(checklist),
        "## 미리 모은 증거", gathered,
        "## 파일 배포 범위", ws.scope_summary(),
        f"## 남은 도구 호출: {remaining}회",
    ])


@dataclass
class Outcome:
    output: dict | None                     # 마지막 판정(verdict 칸)
    model: str = ""
    messages: list[dict] = field(default_factory=list)
    submissions: int = 0                    # 판정 제출 횟수(재요청 포함)
    refused: bool = False
    error: str = ""


def _ask(client: LLMClient, prompt: Prompt, messages: list[dict], final_only: bool, subject: str):
    return client.complete(purpose="decide", prompt_version=prompt.version, messages=messages,
                           schema=step_schema(final_only), schema_name="decision", subject=subject)


def run(finding: Finding, checklist: Checklist, ws: Workspace, client: LLMClient, settings: Settings,
        prompt: Prompt, case: str) -> Outcome:
    messages = [{"role": "system", "content": prompt.text}, {"role": "user", "content": case}]
    remaining = settings.max_tool_calls
    outcome = Outcome(None, client.model, messages)
    while True:
        final_only = remaining <= 0
        try:
            reply = _ask(client, prompt, messages, final_only, finding.key)
        except ModelError as e:
            outcome.error = str(e)
            return outcome
        if reply.refused or reply.data is None:
            outcome.refused = True
            outcome.error = reply.refusal or "모델 거절"
            return outcome
        data = reply.data
        messages.append({"role": "assistant", "content": json.dumps(data, ensure_ascii=False)})
        requests = data.get("tool_requests", [])
        if data.get("action") == "tool" and requests and not final_only:
            take = requests[:remaining]
            results = [ws.run_tool(r) for r in take]
            remaining -= len(take)
            tail = " — 이제 action=final 로 판정하라." if remaining <= 0 else ""
            messages.append({"role": "user", "content": "## 도구 결과\n\n" + "\n\n".join(results)
                             + f"\n\n## 남은 도구 호출: {remaining}회{tail}"})
            continue
        outcome.output = data["verdict"]
        outcome.submissions += 1
        return outcome


def resubmit(outcome: Outcome, message: str, client: LLMClient, prompt: Prompt, subject: str) -> Outcome:
    """검증 위반을 알려 주고 한 번 더 판정을 받는다(도구 없음)."""
    messages = [*outcome.messages, {"role": "user", "content": message}]
    try:
        reply = _ask(client, prompt, messages, True, subject)
    except ModelError as e:
        return Outcome(None, client.model, messages, outcome.submissions, error=str(e))
    if reply.refused or reply.data is None:
        return Outcome(None, client.model, messages, outcome.submissions, refused=True,
                       error=reply.refusal or "모델 거절")
    messages.append({"role": "assistant", "content": json.dumps(reply.data, ensure_ascii=False)})
    return Outcome(reply.data["verdict"], client.model, messages, outcome.submissions + 1)


def to_verdict(output: dict, checklist: Checklist, decided_by: str, attempts: int) -> Verdict:
    keys = {i.key for i in checklist.items}
    items = []
    for raw in output.get("items", []):
        if raw.get("key") not in keys:
            continue
        ids = list(dict.fromkeys(c.get("evidence_id", "") for c in raw.get("citations", []) if c.get("evidence_id")))
        items.append(ItemResult(item_key=raw["key"], status=raw.get("status", "unknown"), evidence_ids=ids,
                                reason=raw.get("reason", "")))
    state = output.get("state", "undetermined")
    return Verdict(
        state=state, justification=output.get("justification", "") if state == "not_affected" else "",
        decided_by=decided_by, item_results=items, rationale_ko=output.get("rationale_ko", "").strip(),
        plain_ko=output.get("plain_ko", "").strip(),
        missing_info=[MissingInfo(what=m["what"].strip(), where=m.get("where", "").strip())
                      for m in output.get("missing_info", []) if m.get("what", "").strip()],
        attempts=attempts)
