"""점검표 항목별 증거를 먼저 결정적으로 모아 주고, 부족하면 모델이 도구를 최대 N회 호출한 뒤 판정한다.

판정은 json_schema 응답으로만 받는다. 도구 요청도 같은 스키마의 action 칸으로 받는다
(공급자·프록시마다 다른 함수 호출 기능에 기대지 않기 위해).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from triage.evidence import EvidenceStore
from triage.models import Checklist, Finding, ItemResult, MissingInfo, Verdict

from .checklist import ASSUMPTION, FIXED_KINDS, LIBRARY_FACT, is_service_condition
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


def tool_budget(finding: Finding, settings: Settings) -> int:
    """판정 한 건의 도구 호출 상한. 심각도별 값(config/judge.yaml)이 있으면 그 값."""
    severity = (finding.vulnerability.severity or "").strip().lower()
    return settings.max_tool_calls_by_severity.get(severity, settings.max_tool_calls)


def advisory_sources(finding: Finding, store: EvidenceStore) -> list[str]:
    """라이브러리 사실의 출처로 다는 조회 근거: 권고문(advisory) 근거, 없으면 링크가 있는 조회 근거."""
    found = []
    for eid in finding.hints.get("evidence_ids", []):
        try:
            found.append(store.get(eid))
        except (KeyError, TypeError):
            continue
    advisory = [e.id for e in found if e.kind == "advisory"]
    return list(dict.fromkeys(advisory or [e.id for e in found if e.url]))


def fill_fixed(output: dict | None, checklist: Checklist, sources: list[str]) -> dict | None:
    """라이브러리 사실·전제 항목의 결과는 모델이 아니라 규칙이 정한다(모델이 적은 값은 덮어쓴다).

    - library_fact: 권고문·패키지 문서에 적힌 영향 버전의 동작이므로 조회 근거(권고문 링크)로 충족.
      권고문 근거가 없으면 출처를 댈 수 없으니 확인되지 않음.
    - assumption: 소스로 확인할 수 없는 운영 환경 전제. 판정 조건이 아니며 보고서에 "전제"로 표시.
    """
    fixed = [i for i in checklist.items if i.kind in FIXED_KINDS]
    if output is None or not fixed:
        return output
    keys = {i.key for i in fixed}
    items = [r for r in output.get("items", []) if r.get("key") not in keys]
    for i in fixed:
        if i.kind == ASSUMPTION:
            items.append({"key": i.key, "status": "assumed", "citations": [],
                          "reason": f"전제(소스로 확인할 수 없는 운영 환경 조건, 판정 조건 아님): {i.question}"})
        elif sources:
            items.append({"key": i.key, "status": "met",
                          "citations": [{"evidence_id": e, "quote": ""} for e in sources],
                          "reason": f"라이브러리 사실(권고문 기준 충족): {i.question}"})
        else:
            items.append({"key": i.key, "status": "unknown", "citations": [],
                          "reason": f"라이브러리 사실이지만 출처로 댈 권고문 근거가 없어 확인되지 않음: {i.question}"})
    return {**output, "items": items}


def checklist_text(checklist: Checklist, sources: list[str] = ()) -> str:
    rows = []
    for n, item in enumerate(checklist.items, 1):
        extra = []
        if item.symbols:
            extra.append("검색어: " + ", ".join(item.symbols))
        if item.config_keys:
            extra.append("설정 키: " + ", ".join(item.config_keys))
        if item.kind == LIBRARY_FACT:
            tag = ("라이브러리 사실 — 권고문 기준 충족으로 둠" + (f"(근거 {', '.join(sources)})" if sources
                                                     else "(권고문 근거 없음 → 확인되지 않음)")
                   + ", 저장소에서 확인하지 않음")
        elif item.kind == ASSUMPTION:
            tag = "전제 — 소스로 확인할 수 없는 운영 환경 조건, 판정 조건 아님"
        else:
            tag = f"{item.kind}, {'필수' if item.required else '선택'}"
        rows.append(f"{n}. `{item.key}` ({tag}) {item.question}" + (f"\n   {' / '.join(extra)}" if extra else ""))
    entry = ", ".join(checklist.vulnerable_entry_points) or "(권고문에 없음)"
    return f"취약 진입점: {entry}\n" + "\n".join(rows)


def case_text(finding: Finding, checklist: Checklist, ws: Workspace, gathered: str, remaining: int) -> str:
    return "\n\n".join([
        "## 후보(조회·수집 단계가 정한 사실 — 바꾸지 않는다)", ws.facts(finding),
        "## 권고문 요약", f"{finding.vulnerability.title}\n{finding.vulnerability.description[:ws.settings.max_description_chars]}",
        "## 발생 조건 점검표", checklist_text(checklist, advisory_sources(finding, ws.store)),
        "## 미리 모은 증거", gathered,
        "## 파일 배포 범위", ws.scope_summary(),
        f"## 남은 도구 호출: {remaining}회",
    ])


def challenge(data: dict, finding: Finding, checklist: Checklist, ws: Workspace, settings: Settings,
              remaining: int, asked: set[str]) -> tuple[str, list[str], str] | None:
    """판단 유보 제출을 한 번 되돌려 보낼 사유(이름, 항목 키, 메시지). 사유마다 한 판정에 한 번만.

    - trace: 값 출처·호출 위치를 묻는 필수 항목이 unknown 인데 모델이 find_callers 와 값 출처 추적을
      하지 않았다(도구 호출이 남아 있을 때만).
    - fixed_only: 서비스 쪽 필수 항목이 모두 충족인데 유보했다. 라이브러리 사실·전제는 유보 사유가 아니다.
    """
    v = data.get("verdict") or {}
    if v.get("state") != "undetermined":
        return None
    status = {i.get("key"): i.get("status") for i in v.get("items", [])}
    service = [i for i in checklist.items if is_service_condition(i)]
    open_items = [i for i in service if status.get(i.key) not in ("met", "not_met")]
    trace = [i.key for i in open_items if i.kind in settings.trace_kinds]
    callers = ws.model_tools.get("find_callers", 0)
    origin = ws.model_tools.get("search_symbol", 0) + ws.model_tools.get("read_lines", 0)
    if "trace" not in asked and trace and remaining > 0 and (callers < 1 or origin < 1):
        need = (["find_callers(호출 위치, 처리기, 요청 입력 전달 여부)"] if callers < 1 else []) + \
               (["값 출처 추적(그 호출에 넘기는 값을 만드는 변수·필드·함수 이름을 search_symbol 로 찾거나, "
                 "read_lines 로 호출부 앞뒤를 읽기)"] if origin < 1 else [])
        return "trace", trace, (
            f"## 판단 유보 전 추적 필요\n필수 항목 {', '.join(trace)} 는 값이 외부 입력에서 오는지·어디서 호출되는지를 "
            f"묻는데 아직 unknown 이다. 아직 하지 않은 추적: {'; '.join(need)}. 이 추적 없이 판단 유보로 닫지 않는다. "
            f"action=tool 로 요청하라.\n\n## 남은 도구 호출: {remaining}회")
    if ("fixed_only" not in asked and service and not open_items and finding.version_in_range is True
            and all(status.get(i.key) == "met" for i in service)):
        keys = [i.key for i in service]
        return "fixed_only", keys, (
            f"## 판단 유보 재확인\n서비스 쪽 필수 항목({', '.join(keys)})이 모두 충족(met)이다. 라이브러리 사실 항목은 "
            "권고문 기준으로 이미 충족이고, 전제 항목은 판정 조건이 아니므로 둘 다 판단 유보 사유가 아니다. "
            "다른 규칙(버전 계산 불가, 배포 여부가 unknown 인 파일만 근거 등)에 걸리지 않으면 affected 로 다시 판정하라. "
            "걸리면 그 사유를 rationale_ko 와 missing_info 에 적고 유보를 유지하라."
            + (f"\n\n## 남은 도구 호출: {remaining}회" if remaining > 0 else " 도구는 더 쓸 수 없다(action=final)."))
    return None


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
        prompt: Prompt, case: str, budget: int | None = None) -> Outcome:
    messages = [{"role": "system", "content": prompt.text}, {"role": "user", "content": case}]
    remaining = settings.max_tool_calls if budget is None else budget
    outcome = Outcome(None, client.model, messages)
    asked: set[str] = set()
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
        again = challenge(data, finding, checklist, ws, settings, remaining, asked)
        if again:
            reason, keys, message = again
            asked.add(reason)
            if ws.log:
                ws.log("judge", "challenge", subject=finding.key, reason=reason, items=keys, remaining=remaining)
            messages.append({"role": "user", "content": message})
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
