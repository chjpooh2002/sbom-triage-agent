"""판정 단계 전체 흐름.

1) 결정적 선판정(모델 호출 없음): 범위 밖 → not_affected, 미배포 → not_affected
2) 점검표 → 3) 증거 수집·판정 → 4) 검증(1회 재요청 후 강등) → 5) 승급 → 6) 설명·작업 요청
"""
from __future__ import annotations

import json
import re
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from triage.evidence import EvidenceStore, build_import_graph
from triage.models import (Anomaly, Checklist, Evidence, Finding, ItemResult, MissingInfo, SourceFileScope,
                           Verdict)

from . import decide, escalate, explain, verify
from .checklist import build_checklist
from .client import LLMClient, load_prompt
from .settings import Settings, load_settings
from .workspace import Workspace

_ID = re.compile(r"\b[A-Za-z][\w]*(?:-[A-Za-z_]\w*)*-\d{4}\b")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _lookup_ids(f: Finding) -> list[str]:
    return list(f.hints.get("evidence_ids", []))


def pre_rule(f: Finding) -> Verdict | None:
    """모델 없이 정해지는 판정. 근거는 조회(lookup)·수집·배포 단계의 근거 ID를 그대로 가리킨다."""
    c, v = f.component, f.vulnerability
    if f.version_in_range is False:
        ids = _lookup_ids(f)
        ranges = "; ".join(v.affected_ranges[-3:]) or ("수정 버전 " + ", ".join(v.fixed_versions))
        return Verdict(state="not_affected", justification="code_not_present", decided_by="rule:out_of_range",
                       item_results=[ItemResult(item_key="version_in_range", status="not_met", evidence_ids=ids,
                                                reason="조회 데이터로 계산한 설치 버전이 영향 범위 밖")],
                       rationale_ko=f"조회 데이터 기준 설치 버전 {c.version}은(는) 영향 범위({ranges}) 밖이다"
                                    f" (근거 {', '.join(ids) or '없음'}).",
                       attempts=0, decided_at=now())
    if c.deployed == "no":
        ids = list(c.evidence_ids)
        return Verdict(state="not_affected", justification="code_not_present", decided_by="rule:not_deployed",
                       item_results=[ItemResult(item_key="deployed", status="not_met", evidence_ids=ids,
                                                reason=c.deployed_reason)],
                       rationale_ko=f"배포 결과물에 포함되지 않는다: {c.deployed_reason or '사유 없음'}"
                                    f" (근거 {', '.join(ids) or '없음'}).",
                       attempts=0, decided_at=now())
    return None


def baseline(f: Finding) -> Verdict:
    """SBOMTRIAGE_JUDGE=off: 코드를 보지 않고 버전 일치만으로 정하는 스캐너식 기준선(비교 실험용)."""
    ids = _lookup_ids(f)
    if f.version_in_range:
        return Verdict(state="affected", decided_by="rule:version_match",
                       item_results=[ItemResult(item_key="version_in_range", status="met", evidence_ids=ids)],
                       rationale_ko=f"판정 단계 꺼짐: 조회 데이터상 버전이 영향 범위 안이라 영향 있음으로 둔다 (근거 {', '.join(ids)}).",
                       attempts=0, decided_at=now())
    return Verdict(state="undetermined", decided_by="rule:version_unknown",
                   item_results=[ItemResult(item_key="version_in_range", status="unknown", evidence_ids=ids)],
                   rationale_ko="판정 단계 꺼짐: 설치 버전의 영향 범위 여부를 계산할 수 없다.",
                   missing_info=[MissingInfo(what="정확한 설치 버전(패치 버전까지)",
                                             where=", ".join(f.component.sources) or "빌드·배포 설정")],
                   attempts=0, decided_at=now())


def unavailable(f: Finding, reason: str, checklist: Checklist | None = None) -> Verdict:
    items = checklist.items if checklist else []
    missing = [MissingInfo(what=i.question, where="애플리케이션 코드(배포 대상 파일)") for i in items if i.required]
    return Verdict(state="undetermined", decided_by="fallback", rationale_ko=f"모델 판정을 얻지 못해 판단 유보: {reason}",
                   missing_info=missing or [MissingInfo(what="취약 기능의 코드 사용 여부",
                                                        where="애플리케이션 코드 또는 담당 개발자")],
                   verifier_notes=[reason], attempts=0)


def demote(f: Finding, checklist: Checklist, output: dict | None, notes: list[str], attempts: int) -> Verdict:
    """검증을 두 번 통과하지 못한 판정은 판단 유보로 내리고, 무엇을 확인해야 하는지 남긴다."""
    base = decide.to_verdict(output, checklist, "fallback", attempts) if output else Verdict(state="undetermined")
    missing = list(base.missing_info)
    if not missing:
        done = {r.item_key for r in base.item_results if r.status in ("met", "not_met")}
        missing = [MissingInfo(what=i.question, where="애플리케이션 코드(배포 대상 파일)")
                   for i in checklist.items if i.required and i.key not in done] or \
                  [MissingInfo(what=i.question, where="애플리케이션 코드(배포 대상 파일)") for i in checklist.items[:2]]
    return Verdict(state="undetermined", decided_by="fallback", item_results=base.item_results,
                   rationale_ko="모델 판정이 근거 검증을 통과하지 못해 판단 유보로 둔다. " + "; ".join(notes[:3]),
                   missing_info=missing, verifier_notes=[*notes, "검증 2회 실패로 판단 유보로 강등"],
                   attempts=attempts)


class _Run:
    def __init__(self, root: Path, files: list[SourceFileScope], base: list[Evidence], graph: dict,
                 settings: Settings, client: LLMClient | None, escalate_client: LLMClient | None, log):
        self.root, self.files, self.base, self.graph = root, files, base, graph
        self.settings, self.client, self.escalate_client, self.log = settings, client, escalate_client, log
        self.scope = {Path(f.path).as_posix(): f for f in files}

    def emit(self, event: str, **data) -> None:
        if self.log:
            self.log("judge", event, **data)

    def judge(self, f: Finding) -> tuple[Verdict, Workspace, list[Anomaly]]:
        ws = Workspace(self.root, self.files, self.base, self.settings, self.log, subject=f.key)
        try:
            verdict, extra = self._judge(f, ws)
        except Exception as e:  # 한 건의 예기치 못한 오류가 전체 실행을 멈추지 않게 한다
            self.emit("error", subject=f.key, error=type(e).__name__, trace=traceback.format_exc(limit=4)[-1500:])
            verdict, extra = unavailable(f, f"판정 중 오류({type(e).__name__})", ws.checklist), []
        if not verdict.decided_at:
            verdict.decided_at = now()
        # 강등·검증 꺼짐 판정에도 없는 근거 ID가 보고서로 새지 않게 한다
        dropped = 0
        for r in verdict.item_results:
            keep = [e for e in r.evidence_ids if ws.exists(e)]
            dropped += len(r.evidence_ids) - len(keep)
            r.evidence_ids = keep
        if dropped:
            verdict.verifier_notes.append(f"존재하지 않는 근거 ID {dropped}개를 판정 기록에서 제거")
        # 6) 설명: 판정이 끝난 뒤 붙이는 표현 단계(판정 결과를 바꾸지 않는다)
        verdict.plain_ko = explain.plain_sentence(f, verdict, self.settings)
        if verdict.state == "undetermined" and verdict.work_request is None:
            try:
                verdict.work_request = explain.work_request(f, verdict, ws.checklist, self.client, self.log)
            except Exception as e:  # 요청서 문구 실패는 템플릿으로 대체
                self.emit("explain.error", subject=f.key, error=type(e).__name__)
                verdict.work_request = explain.template_request(f, verdict, explain.team_for(verdict, ws.checklist))
        return verdict, ws, [*ws.anomalies.values(), *extra]

    def _judge(self, f: Finding, ws: Workspace) -> tuple[Verdict, list[Anomaly]]:
        s = self.settings
        if self.client is None:
            return unavailable(f, "모델 미설정(SBOMTRIAGE_MODEL·OPENAI_API_KEY)"), []
        checklist = build_checklist(f, self.client, s, self.log)
        ws.checklist = checklist
        gathered = ws.gather(f, checklist, self.graph)
        prompt = load_prompt("decide")
        case = decide.case_text(f, checklist, ws, gathered, s.max_tool_calls)
        outcome = decide.run(f, checklist, ws, self.client, s, prompt, case)
        notes = [f"점검표 대체: {checklist.cache_key}"] if checklist.model == "fallback" else []
        verdict = self._settle(f, checklist, ws, outcome, prompt, notes)

        ok, why = escalate.eligible(verdict, ws, s, self.escalate_client)
        self.emit("escalate.check", subject=f.key, eligible=ok, reason=why)
        if ok:
            up = escalate.run(outcome, verdict, self.escalate_client, prompt, case, f.key)
            violations = (verify.check(up.output, finding=f, checklist=checklist, store=ws.store, scope=self.scope)
                          if up.output is not None and s.verify else [])
            if up.output is not None and not violations and up.output.get("state") != "undetermined":
                promoted = decide.to_verdict(up.output, checklist, f"model:{up.model}", verdict.attempts + 1)
                promoted.escalated = True
                promoted.verifier_notes = [*verdict.verifier_notes, f"승급 모델이 판단 유보를 {promoted.state}로 바꿈"]
                verdict, outcome = promoted, up
            else:
                reason = up.error or ("; ".join(map(str, violations[:3])) or "승급 모델도 판단 유보")
                verdict.escalated = True
                verdict.verifier_notes.append(f"승급 판정 미채택: {reason}")
        verdict.decided_at = now()
        return verdict, self._suspicious(outcome, ws)

    def _settle(self, f, checklist, ws, outcome, prompt, notes) -> Verdict:
        """검증 → 1회 재요청 → 강등."""
        s = self.settings
        if outcome.output is None:
            reason = f"모델 거절: {outcome.error}" if outcome.refused else f"모델 호출 실패: {outcome.error}"
            return unavailable(f, reason, checklist)
        if not s.verify:
            v = decide.to_verdict(outcome.output, checklist, f"model:{outcome.model}", outcome.submissions)
            v.verifier_notes = [*notes, "검증 단계 꺼짐(SBOMTRIAGE_VERIFY=off)"]
            return v
        violations = verify.check(outcome.output, finding=f, checklist=checklist, store=ws.store, scope=self.scope)
        self.emit("verify", subject=f.key, submission=1, violations=[str(v) for v in violations])
        if not violations:
            v = decide.to_verdict(outcome.output, checklist, f"model:{outcome.model}", outcome.submissions)
            v.verifier_notes = notes
            return v
        first = [str(v) for v in violations]
        retry = decide.resubmit(outcome, verify.retry_message(violations), self.client, prompt, f.key)
        outcome.messages, outcome.submissions = retry.messages, retry.submissions
        if retry.output is None:
            outcome.output = None
            return demote(f, checklist, None, [*notes, *first, f"재요청 실패: {retry.error}"], retry.submissions)
        outcome.output = retry.output
        again = verify.check(retry.output, finding=f, checklist=checklist, store=ws.store, scope=self.scope)
        self.emit("verify", subject=f.key, submission=2, violations=[str(v) for v in again])
        if not again:
            v = decide.to_verdict(retry.output, checklist, f"model:{retry.model}", retry.submissions)
            v.verifier_notes = [*notes, "1차 검증 위반 후 재요청으로 통과: " + "; ".join(first)]
            return v
        return demote(f, checklist, retry.output, [*notes, *first, *[str(v) for v in again]], retry.submissions)

    def _suspicious(self, outcome, ws: Workspace) -> list[Anomaly]:
        out = []
        for item in ((outcome.output or {}).get("suspicious_comments") or []):
            eid = item.get("evidence_id", "")
            try:
                e = ws.store.get(eid)
            except KeyError:
                continue
            key = (e.file, e.line_start)
            if not any(a.evidence_ids == [eid] for a in ws.anomalies.values()) and key not in ws.anomalies:
                out.append(Anomaly(kind="instruction_like_comment", evidence_ids=[eid],
                                   message=f"{e.file}:{e.line_start} 모델이 판정 지시처럼 보인다고 보고한 문구: "
                                           f"{item.get('text', '')[:160]}"))
        return out


def _publish(items: list[Evidence], store: EvidenceStore, seen: dict[tuple, str], out: list[Evidence]) -> dict[str, str]:
    """후보 전용 근거를 실행 저장소로 옮기며 ID를 다시 매긴다. 같은 내용은 같은 ID로 합친다."""
    mapping: dict[str, str] = {}
    for e in items:
        if e.id in mapping:
            continue
        sig = (e.kind, e.file, e.line_start, e.line_end, e.snippet, e.url, e.command, e.note)
        if sig not in seen:
            g = store.add(e.id.rsplit("-", 1)[0], **e.model_dump(exclude={"id"}))
            seen[sig] = g.id
            out.append(g)
        mapping[e.id] = seen[sig]
    return mapping


def _rewrite(model, mapping: dict[str, str]):
    if not mapping or all(k == v for k, v in mapping.items()):
        return model
    text = json.dumps(model.model_dump(mode="json"), ensure_ascii=False)
    text = _ID.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)
    return type(model).model_validate(json.loads(text))


def judge_all(findings: list[Finding], evidence: list[Evidence], files: list[SourceFileScope], root,
              log=None, *, anomalies: list[Anomaly] | None = None, settings: Settings | None = None,
              client: LLMClient | None = None, escalate_client: LLMClient | None = None,
              usage=None) -> list[Finding]:
    """후보마다 Finding.verdict 를 채운 사본을 돌려준다.

    - 판정 중 새로 만든 근거 가운데 판정·이상 기록이 가리키는 것을 ``evidence`` 목록 끝에 덧붙인다
      (판정이 가리키는 ID가 모두 그 안에 있도록).
    - 판정 지시처럼 보이는 주석은 ``anomalies`` 목록(주어지면)에 덧붙인다.
    - ``log`` 는 ``log(stage, event, **data)``. RunLog.emit 을 넘기면 토큰 사용량도 같은 RunLog 에 합산한다.
    """
    s = settings or load_settings()
    root = Path(root).resolve()
    files = list(files)
    emit = (lambda event, **d: log("judge", event, **d)) if log else (lambda event, **d: None)
    store = EvidenceStore(root)
    store.merge(evidence)
    results: dict[int, Finding] = {}
    pending: list[int] = []
    for i, f in enumerate(findings):
        v = pre_rule(f)
        if v is None and not s.judge:
            v = baseline(f)
        if v is None:
            pending.append(i)
            continue
        v.plain_ko = explain.template_plain(f, v)
        if v.state == "undetermined":
            v.work_request = explain.template_request(f, v, explain.team_for(v, None))
        results[i] = f.model_copy(update={"verdict": v})

    if pending:
        if client is None:
            client = LLMClient.from_env(s, s.model, log=log, usage=usage)
        if escalate_client is None and s.escalate and s.escalate_model and s.escalate_model != s.model:
            escalate_client = LLMClient.from_env(s, s.escalate_model, log=log, usage=usage)
    emit("start", findings=len(findings), rule_decided=len(results), pending=len(pending),
         model=client.model if client else "", escalate_model=escalate_client.model if escalate_client else "",
         switches={"judge": s.judge, "verify": s.verify, "escalate": s.escalate})

    new_evidence: list[Evidence] = []
    found: list[Anomaly] = []
    import_ev: list[Evidence] = []
    if pending:
        graph, import_ev = build_import_graph(root, files, store=store)
        base = [*{e.id: e for e in evidence}.values(), *import_ev]
        run = _Run(root, files, base, graph, s, client, escalate_client, log)
        with ThreadPoolExecutor(max_workers=max(1, s.workers)) as pool:
            jobs = {i: pool.submit(run.judge, findings[i]) for i in pending}
        seen = {(e.kind, e.file, e.line_start, e.line_end, e.snippet, e.url, e.command, e.note): e.id for e in base}
        for i in pending:
            verdict, ws, local = jobs[i].result()
            mapping = _publish(ws.new, store, seen, new_evidence)
            verdict = _rewrite(verdict, mapping)
            found += [_rewrite(a, mapping) for a in local]
            if any(k != v for k, v in mapping.items()):
                emit("evidence.renumber", subject=findings[i].key,
                     mapping={k: v for k, v in mapping.items() if k != v})
            results[i] = findings[i].model_copy(update={"verdict": verdict})

    for i in sorted(results):
        f, v = results[i], results[i].verdict
        emit("verdict", subject=f.key, vuln=f.vulnerability.id, component=f.component.id, state=v.state,
             justification=v.justification, decided_by=v.decided_by, decided_at=v.decided_at, attempts=v.attempts,
             escalated=v.escalated, evidence_ids=[e for r in v.item_results for e in r.evidence_ids],
             verifier_notes=v.verifier_notes)
    unique = {(a.kind, a.message): a for a in found}
    found = list(unique.values())
    # 판정 중 만든 근거(검색 결과 등)는 양이 많으니 판정·이상 기록이 실제로 가리킨 것만 내보낸다.
    # 도구 호출과 결과 근거 ID는 실행 로그(judge.tool, evidence.renumber)에 그대로 남는다.
    cited = {e for f in results.values() for r in f.verdict.item_results for e in r.evidence_ids}
    cited |= {e for a in found for e in a.evidence_ids}
    texts = [t for f in results.values() for t in (f.verdict.rationale_ko, *f.verdict.verifier_notes,
                                                   *(m.what + " " + m.where for m in f.verdict.missing_info))]
    cited |= set(_ID.findall(" ".join(texts)))
    exported = [e for e in [*import_ev, *new_evidence] if e.id in cited]
    evidence.extend(exported)
    new_evidence = exported
    if anomalies is not None:
        anomalies.extend(found)
    states = {}
    for f in results.values():
        states[f.verdict.state] = states.get(f.verdict.state, 0) + 1
    emit("end", states=states, new_evidence=len(new_evidence), anomalies=len(found))
    return [results[i] for i in range(len(findings))]
