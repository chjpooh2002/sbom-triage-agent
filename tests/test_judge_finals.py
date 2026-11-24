"""L1 판정 에이전트. 모델은 가짜 전송 함수로 바꾸고, 검증기 규칙마다 하나씩 확인한다."""
import json
import re
from pathlib import Path

import pytest

from triage.evidence import EvidenceStore, read_lines, search_symbol
from triage.judge import judge_all, load_settings
from triage.judge.checklist import build_checklist
from triage.judge.client import LLMClient, ModelError, Raw, TransientError
from triage.judge.comments import quote_in_comment
from triage.judge.verify import check
from triage.models import (Checklist, Component, ConditionItem, Evidence, Finding, SourceFileScope,
                           Vulnerability)

ROOT = Path(__file__).parent / "fixtures/finals/judge"
APP, TEST = "app/handlers.py", "tests/handlers_check.py"
FILES = [SourceFileScope(path=APP, deployed="yes", category="app"),
         SourceFileScope(path=TEST, deployed="no", category="test"),
         SourceFileScope(path="requirements.txt", deployed="yes", category="app")]
SCOPE = {f.path: f for f in FILES}
CALL = "return xmlkit.parse_entities(body)"

CHECKLIST_JSON = {"vulnerable_entry_points": ["xmlkit.parse_entities"], "items": [
    {"key": "calls_parse", "kind": "api_use", "question": "parse_entities 를 호출하는가?",
     "symbols": ["xmlkit.parse_entities"], "config_keys": [], "required": True},
    {"key": "untrusted_input", "kind": "input_source", "question": "요청 입력이 그 호출에 닿는가?",
     "symbols": [], "config_keys": [], "required": True}]}
CHECKLIST = Checklist(vuln_id="VULN-TEST-1", items=[ConditionItem(**i) for i in CHECKLIST_JSON["items"]])


def finding(in_range=True, deployed="yes", fixed=("2.4.1",), severity="") -> Finding:
    c = Component(id="pkg:pypi/xmlkit@2.3.0", name="xmlkit", version="2.3.0", ecosystem="pypi",
                  deployed=deployed, deployed_reason="테스트", evidence_ids=["collect-0001"])
    v = Vulnerability(id="VULN-TEST-1", title="엔티티 해석", description="parse_entities 가 외부 엔티티를 해석한다.",
                      fixed_versions=list(fixed), affected_ranges=["<2.4.1"], severity=severity)
    return Finding(key=Finding.make_key(v.id, c.id, None), component=c, vulnerability=v,
                   version_in_range=in_range, hints={"evidence_ids": ["lookup-0001"]})


def base_evidence() -> list[Evidence]:
    return [Evidence(id="collect-0001", kind="manifest", file="requirements.txt", line_start=1, line_end=1,
                     snippet="xmlkit==2.3.0"),
            Evidence(id="lookup-0001", kind="advisory", url="https://example.invalid/advisory", note="권고문")]


@pytest.fixture
def store():
    s = EvidenceStore(ROOT)
    s.merge(base_evidence())
    return s


def ids(store):
    hits, ev = search_symbol(ROOT, FILES, "xmlkit.parse_entities", store=store)
    by_file = {h["file"]: h["evidence_ids"][0] for h in hits}
    comment, _ = read_lines(ROOT, FILES, APP, 6, 6, store=store)
    return by_file[APP], by_file[TEST], comment["evidence_ids"][0]


def item(key, status, *cites):
    return {"key": key, "status": status, "reason": "",
            "citations": [{"evidence_id": e, "quote": q} for e, q in cites]}


def verdict(state="affected", items=(), fix="2.4.1", missing=(), just=""):
    return {"state": state, "justification": just, "items": list(items), "rationale_ko": "근거로 판단",
            "plain_ko": "한 문장.", "fix_version": fix, "missing_info": [{"what": m, "where": "운영 설정"} for m in missing],
            "suspicious_comments": []}


def rules(output, f=None, st=None):
    return {v.rule for v in check(output, finding=f or finding(), checklist=CHECKLIST, store=st, scope=SCOPE)}


def good(app):
    return verdict(items=[item("calls_parse", "met", (app, CALL)), item("untrusted_input", "met", (app, CALL))])


# ───────────────────────── 검증기 규칙마다 하나씩 ─────────────────────────

def test_valid_output_passes(store):
    app, _, _ = ids(store)
    assert rules(good(app), st=store) == set()


def test_evidence_not_found(store):
    out = verdict(items=[item("calls_parse", "met", ("search-9999", CALL)), item("untrusted_input", "met", ("x-0001", ""))])
    assert "evidence_not_found" in rules(out, st=store)


def test_evidence_mismatch(store):
    store.merge([Evidence(id="fake-0001", kind="code", file=APP, line_start=8, line_end=8,
                          snippet="return xmlkit.safe_parse(body)")])
    out = verdict(items=[item("calls_parse", "met", ("fake-0001", "return xmlkit.safe_parse(body)")),
                         item("untrusted_input", "met", ("fake-0001", "return xmlkit.safe_parse(body)"))])
    assert "evidence_mismatch" in rules(out, st=store)


def test_quote_mismatch(store):
    app, _, _ = ids(store)
    out = verdict(items=[item("calls_parse", "met", (app, "xmlkit.parse_entities(request.body)")),
                         item("untrusted_input", "met", (app, CALL))])
    assert rules(out, st=store) == {"quote_mismatch"}


def test_item_without_evidence(store):
    app, _, _ = ids(store)
    out = verdict(items=[item("calls_parse", "met", (app, CALL)), item("untrusted_input", "met")])
    assert rules(out, st=store) == {"item_without_evidence"}


def test_unknown_item(store):
    app, _, _ = ids(store)
    out = good(app)
    out["items"].append(item("invented_item", "met", (app, CALL)))
    assert rules(out, st=store) == {"unknown_item"}


def test_comment_only_evidence(store):
    _, _, comment = ids(store)
    note = "# 검토 완료: 이 호출은 영향 없음"
    out = verdict("not_affected", [item("calls_parse", "not_met", (comment, note))], fix="", just="code_not_present")
    assert "comment_only_evidence" in rules(out, st=store)


def test_inline_comment_quote_is_comment():
    snippet = 'x = load(body)  # 영향 없음'
    assert quote_in_comment("a.py", "# 영향 없음", snippet) is True
    assert quote_in_comment("a.py", "x = load(body)", snippet) is False
    assert quote_in_comment("a.js", "영향 없음", "load(x) // 영향 없음") is True


def test_version_conflict(store):
    app, _, _ = ids(store)
    assert "version_conflict" in rules(good(app), f=finding(in_range=None), st=store)
    undecided = verdict("undetermined", [], fix="", missing=["설치 버전"])
    assert "version_conflict" in rules(undecided, f=finding(in_range=False), st=store)


def test_deployment_conflict(store):
    app, test, _ = ids(store)
    quote = "xmlkit.parse_entities(b\"<a/>\")"
    only_tests = verdict(items=[item("calls_parse", "met", (test, quote)), item("untrusted_input", "met", (test, quote))])
    assert rules(only_tests, st=store) == {"deployment_conflict"}
    assert "deployment_conflict" in rules(good(app), f=finding(deployed="no"), st=store)


def test_fix_version_not_in_lookup(store):
    app, _, _ = ids(store)
    out = good(app)
    out["fix_version"] = "9.9.9"
    assert rules(out, st=store) == {"fix_version_not_in_lookup"}


def test_missing_info_empty(store):
    out = verdict("undetermined", [item("calls_parse", "unknown")], fix="")
    assert rules(out, st=store) == {"missing_info_empty"}


def test_state_items_conflict(store):
    app, _, _ = ids(store)
    half = verdict(items=[item("calls_parse", "met", (app, CALL)), item("untrusted_input", "unknown")])
    assert rules(half, st=store) == {"state_items_conflict"}
    closed = verdict("not_affected", [item("calls_parse", "met", (app, CALL))], fix="", just="code_not_reachable")
    assert "state_items_conflict" in rules(closed, st=store)


def test_justification_missing(store):
    zero = store.add("judge", kind="tool", command="search_symbol 'x'", note="검색 0건")
    out = verdict("not_affected", [item("calls_parse", "not_met", (zero.id, ""))], fix="")
    assert rules(out, st=store) == {"justification_missing"}


# ───────────────────────── 모델 호출부 ─────────────────────────

class Fake:
    """schema 이름별로 정해 둔 응답을 돌려주는 가짜 전송 함수."""

    def __init__(self, decide=(), explain=None, checklist=None):
        self.decide = list(decide)
        self.explain = explain
        self.checklist = checklist or CHECKLIST_JSON
        self.calls = []

    def __call__(self, model, messages, schema, name):
        self.calls.append(name)
        usage = dict(prompt_tokens=10, completion_tokens=5, total_tokens=15, reasoning_tokens=3)
        if name == "checklist":
            return Raw(json.dumps(self.checklist), finish_reason="stop", usage=usage)
        if name == "work_request":
            return Raw(json.dumps(self.explain or {"title": "확인 요청", "body": "질문",
                                                   "branches": ["답이 예면 → 2.4.1 로 올림", "답이 아니오면 → 조치 불필요"]}),
                       finish_reason="stop", usage=usage)
        step = self.decide.pop(0)
        if step == "REFUSE":
            return Raw("", refusal="거절", finish_reason="stop", usage=usage)
        if isinstance(step, Exception):
            raise step
        body = step(messages) if callable(step) else step
        if "action" in body:                       # 도구 요청 등 단계 전체를 직접 준 경우
            return Raw(json.dumps(body), finish_reason="stop", usage=usage)
        return Raw(json.dumps({"action": "final", "tool_requests": [], "verdict": body}), finish_reason="stop", usage=usage)


def settings(tmp_path, **kw):
    kw.setdefault("workers", 1)
    kw.setdefault("escalate_model", "")   # 실제 승급 모델을 만들지 않게
    kw.setdefault("llm_cache", True)      # .env·환경변수와 무관하게 캐시 동작을 고정
    kw.setdefault("backoff_seconds", 0)
    return load_settings(cache_dir=tmp_path, **kw)


def client(tmp_path, fake, model="fake-small", log=None, usage=None, **kw):
    return LLMClient(model, fake, settings(tmp_path, **kw), log=log, usage=usage, sleep=lambda s: None)


def app_id(messages):
    text = "\n".join(m["content"] for m in messages)
    return re.search(r"\[(search-\d{4})\] app/handlers\.py:5-11", text).group(1)   # 호출 줄(8행) 주변


def test_client_cache_retry_refusal_and_usage(tmp_path):
    used = []
    fake = Fake([TransientError("timeout"), verdict("undetermined", missing=["x"], fix="")])
    c = client(tmp_path, fake, usage=lambda **u: used.append(u))
    args = dict(purpose="decide", prompt_version="p1", messages=[{"role": "user", "content": "hi"}],
                schema={"type": "object"}, schema_name="decision")
    first = c.complete(**args)
    second = c.complete(**args)
    assert first.data and second.cached and second.data == first.data
    assert fake.calls == ["decision", "decision"]           # 1회 실패 후 재시도, 두 번째 요청은 캐시
    assert used[0]["reasoning_tokens"] == 3 and used[1] == {"total_tokens": 0}

    refusing = client(tmp_path, Fake(["REFUSE", "REFUSE"]))
    args["messages"] = [{"role": "user", "content": "다른 요청"}]
    assert refusing.complete(**args).refused
    assert refusing.complete(**args).refused                # 거절은 캐시하지 않는다

    failing = client(tmp_path, Fake([TransientError("x")] * 3))
    args["messages"] = [{"role": "user", "content": "세 번째"}]
    with pytest.raises(ModelError):
        failing.complete(**args)


def test_checklist_disk_cache_by_vuln_id(tmp_path):
    fake = Fake()
    c = client(tmp_path, fake)
    first = build_checklist(finding(), c, c.settings)
    again = build_checklist(finding(), client(tmp_path, Fake()), c.settings)
    assert [i.key for i in first.items] == ["calls_parse", "untrusted_input"]
    assert again == first and fake.calls == ["checklist"]
    assert (tmp_path / "checklist" / "VULN-TEST-1.json").exists()


# ───────────────────────── 전체 흐름 ─────────────────────────

def run(tmp_path, fake, findings=None, escalate_fake=None, events=None, **kw):
    log = (lambda stage, event, **d: events.append((event, d))) if events is not None else None
    s = settings(tmp_path, **kw)
    evidence, anomalies = base_evidence(), []
    esc = LLMClient("fake-large", escalate_fake, s, sleep=lambda x: None) if escalate_fake else None
    out = judge_all(findings or [finding()], evidence, FILES, ROOT, log=log, anomalies=anomalies, settings=s,
                    client=LLMClient("fake-small", fake, s, sleep=lambda x: None), escalate_client=esc)
    return out, evidence, anomalies


def test_rules_decide_without_model(tmp_path):
    fake = Fake()
    out, _, _ = run(tmp_path, fake, [finding(in_range=False), finding(deployed="no")])
    assert [(f.verdict.state, f.verdict.decided_by) for f in out] == [
        ("not_affected", "rule:out_of_range"), ("not_affected", "rule:not_deployed")]
    assert fake.calls == []
    assert out[0].verdict.item_results[0].evidence_ids == ["lookup-0001"]
    assert all(f.verdict.decided_at and f.verdict.plain_ko for f in out)


def test_model_verdict_cites_real_evidence(tmp_path):
    fake = Fake([lambda m: good(app_id(m))])
    out, evidence, anomalies = run(tmp_path, fake)
    v = out[0].verdict
    assert (v.state, v.decided_by, v.attempts) == ("affected", "model:fake-small", 1)
    assert out[0].hints["judge_fix_version"] == "2.4.1"
    known = {e.id for e in evidence}
    assert {e for r in v.item_results for e in r.evidence_ids} <= known
    assert v.decided_at and v.plain_ko
    # 판정 지시처럼 보이는 주석은 근거가 아니라 이상 기록으로 남는다
    assert any(a.kind == "instruction_like_comment" and APP in a.message for a in anomalies)


def test_violation_retry_then_pass(tmp_path):
    bad = lambda m: verdict(items=[item("calls_parse", "met", (app_id(m), "지어낸 인용")),
                                   item("untrusted_input", "met", (app_id(m), CALL))])
    out, _, _ = run(tmp_path, Fake([bad, lambda m: good(app_id(m))]))
    v = out[0].verdict
    assert v.state == "affected" and v.attempts == 2
    assert any("quote_mismatch" in n for n in v.verifier_notes)


def test_two_violations_demote_to_undetermined(tmp_path):
    bad = lambda m: verdict(items=[item("calls_parse", "met", ("search-9999", CALL)),
                                   item("untrusted_input", "met", (app_id(m), CALL))])
    out, _, _ = run(tmp_path, Fake([bad, bad]), escalate=False)
    v = out[0].verdict
    assert (v.state, v.decided_by) == ("undetermined", "fallback")
    assert any("evidence_not_found" in n for n in v.verifier_notes) and any("강등" in n for n in v.verifier_notes)
    assert v.missing_info and v.work_request and v.work_request.to_team
    assert "search-9999" not in {e for r in v.item_results for e in r.evidence_ids}   # 없는 ID는 기록에서 제거


def test_refusal_becomes_undetermined(tmp_path):
    out, _, _ = run(tmp_path, Fake(["REFUSE"]), escalate=False)
    v = out[0].verdict
    assert v.state == "undetermined" and "모델 거절" in v.rationale_ko and v.missing_info


def test_judge_switch_off_is_version_baseline(tmp_path):
    fake = Fake()
    out, _, _ = run(tmp_path, fake, [finding(), finding(in_range=None)], judge=False)
    assert [(f.verdict.state, f.verdict.decided_by) for f in out] == [
        ("affected", "rule:version_match"), ("undetermined", "rule:version_unknown")]
    assert fake.calls == []


def test_verify_switch_off_accepts_unchecked_output(tmp_path):
    bad = lambda m: verdict(items=[item("calls_parse", "met", ("search-9999", CALL))])
    out, _, _ = run(tmp_path, Fake([bad]), verify=False)
    notes = out[0].verdict.verifier_notes
    assert out[0].verdict.state == "affected" and any("검증 단계 꺼짐" in n for n in notes)
    assert any("존재하지 않는 근거 ID 1개" in n for n in notes)


def test_escalate_only_when_undetermined_with_evidence(tmp_path):
    unsure = verdict("undetermined", [item("calls_parse", "unknown")], fix="", missing=["요청 입력 여부"])
    big = Fake([lambda m: good(app_id(m))])
    # 입력 출처 항목이 unknown 이라 한 번은 추적 요청으로 되돌아오고, 그래도 유보하면 받아들인다
    out, _, _ = run(tmp_path, Fake([unsure, unsure]), escalate_fake=big)
    v = out[0].verdict
    assert v.escalated and v.state == "affected" and v.decided_by == "model:fake-large"
    assert big.calls == ["decision"]

    off = Fake([lambda m: good(app_id(m))])
    out, _, _ = run(tmp_path / "off", Fake([unsure, unsure]), escalate_fake=off, escalate=False)
    assert out[0].verdict.state == "undetermined" and off.calls == []


def test_env_switches(monkeypatch):
    monkeypatch.setenv("SBOMTRIAGE_JUDGE", "off")
    monkeypatch.setenv("SBOMTRIAGE_VERIFY", "OFF")
    monkeypatch.setenv("SBOMTRIAGE_ESCALATE", "on")
    s = load_settings()
    assert (s.judge, s.verify, s.escalate) == (False, False, True)
    monkeypatch.setenv("SBOMTRIAGE_VERIFY", "maybe")
    with pytest.raises(ValueError):
        load_settings()


def test_code_after_docstring_is_not_comment(tmp_path):
    """근거 조각이 독스트링 중간에서 시작해도 닫는 따옴표 뒤 코드 줄은 코드로 본다."""
    files = [*FILES, SourceFileScope(path="app/client.py", deployed="yes", category="app")]
    store = EvidenceStore(ROOT)
    hit, _ = read_lines(ROOT, files, "app/client.py", 7, 10, store=store)
    eid = hit["evidence_ids"][0]
    out = verdict(items=[item("calls_parse", "met", (eid, "doc = xmlkit.parse_entities(body)")),
                         item("untrusted_input", "met", (eid, "doc = xmlkit.parse_entities(body)"))])
    scope = {f.path: f for f in files}
    assert "comment_only_evidence" not in {
        v.rule for v in check(out, finding=finding(), checklist=CHECKLIST, store=store, scope=scope)}
    docline = verdict("not_affected", [item("calls_parse", "not_met", (eid, "엔티티 해석 여부는 여기서 정하지 않는다."))],
                      fix="", just="code_not_present")
    assert "comment_only_evidence" in {
        v.rule for v in check(docline, finding=finding(), checklist=CHECKLIST, store=store, scope=scope)}


def test_only_cited_evidence_is_exported(tmp_path):
    out, evidence, anomalies = run(tmp_path, Fake([lambda m: good(app_id(m))]))
    exported = {e.id for e in evidence} - {e.id for e in base_evidence()}
    cited = {e for r in out[0].verdict.item_results for e in r.evidence_ids}
    cited |= {e for a in anomalies for e in a.evidence_ids}
    assert exported and exported <= cited


# ───────────────────────── 캐시 스위치·실행 집계·오류 기록 ─────────────────────────

ARGS = dict(purpose="decide", prompt_version="p1", messages=[{"role": "user", "content": "hi"}],
            schema={"type": "object"}, schema_name="decision")
SECRET = "C:/Users/someone/secret_config.py 게이트웨이 응답 본문 sk-hidden"


def cached_files(tmp_path):
    return sorted(p.name for p in tmp_path.rglob("*.json"))


def test_llm_cache_off_calls_model_every_time_and_writes_nothing(tmp_path):
    fake = Fake([verdict("undetermined", missing=["x"], fix="")] * 2)
    c = client(tmp_path, fake, llm_cache=False)
    first, second = c.complete(**ARGS), c.complete(**ARGS)
    assert first.data and second.data and not first.cached and not second.cached
    assert fake.calls == ["decision", "decision"]           # 같은 요청도 두 번 모두 전송
    assert cached_files(tmp_path) == []                       # 캐시 파일을 만들지 않는다
    assert c.counts["llm_calls"] == 2 and c.counts["cache_hits"] == 0


def test_checklist_cache_off_skips_disk_but_reuses_within_run(tmp_path):
    fake = Fake()
    c = client(tmp_path, fake, llm_cache=False)
    build_checklist(finding(), c, c.settings)
    build_checklist(finding(), c, c.settings)
    assert fake.calls == ["checklist", "checklist"]          # 디스크 캐시를 읽지 않는다
    assert cached_files(tmp_path) == []                       # 쓰지도 않는다
    memo = {}
    build_checklist(finding(), c, c.settings, memo=memo)
    build_checklist(finding(), c, c.settings, memo=memo)
    assert fake.calls == ["checklist"] * 3                    # 한 실행 안에서는 한 번만 만든다


def _end(events):
    return [d for e, d in events if e == "end"][-1]


def test_end_event_reports_calls_cache_hits_and_mode(tmp_path):
    runs = []
    for _ in range(2):
        events = []
        run(tmp_path / "on", Fake([lambda m: good(app_id(m))]), events=events)
        runs.append(_end(events))
    assert runs[0]["cache_mode"] == "on" and runs[0]["llm_calls"] == 2 and runs[0]["cache_hits"] == 0
    assert runs[1]["llm_calls"] == 0 and runs[1]["cache_hits"] == 2   # 두 번째는 점검표·판정 모두 캐시

    runs = []
    for _ in range(2):
        events = []
        run(tmp_path / "off", Fake([lambda m: good(app_id(m))]), events=events, llm_cache=False)
        runs.append(_end(events))
    assert [(r["cache_mode"], r["llm_calls"], r["cache_hits"]) for r in runs] == [("off", 2, 0), ("off", 2, 0)]
    assert cached_files(tmp_path / "off") == []
    assert {"llm_retries", "workers", "seconds"} <= set(runs[0])


def test_retry_waits_grow_exponentially(tmp_path):
    events, waits = [], []
    s = settings(tmp_path, backoff_seconds=1.0, max_attempts=3)
    fake = Fake([TransientError("x", status=429), TransientError("x", status=503),
                 verdict("undetermined", missing=["x"], fix="")])
    c = LLMClient("fake-small", fake, s, log=lambda st, ev, **d: events.append((ev, d)), sleep=waits.append)
    assert c.complete(**ARGS).data
    assert waits == [1.0, 2.0]
    retries = [d for e, d in events if e == "llm.retry"]
    assert [(r["status"], r["wait_seconds"]) for r in retries] == [(429, 1.0), (503, 2.0)]
    assert c.counts["retries"] == 2


def test_error_events_keep_type_and_location_not_message(tmp_path):
    events = []
    log = lambda st, ev, **d: events.append((ev, d))
    c = client(tmp_path, Fake([ModelError(SECRET, status=400)]), log=log)
    with pytest.raises(ModelError) as raised:
        c.complete(**ARGS)
    assert SECRET not in str(raised.value)                    # 판정 기록으로 넘어가는 문구도 안전하게
    t = client(tmp_path, Fake([TransientError(SECRET, status=502)] * 3), log=log)
    with pytest.raises(ModelError):
        t.complete(**{**ARGS, "messages": [{"role": "user", "content": "other"}]})

    error = [d for e, d in events if e == "llm.error"][0]
    assert (error["error"], error["status"]) == ("ModelError", 400) and re.search(r":\d+$", error["where"])
    assert [d["status"] for e, d in events if e == "llm.retry"] == [502, 502, 502]

    # 판정 중 예기치 못한 오류(전체 흐름): 예외 종류와 발생 위치(모듈:줄)만 남는다
    out, _, _ = run(tmp_path / "flow", Fake([RuntimeError(SECRET)]), events=events, escalate=False)
    crash = [d for e, d in events if e == "error"][0]
    assert crash["error"] == "RuntimeError" and re.search(r"^[\w.]+:\d+$", crash["where"])
    assert "trace" not in crash
    assert out[0].verdict.state == "undetermined"
    assert SECRET not in json.dumps(events, ensure_ascii=False, default=str)
    assert SECRET not in out[0].verdict.model_dump_json()


def test_workers_and_cache_env(monkeypatch):
    monkeypatch.setenv("SBOMTRIAGE_JUDGE_WORKERS", "12")
    monkeypatch.setenv("SBOMTRIAGE_LLM_CACHE", "off")
    s = load_settings()
    assert (s.workers, s.llm_cache) == (12, False)
    for bad in ("0", "abc", "-3"):
        monkeypatch.setenv("SBOMTRIAGE_JUDGE_WORKERS", bad)
        with pytest.raises(ValueError):
            load_settings()


def test_progress_event_after_each_finding(tmp_path):
    """규칙 판정 1건 + 모델 판정 2건(작업 스레드 3개). 실제 실행 로그와 on_event 콜백을 거쳐도 멈추지 않는다."""
    from triage.output import RunLog

    seen = []
    runlog = RunLog(tmp_path / "log.jsonl", on_event=seen.append)
    s = settings(tmp_path, workers=3)
    fake = Fake([lambda m: good(app_id(m))] * 3)
    judge_all([finding(), finding(in_range=False), finding()], base_evidence(), FILES, ROOT, log=runlog.emit,
              settings=s, client=LLMClient("fake-small", fake, s, sleep=lambda x: None))
    runlog.close(status="ok")

    judge = [r for r in seen if r["stage"] == "judge"]
    progress = [r["data"] for r in judge if r["event"] == "progress"]
    assert [p["done"] for p in progress] == [1, 2, 3] and {p["total"] for p in progress} == {3}
    order = [r["event"] for r in judge]
    first = order.index("progress")
    last = len(order) - 1 - order[::-1].index("progress")
    assert order.index("start") < first and last < order.index("end")


# ───────────────────────── 판정 품질 원칙(라이브러리 사실·전제·유보 전 추적) ─────────────────────────

FIXED_KINDS = ("library_fact", "assumption")
QUALITY_JSON = {"vulnerable_entry_points": ["xmlkit.parse_entities"], "items": [
    *CHECKLIST_JSON["items"],
    {"key": "default_resolves_external", "kind": "library_fact",
     "question": "영향 버전의 parse_entities 는 옵션을 생략하면 외부 엔티티를 해석하는가?",
     "symbols": [], "config_keys": [], "required": True},
    {"key": "attacker_reaches_service", "kind": "assumption",
     "question": "공격자가 이 서비스에 요청을 보낼 수 있는 네트워크 위치에 있는가?",
     "symbols": [], "config_keys": [], "required": True}]}
BLANK_TOOL = {"tool": "", "symbol": "", "path": "", "start": 0, "end": 0, "key": "", "why": ""}


def tool_step(*requests):
    return {"action": "tool", "tool_requests": [{**BLANK_TOOL, **r} for r in requests],
            "verdict": verdict("undetermined", fix="")}


def unsure_input(m):
    """호출은 확인했지만 입력 출처(input_source)를 모른다며 유보."""
    return verdict("undetermined", [item("calls_parse", "met", (app_id(m), CALL)), item("untrusted_input", "unknown")],
                   fix="", missing=["요청 입력이 호출에 닿는지"])


def test_checklist_splits_library_facts_and_assumptions(tmp_path):
    from triage.judge.checklist import normalize, schema

    assert set(FIXED_KINDS) <= set(schema()["properties"]["items"]["items"]["properties"]["kind"]["enum"])
    s = settings(tmp_path)
    cl, _ = normalize(QUALITY_JSON, finding(), s, "m", "k")
    kinds = {i.key: (i.kind, i.required) for i in cl.items}
    assert kinds["default_resolves_external"] == ("library_fact", True)
    assert kinds["attacker_reaches_service"] == ("assumption", False)   # 운영 환경 전제는 필수 조건이 아니다
    # 서비스 쪽 필수 조건이 하나도 없으면 패키지 사용 여부를 필수로 넣는다(권고문만으로 영향 있음이 되지 않게)
    only = {"vulnerable_entry_points": [], "items": QUALITY_JSON["items"][2:]}
    cl, _ = normalize(only, finding(), s, "m", "k")
    service = [i for i in cl.items if i.required and i.kind not in FIXED_KINDS]
    assert [i.kind for i in service] == ["api_use"] and service[0].symbols


def test_library_fact_is_met_by_advisory_and_assumption_is_premise(tmp_path):
    seen = []

    def decide_step(m):
        seen.append(m[1]["content"])
        out = good(app_id(m))
        # 모델이 라이브러리 사실·전제를 unknown 으로 적어도 규칙이 덮어쓴다
        out["items"] += [item("default_resolves_external", "unknown"), item("attacker_reaches_service", "unknown")]
        return out

    out, _, _ = run(tmp_path, Fake([decide_step], checklist=QUALITY_JSON), escalate=False)
    v = out[0].verdict
    assert (v.state, v.decided_by, v.attempts) == ("affected", "model:fake-small", 1)
    by = {r.item_key: r for r in v.item_results}
    assert by["default_resolves_external"].status == "met"
    assert by["default_resolves_external"].evidence_ids == ["lookup-0001"]   # 권고문 링크가 근거
    assert by["attacker_reaches_service"].status == "assumed"
    assert not by["attacker_reaches_service"].evidence_ids and "전제" in by["attacker_reaches_service"].reason
    assert "라이브러리 사실" in seen[0] and "전제" in seen[0]                 # 판정 요청에도 구분해 보여 준다


def test_library_fact_without_advisory_source_stays_unknown():
    from triage.judge.decide import fill_fixed

    cl = Checklist(vuln_id="V", items=[ConditionItem(**i) for i in QUALITY_JSON["items"]])
    out = fill_fixed(verdict("undetermined", missing=["x"], fix=""), cl, [])
    by = {i["key"]: i for i in out["items"]}
    assert by["default_resolves_external"]["status"] == "unknown" and not by["default_resolves_external"]["citations"]
    assert by["attacker_reaches_service"]["status"] == "assumed"


def test_undetermined_only_on_facts_or_premises_is_asked_again(tmp_path):
    asked = []
    hold = lambda m: verdict("undetermined", good(app_id(m))["items"], fix="", missing=["운영 네트워크 위치"])

    def second(m):
        asked.append(m[-1]["content"])
        return good(app_id(m))

    fake = Fake([hold, second], checklist=QUALITY_JSON)
    out, _, _ = run(tmp_path, fake, escalate=False)
    assert out[0].verdict.state == "affected" and fake.calls.count("decision") == 2
    assert "전제" in asked[0] and "라이브러리 사실" in asked[0]


def test_unavailable_asks_only_service_side_conditions():
    from triage.judge.agent import unavailable

    cl = Checklist(vuln_id="V", items=[ConditionItem(**i) for i in QUALITY_JSON["items"]])
    whats = {m.what for m in unavailable(finding(), "x", cl).missing_info}
    assert whats == {i["question"] for i in CHECKLIST_JSON["items"]}


def test_undetermined_on_input_source_requires_trace_first(tmp_path):
    asked, events = [], []

    def trace(m):
        asked.append(m[-1]["content"])
        return tool_step({"tool": "find_callers", "symbol": "xmlkit.parse_entities"},
                         {"tool": "search_symbol", "symbol": "body"})

    fake = Fake([unsure_input, trace, lambda m: good(app_id(m))])
    out, _, _ = run(tmp_path, fake, events=events, escalate=False)
    assert out[0].verdict.state == "affected" and fake.calls.count("decision") == 3
    assert "untrusted_input" in asked[0] and "find_callers" in asked[0]
    assert any(e == "challenge" and d["reason"] == "trace" for e, d in events)


def test_traced_or_budgetless_undetermined_is_accepted(tmp_path):
    first = tool_step({"tool": "find_callers", "symbol": "upload"}, {"tool": "read_lines", "path": APP, "start": 5, "end": 9})
    fake = Fake([first, unsure_input])
    out, _, _ = run(tmp_path, fake, escalate=False)
    assert out[0].verdict.state == "undetermined" and fake.calls.count("decision") == 2

    none_left = Fake([unsure_input])
    out, _, _ = run(tmp_path / "zero", none_left, escalate=False, max_tool_calls=0)
    assert out[0].verdict.state == "undetermined" and none_left.calls.count("decision") == 1


def test_high_severity_gets_larger_tool_budget(tmp_path):
    seen = []

    def step(m):
        seen.append(m[1]["content"])
        return good(app_id(m))

    s = settings(tmp_path)
    assert s.max_tool_calls_by_severity["high"] > s.max_tool_calls
    run(tmp_path, Fake([step, step]), [finding(severity="high"), finding(severity="medium")], escalate=False)
    budgets = sorted(int(re.search(r"남은 도구 호출: (\d+)회", t).group(1)) for t in seen)
    assert budgets == sorted([s.max_tool_calls_by_severity["high"], s.max_tool_calls])
