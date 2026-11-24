"""plain_ko(보안 비전문 개발자용 한 문장)와 판단 유보 항목의 작업 요청(WorkRequest).

받는 팀은 config/teams.yaml 규칙으로 정하고(모델이 정하지 않음), 요청 문구는 모델이 쓰되
모델이 없거나 결과가 규칙을 어기면 템플릿으로 대체한다.
"""
from __future__ import annotations

import re

from triage.config import load_yaml
from triage.models import Checklist, Finding, Verdict, WorkRequest
from triage.remediation.versions import fix_for_line

from .checklist import package_label
from .client import LLMClient, ModelError, load_prompt
from .decide import _obj, _S
from .settings import Settings

_IDS = re.compile(r"\s*[\[(]?\b[a-z][\w-]*-\d{4}\b[\])]?,?")
_VERSIONS = re.compile(r"(?<![\w.])v?\d+(?:\.\d+)+(?![\w.])")


def line_fix(finding: Finding) -> str:
    c, v = finding.component, finding.vulnerability
    try:
        return fix_for_line(c.version, v.fixed_versions, c.ecosystem) or "" if c.version else ""
    except Exception:  # 버전 문자열을 해석할 수 없으면 제안하지 않는다
        return ""


def template_plain(finding: Finding, verdict: Verdict) -> str:
    c = finding.component
    pkg, ver = package_label(c), c.version
    fix = line_fix(finding)
    by = verdict.decided_by
    if by == "rule:out_of_range":
        return f"설치된 {pkg} {ver}은(는) 이 취약점의 영향 범위 밖이라 조치가 필요 없습니다."
    if by == "rule:not_deployed":
        return f"{pkg}은(는) 실제 배포되는 결과물에 들어가지 않아 이 취약점의 영향이 없습니다."
    if verdict.state == "affected":
        tail = f"{fix} 이상으로 올려야 합니다" if fix else "수정 버전이 없어 우회 조치가 필요합니다"
        return f"{pkg} {ver}의 취약한 부분이 이 서비스에서 실제로 쓰일 수 있어 {tail}."
    if verdict.state == "not_affected":
        return f"{pkg} {ver}에 취약점이 있지만 이 서비스는 문제 되는 기능을 쓰지 않아 당장 영향은 없습니다."
    need = verdict.missing_info[0].what if verdict.missing_info else "추가 정보"
    return f"{pkg} {ver}의 영향 여부를 정하려면 '{need}' 확인이 필요합니다."


def clean_plain(text: str, limit: int) -> str:
    text = _IDS.sub("", re.sub(r"\s+", " ", text or "")).strip()
    if not text:
        return ""
    first = re.split(r"(?<=[.!?。])\s", text, maxsplit=1)[0]
    return first if len(first) <= limit else first[:limit - 1].rstrip() + "…"


def plain_sentence(finding: Finding, verdict: Verdict, settings: Settings) -> str:
    if verdict.decided_by.startswith("model:"):
        cleaned = clean_plain(verdict.plain_ko, settings.plain_ko_max_chars)
        if cleaned:
            return cleaned
    return template_plain(finding, verdict)


def team_for(verdict: Verdict, checklist: Checklist | None) -> str:
    cfg = load_yaml("teams.yaml")
    rules = cfg.get("rules", [])
    text = " ".join(f"{m.what} {m.where}" for m in verdict.missing_info).lower()
    for rule in rules:
        if any(str(k).lower() in text for k in rule.get("keywords", [])):
            return rule["team"]
    open_keys = {r.item_key for r in verdict.item_results if r.status == "unknown"}
    kinds = {i.kind for i in (checklist.items if checklist else []) if i.key in open_keys or not open_keys}
    for rule in rules:
        if kinds & set(rule.get("kinds", [])):
            return rule["team"]
    return cfg.get("default", "개발팀")


def template_request(finding: Finding, verdict: Verdict, team: str) -> WorkRequest:
    c, v = finding.component, finding.vulnerability
    pkg, fix = package_label(c), line_fix(finding)
    asks = verdict.missing_info or []
    body = [f"{pkg} {c.version}에 알려진 취약점({v.id})이 있으나 아래 정보가 없어 영향 여부를 정하지 못했습니다."]
    body += [f"{n}. {m.what} (확인 위치: {m.where or '담당 팀'})" for n, m in enumerate(asks, 1)]
    yes = (f"답이 '해당함'이면 → 영향 있음: {pkg}를 {fix} 이상으로 올리고 재배포" if fix
           else "답이 '해당함'이면 → 영향 있음: 수정 버전 없음 — 우회 조치 검토")
    return WorkRequest(to_team=team, title=f"{pkg} {c.version} 취약점 영향 확인 요청"[:60], body="\n".join(body),
                       branches=[yes, "답이 '해당 없음'이면 → 조치 불필요, 확인 결과를 근거로 기록"])


def _request_schema() -> dict:
    return _obj({"title": _S, "body": _S, "branches": {"type": "array", "items": _S}})


def work_request(finding: Finding, verdict: Verdict, checklist: Checklist | None, client: LLMClient | None,
                 log=None) -> WorkRequest:
    team = team_for(verdict, checklist)
    fallback = template_request(finding, verdict, team)
    if client is None or not verdict.missing_info:
        return fallback
    c, v = finding.component, finding.vulnerability
    prompt = load_prompt("explain")
    data = "\n".join([
        f"구성요소: {package_label(c)} {c.version}", f"취약점: {v.id} — {v.title}",
        f"조회된 수정 버전: {', '.join(v.fixed_versions) or '(없음)'}", f"받는 팀: {team}",
        f"판단 유보 이유: {verdict.rationale_ko}",
        "필요한 정보:", *[f"- {m.what} (확인 위치: {m.where})" for m in verdict.missing_info]])
    try:
        reply = client.complete(purpose="explain", prompt_version=prompt.version, schema=_request_schema(),
                                schema_name="work_request", subject=finding.key,
                                messages=[{"role": "system", "content": prompt.text}, {"role": "user", "content": data}])
    except ModelError:
        return fallback
    if reply.refused or not reply.data:
        return fallback
    d = reply.data
    allowed = {x.lstrip("v") for x in [c.version, *v.fixed_versions]}
    text = " ".join([d["title"], d["body"], *d["branches"]])
    stray = [x for x in _VERSIONS.findall(text) if x.lstrip("v") not in allowed]
    if stray or len(d["branches"]) < 2 or not d["title"].strip():
        if log:
            log("judge", "explain.fallback", subject=finding.key, stray_versions=stray[:5])
        return fallback
    return WorkRequest(to_team=team, title=d["title"].strip()[:80], body=d["body"].strip(),
                       branches=[b.strip() for b in d["branches"] if b.strip()][:4])
