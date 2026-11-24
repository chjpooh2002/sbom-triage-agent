"""권고문 → 발생 조건 점검표(Checklist). 취약점 ID별 디스크 캐시(SBOMTRIAGE_LLM_CACHE 로 끄고 켬)."""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

from triage.models import Checklist, Component, ConditionItem, Finding

from .client import LLMClient, ModelError, load_prompt
from .settings import Settings

LIBRARY_FACT = "library_fact"   # 영향 버전 라이브러리 자체의 동작(권고문·패키지 문서 기준). 저장소에서 확인하지 않는다
ASSUMPTION = "assumption"       # 소스로 확인할 수 없는 운영 환경 전제. 판정 조건이 아니라 보고서에 "전제"로 표시
FIXED_KINDS = (LIBRARY_FACT, ASSUMPTION)   # 모델이 아니라 규칙이 항목 결과를 정하는 종류
KINDS = ["api_use", "input_source", "config", "platform", "deployment", "other", *FIXED_KINDS]
# 버전 범위를 다시 묻는 항목(예: version_below_fix, installed_version_in_range)
_VERSION_ITEM = re.compile(r"version_(below|before|lt|le|in|range|affected|vulnerable|older)"
                           r"|(below|before|older_than)_(fix|patch|fixed)|in_affected_range", re.IGNORECASE)
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def schema() -> dict:
    item = {"type": "object", "additionalProperties": False,
            "properties": {"key": {"type": "string"}, "kind": {"type": "string", "enum": KINDS},
                           "question": {"type": "string"},
                           "symbols": {"type": "array", "items": {"type": "string"}},
                           "config_keys": {"type": "array", "items": {"type": "string"}},
                           "required": {"type": "boolean"}},
            "required": ["key", "kind", "question", "symbols", "config_keys", "required"]}
    return {"type": "object", "additionalProperties": False,
            "properties": {"vulnerable_entry_points": {"type": "array", "items": {"type": "string"}},
                           "items": {"type": "array", "items": item}},
            "required": ["vulnerable_entry_points", "items"]}


def package_label(c: Component) -> str:
    return f"{c.group}:{c.name}" if c.group else c.name


def import_names(c: Component) -> list[str]:
    """배포 이름에서 코드가 import 할 법한 이름 후보(일반 관례만)."""
    name = c.name.lower()
    names = [name, name.replace("-", "_"), name.replace("-", ".")]
    if c.ecosystem == "pypi":
        for prefix in ("python-", "py-", "py"):
            if name.startswith(prefix) and len(name) > len(prefix) + 1:
                names.append(name[len(prefix):].replace("-", "_"))
    if c.group:
        names.append(c.group)
    return list(dict.fromkeys(n for n in names if n))


def advisory_text(finding: Finding, settings: Settings) -> str:
    v, c = finding.vulnerability, finding.component
    lines = [f"취약점: {v.id}" + (f" (별칭: {', '.join(v.aliases)})" if v.aliases else ""),
             f"패키지: {package_label(c)} (생태계: {c.ecosystem or '-'}, 구성요소 종류: {c.kind})",
             f"제목: {v.title or '(없음)'}",
             "설명:", (v.description or "(설명 없음)")[:settings.max_description_chars]]
    if v.references:
        lines += ["참고 링크:", *v.references[:8]]
    return "\n".join(lines)


def uses_package_item(c: Component, key: str = "uses_package") -> ConditionItem:
    return ConditionItem(key=key, kind="api_use", required=True, symbols=import_names(c),
                         question=f"배포되는 코드가 {package_label(c)} 를 사용하는가?")


def is_service_condition(item: ConditionItem) -> bool:
    """서비스 코드·설정으로 확인할 필수 조건(라이브러리 사실·전제가 아닌 것)."""
    return item.required and item.kind not in FIXED_KINDS


def fallback_checklist(finding: Finding, note: str) -> Checklist:
    c = finding.component
    return Checklist(
        vuln_id=finding.vulnerability.id, ecosystem=c.ecosystem, package=package_label(c),
        items=[uses_package_item(c)], model="fallback", cache_key=note)


def normalize(data: dict, finding: Finding, settings: Settings, model: str, key: str) -> tuple[Checklist, list[str]]:
    """모델 출력 정리.

    - 버전 항목은 규칙 1 위반이라 버린다(버전은 조회 데이터가 기준).
    - 운영 환경 전제(assumption)는 소스로 확인할 수 없으므로 필수 조건에서 뺀다.
    - 서비스 쪽 필수 조건이 하나도 없으면(라이브러리 사실·전제뿐이면) 패키지 사용 여부를 필수로 넣는다.
      권고문 사실만으로 저장소 증거 없이 영향 있음이 되지 않게 하기 위해서다.
    """
    dropped, items, seen = [], [], set()
    for raw in data.get("items", []):
        k = re.sub(r"[^a-z0-9_]+", "_", str(raw.get("key", "")).lower()).strip("_") or f"item_{len(items) + 1}"
        if _VERSION_ITEM.search(k) or re.search(r"버전.{0,20}(미만|이하|이상|초과|범위|이전|이후)", raw.get("question", "")):
            dropped.append(k)
            continue
        while k in seen:
            k += "_2"
        seen.add(k)
        kind = raw.get("kind", "other") if raw.get("kind") in KINDS else "other"
        symbols = list(dict.fromkeys(s.strip()[:120] for s in raw.get("symbols", []) if s and s.strip()))
        keys = list(dict.fromkeys(s.strip()[:120] for s in raw.get("config_keys", []) if s and s.strip()))
        items.append(ConditionItem(key=k, kind=kind, question=raw.get("question", "").strip(),
                                   symbols=symbols, config_keys=keys,
                                   required=bool(raw.get("required", True)) and kind != ASSUMPTION))
    limit = settings.max_checklist_items
    items = items[:limit]
    c = finding.component
    if items and not any(is_service_condition(i) for i in items):
        k = "uses_package"
        while k in seen:
            k += "_2"
        items = [*items[:max(0, limit - 1)], uses_package_item(c, k)]
    checklist = Checklist(vuln_id=finding.vulnerability.id, ecosystem=c.ecosystem, package=package_label(c),
                          vulnerable_entry_points=[e for e in data.get("vulnerable_entry_points", []) if e][:10],
                          items=items, model=model, cache_key=key)
    return checklist, dropped


def _cache_path(settings: Settings, vuln_id: str) -> Path:
    return Path(settings.cache_dir) / "checklist" / (re.sub(r"[^\w.-]+", "_", vuln_id) + ".json")


def _lock(vuln_id: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(vuln_id, threading.Lock())


def build_checklist(finding: Finding, client: LLMClient | None, settings: Settings,
                    log=None, memo: dict | None = None) -> Checklist:
    """모델이 없거나 거절·실패하면 결정적 기본 점검표(패키지 사용 여부 하나).

    - 디스크 캐시(취약점 ID별 파일)는 SBOMTRIAGE_LLM_CACHE=off 면 읽지도 쓰지도 않는다.
    - ``memo`` 는 한 번의 실행 안에서만 쓰는 메모리 사본이다. 같은 취약점·같은 패키지 후보가
      여럿이어도 점검표를 한 번만 만들어 같은 기준으로 판정한다(캐시 off 에서도 유지).
    """
    if client is None:
        return fallback_checklist(finding, "모델 미설정")
    prompt = load_prompt("checklist")
    c = finding.component
    entry = f"{c.ecosystem}:{package_label(c)}|{client.model}|{prompt.version}"
    vid = finding.vulnerability.id
    path = _cache_path(settings, vid)
    with _lock(vid):
        if memo is not None and (vid, entry) in memo:
            checklist = memo[(vid, entry)]
            if log:
                log("judge", "checklist", vuln=vid, cached=False, reused=True, items=len(checklist.items))
            return checklist
        cached = None
        if settings.llm_cache:
            try:
                cached = json.loads(path.read_text(encoding="utf-8")).get(entry)
            except (OSError, ValueError):
                cached = None
        if cached:
            checklist = Checklist.model_validate(cached)
            client.count("checklist_cache_hits")
            if log:
                log("judge", "checklist", vuln=vid, cached=True, items=len(checklist.items))
            return _remember(memo, vid, entry, checklist)
        messages = [{"role": "system", "content": prompt.text},
                    {"role": "user", "content": advisory_text(finding, settings)}]
        try:
            reply = client.complete(purpose="checklist", prompt_version=prompt.version, messages=messages,
                                    schema=schema(), schema_name="checklist", subject=vid)
        except ModelError as e:   # 메시지는 예외 종류·상태 코드로만 만든 것(client.py)
            return fallback_checklist(finding, f"점검표 모델 호출 실패: {e}")
        if reply.refused or reply.data is None:
            return fallback_checklist(finding, "점검표 모델 거절")
        checklist, dropped = normalize(reply.data, finding, settings, client.model, entry)
        if log:
            log("judge", "checklist", vuln=vid, cached=False, items=len(checklist.items),
                dropped_version_items=dropped)
        if not checklist.items:
            return fallback_checklist(finding, "점검표 항목 없음")
        if settings.llm_cache:
            try:
                doc = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
            except (OSError, ValueError):
                doc = {}
            doc[entry] = checklist.model_dump(mode="json")
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(f".{os.getpid()}.{time.monotonic_ns()}.tmp")
            tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
            os.replace(tmp, path)
        return _remember(memo, vid, entry, checklist)


def _remember(memo: dict | None, vid: str, entry: str, checklist: Checklist) -> Checklist:
    if memo is not None:
        memo[(vid, entry)] = checklist
    return checklist
