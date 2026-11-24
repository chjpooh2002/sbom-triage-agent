"""권고문 → 발생 조건 점검표(Checklist). 취약점 ID별 디스크 캐시."""
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

KINDS = ["api_use", "input_source", "config", "platform", "deployment", "other"]
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


def fallback_checklist(finding: Finding, note: str) -> Checklist:
    c = finding.component
    return Checklist(
        vuln_id=finding.vulnerability.id, ecosystem=c.ecosystem, package=package_label(c),
        items=[ConditionItem(key="uses_package", kind="api_use", required=True, symbols=import_names(c),
                             question=f"배포되는 코드가 {package_label(c)} 를 사용하는가?")],
        model="fallback", cache_key=note)


def normalize(data: dict, finding: Finding, settings: Settings, model: str, key: str) -> tuple[Checklist, list[str]]:
    """모델 출력 정리. 버전 항목은 규칙 1 위반이라 버린다(버전은 조회 데이터가 기준)."""
    dropped, items, seen = [], [], set()
    for raw in data.get("items", []):
        k = re.sub(r"[^a-z0-9_]+", "_", str(raw.get("key", "")).lower()).strip("_") or f"item_{len(items) + 1}"
        if _VERSION_ITEM.search(k) or re.search(r"버전.{0,20}(미만|이하|이상|초과|범위|이전|이후)", raw.get("question", "")):
            dropped.append(k)
            continue
        while k in seen:
            k += "_2"
        seen.add(k)
        symbols = list(dict.fromkeys(s.strip()[:120] for s in raw.get("symbols", []) if s and s.strip()))
        keys = list(dict.fromkeys(s.strip()[:120] for s in raw.get("config_keys", []) if s and s.strip()))
        items.append(ConditionItem(key=k, kind=raw.get("kind", "other"), question=raw.get("question", "").strip(),
                                   symbols=symbols, config_keys=keys, required=bool(raw.get("required", True))))
    c = finding.component
    checklist = Checklist(vuln_id=finding.vulnerability.id, ecosystem=c.ecosystem, package=package_label(c),
                          vulnerable_entry_points=[e for e in data.get("vulnerable_entry_points", []) if e][:10],
                          items=items[:settings.max_checklist_items], model=model, cache_key=key)
    return checklist, dropped


def _cache_path(settings: Settings, vuln_id: str) -> Path:
    return Path(settings.cache_dir) / "checklist" / (re.sub(r"[^\w.-]+", "_", vuln_id) + ".json")


def _lock(vuln_id: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(vuln_id, threading.Lock())


def build_checklist(finding: Finding, client: LLMClient | None, settings: Settings,
                    log=None) -> Checklist:
    """모델이 없거나 거절·실패하면 결정적 기본 점검표(패키지 사용 여부 하나)."""
    if client is None:
        return fallback_checklist(finding, "모델 미설정")
    prompt = load_prompt("checklist")
    c = finding.component
    entry = f"{c.ecosystem}:{package_label(c)}|{client.model}|{prompt.version}"
    path = _cache_path(settings, finding.vulnerability.id)
    with _lock(finding.vulnerability.id):
        try:
            cached = json.loads(path.read_text(encoding="utf-8")).get(entry)
        except (OSError, ValueError):
            cached = None
        if cached:
            checklist = Checklist.model_validate(cached)
            if log:
                log("judge", "checklist", vuln=finding.vulnerability.id, cached=True, items=len(checklist.items))
            return checklist
        messages = [{"role": "system", "content": prompt.text},
                    {"role": "user", "content": advisory_text(finding, settings)}]
        try:
            reply = client.complete(purpose="checklist", prompt_version=prompt.version, messages=messages,
                                    schema=schema(), schema_name="checklist", subject=finding.vulnerability.id)
        except ModelError as e:
            return fallback_checklist(finding, f"점검표 모델 호출 실패: {e}")
        if reply.refused or reply.data is None:
            return fallback_checklist(finding, "점검표 모델 거절")
        checklist, dropped = normalize(reply.data, finding, settings, client.model, entry)
        if log:
            log("judge", "checklist", vuln=finding.vulnerability.id, cached=False, items=len(checklist.items),
                dropped_version_items=dropped)
        if not checklist.items:
            return fallback_checklist(finding, "점검표 항목 없음")
        try:
            doc = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        except (OSError, ValueError):
            doc = {}
        doc[entry] = checklist.model_dump(mode="json")
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.{time.monotonic_ns()}.tmp")
        tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, path)
        return checklist
