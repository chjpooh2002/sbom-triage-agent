"""판정 단계 설정: config/judge.yaml 의 기준값과 환경변수 스위치."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from triage.config import ROOT, load_yaml

CACHE_DIR = ROOT / "data" / "cache" / "judge"

_ON = {"on", "1", "true", "yes"}
_OFF = {"off", "0", "false", "no"}


def switch(name: str, default: bool) -> bool:
    """on|off 환경변수. 비어 있으면 기본값, 알 수 없는 값은 실험 설정 실수이므로 바로 알린다."""
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in _ON:
        return True
    if raw in _OFF:
        return False
    raise ValueError(f"{name} 값은 on 또는 off 여야 합니다")


def positive_int(name: str, default: int) -> int:
    """양의 정수 환경변수. 비어 있으면 기본값, 잘못된 값은 실험 설정 실수이므로 바로 알린다."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    if not (raw.isascii() and raw.isdigit()) or int(raw) < 1:
        raise ValueError(f"{name} 값은 1 이상의 정수여야 합니다")
    return int(raw)


@dataclass(frozen=True)
class Settings:
    judge: bool = True                    # SBOMTRIAGE_JUDGE: off 면 버전 일치만 보는 기준선
    verify: bool = True                   # SBOMTRIAGE_VERIFY: off 면 검증·재요청 생략
    escalate: bool = True                 # SBOMTRIAGE_ESCALATE: off 면 승급 생략
    llm_cache: bool = True                # SBOMTRIAGE_LLM_CACHE: off 면 모델 응답·점검표 디스크 캐시를 읽지도 쓰지도 않음
    model: str = ""                       # SBOMTRIAGE_MODEL
    escalate_model: str = ""              # SBOMTRIAGE_ESCALATE_MODEL
    max_attempts: int = 3
    backoff_seconds: float = 1.0
    timeout_seconds: float = 60.0
    max_tool_calls: int = 3
    max_tool_calls_by_severity: dict[str, int] = field(default_factory=dict)   # 등급별 상한(없으면 위 값)
    trace_kinds: tuple[str, ...] = ("input_source",)   # 유보 전에 데이터 흐름 추적을 요구할 항목 종류
    workers: int = 4                      # SBOMTRIAGE_JUDGE_WORKERS 가 있으면 그 값
    max_symbols_per_item: int = 4
    max_config_keys_per_item: int = 3
    max_prompt_evidence_chars: int = 24000
    max_description_chars: int = 3000
    max_checklist_items: int = 6
    min_deployed_code_evidence: int = 1
    plain_ko_max_chars: int = 160
    instruction_patterns: tuple[re.Pattern, ...] = field(default_factory=tuple)
    cache_dir: Path = CACHE_DIR


def load_settings(**overrides) -> Settings:
    try:
        from dotenv import load_dotenv
        load_dotenv(override=False)
    except ImportError:  # pragma: no cover - 의존성에 포함되어 있음
        pass
    cfg = load_yaml("judge.yaml")
    call, decide = cfg.get("model_call", {}), cfg.get("decide", {})
    timeout = os.environ.get("LLM_TIMEOUT", "").strip()
    values = dict(
        judge=switch("SBOMTRIAGE_JUDGE", True),
        verify=switch("SBOMTRIAGE_VERIFY", True),
        escalate=switch("SBOMTRIAGE_ESCALATE", True),
        llm_cache=switch("SBOMTRIAGE_LLM_CACHE", True),
        model=os.environ.get("SBOMTRIAGE_MODEL", "").strip(),
        escalate_model=os.environ.get("SBOMTRIAGE_ESCALATE_MODEL", "").strip(),
        max_attempts=int(call.get("max_attempts", 3)),
        backoff_seconds=float(call.get("backoff_seconds", 1.0)),
        timeout_seconds=float(timeout or call.get("timeout_seconds", 60)),
        max_tool_calls=int(decide.get("max_tool_calls", 3)),
        max_tool_calls_by_severity={str(k).lower(): int(v)
                                    for k, v in (decide.get("max_tool_calls_by_severity") or {}).items()},
        trace_kinds=tuple(decide.get("trace_before_undetermined_kinds", ["input_source"]) or ()),
        workers=positive_int("SBOMTRIAGE_JUDGE_WORKERS", int(decide.get("workers", 4))),
        max_symbols_per_item=int(decide.get("max_symbols_per_item", 4)),
        max_config_keys_per_item=int(decide.get("max_config_keys_per_item", 3)),
        max_prompt_evidence_chars=int(decide.get("max_prompt_evidence_chars", 24000)),
        max_description_chars=int(decide.get("max_description_chars", 3000)),
        max_checklist_items=int(cfg.get("checklist", {}).get("max_items", 6)),
        min_deployed_code_evidence=int(cfg.get("escalate", {}).get("min_deployed_code_evidence", 1)),
        plain_ko_max_chars=int(cfg.get("explain", {}).get("plain_ko_max_chars", 160)),
        instruction_patterns=tuple(re.compile(p, re.IGNORECASE)
                                   for p in cfg.get("instruction_patterns", [])),
    )
    values.update(overrides)
    return Settings(**values)
