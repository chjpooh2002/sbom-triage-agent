"""변환기 등록과 형식 자동 판별.

새 형식을 붙이는 방법(본선용):
    @register("my-scanner", kind="scan", sniff=lambda path, data: isinstance(data, dict) and "myKey" in data)
    def parse_my(path: Path, data) -> ParsedInput: ...
그리고 `triage/ingest/__init__.py` 의 import 목록에 모듈을 추가하면 끝이다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from ..models import AssetContext, Component, Finding

TABLE_SUFFIXES = {".csv", ".tsv", ".xlsx", ".xls"}


@dataclass
class ParsedInput:
    """변환기 한 번의 결과. 자산 연결과 병합은 merge.py 가 맡는다."""

    source: str                              # 입력 파일 경로
    converter: str
    kind: str                                # sbom | scan | assets
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)   # asset_id 는 아직 비어 있다
    assets: list[AssetContext] = field(default_factory=list)
    target: str = ""                         # 스캔·SBOM 대상 이름(자산 연결에 사용)
    warnings: list[str] = field(default_factory=list)


@dataclass
class Converter:
    name: str
    kind: str
    sniff: Callable[[Path, Any], bool]
    parse: Callable[[Path, Any], ParsedInput]
    priority: int = 0                        # 여러 개가 맞으면 큰 쪽


_REGISTRY: list[Converter] = []


def register(name: str, kind: str, sniff: Callable[[Path, Any], bool], priority: int = 0):
    def deco(fn: Callable[[Path, Any], ParsedInput]):
        _REGISTRY.append(Converter(name, kind, sniff, fn, priority))
        return fn
    return deco


def converters() -> list[Converter]:
    return sorted(_REGISTRY, key=lambda c: -c.priority)


def load_raw(path: Path) -> Any:
    """JSON 은 dict/list 로, 표 파일은 경로 그대로 넘긴다(표 변환기가 직접 읽음)."""
    if path.suffix.lower() in TABLE_SUFFIXES:
        return None
    text = path.read_text(encoding="utf-8-sig")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def detect(path: Path, raw: Any = None, forced: Optional[str] = None) -> Converter:
    if forced:
        for c in _REGISTRY:
            if c.name == forced:
                return c
        raise ValueError(f"등록되지 않은 변환기: {forced} (가능: {[c.name for c in _REGISTRY]})")
    for c in converters():
        try:
            if c.sniff(path, raw):
                return c
        except Exception:
            continue
    raise ValueError(f"{path}: 형식을 알아낼 수 없습니다. --format 으로 변환기를 지정하거나 변환기를 추가하세요 "
                     f"(등록된 변환기: {[c.name for c in _REGISTRY]})")


def parse_file(path: str | Path, forced: Optional[str] = None) -> ParsedInput:
    p = Path(path)
    raw = load_raw(p)
    conv = detect(p, raw, forced)
    out = conv.parse(p, raw)
    out.converter, out.kind, out.source = conv.name, conv.kind, str(p)
    return out
