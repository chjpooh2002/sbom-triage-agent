"""입력 정규화 계층. 새 형식을 붙이려면 변환기 모듈을 만들고 아래 import 목록에 추가한다."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import assets_table, sbom_cyclonedx, sbom_spdx, scan_grype, scan_osv, scan_trivy  # noqa: F401  (등록)
from .merge import merge
from .registry import ParsedInput, converters, parse_file, register

__all__ = ["ingest_paths", "parse_file", "register", "converters", "ParsedInput", "merge"]


def split_spec(spec: str) -> tuple[str, Optional[str]]:
    """'out/grype.json=shop-api' → (경로, 자산 id). 윈도우 드라이브 문자(C:\\)는 건드리지 않는다."""
    if "=" in spec:
        path, _, asset = spec.rpartition("=")
        if path:
            return path, asset or None
    return spec, None


def ingest_paths(specs: list[str], forced_format: Optional[str] = None):
    """경로 목록(디렉터리면 안의 파일 전부)을 읽어 TriageBundle 로 만든다."""
    parsed, explicit, skipped = [], {}, []
    for spec in specs:
        path, asset = split_spec(spec)
        p = Path(path)
        files = sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]
        for f in files:
            try:
                item = parse_file(f, forced_format)
            except ValueError as e:
                if p.is_dir():           # 디렉터리 안의 모르는 파일은 건너뛰고 기록만
                    skipped.append(f"{f}: {e}".split(". ")[0])
                    continue
                raise
            parsed.append(item)
            if asset:
                explicit[item.source] = asset
    bundle = merge(parsed, explicit)
    if skipped:
        bundle.meta["warnings"] = bundle.meta.get("warnings", []) + [f"건너뜀 {s}" for s in skipped]
    return bundle
