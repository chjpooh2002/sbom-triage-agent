"""설정 파일 위치와 로드. 경로는 환경 변수 TRIAGE_CONFIG_DIR 로 바꿀 수 있다."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def config_dir() -> Path:
    return Path(os.environ.get("TRIAGE_CONFIG_DIR", ROOT / "config"))


@lru_cache(maxsize=8)
def _load(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def load_yaml(name: str) -> dict:
    return _load(str(config_dir() / name))


def load_ingest_config() -> dict:
    return load_yaml("ingest.yaml")
