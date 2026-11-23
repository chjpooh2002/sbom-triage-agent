"""정책 파일(config/policy.yaml) 로드와 검증."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from ..config import config_dir
from ..models import Tier


class LayerToggle(BaseModel):
    enabled: bool = True
    tier: Tier


class Layers(BaseModel):
    not_affected: LayerToggle = LayerToggle(tier=Tier.P4)
    kev: LayerToggle = LayerToggle(tier=Tier.P1)


class ScoreCfg(BaseModel):
    weights: dict[str, float]
    epss_scale: list[tuple[float, float]]
    thresholds: dict[Tier, float]

    @field_validator("weights")
    @classmethod
    def _w(cls, v):
        unknown = set(v) - {"epss", "cvss", "exposure", "criticality"}
        if unknown:
            raise ValueError(f"알 수 없는 가중치 항목: {unknown}")
        if sum(v.values()) <= 0:
            raise ValueError("가중치 합이 0 이하")
        return v

    @field_validator("epss_scale")
    @classmethod
    def _scale(cls, v):
        xs = [x for x, _ in v]
        if xs != sorted(xs) or xs[0] > 0 or xs[-1] < 1:
            raise ValueError("epss_scale 은 0~1 구간을 오름차순으로 덮어야 함")
        return v

    @field_validator("thresholds")
    @classmethod
    def _th(cls, v):
        vals = [v[t] for t in sorted(v, key=lambda t: t.rank)]
        if vals != sorted(vals, reverse=True):
            raise ValueError("thresholds 는 P1 ≥ P2 ≥ P3 순이어야 함")
        return v


class Missing(BaseModel):
    epss: float = 0.0
    cvss_by_severity: dict[str, float] = {"unknown": 5.0}
    exposure: float = 1.0
    criticality: float = 0.5


class Override(BaseModel):
    name: str
    when: dict[str, float | bool | int]
    min_tier: Optional[Tier] = None
    max_tier: Optional[Tier] = None

    @model_validator(mode="after")
    def _one(self):
        allowed = {"epss_gte", "cvss_gte", "internet_exposed", "criticality_gte", "criticality_lte", "direct", "has_fix"}
        bad = set(self.when) - allowed
        if bad:
            raise ValueError(f"{self.name}: 알 수 없는 조건 {bad} (가능: {sorted(allowed)})")
        if not self.min_tier and not self.max_tier:
            raise ValueError(f"{self.name}: min_tier 나 max_tier 중 하나는 있어야 함")
        return self


class Policy(BaseModel):
    version: int = 1
    name: str = ""
    tiers: dict[Tier, dict[str, str]] = {}
    layers: Layers = Layers()
    score: ScoreCfg
    missing: Missing = Missing()
    overrides: list[Override] = []
    due_days: dict[Tier, Optional[int]] = Field(default_factory=dict)
    exposed_due_factor: float = 1.0
    fingerprint: str = ""                    # 파일 내용 해시(결과에 남겨 재현 가능하게)

    def label(self, t: Tier) -> str:
        return self.tiers.get(t, {}).get("label", t.value)

    def action(self, t: Tier) -> str:
        return self.tiers.get(t, {}).get("action", "")


def load_policy(path: str | Path | None = None) -> Policy:
    p = Path(path) if path else config_dir() / "policy.yaml"
    text = p.read_text(encoding="utf-8")
    pol = Policy.model_validate(yaml.safe_load(text))
    pol.fingerprint = f"v{pol.version}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:8]}"
    return pol
