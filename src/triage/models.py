"""내부 공통 구조. 모든 변환기는 원본 형식을 이 구조로 바꾸고, 이후 단계는 원본 형식을 모른다."""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Tier(str, Enum):
    P1 = "P1"  # 긴급
    P2 = "P2"  # 높음
    P3 = "P3"  # 보통
    P4 = "P4"  # 낮음

    @property
    def rank(self) -> int:
        return int(self.value[1])

    @classmethod
    def from_rank(cls, n: int) -> "Tier":
        return cls(f"P{min(max(n, 1), 4)}")


class Status(str, Enum):
    affected = "affected"
    not_affected = "not_affected"   # VEX 등으로 영향 없음이 명시됨
    unknown = "unknown"


class Component(BaseModel):
    id: str                                  # 정규화 purl(한정자 제거). purl 이 없으면 ecosystem:name@version
    name: str
    group: str = ""
    version: str = ""
    ecosystem: str = ""                      # maven, npm, pypi …(purl type)
    purl: str = ""
    direct: Optional[bool] = None            # 직접 의존성인가(모르면 None)
    dependency_paths: list[list[str]] = []   # 루트 → … → 이 구성요소 (구성요소 id)
    licenses: list[str] = []
    sources: list[str] = []                  # 이 구성요소를 보고한 입력 파일들

    @property
    def display(self) -> str:
        n = f"{self.group}:{self.name}" if self.group else self.name
        return f"{n}@{self.version}" if self.version else n


class Vulnerability(BaseModel):
    id: str                                  # 대표 식별자(CVE 우선)
    aliases: list[str] = []
    title: str = ""
    description: str = ""
    severity: str = ""                       # 스캐너가 준 등급 문자열(정규화: critical/high/medium/low/unknown)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    cvss_source: str = ""                    # 점수 출처(nvd, ghsa …)
    fixed_versions: list[str] = []
    affected_ranges: list[str] = []          # 예: ">=2.13.0,<2.15.0"
    references: list[str] = []
    published: str = ""

    @property
    def all_ids(self) -> list[str]:
        return [self.id, *self.aliases]


class AssetContext(BaseModel):
    asset_id: str
    service_name: str = ""
    internet_exposed: Optional[bool] = None
    criticality: Optional[int] = None        # 1(낮음) ~ 5(매우 높음)
    environment: str = ""                    # prod, stg, dev …
    owner: str = ""
    match: list[str] = []                    # 입력 파일 이름·SBOM 대상 이름과 맞춰 볼 문자열
    extra: dict[str, Any] = {}               # 모르는 열은 버리지 않고 보관


class KevInfo(BaseModel):
    listed: bool = False
    date_added: str = ""
    due_date: str = ""
    ransomware: Optional[bool] = None
    source: str = ""                         # cache, grype …


class Signals(BaseModel):
    kev: KevInfo = KevInfo()
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_date: str = ""
    epss_source: str = ""


class Finding(BaseModel):
    """(취약점, 구성요소, 자산) 한 쌍. 여러 스캐너가 보고한 같은 건은 하나로 합친다."""

    key: str
    component: Component
    vulnerability: Vulnerability
    asset_id: Optional[str] = None
    scanners: list[str] = []
    status: Status = Status.affected
    status_note: str = ""                    # not_affected 사유 등
    signals: Signals = Signals()
    hints: dict[str, Any] = {}               # 스캐너가 함께 준 보조 지표(KEV, EPSS 등). 캐시가 없을 때만 쓴다

    @staticmethod
    def make_key(vuln_id: str, component_id: str, asset_id: Optional[str]) -> str:
        return f"{vuln_id}|{component_id}|{asset_id or '-'}"


class Reason(BaseModel):
    signal: str                              # kev, epss, cvss, exposure, criticality, status, override …
    value: Any = None
    effect: str = ""                         # "P1 확정", "+0.32", "기한 7일" …
    source: str = ""


class PriorityResult(BaseModel):
    finding_key: str
    tier: Tier
    score: float
    rank: int = 0
    layer: str = ""                          # 어느 계층에서 정해졌는가
    due_date: Optional[str] = None
    due_days: Optional[int] = None
    reasons: list[Reason] = []
    policy_version: str = ""


class Remediation(BaseModel):
    finding_key: str
    target_version: Optional[str] = None
    verified: bool = False
    verify_notes: list[str] = []
    summary_ko: str = ""
    steps: list[str] = []
    workaround: str = ""
    provider: str = ""
    fallback_used: bool = False


class TriageBundle(BaseModel):
    components: list[Component] = []
    findings: list[Finding] = []
    assets: list[AssetContext] = []
    results: list[PriorityResult] = []
    remediations: list[Remediation] = []
    meta: dict[str, Any] = Field(default_factory=dict)

    def asset(self, asset_id: Optional[str]) -> Optional[AssetContext]:
        return next((a for a in self.assets if a.asset_id == asset_id), None)

    def finding(self, key: str) -> Optional[Finding]:
        return next((f for f in self.findings if f.key == key), None)
