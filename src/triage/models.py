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
    direct_evidence: int = 0                 # direct 판단 근거의 깊이(의존 그래프 최대 깊이). 출처가 엇갈리면 큰 쪽을 믿는다
    dependency_paths: list[list[str]] = []   # 루트 → … → 이 구성요소 (구성요소 id)
    licenses: list[str] = []
    sources: list[str] = []                  # 이 구성요소를 보고한 입력 파일들
    # ── 본선 확장: 소스에서 직접 수집할 때 채운다(스캐너 입력 경로에서는 기본값 유지) ──
    kind: str = "library"                    # library | runtime | base-image | server | os-package
    version_source: str = ""                 # lockfile | manifest_pinned | manifest_range | managed | property_override | vendored | dockerfile | tool | unknown
    declared_spec: str = ""                  # 명세에 적힌 원래 표기. 예: ^3.1.6, 버전 생략
    module: str = ""                         # 다중 모듈 프로젝트의 모듈 이름
    scope: str = "unknown"                   # runtime | dev | test | build_only | optional | unknown
    deployed: str = "unknown"                # yes | no | unknown (모르면 unknown, 추측 금지)
    deployed_reason: str = ""
    depends_on: list[str] = []               # 자식 구성요소 id
    evidence_ids: list[str] = []             # 버전·범위·배포 판단 근거
    discovered_by: str = ""                  # 어댑터 이름 또는 tool:syft

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
    version_in_range: Optional[bool] = None  # 조회 단계가 코드로 재계산한 결과(None = 계산 불가)
    verdict: Optional["Verdict"] = None      # 판정 단계 결과(본선 확장)

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


# ───────────────────────── 본선 확장: 근거와 판정 ─────────────────────────
# 규칙: 버전·배포 여부·판정 같은 모든 주장은 Evidence.id 로 근거를 가리킨다.
# 모델이 만드는 값은 Checklist 와 Verdict(+ WorkRequest 문구)뿐이고, 나머지는 결정적 코드가 만든다.

class Evidence(BaseModel):
    id: str                                  # 실행 안에서 유일. 예: E0042
    kind: str                                # manifest | lockfile | build | config | code | advisory | tool
    file: str = ""                           # 프로젝트 루트 기준 상대 경로
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    snippet: str = ""                        # 해당 줄 원문(최대 600자). 검증기가 실제 파일과 대조한다
    url: str = ""
    command: str = ""
    note: str = ""


class Anomaly(BaseModel):
    """입력 자체의 이상: 명세·잠금 파일 불일치, 설정 충돌, 주석과 실제 값 불일치, SBOM 도구 누락 등."""
    kind: str
    message: str
    evidence_ids: list[str] = []


class SourceFileScope(BaseModel):
    path: str
    deployed: str = "unknown"                # yes | no | unknown
    category: str = "app"                    # app | test | script | legacy | generated | vendored_bundle | config | other
    reason: str = ""
    evidence_ids: list[str] = []


class ConditionItem(BaseModel):
    key: str                                 # 점검표 안에서 유일. 예: uses_template_imports
    kind: str                                # api_use | input_source | config | platform | deployment | other
    question: str                            # 한국어 예/아니오 질문
    symbols: list[str] = []                  # 코드 검색어
    config_keys: list[str] = []
    required: bool = True


class Checklist(BaseModel):
    vuln_id: str
    ecosystem: str = ""
    package: str = ""
    vulnerable_entry_points: list[str] = []
    items: list[ConditionItem] = []
    model: str = ""
    cache_key: str = ""


class ItemResult(BaseModel):
    item_key: str
    status: str                              # met | not_met | unknown
    evidence_ids: list[str] = []
    reason: str = ""


class MissingInfo(BaseModel):
    what: str                                # 추가로 필요한 정보
    where: str                               # 확인할 위치(파일, 배포 매니페스트, 담당 팀 등)


class WorkRequest(BaseModel):
    """개발자 혼자 해결 못 하는 항목을 담당 팀에 보낼 요청 초안. 받는 팀은 규칙으로 정한다."""
    to_team: str
    title: str
    body: str
    branches: list[str] = []                 # "답이 A면 조치 불필요" 같은 분기


class Verdict(BaseModel):
    state: str                               # affected | not_affected | undetermined (CycloneDX: exploitable | not_affected | in_triage)
    justification: str = ""                  # CycloneDX analysis.justification 값
    decided_by: str = ""                     # rule:out_of_range | rule:not_deployed | model:<이름> | fallback
    item_results: list[ItemResult] = []
    rationale_ko: str = ""
    plain_ko: str = ""                       # 보안 비전문 개발자용 한 문장 설명
    missing_info: list[MissingInfo] = []
    work_request: Optional[WorkRequest] = None
    verifier_notes: list[str] = []           # 검증기가 강등·교체한 기록
    attempts: int = 1
    escalated: bool = False                  # 상위 모델로 승급했는가
    decided_at: str = ""                     # ISO 시각. 실행 로그의 '판정 완료 시점'


class TriageBundle(BaseModel):
    components: list[Component] = []
    findings: list[Finding] = []
    assets: list[AssetContext] = []
    results: list[PriorityResult] = []
    remediations: list[Remediation] = []
    meta: dict[str, Any] = Field(default_factory=dict)
    # 본선 확장
    evidence: list[Evidence] = []
    anomalies: list[Anomaly] = []
    files: list[SourceFileScope] = []

    def asset(self, asset_id: Optional[str]) -> Optional[AssetContext]:
        return next((a for a in self.assets if a.asset_id == asset_id), None)

    def finding(self, key: str) -> Optional[Finding]:
        return next((f for f in self.findings if f.key == key), None)


Finding.model_rebuild()
