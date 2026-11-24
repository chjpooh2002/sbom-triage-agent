# 본선 작업 지시서 (2026-11-24 13:00 ~ 11-25 07:00)

설계 문서: https://claude.ai/artifact/Br8GkoMyJHb2DKEVcYzV8K
모든 작업은 먼저 `AGENTS.md`(본선 절 포함)와 `src/triage/models.py`를 읽는다.

## 0. 공통 규칙
- **`models.py`는 동결.** 필드가 더 필요하면 PR 본문에 적고 Claude 작업 공간이 합친다. 각 작업은 자기 폴더만 만든다.
- 대회 샘플(svc-a/b/c)은 `data/field/`에만 둔다(커밋 금지). 테스트 고정 데이터는 `tests/fixtures/finals/`에 **직접 만든 최소 예제**로.
- 샘플 파일명·패키지명·취약점 ID를 코드·프롬프트에 하드코딩 금지(`scripts/check_no_sample_leak.py`).
- 모든 주장에 `Evidence.id`. 모르면 `unknown`/판단 유보. 추측 금지.
- 모델 호출은 `src/triage/judge/` 안에서만.
- 완료 기준: `uv run pytest` 통과 + 범위 밖 파일 미수정 + PR 본문 양식(AGENTS.md).

## 1. 요구사항 대조표 (빠지면 감점되는 것)
| 요구 | 출처 | 담당 작업 |
|---|---|---|
| 웹 화면에서 샘플 입력 → 결과 확인 → PDF 내보내기 | 제출 가이드 2) | L3 |
| 단일 명령으로 SBOM·보고서·로그 생성 (`./run.sh A ./svc ./out`) | 제출 가이드 2) | L3 |
| CycloneDX JSON, 프로젝트 식별, 이름·버전, 직접·간접 관계 | 3) | C1, C5 |
| SBOM 도구 누락분 README 기록 + 재실행 시 포함 | 3) | C1(Anomaly) → L4 |
| 보고서 PDF 5개 필수 항목, 텍스트 복사 가능, 0건 문구 | 4) | C5, L3 |
| 로그 JSONL: 의존성 확인, 도구 호출·결과, 재시도, 후보별 판정·**판정 완료 시점**, 마지막 줄 총 시간·총 토큰(또는 측정 불가+사유) | 5) | C5(runlog), L1(decided_at) |
| 파일명 `sbom-A.json` `report-A.pdf` `log-A-run1.jsonl`, extra 폴더 | 2절 | L3 |
| README 5개 항목(환경, 실행, 단일 명령, 입출력·시간, 외부 자료·직접 구현 구분) | 2) | L4 |
| 비밀값이 소스·로그·보고서에 없음 | 유의사항 | C5, L1 |
| 상용 AI 비교: 샘플·모델·요청문 명시, 결과 구분 | 발표 5 | 사람(기준선) + L4 |
| 품질·비용·시간 실측 근거 (10점) | 평가표 | L4(단계별 비교 실행기) |
| 취약점 출처는 공개 권고문·공인 DB, 링크 | 4)-3 | C3 |
| 런타임·기반 이미지(JDK, Node, nginx) 취약점 — 의존성 스캔이 못 보는 영역 | 과제 안내 사례 | C1(dockerfile), C3(nvd), C4(nginx 설정) |

## 2. 작업 카드

### Codex 작업 공간 (동시에 시작)
**C1 수집 — `src/triage/collect/`**
- 공통: `collect(root) -> (list[Component], list[Evidence], list[Anomaly])`, 어댑터 등록·자동 감지.
- npm: `package-lock.json` v2/v3 `packages`. 중첩 경로는 별도 구성요소(id에 `#경로`). `dev:true` → scope=dev. 직접 여부는 `package.json`. 명세 표기는 `declared_spec`. 잠금 파일 없으면 `manifest_range` + Anomaly.
- pypi: `requirements*.txt`(`-r` 재귀, `==` 고정), `poetry.lock`, `Pipfile.lock`. 간접 관계 모르면 비움.
- maven: 다중 모듈, 부모 상속, `dependencyManagement`, `${속성}` 치환, **버전 생략 의존성은 부모 BOM을 Maven Central에서 받아 해석**(`version_source=managed`, 근거=BOM URL), 속성 덮어쓰기(`property_override`), test 범위, `module`. BOM은 `data/cache/maven/`에 저장해 오프라인 재실행.
- vendored: `*.min.js`·`vendor/`·`*.jar` 배너·버전 문자열로 식별. 실패하면 구성요소 만들지 않음.
- dockerfile: `FROM` 이미지를 `kind=base-image`/`runtime` 구성요소로(예: 이미지 이름·태그 → 런타임 이름·버전 줄). 태그가 떠다니는 경우(`11-jre`) 버전은 줄 단위로만, `version_source=dockerfile`.
- syft 대체: 감지된 어댑터가 없을 때만.
- 테스트: 잠금 불일치, 중첩 두 버전, BOM 관리 버전, 속성 덮어쓰기, dev/test 범위, 기반 이미지.

**C2 배포 범위 — `src/triage/scope/`**
- 입력: 루트 + 구성요소. 출력: `deployed`/`deployed_reason` 갱신 + `list[SourceFileScope]`.
- Dockerfile `COPY/ADD`, 최종 스테이지, `npm ci --omit=dev`, `--production`, `pip install -r`, `mvn -pl … -am` 인자, `.dockerignore`.
- Maven: 빌드 대상 모듈과 그 의존 모듈만 배포. 파일 분류: test/script/legacy/generated(`AUTO-GENERATED` 헤더, `generated/`)/vendored_bundle(긴 줄, `.min.`)/config.
- Dockerfile 없으면 전부 unknown.

**C3 조회 — `src/triage/lookup/`**
- OSV `querybatch` → `vulns/{id}` 상세 → `models.Vulnerability`. 별칭 병합(CVE 대표).
- 런타임·서버(`kind != library`)는 NVD CVE API 2.0(CPE 일치). 이미지→CPE 대응은 `config/runtime_cpe.yaml`(일반 규칙, 샘플 특정 금지).
- 범위 재계산: 기존 `remediation/versions.py`의 `is_affected`/`in_range`를 재사용해 `Finding.version_in_range`.
- KEV·EPSS는 기존 `intel/enrich.py` 재사용.
- 스냅샷: 응답 전부 `data/cache/lookup/<날짜>/`, `--offline`은 캐시만. 네트워크 오류 지수 백오프 3회, 각 시도 로그.

**C4 증거 검색 — `src/triage/evidence/`**
- `EvidenceStore`(id 발급, 파일 원문과 snippet 대조 `verify`).
- 가져오기 그래프(Python ast, JS require/import, Java import) → 패키지별 사용 파일.
- 기호 검색(앞뒤 3줄, 항목당 최대 8개, generated·vendored_bundle 기본 제외).
- 설정 실효값: Spring(.properties > .yml 같은 위치, 프로파일 파일은 활성 시에만, 활성 프로파일 불명 표시), nginx(`listen … http2`, `http2 on|off`, `proxy_pass`, `resolver`), 일반 YAML/JSON/.env.example.
- 처리기 판별(Flask route, Express router, Spring `@*Mapping`)과 같은 파일 안의 요청 인자 추적.
- 판정 에이전트용 도구 4개 함수: `search_symbol`, `read_lines`(60줄), `resolve_config`, `find_callers`.

**C5 출력 — `src/triage/output/`**
- `cyclonedx.py`: 1.6 JSON. metadata.component, tools, components(purl, scope required/optional/excluded, properties: version_source·deployed·module·근거 위치), dependencies, vulnerabilities(ratings, advisories, affects, analysis.state/justification/detail). 상태 대응 affected→exploitable, not_affected→not_affected, undetermined→in_triage. 스키마 검증 함수.
- `runlog.py`: JSONL 이벤트(stage, event, data), 비밀값 가림, 마지막 `run.end`에 total_seconds·total_tokens(또는 "측정 불가"+사유).
- `report_pdf/`: Jinja2 HTML → WeasyPrint. **한글 글꼴 파일 저장소에 포함(OFL 라이선스 파일 함께)**. 구성은 설계 문서 '보고서 구성' + '필수 외 추가 항목'. `pdftotext`로 한글 추출 테스트 필수. 0건·전부 영향 없음 문구.

**C6 정답지 (Codex 별도 세션, AGENTS.md 규칙대로) — `eval/gold_finals.csv`**
- 샘플 A·B·C의 후보별 기대 판정·핵심 근거 위치·기대 조치. 사람이 검증. 엔진 코드는 보지 않고 작성.

### Claude 작업 공간
**L1 판정 에이전트 — `src/triage/judge/`** (사용자와 함께 설계·구현)
- `client.py`: Chat Completions + json_schema, `OPENAI_BASE_URL`, 사용량(추론 토큰 포함) 기록, 디스크 캐시, 거절 → 판단 유보(사유 기록), 재시도 3회.
- `checklist.py` → `decide.py`(도구 루프 ≤3) → `verify.py`(근거·버전·배포·수정 버전 대조, 1회 재요청 후 강등) → `escalate.py`(유보 + 증거 충분할 때만 승급 모델 1회) → `explain.py`(plain_ko, WorkRequest. 받는 팀은 `config/teams.yaml` 규칙).
- 결정적 선판정: 범위 밖 → not_affected(rule), 미배포 → not_affected(rule). 모델 호출 없음.
**L3 통합** — `pipeline_finals.py`, `triage scan <라벨> <경로> <출력> [--offline] [--run N]`, `run.sh`, `Dockerfile`, 스트림릿 화면(업로드→진행→결과 세 묶음→상세→PDF 내려받기).
**L4 근거·문서** — `eval/ablation.py`(하네스 장치 켜고 끄기 × 모델 3종), README 5항목, 발표 수치표.

### 사람 (지금 바로)
- `uv run python scripts/check_llm.py <모델들>`로 프록시·모델 이름 확인.
- 상용 AI 기준선 실험(Codex에 샘플 그대로 + 정해진 요청문). 시간·토큰 기록, 원문 저장.

## 3. 순서와 시각
| 시각 | 이정표 |
|---|---|
| 13:00 | 이 문서 + models 확장 main 반영 → C1~C5, C6, L1 동시 시작 |
| 15:30 | C1~C5 1차 PR 머지 |
| 17:00 | **샘플 A 처음부터 끝까지 관통** (SBOM·PDF·로그) — 가장 중요한 이정표 |
| 21:00 | 정답지 대비 1차 채점, 판정 품질 개선 |
| 24:00 | 화면·PDF 다듬기, 가산점 프로젝트 1개 |
| 03:00 | A·B·C 최종 run1·run2, 단계별 비교표 |
| 06:00 | 발표자료, README |
| 07:00 | 깨끗한 환경에서 `run.sh` 재실행 후 제출 |
