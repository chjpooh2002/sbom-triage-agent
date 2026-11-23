# SW 공급망 스캐닝 에이전트

SBOM(CycloneDX·SPDX)과 취약점 스캔 결과(Trivy·Grype·OSV-Scanner), 자산 목록(엑셀·CSV)을 하나의 구조로 정규화하고,
CISA KEV·EPSS·CVSS·외부 노출·자산 중요도로 **결정적 우선순위**를 매긴 뒤, 언어 모델로 조치안을 만들고
**모델이 제안한 목표 버전을 규칙으로 재검증**해 현업 담당자용 한국어 보고서(마크다운·엑셀)로 낸다.

작업 규칙은 [AGENTS.md](AGENTS.md)(Claude Code·Codex 공용)에 있다.

## 흐름

```
입력(어떤 형식이든)          정규화                  보강               우선순위(규칙)              조치안(모델+규칙)            산출물
SBOM / 스캔 / 자산표  →  변환기 → 공통 구조  →  KEV·EPSS 캐시  →  영향 없음 → KEV → 가중 점수  →  묶음별 초안 → 버전 재검증  →  보고서·화면
                         (ingest/)              (intel/)           (priority/, policy.yaml)       (remediation/)               (report/, app/)
```

- **순위는 규칙, 설명은 모델**: 등급·순위·기한은 `config/policy.yaml`의 계층 규칙으로만 정한다. 모든 결과에 판단 근거(신호별 기여, 결측 가정, 보정 규칙, 기한 계산)를 남긴다.
- **모델 출력은 믿지 않고 검증**: 목표 버전이 실제로 배포된 버전인지, 같은 구성요소의 급한 취약점을 모두 고치는지 규칙으로 확인하고, 아니면 규칙이 고른 버전으로 바꾼다.
- **네트워크 없이도 동작**: KEV·EPSS 전체 파일을 캐시해 두고 보강은 캐시만 읽는다. 키가 없으면 템플릿 조치안으로 대체한다.

## 빠른 시작

```bash
uv sync
uv run triage fetch-intel                 # KEV·EPSS 전체 파일 캐시 (본선 전날 꼭 실행)
uv run triage run samples/demo-app/scan   # 시연 데이터로 전체 실행 → out/report.md, out/report.xlsx
uv run streamlit run app/streamlit_app.py # 시연 화면
uv run pytest                             # 테스트
```

모델을 쓰려면 `.env.example`을 `.env`로 복사하고 `LLM_PROVIDER=anthropic`(또는 `openai`)과 키를 넣는다.
처음에는 `uv run triage remediate --provider anthropic --llm-limit 1`로 1건만 확인한다.

## 명령

| 명령 | 하는 일 |
| --- | --- |
| `triage formats` | 등록된 변환기 목록 |
| `triage ingest 입력... [-o out/bundle.json]` | 정규화만. 자동 매칭이 안 되는 입력은 `경로=자산ID` |
| `triage prioritize [bundle] [--as-of YYYY-MM-DD] [--policy 파일]` | KEV·EPSS 보강 + 우선순위·기한·근거 |
| `triage remediate [bundle] [--provider] [--llm-limit N] [--offline]` | 조치안 + 목표 버전 재검증 |
| `triage run 입력... [-o out]` | 위 전부 + 보고서(md·xlsx) |
| `triage eval --gold eval/gold.csv [--check] [-o 결과.md]` | 정답 사례와 비교한 정확도(규칙 엔진 vs CVSS 단독) |
| `triage fetch-intel [--only kev\|epss]` | KEV·EPSS 내려받기(실패해도 기존 캐시 유지) |

## 본선 당일: 새 형식이 오면

1. `uv run triage formats`와 `uv run triage ingest 파일`로 기존 변환기가 알아보는지 먼저 본다.
2. 자산표 열 이름만 다르면 코드 수정 없이 `config/ingest.yaml`에 별칭을 추가한다(값 해석도 같은 파일).
3. 새 스캔·SBOM 형식이면 `src/triage/ingest/`에 변환기 하나를 추가한다. 예시는 `tests/test_extensibility.py`(CSV 스캔 결과, 30줄 안팎).
   ```python
   @register("vendor-csv", kind="scan", sniff=lambda path, raw: ..., priority=10)
   def parse(path, raw) -> ParsedInput:  # 원본 → Component / Vulnerability / Finding
       ...
   ```
   모듈을 `src/triage/ingest/__init__.py`의 import 목록에 넣으면 이후 단계(보강·우선순위·조치안·보고서·화면)는 그대로 돈다.
4. 기준값(가중치·임계값·기한)은 `config/policy.yaml`에서만 바꾼다. 정책 해시가 보고서에 찍힌다.
5. 현장 데이터는 `data/field/`에만 둔다(커밋되지 않음).

## 시연 샘플 (`samples/demo-app/`)

Spring Boot 2.6.1 + `spring-boot-starter-log4j2`. log4j-core 2.14.1이 **전이 의존성**으로 들어오고 실제 로깅 백엔드로 쓰인다
(`spring-boot-starter-log4j2 → log4j-slf4j-impl → log4j-core`). 배포하지 않는다.

```bash
export JAVA_HOME=<JDK 17 경로>
bash scripts/scan.sh                      # → samples/demo-app/scan/ (syft CDX·SPDX, Gradle CDX, grype, trivy, osv)
uv run triage run samples/demo-app/scan --as-of 2026-11-24 -o out/demo
```

`samples/demo-app/scan/assets.xlsx`의 `스캔대상` 열(`demo-shop`)로 스캔 결과가 자산 "온라인몰 주문 API"(외부 노출, 중요도 상)에 연결된다.
결과: 취약점 152건 → 조치 단위 18개, 1위 CVE-2021-44228(KEV, 전이 경로 표시), log4j-core 2.14.1 → 2.25.4(같은 메이저, 8건 해결).

## 정확도 측정

정답 사례(`eval/gold.csv`)는 **엔진을 만든 쪽이 아니라 Codex가 만들고 사람이 검증**한다. 작성 지침은 [eval/GOLD_GUIDE.md](eval/GOLD_GUIDE.md).
KEV·EPSS·CVSS 값을 사례 안에 고정하므로 외부 값이 바뀌어도 채점이 흔들리지 않는다.
지표: 정확 일치, 한 단계 이내, P1 재현율, 불필요 P1, 과소 평가(놓침 위험), 순위 상관(τ), CVSS 단독 기준선과 비교.

## 폴더

```
config/          policy.yaml(우선순위 정책) · ingest.yaml(자산표 열 별칭) · intel.yaml(위협 정보 출처)
src/triage/      models.py · ingest/ · intel/ · priority/ · remediation/ · report/ · evaluation/ · pipeline.py · cli.py
app/             스트림릿 화면
eval/            정답 작성 지침 · 양식 · 측정 결과
samples/         fixtures(형식별 실제 도구 출력) · demo-app(시연 앱과 스캔 결과)
data/snapshot/   테스트용 KEV·EPSS 발췌본(전체 캐시는 data/cache/, 커밋 안 함)
```

## 한계

- 코드 도달성(취약 함수를 실제로 호출하는지)은 보지 않는다. 판단은 KEV·EPSS·CVSS·자산 맥락·VEX 기준이다.
- 우선순위 정책의 가중치·임계값은 첫 추정치다. 정답 세트가 준비되면 측정 후 보정한다(사례 하나에 맞추는 조정은 하지 않음).
- 모델 공급자 코드는 가짜 클라이언트로만 시험했다(이 저장소 작업 중에는 API 키가 없었다).
