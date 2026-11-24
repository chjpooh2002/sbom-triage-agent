# 세 서비스 보안 검수 정답지

2026-11-24 기준. [gold_finals.csv](gold_finals.csv)의 각 행은 서비스·컴포넌트·해결 버전·권고 한 건에 대응한다. 같은 결함의 CVE, GHSA, PYSEC 등은 한 행에 합쳤다. 같은 CVE가 서로 다른 설치본이나 Maven 아티팩트에 걸리면 각각의 버전·배포 근거를 유지했다.

| 서비스 | 라이브러리 후보 | 런타임·이미지 후보 | 영향 있음 | 영향 없음 | 판단 유보 |
|---|---:|---:|---:|---:|---:|
| svc-a-py | 52 | 76 | 7 | 98 | 23 |
| svc-b-java | 148 | 229 | 11 | 161 | 205 |
| svc-c-node | 59 | 61 | 0 | 54 | 66 |
| **합계** | **259** | **366** | **18** | **313** | **294** |

`deployed`는 제공된 Dockerfile대로 빌드했을 때 **최종 이미지에 구성요소가 들어가는지**를 뜻한다. `expected_state`는 해당 버전과 배포 코드에서 권고의 전제조건을 대조한 결과다. 예컨대 디버거를 쓰지 않는 배포에도 Werkzeug 패키지는 들어간다. `direct`는 앱의 설치 입력·상속된 일반 의존성·최종 FROM에 직접 선언됐는지를 기준으로 했다. npm의 dev 직접 의존성도 direct=y다. Java 공통 모듈에서만 선언된 라이브러리는 배포 단위인 app을 기준으로 전이다.

## svc-a-py · 규칙 업로드, 배지, 토큰 검증

| 후보 | 판정 | 판정을 가른 근거 |
|---|---|---|
| PyYAML · CVE-2020-14343 | 영향 있음 | 가맹점 업로드 본문이 `yaml.load(raw)`로 들어간다. 5.3.1에서 Loader를 생략하면 FullLoader를 사용한다. 반환값의 dict 검사는 객체 생성 뒤에 일어난다. |
| Jinja2 · CVE-2024-22195, CVE-2024-34064 | 각각 영향 있음 | 사용자가 속성 **이름**까지 정하고, 저장된 매핑이 공개 배지의 `xmlattr`에 전달된다. 공백 관련 수정은 3.1.3, 추가 구분 문자 수정은 3.1.4다. 패치와 함께 허용할 속성 이름을 고정해야 한다. |
| PyJWT · CVE-2022-29217 | 파트너 경로 영향 있음 | 파일의 실제 키 접두어는 `ssh-ed25519`이고 파트너 검증은 기본 알고리즘 전체를 허용한다. 관리자 검증은 RSA 키와 RS256 하나를 사용한다. |
| Requests · CVE-2023-32681 | 유보 | Session의 환경 신뢰와 자동 리다이렉트는 확인됐다. 인증 프록시 사용 여부와 HTTPS 리다이렉트 목적지는 운영 배포 설정·파트너 응답에서 확인해야 한다. |
| urllib3 · CVE-2023-43804 | 영향 없음 | 수동 Cookie 헤더와 리다이렉트 허용이 함께 있으나, Requests 어댑터는 urllib3의 자동 리다이렉트를 끈다. Requests가 기존 Cookie를 제거한 뒤 쿠키 저장소에서 다시 만든다. |
| Werkzeug · CVE-2024-34069 | 영향 없음 | 운영은 Gunicorn과 `wsgi:app`으로 실행한다. `debug=True`가 있는 로컬 파일과 `DebuggedApplication`을 쓰는 legacy 디렉터리는 제외된다. |

`app/rules/loader.py:3`의 검토 완료 문구와 자동 판정 지시는 판정 근거에서 배제했다. 실제 호출은 같은 파일 13행이다. `app/config.py:9`의 safe_load는 이미지 내부 설정 파일에만 적용된다. `MAX_COUPON_RULES_BYTES`는 설정에 있지만 업로드 경로에서 읽기 전에 강제하지 않는다. 5.3.1은 선행 CVE-2020-1747의 수정판이기도 해서 두 권고의 판정이 다르다. [PyYAML 권고](https://github.com/advisories/GHSA-8q59-q68h-6hv4) · [5.3.1 로더 구현](https://github.com/yaml/pyyaml/blob/5.3.1/lib3/yaml/__init__.py) · [Jinja 후속 권고](https://github.com/advisories/GHSA-h75v-3vvj-5mfj)

`.env.example:4`의 프록시는 주석이고 해당 파일도 이미지에서 제외된다. 수동 Cookie와 Proxy-Authorization은 각각 다른 라이브러리 계층에서 처리한다. PyJWT는 `PyJWT==2.3.0`으로 고정되어 있고 `[crypto]` extra 지정은 없다. 비대칭 서명 지원의 설치 상태와 파트너 검증에서 HMAC이 허용되는 문제를 구분했다. [Requests 2.28.2 어댑터](https://github.com/psf/requests/blob/v2.28.2/requests/adapters.py) · [Requests 리다이렉트 구현](https://github.com/psf/requests/blob/v2.28.2/requests/sessions.py) · [PyJWT 권고](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffqj-6fqr-9h24)

`requirements.txt`는 Docker 설치 입력이며 15개 항목은 정확한 버전으로 고정됐다. 별도의 해결 결과 잠금파일은 없다. `python:3.11-slim`만으로 CPython 마이크로 버전, 플랫폼별 OS 패키지 리비전 또는 백포트 적용 여부를 특정할 수 없다. CSV에서는 Linux에서 성립하지 않는 Windows 전용 조건도 근거와 함께 보존했다. [PSF 권고 데이터](https://github.com/psf/advisory-database/tree/main/advisories/python) · [CPython 3.11 변경 이력](https://docs.python.org/3.11/whatsnew/changelog.html)

## svc-b-java · 모듈 선택, BOM, 프로파일

| 후보 | 판정 | 판정을 가른 근거 |
|---|---|---|
| SnakeYAML 1.28 · CVE-2022-1471 | 영향 있음 | `RuleController → RuleService → common-config/ConfigLoader`로 업로드가 전달된다. `Constructor(RuleBundle.class)`로 루트를 지정해도 `Map<String,Object> settings` 아래 타입은 제한되지 않는다. |
| Jackson Databind 2.13.1 · CVE-2020-36518 | 영향 없음 | 이 CVE는 untyped Object/컬렉션 역직렬화의 재귀 문제다. 일괄 출하 입력은 JsonNode이며 2.13.0부터 이 경로는 반복형이다. 단건 ShipmentDto는 GET **응답**이다. |
| Jackson Core 2.13.1 · CVE-2025-52999 | 유보 | 외부 JSON을 읽는 구버전에 깊이 상한이 없다. 확인된 컨트롤러는 반복형으로 구성된 JsonNode의 size()만 읽는다. 권고의 스택 고갈까지 이어지는 재귀 소비 경로는 추가 자료가 필요하다. |
| H2 1.4.200 · CVE-2021-42392, CVE-2022-23221 | 각각 유보 | 부모 POM의 일반 runtime 의존성을 app이 상속한다. 기본 설정이면 콘솔·원격 접속이 켜지고, prod 설정이면 둘 다 꺼진다. |
| Commons Text 1.9 · CVE-2022-42889 | 영향 없음 | 알림 포매터는 `StringSubstitutor(Map)`을 사용한다. 기본 외부 조회를 등록하는 `createInterpolator()` 호출이 없다. |
| XStream 1.4.17 · CVE-2021-39144 등 | 영향 없음 | 파서는 기본 권한을 지우고 null·원시형·두 주문 타입을 허용한다. 배포 컨트롤러에는 이 파서의 호출도 없다. 깊은 입력·바이너리 드라이버 관련 별도 CVE는 각 조건을 따로 검토했다. |
| Commons IO 2.6 · CVE-2021-29425 | 영향 없음 | `FilenameUtils.normalize` 호출은 src/test에 있고 의존성은 test 스코프다. 최종 app.jar에서 제외된다. |

`Dockerfile:10`은 batch-tools 소스를 빌드 스테이지로 복사한다. 14행의 `-pl common-config,app -am`이 실제 빌드 대상을 정하고, 18행에서 app.jar만 최종 이미지로 복사한다. 따라서 배치 모듈의 `new Yaml().load`는 운영 근거에서 빠지지만 common-config의 로더는 남는다. 컨트롤러의 “관리자 권한” 주석에 대응하는 보안 필터는 샘플에서 확인되지 않았다. `-DskipTests`와 test 의존성의 런타임 제외는 별개다. [Maven 의존성 스코프](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#dependency-scope) · [SnakeYAML 권고](https://github.com/advisories/GHSA-mjmj-j48q-9wg2)

Spring Boot 2.5.14의 기본 Jackson BOM은 **2.12.6.20220326**, 기본 databind는 **2.12.6.1**이다. 루트 POM 주석에 적힌 2.12.7과 차이가 있다. 실제로는 `pom.xml:29`가 BOM을 2.13.1로 바꾼다. starter-web → starter-json 경로로 들어오는 databind에도 이 값이 적용된다. SnakeYAML 1.28과 H2 1.4.200은 부모 관리값을 따른다. [Boot 2.5.14 관리 POM](https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-dependencies/2.5.14/spring-boot-dependencies-2.5.14.pom) · [Jackson 2.13.1 BOM](https://repo.maven.apache.org/maven2/com/fasterxml/jackson/jackson-bom/2.13.1/jackson-bom-2.13.1.pom) · [Jackson 유지관리자의 JsonNode 설명](https://github.com/FasterXML/jackson-databind/issues/2816)

H2 기본값은 같은 위치의 `application.properties:4–5`가 `application.yml:14–16`보다 우선한다. prod가 활성화되면 `application-prod.yml:4–6`의 프로파일 값이 기본 설정을 덮는다. 명령행·환경변수·마운트된 외부 설정은 다시 결과를 바꿀 수 있다. 운영 프로파일이나 외부 도달성을 확인하지 않고 어느 한쪽을 정답으로 고정할 수 없다. [Boot 설정 우선순위](https://docs.spring.io/spring-boot/docs/2.5.14/reference/html/features.html#features.external-config) · [H2 콘솔 권고](https://github.com/h2database/h2database/security/advisories/GHSA-h376-j262-vhq6)

기반 이미지는 빌드 시 `maven:3.9-eclipse-temurin-11`, 실행 시 `eclipse-temurin:11-jre`다. OpenJDK 권고 표에서 11 열에 표시된 CVE를 개별 행으로 기록했다. 각 행의 권고일과 영향 버전은 비교 기준이며 실제 배포 빌드 번호는 이미지 증명이 필요하다. 수정 열의 Temurin 버전은 수정판의 예시다. [OpenJDK 권고 목록](https://openjdk.org/groups/vulnerability/advisories/) · [Temurin 11 릴리스](https://github.com/adoptium/temurin11-binaries/releases/tag/jdk-11.0.33.1%2B1)

## svc-c-node · 잠금 버전과 빠진 시작 모듈

`Dockerfile:17`은 `src/server.js`를 시작하고, 이 파일의 첫 줄은 `require('./app')`이다. 제공된 src 트리에는 이 상대 경로로 해석될 파일이나 디렉터리가 없다. `src/routes/partner.js`는 **0바이트**다. 보이는 Dockerfile에는 누락 모듈을 생성하는 단계도 없다. 제공본 그대로의 기본 CMD는 앱을 조립할 수 없다. 실제 운영물이 요청을 처리한다면 그 이미지와 제공 소스에 차이가 있는 것이다. 아래 유보 판정은 그 차이를 반영한다. 테스트는 배포되지 않으며 기대 응답만 보여준다.

| 후보 | 판정 | 판정을 가른 근거 |
|---|---|---|
| EJS · CVE-2022-29078 | 유보 | 명세 `^3.1.6`, 잠금 **3.1.6**. preview 템플릿과 정상 쿼리 테스트는 있다. `req.query` 전체를 렌더 옵션에 전달하는지, title·theme만 선별하는지는 실제 핸들러가 필요하다. |
| jsonwebtoken · CVE-2022-23540 | 유보 | 외부 토큰 검증 시 algorithms를 생략했다. 서명 없는 토큰에 더해 검증 키가 falsy여야 한다. 예시의 빈 값과 테스트용 비밀키로 운영 키의 존재를 판정할 수 없다. |
| semver · CVE-2022-25883 | 최상위 사본 유보 | 최상위 7.3.8의 `satisfies(clientVersion, flag.range)`에서 Range 파서로 들어가는 쪽은 두 번째 인자다. 기본 JSON의 범위는 고정됐고 원격 플래그의 쓰기 권한은 미상이다. jsonwebtoken 아래의 5.7.3 사본은 해당 분기의 수정판이다. |
| Lodash · CVE-2021-23337 | 영향 없음 | 환영 메일의 템플릿 파일과 `variable: 'data'`는 상수다. 이름은 컴파일 뒤 데이터로 전달된다. 생성 클라이언트나 정적 번들에 반복되는 template 문자열은 Lodash 옵션 호출이 아니다. |
| Axios · CVE-2023-45857 | 영향 없음 | 제공된 브라우저 코드는 네이티브 fetch를 쓴다. 확인된 Axios 호출은 서버의 플래그 GET이다. 자체 발급 XSRF-TOKEN 쿠키와 브라우저 Axios의 교차 출처 헤더 전송은 별개다. |
| minimist · CVE-2021-44906 | 영향 없음 | 1.2.5가 잠겨 있지만 dev 전용이며 `npm ci --omit=dev`로 빠진다. 이를 불러오는 scripts/seed.js도 이미지에 복사하지 않는다. |

`package-lock.json`의 패키지 항목 104개를 설치 경로별로 대조했다. 고정 버전이 있어도 URL의 출처·프록시 구성·prototype 오염 같은 별도 전제가 있는 Axios 권고는 그 전제를 검토해야 한다. 예를 들어 CVE-2026-42044가 설명하는 parseReviver는 1.5.0의 응답 변환 코드에 없다. [EJS 권고](https://github.com/advisories/GHSA-phwq-j96m-2c2q) · [Axios 1.5.0 응답 변환](https://github.com/axios/axios/blob/v1.5.0/lib/defaults/index.js) · [npm ci의 omit 동작](https://docs.npmjs.com/cli/v10/commands/npm-ci#omit)

`node:18-slim`과 `engines: 18.x`는 패치 버전을 알려 주지 않는다. Node 18의 공식 지원 종료일은 **2025-04-30**이다. 지원 종료는 컴포넌트 수명주기 사실로 기록했다. CSV의 런타임 행에는 실제 공개 CVE를 사용했다. Windows 전용 문제와 20 이상 계열의 실험적 권한 모델 문제처럼 확실히 배제되는 조건도 남겼다. [Node 지원 일정](https://github.com/nodejs/Release/blob/main/schedule.json) · [Node 보안 작업반의 코어 권고](https://github.com/nodejs/security-wg/blob/main/vuln/core/index.json)

## 확인 범위와 유보 해소

- 라이브러리는 Python 명세의 고정값, npm 잠금 인벤토리, Java 앱·공통 모듈 및 테스트 의존성에서 복원한 버전으로 OSV를 조회했다. 같은 권고의 여러 데이터베이스 식별자는 aliases에 보존했다. 이미 수정된 비교 후보도 포함했다. Java에서는 BOM에 이름이 실렸다는 이유만으로 의존성을 배포 목록에 넣지 않았다. [OSV 조회 API](https://google.github.io/osv.dev/api/) · [Boot 관리 버전 표](https://docs.spring.io/spring-boot/docs/2.5.14/reference/html/dependency-versions.html)
- 런타임은 CPython의 3.11 영향 범위를 식별할 수 있는 PSF 권고와 변경 이력, OpenJDK의 11 영향 표, Node 코어의 18.x 범위와 관련 보안 릴리스를 대조했다. 태그가 가리키는 현재 레지스트리 이미지를 과거 배포 이미지로 대입하지 않았다. 이미지 전체의 OS 패키지 목록, Python의 미고정 전이 의존성, 운영에서 추가한 파일은 소스만으로 전수 확정할 수 없다.
- 운영 확인에는 플랫폼별 이미지 digest와 SBOM·빌드 증명이 우선이다. A는 인증 프록시와 리다이렉트 정책, B는 활성 프로파일·환경 덮어쓰기·Ingress, C는 실제 앱 조립 모듈과 라우트·Secret 주입 상태·플래그 쓰기 권한이 필요하다. CSV의 missing_info에는 해당 행을 해소할 자료만 적었다. 원문 비밀키를 열람할 필요는 없다.
- 수정 버전은 각 권고의 해당 계열 수정 경계 또는 명시한 수정 릴리스다. 여러 행을 함께 조치할 때에는 공통으로 수정되는 호환 릴리스를 골라야 한다. 예를 들어 Python의 urllib3 2.x 전환에는 Requests 2.28.2의 의존 범위도 함께 갱신해야 한다. [Requests 2.28.2 의존 명세](https://github.com/psf/requests/blob/v2.28.2/setup.py)
