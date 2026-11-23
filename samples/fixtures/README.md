# 형식별 입력 샘플

변환기 테스트용 **실제 도구 출력**이다. 측정에 쓰지 않는다.
대상은 `target/pom.xml`(log4j-core 2.14.1, commons-text 1.9, snakeyaml 1.29, guava 33.3.1-jre) 하나다.

| 파일 | 만든 명령 | 도구 버전 |
| --- | --- | --- |
| sbom.cdx.json / sbom.spdx.json | `syft dir:target -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json` | syft 1.54.1 |
| grype.json | `grype sbom:sbom.cdx.json -o json` | grype 0.121.0 |
| trivy.json | `docker run --rm -v <target>:/src aquasec/trivy:0.69.1 fs --scanners vuln --format json /src` | trivy 0.69.1 |
| osv.json | `docker run --rm -v <target>:/src ghcr.io/google/osv-scanner:v2.2.4 scan source --format json -r /src` | osv-scanner 2.2.4 |

참고: syft·trivy는 pom에 선언된 직접 의존성만 잡고, osv-scanner는 전이 의존성(log4j-api, commons-lang3)까지 풀어서 잡는다.
같은 대상이라도 도구마다 구성요소 수가 다르다는 점을 병합 테스트에서 확인한다.
