#!/usr/bin/env bash
# 분석 대상 스프링 부트 프로젝트를 빌드하고 SBOM과 취약점 스캔 결과를 만든다.
# 사용: bash scripts/scan.sh [앱 폴더=samples/demo-app] [출력 폴더=<앱 폴더>/scan]
# 필요: JDK 17(JAVA_HOME), syft, grype, docker(trivy·osv-scanner 용, 없으면 건너뜀)
set -euo pipefail

APP_DIR="${1:-samples/demo-app}"
OUT_DIR="${2:-$APP_DIR/scan}"
TRIVY_IMAGE="aquasec/trivy:0.69.1"
OSV_IMAGE="ghcr.io/google/osv-scanner:v2.2.4"
mkdir -p "$OUT_DIR"
NAME=$(sed -n "s/rootProject.name *= *'\(.*\)'/\1/p" "$APP_DIR/settings.gradle")

# 1) 실행 jar 와 Gradle 의존 그래프 SBOM(직접/전이 구분용)
(cd "$APP_DIR" && ./gradlew -q bootJar cyclonedxBom)
JAR=$(ls "$APP_DIR"/build/libs/*.jar | grep -v plain | head -1)
cp "$APP_DIR/build/reports/$NAME.gradle.cdx.json" "$OUT_DIR/"

# 2) 실행 jar 기준 SBOM(실제로 배포되는 구성요소)
syft "$JAR" -q -o cyclonedx-json="$OUT_DIR/$NAME.cdx.json" -o spdx-json="$OUT_DIR/$NAME.spdx.json"

# 3) 취약점 스캔
grype "sbom:$OUT_DIR/$NAME.cdx.json" -q -o json > "$OUT_DIR/$NAME.grype.json"
if command -v docker >/dev/null 2>&1; then
  ABS_JAR_DIR=$(cd "$(dirname "$JAR")" && pwd -W 2>/dev/null || pwd)
  ABS_OUT=$(cd "$OUT_DIR" && pwd -W 2>/dev/null || pwd)
  MSYS_NO_PATHCONV=1 docker run --rm -v "$ABS_JAR_DIR:/work/$NAME" -v trivy-cache:/root/.cache "$TRIVY_IMAGE" \
    rootfs --scanners vuln --format json --quiet "/work/$NAME/$(basename "$JAR")" > "$OUT_DIR/$NAME.trivy.json"
  # osv-scanner 는 종료 코드 1 = 취약점 발견
  MSYS_NO_PATHCONV=1 docker run --rm -v "$ABS_OUT:/work" "$OSV_IMAGE" \
    scan source --format json -L "/work/$NAME.spdx.json" > "$OUT_DIR/$NAME.osv.json" || [ $? -eq 1 ]
else
  echo "docker 없음: trivy·osv-scanner 건너뜀" >&2
fi
echo "완료: $OUT_DIR"
ls -la "$OUT_DIR"
