# SW 공급망 스캐닝 에이전트

SBOM(CycloneDX·SPDX)과 취약점 스캔 결과(Trivy·Grype·OSV-Scanner), 자산 목록(엑셀·CSV)을 하나의 구조로 정규화하고,
CISA KEV·EPSS·CVSS·외부 노출·자산 중요도로 우선순위를 매긴 뒤, 언어 모델로 조치안을 만들어 한국어 보고서로 낸다.

작업 규칙은 [AGENTS.md](AGENTS.md)에 있다.

## 빠른 시작
```bash
uv sync
uv run pytest
```
