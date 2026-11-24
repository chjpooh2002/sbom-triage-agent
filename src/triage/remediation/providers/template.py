"""키 없이 동작하는 규칙 기반 조치안. 모델 호출이 실패했을 때의 대체 수단이기도 하다."""
from __future__ import annotations

from ..prompt import RemediationDraft


def _force_snippet(eco: str, coord: str, version: str) -> str:
    if eco == "maven":
        g, _, a = coord.partition(":")
        return (f"Gradle: dependencies {{ constraints {{ implementation('{g}:{a}:{version}') }} }} / "
                f"Maven: <dependencyManagement> 에 {g}:{a}:{version} 고정")
    if eco == "npm":
        return f'package.json "overrides": {{ "{coord}": "{version}" }}'
    if eco == "pypi":
        return f"requirements/constraints 에 {coord}=={version} 고정"
    return f"{coord} 를 {version} 으로 고정"


class TemplateProvider:
    name = "template"
    model = "rules"
    init_warning = ""

    def draft(self, ctx: dict) -> RemediationDraft:
        comp = ctx["component"]
        coord = comp["name"].rsplit("@", 1)[0]
        target = ctx.get("rule_suggestion")
        vulns = ctx["vulnerabilities"]
        ids = ", ".join(v["id"] for v in vulns[:5]) + (f" 외 {len(vulns) - 5}건" if len(vulns) > 5 else "")
        kev = [v["id"] for v in vulns if v.get("kev")]
        top = vulns[0]
        risk = (f"{', '.join(kev)} 은 실제 악용이 확인된 취약점(KEV)이다. " if kev else "") + \
               f"가장 높은 등급은 {top['tier']}(기한 {top.get('due_date') or '없음'})이다."
        transitive = comp.get("direct") is False
        path = " → ".join(p.rsplit("/", 1)[-1] for p in comp["dependency_paths"][0]) if comp.get("dependency_paths") else ""
        if target:
            summary = f"{coord} {comp['installed_version']} 의 관련 권고문은 {len(vulns)}건({ids})이다. {risk} {target} 적용 후 영향 범위를 다시 확인한다."
            steps = []
            if transitive:
                steps.append(f"이 라이브러리는 전이 의존성이다{f'({path})' if path else ''}. 먼저 상위 라이브러리를 최신으로 올려 해결되는지 확인한다.")
                steps.append(f"해결되지 않으면 버전을 강제한다: {_force_snippet(comp['ecosystem'], coord, target)}")
            else:
                steps.append(f"빌드 파일에서 {coord} 버전을 {target} 으로 바꾼다.")
            steps += ["의존성 트리를 다시 확인해 다른 경로로 낮은 버전이 들어오지 않는지 본다(gradle dependencies / mvn dependency:tree).",
                      "회귀 테스트 후 배포하고, SBOM을 다시 생성해 스캔 결과에서 사라졌는지 확인한다."]
        else:
            summary = f"{coord} {comp['installed_version']} 의 관련 권고문은 {len(vulns)}건({ids})이고 확인된 수정 버전이 없다. {risk}"
            steps = ["벤더 권고와 이슈 트래커에서 수정 계획을 확인한다.", "취약한 기능을 끄거나 대체 라이브러리를 검토한다.",
                     "외부 노출 경로에 차단 규칙(WAF 등)을 적용하고 모니터링한다."]
        notes = ctx.get("rule_notes") or []
        if notes:
            summary += " (" + "; ".join(notes) + ")"
        return RemediationDraft(target_version=target, summary_ko=summary, steps=steps,
                                workaround="업그레이드 전까지 벤더 권고의 임시 완화책을 적용하고, 외부 노출 경로의 접근을 제한한다.")
