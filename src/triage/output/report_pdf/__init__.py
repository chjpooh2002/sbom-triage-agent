"""근거와 조치 계획을 한국어 PDF로 내보낸다."""
from pathlib import Path

from jinja2 import Environment

from triage.models import Evidence, TriageBundle

from .._common import (
    artifact_evidence, file_location, finding_evidence, finding_state, public_url, write_artifact,
)
from .._redact import Redactor


_DIRECTORY = Path(__file__).parent
_STATES = {"affected": "영향 있음", "not_affected": "영향 없음", "undetermined": "판단 유보"}
_DEPLOYMENT = {"yes": "배포됨", "no": "배포되지 않음", "unknown": "확인되지 않음"}
_CONDITIONS = {"met": "충족", "not_met": "미충족", "unknown": "확인되지 않음"}


def _context(bundle: TriageBundle, meta: dict, evidence: Evidence) -> dict:
    priorities = {priority.finding_key: priority for priority in bundle.results}
    remediations = {remediation.finding_key: remediation for remediation in bundle.remediations}
    groups: dict[str, list[dict]] = {state: [] for state in _STATES}
    for finding in bundle.findings:
        verdict = finding.verdict
        priority = priorities.get(finding.key)
        remediation = remediations.get(finding.key)
        groups[finding_state(finding)].append({
            "component": finding.component.model_dump(mode="json"),
            "vulnerability": finding.vulnerability.model_dump(mode="json"),
            "asset": finding.asset_id,
            "status_note": finding.status_note,
            "version_in_range": finding.version_in_range,
            "verdict": verdict.model_dump(mode="json") if verdict else {},
            "priority": priority.model_dump(mode="json") if priority else {},
            "remediation": remediation.model_dump(mode="json") if remediation else {},
            "evidence_ids": finding_evidence(finding),
        })
    for findings in groups.values():
        findings.sort(key=lambda item: (
            item["priority"].get("tier", "P5"), item["priority"].get("rank") or float("inf"),
            item["vulnerability"]["id"], item["component"]["id"], item["asset"] or "",
        ))
    work_requests = [
        item for findings in groups.values() for item in findings
        if item["verdict"].get("work_request")
    ]
    return {
        "meta": meta,
        "components_count": len({item.id for item in bundle.components}
                                | {item.component.id for item in bundle.findings}),
        "findings_count": len(bundle.findings),
        "groups": groups,
        "work_requests": work_requests,
        "states": _STATES,
        "deployment": _DEPLOYMENT,
        "conditions": _CONDITIONS,
        "anomalies": [item.model_dump(mode="json") for item in bundle.anomalies],
        "evidence": [
            {**item.model_dump(mode="json"), "location": file_location(item)}
            for item in [*bundle.evidence, evidence]
        ],
    }


def render_pdf(bundle: TriageBundle, meta: dict, out: Path) -> list[Evidence]:
    """HTML을 렌더링해 PDF를 저장하고 이번 출력의 근거를 돌려준다."""
    from weasyprint import HTML
    from weasyprint.text.fonts import FontConfiguration
    from weasyprint.urls import URLFetcher

    evidence = artifact_evidence("pdf", out, "한국어 취약점 조치 보고서 생성", bundle)
    environment = Environment(
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["public_url"] = public_url
    context = Redactor().value(_context(bundle, {**bundle.meta, **meta}, evidence))
    font = (_DIRECTORY / "fonts" / "NotoSansKR.ttf").resolve().as_uri()
    template = (_DIRECTORY / "report.html").read_text(encoding="utf-8")
    page = environment.from_string(template).render(**context, font=font)
    fetcher = URLFetcher(allowed_protocols={"file"})
    pdf = HTML(string=page, url_fetcher=fetcher).write_pdf(font_config=FontConfiguration())
    write_artifact(out, pdf)
    return [evidence]
