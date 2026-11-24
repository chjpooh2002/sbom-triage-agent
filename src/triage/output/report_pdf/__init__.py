"""근거와 조치 계획을 한국어 PDF로 내보낸다."""
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from jinja2 import Environment

from triage.models import Evidence, TriageBundle

from .._common import (
    artifact_evidence, file_location, finding_state, public_url, write_artifact,
)
from .._redact import Redactor


_DIRECTORY = Path(__file__).parent
_STATES = {"affected": "영향 있음", "not_affected": "영향 없음", "undetermined": "판단 유보"}
_DEPLOYMENT = {"yes": "배포됨", "no": "배포되지 않음", "unknown": "확인되지 않음"}
_CONDITIONS = {"met": "충족", "not_met": "미충족", "unknown": "확인되지 않음"}
_FILE_SCOPE = {"yes": "배포 포함", "no": "배포 제외", "unknown": "배포 여부 미확인"}
_SNAPSHOT_DATE = re.compile(r"^data/cache/lookup/(\d{4}-\d{2}-\d{2})/")
_LOOKUP_NAMES = {
    "api.osv.dev": "OSV", "osv.dev": "OSV",
    "services.nvd.nist.gov": "NVD", "nvd.nist.gov": "NVD",
    "www.cisa.gov": "CISA KEV", "www.first.org": "FIRST EPSS",
}


def _evidence_details(ids: Iterable[str], by_id: dict[str, Evidence]) -> list[dict]:
    return [
        {
            "id": item.id,
            "location": file_location(item),
            "has_line": item.line_start is not None,
            "url": item.url,
            "snippet": "\n".join(item.snippet.splitlines()[:2]),
        }
        for item_id in dict.fromkeys(ids)
        if (item := by_id.get(item_id)) is not None
    ]


def _file_groups(bundle: TriageBundle, by_id: dict[str, Evidence]) -> dict:
    groups = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for file in sorted(bundle.files, key=lambda item: item.path):
        status = file.deployed if file.deployed in _FILE_SCOPE else "unknown"
        groups[status][file.category or "other"][(file.reason, tuple(file.evidence_ids))].append(file.path)
    return {
        label: {
            category: [
                {"reason": reason, "paths": paths, "evidence": _evidence_details(ids, by_id)}
                for (reason, ids), paths in records.items()
            ]
            for category, records in sorted(groups[status].items())
        }
        for status, label in _FILE_SCOPE.items()
        if status in groups
    }


def _lookup_sources(bundle: TriageBundle, meta: dict) -> list[dict]:
    sources = {}
    for evidence in bundle.evidence:
        if not evidence.id.startswith("lookup-") or not public_url(evidence.url):
            continue
        host = urlsplit(evidence.url).hostname
        name = _LOOKUP_NAMES.get(host, host)
        source = sources.setdefault(name, {"url": evidence.url, "dates": set()})
        if match := _SNAPSHOT_DATE.match(evidence.file.replace("\\", "/")):
            source["dates"].add(match[1])
    if epss := sources.get("FIRST EPSS"):
        epss["dates"].update(
            item.signals.epss_date for item in bundle.findings if item.signals.epss_date
        )
    records = meta.get("lookup_sources")
    if isinstance(records, (list, tuple)):
        for record in records:
            name = record.get("name") if isinstance(record, dict) else None
            if not isinstance(name, str) or not name:
                continue
            source = sources.setdefault(name, {"url": "", "dates": set()})
            if url := record.get("url"):
                source["url"] = url
            if retrieved_at := record.get("retrieved_at"):
                source["retrieved_at"] = retrieved_at
    return [
        {**source, "name": name, "dates": sorted(source["dates"])}
        for name, source in sorted(sources.items())
    ]


def _context(bundle: TriageBundle, meta: dict) -> dict:
    priorities = {priority.finding_key: priority for priority in bundle.results}
    remediations = {remediation.finding_key: remediation for remediation in bundle.remediations}
    by_id = {item.id: item for item in bundle.evidence}
    # 본문의 버전·배포·조회 근거와 별도로, 부록은 판정 조건의 직접 인용만 모은다.
    decision_ids = []
    groups: dict[str, list[dict]] = {state: [] for state in _STATES}
    for finding in bundle.findings:
        verdict = finding.verdict
        priority = priorities.get(finding.key)
        remediation = remediations.get(finding.key)
        verdict_ids = [ref for item in verdict.item_results for ref in item.evidence_ids] if verdict else []
        decision_ids.extend(verdict_ids)
        lookup_ids = finding.hints.get("evidence_ids")
        lookup_ids = [ref for ref in lookup_ids if isinstance(ref, str)] if isinstance(lookup_ids, list) else []
        groups[finding_state(finding)].append({
            "component": finding.component.model_dump(mode="json"),
            "vulnerability": finding.vulnerability.model_dump(mode="json"),
            "asset": finding.asset_id,
            "status_note": finding.status_note,
            "version_in_range": finding.version_in_range,
            "verdict": verdict.model_dump(mode="json") if verdict else {},
            "priority": priority.model_dump(mode="json") if priority else {},
            "remediation": remediation.model_dump(mode="json") if remediation else {},
            "evidence": _evidence_details([*verdict_ids, *finding.component.evidence_ids, *lookup_ids], by_id),
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
    components = [*bundle.components, *(finding.component for finding in bundle.findings)]
    return {
        "meta": meta,
        "components_count": len({item.id for item in components}),
        "ecosystems": sorted({item.ecosystem for item in components if item.ecosystem}),
        "file_groups": _file_groups(bundle, by_id),
        "lookup_sources": _lookup_sources(bundle, meta),
        "findings_count": len(bundle.findings),
        "groups": groups,
        "top_actions": groups["affected"][:3],
        "work_requests": work_requests,
        "states": _STATES,
        "deployment": _DEPLOYMENT,
        "conditions": _CONDITIONS,
        "anomalies": sorted(Counter(item.kind for item in bundle.anomalies).items()),
        "decision_evidence": _evidence_details(decision_ids, by_id),
    }


def render_pdf(bundle: TriageBundle, meta: dict, out: Path) -> list[Evidence]:
    """PDF를 저장하고 생성 근거를 반환한다.

    조회 기록은 meta의 lookup_at 또는 lookup_sources(name, url, retrieved_at)로 전달한다.
    """
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
    context = Redactor().value(_context(bundle, {**bundle.meta, **meta}))
    font = (_DIRECTORY / "fonts" / "NotoSansKR.ttf").resolve().as_uri()
    template = (_DIRECTORY / "report.html").read_text(encoding="utf-8")
    page = environment.from_string(template).render(**context, font=font)
    fetcher = URLFetcher(allowed_protocols={"file"})
    pdf = HTML(string=page, url_fetcher=fetcher).write_pdf(font_config=FontConfiguration())
    write_artifact(out, pdf)
    return [evidence]
