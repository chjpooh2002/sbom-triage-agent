"""근거와 조치 계획을 한국어 PDF로 내보낸다."""
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from jinja2 import Environment

from triage.models import Evidence, Finding, TriageBundle

from .._common import (
    artifact_evidence, file_location, finding_state, public_url, write_artifact,
)
from .._redact import Redactor


_DIRECTORY = Path(__file__).parent
_STATES = {"affected": "영향 있음", "not_affected": "영향 없음", "undetermined": "판단 유보"}
_DEPLOYMENT = {"yes": "배포됨", "no": "배포되지 않음", "unknown": "확인되지 않음"}
_CONDITIONS = {"met": "충족", "not_met": "미충족", "unknown": "확인되지 않음"}
_FILE_SCOPE = {"yes": "배포됨", "no": "미배포", "unknown": "배포 미확인"}
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


def _appendix_citations(ids: Iterable[str], by_id: dict[str, Evidence]) -> list[dict]:
    citations = {}
    for item in _evidence_details(ids, by_id):
        url = public_url(item["url"])
        location = item["location"] if item["has_line"] or not url else ""
        citation = citations.setdefault((location, url), {
            "location": location, "has_line": item["has_line"], "url": url, "ids": [],
        })
        citation["ids"].append(item["id"])
    return list(citations.values())


def _folders(bundle: TriageBundle, by_id: dict[str, Evidence]) -> list[dict]:
    folders = defaultdict(list)
    for file in sorted(bundle.files, key=lambda item: item.path):
        path = PurePosixPath(file.path.replace("\\", "/"))
        folders[path.parent.as_posix()].append((path.name, file))
    result = []
    for folder, files in sorted(folders.items()):
        states = Counter()
        reasons = defaultdict(Counter)
        refs = Counter()
        entries = defaultdict(list)
        for name, file in files:
            state = file.deployed if file.deployed in _FILE_SCOPE else "unknown"
            reason = file.reason or "분류 사유 미기록"
            states[state] += 1
            reasons[state][reason] += 1
            refs.update(dict.fromkeys(file.evidence_ids).keys())
            entries[(state, file.category or "other", reason)].append(name)
        representatives = (
            ref for ref, _ in refs.most_common()
            if ref in by_id and (by_id[ref].file or by_id[ref].url)
        )
        result.append({
            "path": folder, "counts": states,
            "reasons": [
                {"state": _FILE_SCOPE[state], "text": reasons[state].most_common(1)[0][0],
                 "others": len(reasons[state]) - 1}
                for state in _FILE_SCOPE if state in reasons
            ],
            "evidence": _evidence_details(representatives, by_id)[:2],
            "entries": [
                {"state": _FILE_SCOPE[state], "category": category, "reason": reason, "names": names}
                for (state, category, reason), names in sorted(entries.items())
            ],
        })
    return result


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


def _link_label(url: str) -> str:
    parts = urlsplit(url)
    if parts.hostname == "github.com" and "/advisories/" in parts.path:
        return "GHSA"
    return _LOOKUP_NAMES.get(parts.hostname, parts.hostname or "")


def _references(urls: Iterable[str]) -> list[str]:
    preferred = {"OSV": 0, "GHSA": 0, "NVD": 1}
    links = dict.fromkeys(filter(None, map(public_url, urls)))
    return sorted(links, key=lambda url: preferred.get(_link_label(url), 2))


def _reason(finding: Finding, state: str) -> str:
    verdict = finding.verdict
    if verdict and (verdict.rationale_ko or verdict.plain_ko):
        return verdict.rationale_ko or verdict.plain_ko
    if finding.status_note:
        return finding.status_note
    if verdict and (reason := next((item.reason for item in verdict.item_results if item.reason), "")):
        return reason
    if state == "not_affected":
        if finding.version_in_range is False:
            return "설치 버전이 권고문의 영향 범위 밖입니다."
        if finding.component.deployed == "no":
            return finding.component.deployed_reason or "배포 범위에 포함되지 않습니다."
    return "판정 사유가 기록되지 않았습니다."


def _compact(text: str, length: int) -> str:
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= length else one_line[:length - 1].rstrip() + "…"


def _detail_groups(findings: list[dict], state: str) -> list[dict]:
    details = {}
    for item in findings:
        verdict = item["verdict"]
        conditions = verdict.get("item_results", [])
        key = (
            item["component"]["id"], item["asset"], item["reason"],
            tuple(sorted(item["body_ids"])),
            tuple((condition["item_key"], condition["status"], condition["reason"]) for condition in conditions),
        )
        if key not in details:
            details[key] = {**item, "identifiers": [], "missing_info": {}, "members": []}
        detail = details[key]
        detail["identifiers"].append(item["vulnerability"]["id"])
        detail["members"].append(item)
        for missing in verdict.get("missing_info", []):
            detail["missing_info"].setdefault((missing["what"], missing["where"]), missing)

    for detail in details.values():
        members = detail.pop("members")
        detail["identifiers"] = list(dict.fromkeys(detail["identifiers"]))
        detail["links"] = _references(url for item in members for url in item["links"])[:2]
        for item in members:
            item["shown_links"].update(detail["links"])
        missing_info = list(detail["missing_info"].values())
        if state == "undetermined":
            fallback = {
                "what": "공개 권고문의 영향 조건에 해당하는 기능의 실제 사용과 배포 여부",
                "where": detail["location"] or "배포 설정, 애플리케이션 호출 코드, 대표 권고문",
            }
            missing_info = [
                {field: item[field] or value for field, value in fallback.items()}
                for item in missing_info or [fallback]
            ]
        detail["missing_info"] = missing_info
    return list(details.values())


def _context(bundle: TriageBundle, meta: dict) -> dict:
    priorities = {priority.finding_key: priority for priority in bundle.results}
    remediations = {remediation.finding_key: remediation for remediation in bundle.remediations}
    by_id = {item.id: item for item in bundle.evidence}
    decision_ids = []
    groups: dict[str, list[dict]] = {state: [] for state in _STATES}
    for finding in bundle.findings:
        verdict = finding.verdict
        priority = priorities.get(finding.key)
        remediation = remediations.get(finding.key)
        state = finding_state(finding)
        verdict_ids = [ref for item in verdict.item_results for ref in item.evidence_ids] if verdict else []
        decision_ids.extend(verdict_ids)
        lookup_ids = finding.hints.get("evidence_ids")
        lookup_ids = {ref for ref in lookup_ids if isinstance(ref, str)} if isinstance(lookup_ids, list) else set()
        # 선판정 유보의 조회 레코드는 후보별 출처다. 공통 소스 근거와 별도로 보관한다.
        body_ids = verdict_ids
        if verdict and verdict.decided_by == "rule:insufficient_evidence":
            body_ids = [ref for ref in verdict_ids if ref not in lookup_ids]
        body_ids = list(dict.fromkeys([*body_ids, *finding.component.evidence_ids]))
        evidence = _evidence_details(body_ids, by_id)
        locations = [item for item in evidence if item["location"] and item["has_line"]]
        if verdict and verdict.decided_by == "rule:not_deployed":
            locations.sort(key=lambda item: not item["id"].startswith("scope-"))
        reason = _reason(finding, state)
        links = _references([*finding.vulnerability.references, *(item["url"] for item in evidence)])
        groups[state].append({
            "component": finding.component.model_dump(mode="json"),
            "vulnerability": finding.vulnerability.model_dump(mode="json"),
            "asset": finding.asset_id,
            "state": state,
            "version_in_range": finding.version_in_range,
            "reason": reason,
            "summary_reason": _compact(reason, 52),
            "location": locations[0]["location"] if locations else "",
            "body_ids": body_ids,
            "verdict": verdict.model_dump(mode="json") if verdict else {},
            "priority": priority.model_dump(mode="json") if priority else {},
            "remediation": remediation.model_dump(mode="json") if remediation else {},
            "evidence": locations[:2],
            "links": links,
            "link": links[0] if links else "",
            "shown_links": set(links[:1]),
        })
    for findings in groups.values():
        findings.sort(key=lambda item: (
            item["priority"].get("tier", "P5"), item["priority"].get("rank") or float("inf"),
            item["vulnerability"]["id"], item["component"]["id"], item["asset"] or "",
        ))
    summaries = [item for findings in groups.values() for item in findings]
    details = {state: _detail_groups(groups[state], state) for state in ("affected", "undetermined")}
    extra_links = defaultdict(dict)
    for item in summaries:
        for url in item["links"]:
            if url not in item["shown_links"]:
                extra_links[item["vulnerability"]["id"]][url] = None
    work_requests = [
        item for item in summaries if item["verdict"].get("work_request")
    ]
    components = [*bundle.components, *(finding.component for finding in bundle.findings)]
    return {
        "meta": meta,
        "components_count": len({item.id for item in components}),
        "ecosystems": sorted({item.ecosystem for item in components if item.ecosystem}),
        "folders": _folders(bundle, by_id),
        "lookup_sources": _lookup_sources(bundle, meta),
        "findings_count": len(bundle.findings),
        "groups": groups,
        "summaries": summaries,
        "details": details,
        "top_actions": groups["affected"][:3],
        "work_requests": work_requests,
        "states": _STATES,
        "deployment": _DEPLOYMENT,
        "conditions": _CONDITIONS,
        "anomalies": [
            {"kind": item.kind, "message": item.message,
             "evidence": _evidence_details(item.evidence_ids, by_id)}
            for item in bundle.anomalies
        ],
        "failed_stages": list(dict.fromkeys(
            item.message.partition(" 단계 실패")[0].strip() if " 단계 실패" in item.message else "단계 미기록"
            for item in bundle.anomalies if item.kind == "stage_failure"
        )),
        "extra_links": [{"id": identifier, "links": list(urls)} for identifier, urls in extra_links.items()],
        "decision_evidence": _appendix_citations(decision_ids, by_id),
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
    environment.filters["link_label"] = _link_label
    context = Redactor().value(_context(bundle, {**bundle.meta, **meta}))
    font = (_DIRECTORY / "fonts" / "NotoSansKR.ttf").resolve().as_uri()
    template = (_DIRECTORY / "report.html").read_text(encoding="utf-8")
    page = environment.from_string(template).render(**context, font=font)
    fetcher = URLFetcher(allowed_protocols={"file"})
    pdf = HTML(string=page, url_fetcher=fetcher).write_pdf(font_config=FontConfiguration())
    write_artifact(out, pdf)
    return [evidence]
