"""OSV의 패키지 조회와 상세 권고문 정규화."""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterator
from urllib.parse import quote

from univers.versions import Version

from ..ingest.common import normalize_purl, normalize_severity, parse_purl, score_from_vector
from ..models import Component, Vulnerability
from ..remediation.versions import V, in_range
from ._advisory import Advisory, EvidenceList, any_match, exact_version
from ._http import Responses

API = "https://api.osv.dev/v1"
BATCH = f"{API}/querybatch"
ECOSYSTEMS = {
    "maven": "Maven", "npm": "npm", "pypi": "PyPI", "golang": "Go", "go": "Go",
    "cargo": "crates.io", "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist",
    "pub": "Pub", "hex": "Hex", "swift": "SwiftURL",
}


def _package(component: Component) -> dict[str, str]:
    parts = parse_purl(component.purl)
    eco = ECOSYSTEMS.get(component.ecosystem.lower()) or ECOSYSTEMS.get(parts.get("type", ""))
    name = component.name or parts.get("name", "")
    group = component.group or parts.get("group", "")
    if eco and name:
        if eco == "Maven" and group and ":" not in name:
            name = f"{group}:{name}"
        if eco in ("npm", "Go") and group and "/" not in name:
            name = f"{group}/{name}"
        return {"name": name, "ecosystem": eco}
    return {"purl": _unversioned(component.purl)} if parts else {}


def _unversioned(purl: str) -> str:
    purl = normalize_purl(purl)
    path, sep, suffix = purl.rpartition("@")
    return path if sep and "/" not in suffix else purl


def _canonical_name(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name.lower())
    if ecosystem == "crates.io":
        return name.replace("_", "-").lower()
    return name.lower() if ecosystem == "NuGet" else name


def _same_package(affected: dict, package: dict) -> bool:
    if "purl" in package:
        return _unversioned(affected.get("purl", "")) == package["purl"]
    eco = package["ecosystem"]
    return (affected.get("ecosystem") == eco
            and _canonical_name(affected.get("name", ""), eco) == _canonical_name(package["name"], eco))


def _event_ranges(events: list[dict]) -> tuple[list[str], list[str], bool]:
    ranges, fixes = [], []
    lower = None
    valid = bool(events)
    for event in events:
        if len(event) != 1:
            valid = False
            break
        kind, version = next(iter(event.items()))
        if not isinstance(version, str) or not exact_version(version):
            valid = False
            break
        if kind == "introduced" and lower is None:
            lower = "" if version == "0" else f">={version}"
        elif kind in ("fixed", "last_affected", "limit") and lower is not None:
            upper = f"{'<=' if kind == 'last_affected' else '<'}{version}"
            ranges.append(f"{lower},{upper}" if lower else upper)
            if kind == "fixed":
                fixes.append(version)
            lower = None
        else:
            valid = False
            break
    if valid and lower is not None:
        ranges.append(lower or ">=0")
    return ranges, fixes, valid


def _range_match(version: str, expr: str, ecosystem: str) -> bool | None:
    if not version:
        return None
    if expr == ">=0":  # OSV의 introduced=0은 생태계와 관계없이 시작 버전 제한이 없다.
        return True
    bounds = [clause.lstrip("<>=") for clause in expr.split(",")]
    if not all(isinstance(V(value, ecosystem), Version) for value in [version, *bounds]):
        return None
    return in_range(version, expr, ecosystem)


def _bounds(doc: dict, component: Component, query: dict) -> tuple[list[str], list[str], bool | None]:
    ranges, fixes, checks = [], [], []
    version = query.get("version", "")
    ecosystem = component.ecosystem.lower() or parse_purl(component.purl).get("type", "")
    for affected in doc.get("affected") or []:
        if not _same_package(affected.get("package") or {}, query["package"]):
            continue
        listed = affected.get("versions") or []
        ranges.extend(f"=={value}" for value in listed if exact_version(value))
        if listed and version:
            comparable = isinstance(V(version, ecosystem), Version)
            checks.append(any_match([
                True if version == value else (
                    in_range(version, f"=={value}", ecosystem)
                    if comparable and exact_version(value) and isinstance(V(value, ecosystem), Version) else None
                )
                for value in listed
            ]))
        for rule in affected.get("ranges") or []:
            kind = rule.get("type")
            if kind not in ("SEMVER", "ECOSYSTEM"):
                if not listed:
                    checks.append(None)
                continue
            comparison = "npm" if kind == "SEMVER" else ecosystem
            parsed, fixed, valid = _event_ranges(rule.get("events") or [])
            ranges.extend(parsed)
            fixes.extend(fixed)
            checks.extend(_range_match(version, expr, comparison) for expr in parsed)
            if not valid:
                checks.append(None)
        if not listed and not affected.get("ranges"):
            checks.append(None)
    return list(dict.fromkeys(ranges)), list(dict.fromkeys(fixes)), any_match(checks)


def _candidate(doc: dict, identifier: str, component: Component, query: dict, evidence_id: str) -> Advisory:
    ranges, fixes, result = _bounds(doc, component, query)
    vectors = [(score_from_vector(item.get("score", "")), item.get("score", ""))
               for item in (doc.get("severity") or []) if item.get("type", "").startswith("CVSS_")]
    score, vector = max(((score, vector) for score, vector in vectors if score is not None),
                        key=lambda item: (item[1].startswith("CVSS:3"), item[0]), default=(None, ""))
    url = f"https://osv.dev/vulnerability/{quote(identifier, safe='')}"
    vulnerability = Vulnerability(
        id=identifier, aliases=doc.get("aliases") or [], title=doc.get("summary", ""),
        description=doc.get("details", ""), published=doc.get("published", ""),
        severity=normalize_severity((doc.get("database_specific") or {}).get("severity")),
        cvss_score=score, cvss_vector=vector, cvss_source="osv" if vector else "",
        fixed_versions=fixes, affected_ranges=ranges,
        references=[url, *(ref["url"] for ref in (doc.get("references") or []) if ref.get("url"))],
    )
    return Advisory(vulnerability, result, "osv", evidence_id)


def _query_pages(queries: dict[str, dict], responses: Responses, evidence: EvidenceList) -> Iterator[tuple[str, str, str]]:
    pending = dict(sorted(queries.items()))
    seen = defaultdict(set)
    while pending:
        page = {}
        missing = {}
        for key, query in pending.items():
            index = responses.key("osv-item", query)
            doc, path = responses.cached(index) if responses.client is None else (None, "")
            if doc is None:
                missing[key] = query
            else:
                page[key] = doc, path
        if missing:
            batch, batch_path = responses.request("osv-batch", "POST", BATCH, json={"queries": list(missing.values())})
            rows = batch.get("results") if batch is not None else None
            if isinstance(rows, list) and len(rows) == len(missing):
                for (key, query), row in zip(missing.items(), rows, strict=True):
                    if isinstance(row, dict):
                        if batch_path.startswith(f"data/cache/lookup/{responses.date}/"):
                            responses.save(responses.key("osv-item", query), row)
                        page[key] = row, batch_path
            else:
                # 다른 배치로 이미 조회된 패키지도 요청 실패 시 개별 스냅샷에서 복구한다.
                for key, query in missing.items():
                    doc, path = responses.cached(responses.key("osv-item", query))
                    if doc is not None:
                        page[key] = doc, path
        following = {}
        for key, query in pending.items():
            row, path = page.get(key, ({}, ""))
            ids = [item["id"] for item in (row.get("vulns") or []) if item.get("id")]
            package = query["package"]
            target = package.get("purl") or f"{package['ecosystem']}:{package['name']}"
            note = f"OSV 조회 {target} {query.get('version', '버전 미확정')}: 후보 {len(ids)}건"
            if key not in page:
                note = f"OSV 조회 {target}: 응답을 확인할 수 없음"
            item_id = evidence.add("tool", url=BATCH, file=path, note=note)
            for identifier in ids:
                yield key, identifier, item_id
            token = row.get("next_page_token")
            if token and token not in seen[key]:
                seen[key].add(token)
                following[key] = dict(query, page_token=token)
        pending = following


def lookup(components: list[Component], responses: Responses, evidence: EvidenceList) -> Iterator[tuple[Component, Advisory, str]]:
    groups = defaultdict(list)
    queries = {}
    for component in components:
        package = _package(component)
        if not package:
            evidence.add("tool", note=f"{component.id}: OSV 패키지 식별 정보 없음")
            continue
        query = {"package": package}
        if component.version_source not in ("manifest_range", "unknown") and exact_version(component.version):
            query["version"] = component.version
        key = responses.key("osv-item", query)
        queries[key] = query
        groups[key].append(component)

    matches = list(dict.fromkeys(_query_pages(queries, responses, evidence)))
    details = {}
    for _, identifier, _ in matches:
        if identifier in details:
            continue
        url = f"{API}/vulns/{quote(identifier, safe='')}"
        doc, path = responses.request("osv-vuln", "GET", url)
        doc = doc if doc is not None and doc.get("id") == identifier else None
        evidence_id = evidence.add("advisory", file=path, url=url, note=(
            f"OSV 상세 권고문 {identifier}" if doc is not None else f"OSV 상세 {identifier}: 응답을 확인할 수 없음"
        ))
        details[identifier] = doc, evidence_id
    for key, identifier, query_evidence in matches:
        doc, advisory_evidence = details[identifier]
        if doc is not None and doc.get("withdrawn"):
            continue
        for component in groups[key]:
            candidate = _candidate(doc or {}, identifier, component, queries[key], advisory_evidence)
            yield component, candidate, query_evidence
