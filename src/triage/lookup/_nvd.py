"""NVD 2.0 제품 조회와 CPE 버전 범위 재판정."""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass

from ..config import load_yaml
from ..ingest.common import normalize_severity, to_float
from ..models import Component, Finding, Vulnerability
from ..remediation.versions import cmp, in_range
from ._advisory import Advisory, EvidenceList, any_match
from ._http import Responses

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KINDS = frozenset({"runtime", "base-image", "server"})
VERSION = re.compile(r"v?\d+(?:\.\d+)*")
IMAGE_TAG = re.compile(r"(v?\d+(?:\.\d+)*)(?:-[\w.-]+)?")
BOUND_KEYS = {
    "versionStartIncluding": ">=", "versionStartExcluding": ">",
    "versionEndIncluding": "<=", "versionEndExcluding": "<",
}


@dataclass(frozen=True)
class _Version:
    exact: str = ""
    line: tuple[int, ...] = ()


def _name(component: Component) -> str:
    name = component.name.lower().strip().split("@", 1)[0]
    if "/" not in name:
        return name.split(":", 1)[0]
    prefix, name = name.rsplit("/", 1)
    if prefix not in ("library", "docker.io", "index.docker.io", "docker.io/library", "index.docker.io/library"):
        return ""
    return name.split(":", 1)[0]


def _version(component: Component) -> _Version:
    if component.version_source in ("manifest_range", "unknown"):
        return _Version()
    version = component.version.strip()
    if component.kind == "base-image" or component.version_source == "dockerfile":
        tag = IMAGE_TAG.fullmatch(version)
        if tag:
            version = tag[1]
    if not VERSION.fullmatch(version):
        return _Version()
    version = version.removeprefix("v")
    parts = tuple(int(part) for part in version.split("."))
    return _Version(exact=version) if len(parts) >= 3 else _Version(line=parts)


def _image_origin(component: Component) -> tuple[str, str] | None:
    if component.version_source == "dockerfile" and component.declared_spec and component.evidence_ids:
        # C1은 FROM 원문 근거를 첫 번째 ID에 두고, 이후 단계는 근거를 덧붙인다.
        return component.declared_spec, component.evidence_ids[0]
    return None


def _targets(components: list[Component], products: dict, evidence: EvidenceList) -> dict[str, dict[str, Component]]:
    by_name = {name: product["cpes"] for product in products.values() for name in product["names"]}
    runtimes = defaultdict(list)
    images = defaultdict(list)
    for component in components:
        if origin := _image_origin(component):
            members = images if component.kind == "base-image" else runtimes
            members[origin].append(component)
    owners = {
        images[origin][0].id: members[0]
        for origin, members in runtimes.items() if len(members) == len(images.get(origin, ())) == 1
    }
    targets = defaultdict(dict)
    for component in components:
        cpes = by_name.get(_name(component), ())
        if not cpes:
            evidence.add("tool", note=f"{component.id}: NVD 제품 CPE 대응 규칙 없음")
        owner = owners.get(component.id, component)
        version = _version(owner).exact
        for cpe in cpes:
            target = f"{cpe}:{version}" if version else cpe
            targets[target][owner.id] = owner
    return targets


def _matches(node: dict, conditional: bool = False, negated: bool = False) -> Iterator[tuple[dict, bool, bool]]:
    children = node.get("nodes", []) + node.get("children", [])
    entries = node.get("cpeMatch", [])
    negated = negated or bool(node.get("negate"))
    conditional = conditional or negated or (
        node.get("operator", "OR") != "OR" and len(children) + len(entries) > 1
    )
    for entry in entries:
        if entry.get("vulnerable") is True:
            yield entry, conditional, negated
    for child in children:
        yield from _matches(child, conditional, negated)


def _intersects_line(line: tuple[int, ...], bounds: list[tuple[str, str]]) -> bool:
    low = ".".join(map(str, line))
    high = ".".join(map(str, (*line[:-1], line[-1] + 1)))
    for op, bound in bounds:
        if not VERSION.fullmatch(bound):
            continue  # 해석 불가한 제한이 있어도 확인된 다른 경계는 적용한다.
        bound = bound.removeprefix("v")
        first, last = cmp(bound, low, "maven"), cmp(bound, high, "maven")
        if op in (">", ">=", "==") and last >= 0:
            return False
        if (op in ("<=", "==") and first < 0) or (op == "<" and first <= 0):
            return False
    return True


def _bounds(cve: dict, product: str, version: _Version) -> tuple[list[str], list[bool | None]]:
    ranges, checks = [], []
    for config in cve.get("configurations", []):
        for match, conditional, negated in _matches(config):
            criteria = re.split(r"(?<!\\):", match.get("criteria", ""))
            if len(criteria) != 13 or ":".join(criteria[:5]) != product:
                continue
            specified = criteria[5]
            bounds = [(op, match[key]) for key, op in BOUND_KEYS.items() if key in match]
            if specified != "*":
                bounds.append(("==", specified))
            if version.line and not negated and not _intersects_line(version.line, bounds):
                continue
            if any(not VERSION.fullmatch(bound) for _, bound in bounds):
                checks.append(None)
                continue
            expr = ",".join(f"{op}{bound.removeprefix('v')}" for op, bound in bounds) or ">=0"
            ranges.append(expr)
            qualified = conditional or any(attr != "*" for attr in criteria[6:])
            if not version.exact:
                checks.append(None)
            elif not in_range(version.exact, expr, "maven"):
                checks.append(False if not conditional else None)
            else:
                checks.append(None if qualified else True)
    return list(dict.fromkeys(ranges)), checks


def _cvss(metrics: dict) -> tuple[dict, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        rows = metrics.get(key, [])
        if rows:
            primary = next((row for row in rows if row.get("type") == "Primary"), rows[0])
            return primary.get("cvssData", {}), primary.get("baseSeverity", "")
    return {}, ""


def _vulnerability(cve: dict, ranges: list[str], url: str) -> Vulnerability:
    descriptions = cve.get("descriptions", [])
    description = next((item["value"] for item in descriptions if item.get("lang") == "en"), "")
    score, severity = _cvss(cve.get("metrics", {}))
    return Vulnerability(
        id=cve["id"], description=description, published=cve.get("published", ""),
        severity=normalize_severity(score.get("baseSeverity") or severity),
        cvss_score=to_float(score.get("baseScore")), cvss_vector=score.get("vectorString", ""),
        cvss_source="nvd" if score else "", affected_ranges=ranges,
        references=[url, *(ref["url"] for ref in cve.get("references", []) if ref.get("url"))],
    )


def lookup(components: list[Component], responses: Responses, evidence: EvidenceList) -> Iterator[tuple[Component, Advisory, str]]:
    if not components:
        return
    products = load_yaml("runtime_cpe.yaml")["products"]
    for target, members in _targets(components, products, evidence).items():
        product = ":".join(target.split(":")[:5])
        versions = [(component, _version(component)) for component in members.values()]
        offset = 0
        while True:
            params = {"virtualMatchString": target, "startIndex": offset}
            page, path = responses.request("nvd", "GET", API, params=params)
            records = page.get("vulnerabilities") if page is not None else None
            query_evidence = evidence.add("tool", file=path, url=API, note=(
                f"NVD 조회 {target} (startIndex={offset}): 후보 {len(records)}건" if isinstance(records, list)
                else f"NVD 조회 {target} (startIndex={offset}): 응답을 확인할 수 없음"
            ))
            if not isinstance(records, list) or not records:
                break
            for record in records:
                cve = record.get("cve", {})
                identifier = cve.get("id", "")
                if not re.fullmatch(r"CVE-\d{4}-\d+", identifier) or cve.get("vulnStatus") == "Rejected":
                    continue
                advisory_id = None
                url = f"https://nvd.nist.gov/vuln/detail/{identifier}"
                for component, version in versions:
                    ranges, checks = _bounds(cve, product, version)
                    if not checks:
                        continue
                    if advisory_id is None:
                        advisory_id = evidence.add("advisory", file=path, url=url, note=f"NVD {identifier}, 제품 CPE {product}")
                    candidate = Advisory(_vulnerability(cve, ranges, url), any_match(checks), "nvd", advisory_id)
                    yield component, candidate, query_evidence
            length = page.get("resultsPerPage", len(records))
            total = page.get("totalResults", 0)
            if not isinstance(length, int) or length <= 0 or not isinstance(total, int) or offset + length >= total:
                break
            offset += length


def limit_candidates(findings: list[Finding], responses: Responses, evidence: EvidenceList) -> list[Finding]:
    grouped = defaultdict(list)
    for finding in findings:
        component = finding.component
        if component.kind in KINDS and not _version(component).exact:
            grouped[component.id].append(finding)
    if not grouped:
        return findings

    limit = load_yaml("runtime_cpe.yaml")["line_candidate_limit"]
    limited = [finding for finding in findings if finding.component.id not in grouped]
    for component_id, candidates in grouped.items():
        candidates.sort(key=_candidate_order)
        kept = candidates[:limit]
        if len(candidates) > limit:
            total = len(candidates)
            dropped = total - limit
            responses.emit("candidates_truncated", source="nvd", component_id=component_id,
                           total=total, kept=limit, dropped=dropped)
            truncation = evidence.add("tool", url=API, note=(
                f"{component_id}: NVD 후보 {total}건 중 CVSS 상위 {limit}건을 남겨 {dropped}건 생략"
            ))
            for finding in kept:
                finding.hints["evidence_ids"].append(truncation)
        limited.extend(kept)
    return limited


def _candidate_order(finding: Finding) -> tuple[float, str]:
    score = finding.vulnerability.cvss_score
    return (1 if score is None else -score), finding.vulnerability.id
