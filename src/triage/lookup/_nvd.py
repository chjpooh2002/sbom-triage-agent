"""NVD 2.0 제품 조회와 CPE 버전 범위 재판정."""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterator

from ..config import load_yaml
from ..ingest.common import normalize_severity, to_float
from ..models import Component, Vulnerability
from ..remediation.versions import in_range
from ._advisory import Advisory, EvidenceList, any_match
from ._http import Responses

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KINDS = frozenset({"runtime", "base-image", "server"})
VERSION = re.compile(r"v?\d+(?:\.\d+)*")
BOUND_KEYS = {
    "versionStartIncluding": ">=", "versionStartExcluding": ">",
    "versionEndIncluding": "<=", "versionEndExcluding": "<",
}


def _name(component: Component) -> str:
    name = component.name.lower().strip().split("@", 1)[0]
    if "/" not in name:
        return name.split(":", 1)[0]
    prefix, name = name.rsplit("/", 1)
    if prefix not in ("library", "docker.io", "index.docker.io", "docker.io/library", "index.docker.io/library"):
        return ""
    return name.split(":", 1)[0]


def _version(component: Component) -> str:
    version = component.version.strip()
    if component.version_source in ("manifest_range", "unknown") or not VERSION.fullmatch(version):
        return ""
    if (component.kind == "base-image" or component.version_source == "dockerfile") and version.count(".") < 2:
        return ""
    return version.removeprefix("v")


def _targets(components: list[Component], evidence: EvidenceList) -> dict[str, list[Component]]:
    if not components:
        return {}
    products = load_yaml("runtime_cpe.yaml")["products"]
    by_name = {name: product["cpes"] for product in products.values() for name in product["names"]}
    targets = defaultdict(list)
    for component in components:
        cpes = by_name.get(_name(component), ())
        if not cpes:
            evidence.add("tool", note=f"{component.id}: NVD 제품 CPE 대응 규칙 없음")
        for cpe in cpes:
            version = _version(component)
            target = f"{cpe}:{version}" if version else cpe
            targets[target].append(component)
    return targets


def _matches(node: dict, conditional: bool = False) -> Iterator[tuple[dict, bool]]:
    children = node.get("nodes", []) + node.get("children", [])
    entries = node.get("cpeMatch", [])
    conditional = conditional or bool(node.get("negate")) or (
        node.get("operator", "OR") != "OR" and len(children) + len(entries) > 1
    )
    for entry in entries:
        if entry.get("vulnerable") is True:
            yield entry, conditional
    for child in children:
        yield from _matches(child, conditional)


def _bounds(cve: dict, product: str, version: str) -> tuple[list[str], list[bool | None]]:
    ranges, checks = [], []
    for config in cve.get("configurations", []):
        for match, conditional in _matches(config):
            criteria = re.split(r"(?<!\\):", match.get("criteria", ""))
            if len(criteria) != 13 or ":".join(criteria[:5]) != product:
                continue
            specified = criteria[5]
            bounds = [(op, match[key]) for key, op in BOUND_KEYS.items() if key in match]
            if specified != "*":
                bounds.append(("==", specified))
            if any(not VERSION.fullmatch(bound) for _, bound in bounds):
                checks.append(None)
                continue
            expr = ",".join(f"{op}{bound.removeprefix('v')}" for op, bound in bounds) or ">=0"
            ranges.append(expr)
            qualified = conditional or any(attr != "*" for attr in criteria[6:])
            if not version:
                checks.append(None)
            elif not in_range(version, expr):
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
    for target, members in _targets(components, evidence).items():
        product = ":".join(target.split(":")[:5])
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
                for component in members:
                    ranges, checks = _bounds(cve, product, _version(component))
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
