"""CycloneDX 1.6 SBOM과 구성요소별 VEX 판정을 내보낸다."""
import json
from functools import lru_cache
from importlib.metadata import version
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource

from triage.models import Component, Evidence, Finding, TriageBundle

from ._common import (
    artifact_evidence, file_location, finding_evidence, finding_state, public_url, write_artifact,
)
from ._redact import Redactor


_SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json"
_STATES = {"affected": "exploitable", "not_affected": "not_affected", "undetermined": "in_triage"}
_TYPES = {"base-image": "container", "runtime": "framework", "server": "application",
          "os-package": "operating-system"}
_SCOPES = {"runtime": "required", "dev": "excluded", "test": "excluded",
           "build_only": "excluded", "optional": "optional"}
_METHODS = {"CVSS:3.0": "CVSSv3", "CVSS:3.1": "CVSSv31", "CVSS:4.0": "CVSSv4"}


@lru_cache
def _validator() -> Draft7Validator:
    directory = Path(__file__).with_name("schemas")
    schema = json.loads((directory / "bom-1.6.schema").read_text(encoding="utf-8"))
    registry = Registry().with_resources(
        (
            f"http://cyclonedx.org/schema/{name}.json",
            Resource.from_contents(json.loads((directory / name).read_text(encoding="utf-8"))),
        )
        for name in ("spdx.schema", "jsf-0.82.schema")
    )
    return Draft7Validator(schema, registry=registry, format_checker=Draft7Validator.FORMAT_CHECKER)


def validate_cyclonedx(document: dict) -> None:
    """공식 로컬 스키마로 검증한다. 오류 시 jsonschema.ValidationError를 발생시킨다."""
    _validator().validate(document)


def _properties(**fields: str) -> list[dict]:
    return [{"name": f"triage:{key}", "value": value} for key, value in fields.items() if value]


def _evidence_properties(evidence: dict[str, Evidence], ids: list[str]) -> list[dict]:
    properties = []
    for item_id in dict.fromkeys(ids):
        properties.append({"name": "triage:evidence_id", "value": item_id})
        if item := evidence.get(item_id):
            for location in filter(None, (file_location(item), public_url(item.url))):
                properties.append({"name": "triage:evidence_location", "value": f"{item_id} {location}"})
    return properties


def _component(component: Component, evidence: dict[str, Evidence]) -> dict:
    properties = _properties(
        version_source=component.version_source or "unknown",
        deployed=component.deployed or "unknown",
        deployed_reason=component.deployed_reason,
        module=component.module,
        scope=component.scope,
        declared_spec=component.declared_spec,
        direct="unknown" if component.direct is None else str(component.direct).lower(),
    )
    item = {
        "type": _TYPES.get(component.kind, "library"), "bom-ref": component.id,
        "name": component.name,
        "properties": properties + _evidence_properties(evidence, component.evidence_ids),
    }
    for field in ("group", "version", "purl"):
        if value := getattr(component, field):
            item[field] = value
    scope = _SCOPES.get(component.scope)
    if component.deployed == "no":
        scope = "excluded"
    elif component.deployed == "yes" and scope != "optional":
        scope = "required"
    if scope:
        item["scope"] = scope
    if licenses := list(dict.fromkeys(filter(None, component.licenses))):
        item["licenses"] = [{"license": {"name": name}} for name in licenses]
    return item


def _dependencies(root: str, components: dict[str, Component]) -> list[dict]:
    edges: dict[str, set[str]] = {ref: set() for ref in (root, *components)}
    for ref, component in components.items():
        if component.direct is True:
            edges[root].add(ref)
        edges[ref].update(child for child in component.depends_on if child in components and child != ref)
        for path in component.dependency_paths:
            # 경로에 생략된 중간 노드가 있어도 나머지 노드를 붙여 새 관계를 만들지 않는다.
            if path and path[0] in components and components[path[0]].direct is not False:
                edges[root].add(path[0])
            for parent, child in zip(path, path[1:]):
                if parent in edges and child in components and parent != child:
                    edges[parent].add(child)
    return [{"ref": ref, "dependsOn": sorted(children)} for ref, children in edges.items()]


def _vulnerability(finding: Finding, evidence: dict[str, Evidence], ref: str) -> dict:
    vuln, verdict = finding.vulnerability, finding.verdict
    state = finding_state(finding)
    ids = finding_evidence(finding)
    detail = []
    if verdict:
        detail.extend(filter(None, (verdict.rationale_ko, verdict.plain_ko, verdict.decided_by)))
        detail.extend(f"{item.item_key} ({item.status}) {item.reason}".strip() for item in verdict.item_results)
    elif finding.status_note:
        detail.append(finding.status_note)
    if state == "undetermined" and not detail:
        detail.append("판정 근거를 확인하지 못했습니다.")
    if ids:
        detail.append(f"근거 {', '.join(ids)}")

    analysis = {"state": _STATES[state]}
    if detail:
        analysis["detail"] = "\n".join(detail)
    if verdict and verdict.justification:
        analysis["justification"] = verdict.justification
    properties = _properties(asset_id=finding.asset_id or "")
    properties.extend(_evidence_properties(evidence, ids))
    item = {
        "id": vuln.id, "bom-ref": ref, "affects": [{"ref": finding.component.id}],
        "analysis": analysis, "properties": properties,
    }
    if vuln.description or vuln.title:
        item["description"] = vuln.description or vuln.title
    rating = {}
    if vuln.severity:
        severity = vuln.severity.lower()
        rating["severity"] = severity if severity in {"critical", "high", "medium", "low", "info", "none"} else "unknown"
    if vuln.cvss_score is not None and 0 <= vuln.cvss_score <= 10:
        rating["score"] = vuln.cvss_score
    if vuln.cvss_vector:
        rating["vector"] = vuln.cvss_vector
        method = _METHODS.get(vuln.cvss_vector.split("/", 1)[0])
        if method:
            rating["method"] = method
        elif vuln.cvss_vector.startswith("AV:"):
            rating["method"] = "CVSSv2"
    if rating:
        if vuln.cvss_source:
            rating["source"] = {"name": vuln.cvss_source}
        item["ratings"] = [rating]
    if links := list(dict.fromkeys(filter(None, map(public_url, vuln.references)))):
        item["advisories"] = [{"url": url} for url in links]
    return item


def _unique_ref(value: str, used: set[str]) -> str:
    while value in used:
        value = f"#{value}"
    used.add(value)
    return value


def write_cyclonedx(bundle: TriageBundle, project: dict, out: Path) -> list[Evidence]:
    """SBOM을 검증한 뒤 저장하고 이번 출력의 근거를 돌려준다."""
    components = {component.id: component for component in bundle.components}
    for finding in bundle.findings:
        components.setdefault(finding.component.id, finding.component)

    used_refs = set(components)
    name = project.get("name") or project.get("label") or "unknown"
    root_ref = _unique_ref(project.get("bom-ref") or f"application:{name}", used_refs)
    root = {"type": "application", "bom-ref": root_ref, "name": name}
    for field in ("version", "group", "purl"):
        if value := project.get(field):
            root[field] = value
    evidence = artifact_evidence("cyclonedx", out, "CycloneDX 1.6 공식 스키마 검증 완료", bundle)
    sources = {item.id: item for item in bundle.evidence}
    document = Redactor().value({
        "$schema": _SCHEMA_URL, "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "component": root,
            "tools": {"components": [{"type": "application", "name": "triage", "version": version("triage")}]},
            "properties": _evidence_properties({evidence.id: evidence}, [evidence.id]),
        },
        "components": [_component(item, sources) for item in components.values()],
        "dependencies": _dependencies(root_ref, components),
        "vulnerabilities": [
            _vulnerability(finding, sources, _unique_ref(f"finding:{finding.key}", used_refs))
            for finding in bundle.findings
        ],
    })
    validate_cyclonedx(document)
    content = json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    write_artifact(out, content.encode("utf-8"))
    return [evidence]
