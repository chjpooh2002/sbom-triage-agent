"""검증한 목표 버전을 선언에 반영하고 임시 복사본에서 다시 점검한다."""
from __future__ import annotations

import difflib
import json
import re
import shutil
import tomllib
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from xml.parsers.expat import ExpatError

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .collect.core import Document, LocatedJSON
from .collect.maven import PROPERTY, parse as parse_pom
from .collect.npm import declarations as npm_declarations, matches as npm_matches
from .collect.python_deps import pin, table_lines
from .evidence.store import scoped_path
from .models import Component, Finding, TriageBundle
from .output._common import finding_state


_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]*")
_QUOTED = re.compile(r""""[^"\\]*"|'[^'\\]*'""")
_JSON_PAIR = re.compile(r'("(?:[^"\\]|\\.)*")\s*:\s*("(?:[^"\\]|\\.)*")')
_SPEC = re.compile(r"\s*[\w.-]+(?:\s*\[[^]]+\])?\s*([^;]+?)(?=\s*(?:;|$))")


@dataclass(frozen=True)
class Edit:
    start: int
    end: int
    replacement: str


class FixCheckUnavailable(RuntimeError):
    """재점검 결과를 확정할 수 없다."""


def _document(root: Path, file: str) -> Document:
    path = scoped_path(root, file)
    if any(ord(char) < 32 or char in '\\"' for char in file):
        raise ValueError("패치에서 표현할 수 없는 파일 경로")
    return Document(file, path.read_text(encoding="utf-8-sig"), "manifest")


def _requirements_file(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def _requirement(value: str, component: Component, target: str, *, pinned: bool) -> Edit | None:
    try:
        req = Requirement(value)
        Version(target)
    except (InvalidRequirement, InvalidVersion):
        return None
    if req.url or canonicalize_name(req.name) != canonicalize_name(component.name):
        return None
    spec = str(req.specifier)
    if not spec or (pinned and pin(spec) != component.version) or not (match := _SPEC.match(value)):
        return None
    return Edit(*match.span(1), f"=={target}")


def _python_edits(doc: Document, line: int, component: Component, target: str) -> list[Edit]:
    raw = doc.lines[line - 1]
    if _requirements_file(PurePosixPath(doc.file).name.lower()):
        if raw.rstrip().endswith("\\") or re.search(r"\s--hash(?:=|\s)", raw):
            return []
        value = re.split(r"\s+#", raw, maxsplit=1)[0].rstrip()
        edit = _requirement(value, component, target, pinned=True)
        return [edit] if edit else []
    data = tomllib.loads(doc.text)
    project = data.get("project", {})
    dependencies = set(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        dependencies.update(group)
    edits = []
    previous_end = 0
    for match in _QUOTED.finditer(raw):
        if "#" in raw[previous_end:match.start()]:
            break
        previous_end = match.end()
        value = match[0][1:-1]
        if value in dependencies and (edit := _requirement(value, component, target, pinned=False)):
            offset = match.start() + 1
            edits.append(Edit(edit.start + offset, edit.end + offset, edit.replacement))
    for section, name, at in table_lines(doc):
        if at != line or canonicalize_name(name) != canonicalize_name(component.name):
            continue
        if not re.fullmatch(r"tool\.poetry\.(?:dependencies|dev-dependencies|group\.[\w-]+\.dependencies)", section):
            continue
        pair = re.search(r'''=\s*(["'])([^"'\\]+)\1\s*(?:#.*)?$''', raw)
        if pair and pair[2] == component.declared_spec and re.match(r"[0-9~^<>=!]|\*$", pair[2]):
            edits.append(Edit(*pair.span(2), target))
    return edits


def _npm_edits(doc: Document, line: int, component: Component, target: str) -> list[Edit]:
    manifest = LocatedJSON(doc)
    declaration = npm_declarations(manifest.data).get(component.name)
    if not declaration:
        return []
    section, spec, _ = declaration
    if manifest.line(section, component.name) != line or npm_matches(target, spec) is None:
        return []
    return [Edit(*match.span(2), json.dumps(target)) for match in _JSON_PAIR.finditer(doc.lines[line - 1])
            if json.loads(match[1]) == component.name and json.loads(match[2]) == spec]


def _docker_edits(raw: str, component: Component, target: str) -> list[Edit]:
    match = re.match(r"\s*FROM\s+(?:--[^\s]+\s+)*([^\s]+)", raw, re.IGNORECASE)
    if not match or match[1] != component.declared_spec or any(char in match[1] for char in "@$\\"):
        return []
    image, _, tag = match[1].rpartition(":")
    if not image or "/" in tag or not re.fullmatch(r"[\w][\w.-]{0,127}", target, re.ASCII):
        return []
    if component.kind == "runtime":
        version = re.fullmatch(r"(v?)(\d+(?:\.\d+)*)(-.*)?", tag)
        if not version or version[2] != component.version or not re.fullmatch(r"\d+(?:\.\d+)*", target):
            return []
        target = f"{version[1]}{target}{version[3] or ''}"
    return [Edit(match.end(1) - len(tag), match.end(1), target)]


def _xml_edit(raw: str, tag: str, version: str, target: str) -> list[Edit]:
    field = re.escape(tag)
    return [Edit(*match.span(1), target) for match in re.finditer(
        rf"<{field}>\s*({re.escape(version)})\s*</{field}>", raw)]


def _pom_edits(pom, line: int, component: Component, target: str, properties: set[str]) -> list[Edit]:
    raw = pom.doc.lines[line - 1]
    if not component.version or "<!--" in raw:
        return []
    edits = []
    if component.version_source != "property_override":
        dependencies = pom.root.findall("./dependencies/dependency") + pom.root.findall("./dependencyManagement/dependencies/dependency")
        for node in dependencies:
            version = node.find("version")
            if (node.findtext("groupId"), node.findtext("artifactId")) != (component.group, component.name) or version is None:
                continue
            if pom.lines[version] == line and version.text == component.version:
                edits.extend(_xml_edit(raw, "version", component.version, target))
    for node in pom.root.findall("./properties/*"):
        if pom.lines[node] != line or node.text != component.version:
            continue
        if node.tag in properties:
            edits.extend(_xml_edit(raw, node.tag, component.version, target))
    return edits


def build_fix_plan(bundle: TriageBundle, root: Path) -> list[dict]:
    """구성요소 근거로 입증된 단일 선언만 수정 대상으로 삼는다."""
    root = Path(root).resolve()
    evidence = {item.id: item for item in bundle.evidence}
    remediations = {item.finding_key: item for item in bundle.remediations}
    groups = defaultdict(list)
    for finding in bundle.findings:
        if finding.key in remediations and finding_state(finding) != "not_affected":
            groups[finding.component.id].append(finding)

    plans = []
    lines = defaultdict(list)
    documents = {}
    poms = {}
    for component_id, findings in groups.items():
        component = findings[0].component
        targets = {item.target_version for finding in findings if (item := remediations[finding.key]).verified}
        target = next(iter(targets)) if len(targets) == 1 else None
        row = {"component": component_id, "target": target, "findings": [finding.key for finding in findings]}
        plans.append(row)
        if not target or not _TARGET.fullmatch(target):
            row.update(kind="manual", reason="목표 버전 확인 필요")
            continue
        if component.direct is False:
            row.update(kind="manual", reason="전이 의존성에 직접 수정할 선언이 없습니다.")
            continue

        matches = {}
        refs = dict.fromkeys(ref for finding in findings for ref in finding.component.evidence_ids)
        properties = set(PROPERTY.findall(component.declared_spec))
        if component.version_source in {"managed", "property_override"} and not properties:
            for ref in refs:
                item = evidence.get(ref)
                if item and PurePosixPath(item.file).name == "pom.xml":
                    for value in re.findall(r"<version>([^<]+)</version>", item.snippet):
                        properties.update(PROPERTY.findall(value))
        for ref in refs:
            item = evidence.get(ref)
            if not item or item.url or not item.line_start or item.line_start < 1 or item.kind not in {"manifest", "build"}:
                continue
            file, line = item.file, item.line_start
            name = PurePosixPath(file).name.lower()
            try:
                if file not in documents:
                    documents[file] = _document(root, file)
                doc = documents[file]
                raw = doc.lines[line - 1]
                if not item.snippet or item.snippet != raw[:600]:
                    continue
                if component.ecosystem == "pypi" and (name == "pyproject.toml" or _requirements_file(name)):
                    edits = _python_edits(doc, line, component, target)
                elif component.ecosystem == "npm" and name == "package.json":
                    edits = _npm_edits(doc, line, component, target)
                elif component.ecosystem == "maven" and name == "pom.xml":
                    if file not in poms:
                        poms[file] = parse_pom(doc)
                    edits = _pom_edits(poms[file], line, component, target, properties)
                elif component.version_source == "dockerfile" and (name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")):
                    edits = _docker_edits(raw, component, target)
                else:
                    continue
            except (OSError, ValueError, IndexError, TypeError, ExpatError):
                continue
            matches.update({(file, line, raw, edit): ref for edit in edits if raw[edit.start:edit.end] != edit.replacement})

        if len(matches) > 1 and component.version_source == "property_override" and len(properties) == 1:
            # Maven 수집기가 상속 선언 뒤에 실제로 적용된 덮어쓰기 근거를 붙인다.
            effective = next(reversed(matches))
            matches = {effective: matches[effective]}
        if len(matches) != 1:
            reason = "수정할 선언 원문 줄을 확인할 수 없습니다." if not matches else "수정할 선언 위치가 하나로 확정되지 않습니다."
            row.update(kind="manual", reason=reason)
            continue
        (file, line, raw, edit), ref = next(iter(matches.items()))
        row.update(kind="change", file=file, line=line, before=raw, evidence_ids=[ref])
        lines[file, line].append((row, edit))

    for changes in lines.values():
        edits = sorted(set(edit for _, edit in changes), key=lambda edit: (edit.start, edit.end, edit.replacement))
        if any(left.end > right.start for left, right in zip(edits, edits[1:])):
            for row, _ in changes:
                for key in ("file", "line", "before", "evidence_ids"):
                    row.pop(key)
                row.update(kind="manual", reason="같은 선언에 서로 다른 변경안이 있어 수동 확인이 필요합니다.")
            continue
        after = changes[0][0]["before"]
        for edit in reversed(edits):
            after = after[:edit.start] + edit.replacement + after[edit.end:]
        for row, _ in changes:
            row["after"] = after
    return plans


def prepare_patch(root: Path, plan: list[dict]) -> tuple[str, dict[str, tuple[str, str]]]:
    """동일한 파일 내용 변경을 패치와 임시 복사본 적용에 사용한다."""
    edits = defaultdict(dict)
    for item in plan:
        if item["kind"] == "change":
            edits[item["file"]][item["line"]] = (item["before"], item["after"])
    diff = []
    changes = {}
    for file, replacements in sorted(edits.items()):
        original = scoped_path(root, file).read_bytes().decode("utf-8")
        before = original.splitlines(keepends=True)
        after = before.copy()
        for line, (expected, replacement) in replacements.items():
            raw = before[line - 1]
            text = raw.rstrip("\r\n")
            bom = "\ufeff" if line == 1 and text.startswith("\ufeff") else ""
            if text.removeprefix(bom) != expected:
                raise FixCheckUnavailable("선언이 변경안 생성 후 달라졌습니다.")
            after[line - 1] = bom + replacement + raw[len(text):]
        changes[file] = (original, "".join(after))
        for row in difflib.unified_diff(before, after, f"a/{file}\t", f"b/{file}\t"):
            diff.append(row if row.endswith("\n") else row + "\n\\ No newline at end of file\n")
    return "".join(diff), changes


def _component_key(component: Component) -> tuple:
    return (component.ecosystem, component.group, component.name, component.kind,
            component.module, component.id.partition("#")[2])


def _candidate_index(findings: list[Finding]) -> dict:
    index = defaultdict(set)
    for finding in findings:
        key = (_component_key(finding.component), finding.asset_id)
        index[key].update(identifier.upper() for identifier in finding.vulnerability.all_ids)
    return index


def compare_candidates(before: list[Finding], after: list[Finding]) -> dict:
    def present(finding: Finding, index: dict) -> bool:
        ids = index.get((_component_key(finding.component), finding.asset_id), set())
        return any(identifier.upper() in ids for identifier in finding.vulnerability.all_ids)

    before_index, after_index = _candidate_index(before), _candidate_index(after)
    return {"before_candidates": len(before), "after_candidates": len(after),
            "resolved": [finding.key for finding in before if not present(finding, after_index)],
            "remaining": [finding.key for finding in before if present(finding, after_index)],
            "new": [finding.key for finding in after if not present(finding, before_index)]}


def recheck(
    root: Path, changes: dict[str, tuple[str, str]], bundle: TriageBundle, plan: list[dict],
    scan: Callable[[Path], tuple[list[Component], list[Finding]]], *, exclude: set[Path],
) -> dict:
    def ignored(directory: str, names: list[str]) -> list[str]:
        folder = Path(directory)
        return [name for name in names if name == ".git" or (folder / name) in exclude
                or (folder / name).is_symlink() or (folder / name).resolve() != folder / name]

    with TemporaryDirectory(prefix="triage-fixplan-") as temporary:
        temporary_path = Path(temporary).resolve()
        exclude = {*exclude, temporary_path}
        copied = temporary_path / "source"
        shutil.copytree(root, copied, ignore=ignored)
        for file, (before, after) in changes.items():
            path = scoped_path(copied, file)
            if path.read_bytes() != before.encode("utf-8"):
                raise FixCheckUnavailable("복사본의 선언이 변경안과 다릅니다.")
            path.write_bytes(after.encode("utf-8"))
        components, findings = scan(copied)
        after_keys = {_component_key(item) for item in components if item.version}
        changed = {item["component"] for item in plan if item["kind"] == "change"}
        if any(_component_key(item.component) not in after_keys for item in bundle.findings if item.component.id in changed):
            raise FixCheckUnavailable("변경한 구성요소의 버전을 재수집하지 못했습니다.")
    return compare_candidates(bundle.findings, findings)
