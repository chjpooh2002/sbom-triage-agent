"""설치 없이 requirements, Poetry, Pipenv 선언과 잠금을 읽는다."""
import re
import tomllib
from collections import defaultdict
from dataclasses import dataclass

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion

from .core import LocatedJSON, safe_file


@dataclass
class Record:
    name: str
    spec: str
    scope: str
    file: str
    ref: str
    version: str = ""


def pin(spec):
    match = re.fullmatch(r"==\s*([^*,\s]+)", spec)
    return match[1] if match else ""


def requirements(ctx, path, seen):
    if path in seen:
        return
    seen.add(path)
    doc = ctx.read(path, "manifest")
    start = 1
    pending = ""
    for line, raw in enumerate(doc.lines, 1):
        if not pending:
            start = line
        pending += raw.strip()
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        value = re.split(r"\s+#|\s+--hash[= ]", pending, maxsplit=1)[0].strip()
        pending = ""
        if not value or value.startswith("#"):
            continue
        include = re.fullmatch(r"(?:-r\s*|--requirement[= \t]+)(.+)", value)
        if include:
            child = (path.parent / include[1].strip("'\"")).resolve()
            if safe_file(ctx.root, child) and child.is_file():
                yield from requirements(ctx, child, seen)
            else:
                ctx.anomaly("missing_include", "참조한 requirements 파일을 읽을 수 없습니다.", ctx.evidence(doc, start))
            continue
        if value.startswith("-"):
            continue
        try:
            req = Requirement(value)
        except InvalidRequirement:
            ctx.anomaly("unresolved_requirement", "패키지 선언을 해석할 수 없습니다.", ctx.evidence(doc, start))
            continue
        spec = str(req.specifier)
        yield Record(canonicalize_name(req.name), spec, "unknown", doc.file, ctx.evidence(doc, start), pin(spec))


def table_lines(doc):
    """단순/인용 키의 TOML 대입 위치를 테이블별로 인덱싱한다."""
    section = ""
    for line, raw in enumerate(doc.lines, 1):
        header = re.fullmatch(r"\s*\[([^][\n]+)\]\s*(?:#.*)?", raw)
        if header:
            section = header[1]
        key = re.match(r"""\s*(?:"([^"]+)"|'([^']+)'|([\w.-]+))\s*=""", raw)
        if key:
            yield section, next(v for v in key.groups() if v is not None), line


def manifest_records(ctx, path, flavor):
    doc = ctx.read(path, "manifest")
    data = tomllib.loads(doc.text)
    for section, name, line in table_lines(doc):
        if flavor == "poetry" and ((section, name) == ("project", "dependencies") or section == "project.optional-dependencies"):
            table = data.get("project", {})
            optional = section.endswith(".optional-dependencies")
            values = (table.get("optional-dependencies", {}) if optional else table).get(name, [])
            for value in values:
                try:
                    req = Requirement(value)
                except InvalidRequirement:
                    ctx.anomaly("unresolved_requirement", "프로젝트 의존성을 해석할 수 없습니다.", ctx.evidence(doc, line))
                    continue
                at = line
                for n in range(line - 1, len(doc.lines)):
                    if n > line - 1 and doc.lines[n].lstrip().startswith(("[", "]")):
                        break
                    if value in doc.lines[n]:
                        at = n + 1
                        break
                spec = str(req.specifier)
                yield Record(canonicalize_name(req.name), spec, "optional" if optional else "runtime",
                             doc.file, ctx.evidence(doc, at), pin(spec))
            continue
        if flavor == "pipenv":
            if section not in ("packages", "dev-packages"):
                continue
            scope = "dev" if section == "dev-packages" else "runtime"
        else:
            if section != "tool.poetry.dependencies" and not re.fullmatch(r"tool\.poetry\.group\.[\w-]+\.dependencies|tool\.poetry\.dev-dependencies", section):
                continue
            if name.lower() == "python":
                continue
            scope = {"tool.poetry.dependencies": "runtime", "tool.poetry.group.dev.dependencies": "dev",
                     "tool.poetry.dev-dependencies": "dev"}.get(section, "unknown")
        table = data
        for part in section.split("."):
            table = table.get(part, {})
        spec = table.get(name)
        if isinstance(spec, dict):
            spec = spec.get("version", "")
        if isinstance(spec, str):
            yield Record(canonicalize_name(name), spec, scope, doc.file, ctx.evidence(doc, line))


def locked_records(ctx, path):
    doc = ctx.read(path, "lockfile")
    if path.name == "Pipfile.lock":
        tree = LocatedJSON(doc)
        for section, scope in (("default", "runtime"), ("develop", "dev")):
            for name, attrs in tree.data.get(section, {}).items():
                spec = attrs.get("version", "")
                line = tree.line(section, name, "version") if spec else tree.line(section, name)
                yield Record(canonicalize_name(name), spec, scope, doc.file, ctx.evidence(doc, line), pin(spec))
        return
    packages = tomllib.loads(doc.text).get("package", [])
    starts = [i for i, raw in enumerate(doc.lines) if re.fullmatch(r"\s*\[\[package\]\]\s*(?:#.*)?", raw)]
    if len(starts) != len(packages):
        raise ValueError("Poetry 잠금 항목의 위치를 확인할 수 없습니다.")
    for attrs, start, end in zip(packages, starts, [*starts[1:], len(doc.lines)]):
        line = next((i for i in range(start + 1, end) if re.match(r"\s*version\s*=", doc.lines[i])), start)
        groups = attrs.get("groups", [attrs.get("category")])
        scope = "runtime" if "main" in groups else "dev" if groups == ["dev"] else "unknown"
        yield Record(canonicalize_name(attrs["name"]), "", scope, doc.file, ctx.evidence(doc, line + 1),
                     attrs.get("version", ""))


def compatible(spec, version):
    if not spec or not version or spec == "*":
        return None
    try:
        if re.fullmatch(r"\d+(?:\.\d+)*(?:[a-z]+\d+)?", spec):
            spec = "==" + spec
        if spec.startswith(("^", "~")) and not spec.startswith("~="):
            numbers = [int(part) for part in spec[1:].split(".")]
            pivot = (min(1, len(numbers) - 1) if spec[0] == "~" else
                     next((i for i, n in enumerate(numbers) if n), len(numbers) - 1))
            upper = ".".join(map(str, [*numbers[:pivot], numbers[pivot] + 1]))
            spec = f">={spec[1:]},<{upper}"
        return SpecifierSet(spec).contains(version, prereleases=True)
    except (InvalidSpecifier, InvalidVersion, ValueError):
        return None


def collect_python(ctx, folder, files):
    seen = set()
    reqs = [record for path in files if path.match("requirements*.txt")
            for record in requirements(ctx, path, seen)]
    matched = set()
    module = folder.relative_to(ctx.root).as_posix()
    for lock_name, manifest, flavor in (("poetry.lock", "pyproject.toml", "poetry"),
                                        ("Pipfile.lock", "Pipfile", "pipenv")):
        lock = folder / lock_name
        if not lock.is_file():
            continue
        other = list(manifest_records(ctx, folder / manifest, flavor)) if (folder / manifest).is_file() else []
        try:
            locked = list(locked_records(ctx, lock))
        except (ValueError, KeyError, TypeError):
            ctx.anomaly("invalid_lockfile", f"{flavor} 잠금 파일을 해석할 수 없습니다.", ctx.evidence(ctx.read(lock, "lockfile")))
            reqs.extend(other)
            continue
        by_name = defaultdict(list)
        for declaration in [*other, *reqs]:
            by_name[declaration.name].append(declaration)
        locked_names = {dep.name for dep in locked}
        for dep in locked:
            declarations = by_name[dep.name]
            refs = [dep.ref, *[r.ref for r in declarations]]
            for r in declarations:
                matched.add(r.ref)
                if compatible(r.spec, dep.version) is False:
                    ctx.anomaly("lock_mismatch", f"{r.name} 명세 {r.spec}와 잠금 버전 {dep.version}이 다릅니다.", r.ref, dep.ref)
            ctx.add(name=dep.name, ecosystem="pypi", version=dep.version, scope=dep.scope, discovered_by=flavor,
                    version_source="lockfile" if dep.version else "unknown", declared_spec=declarations[0].spec if declarations else "",
                    direct=True if declarations else None, module="" if module == "." else module,
                    evidence_ids=refs, sources=[dep.file, *[r.file for r in declarations]], location=dep.file)
        for r in other:
            if r.name not in locked_names:
                ctx.anomaly("lock_mismatch", f"{r.name} 선언에 해당하는 잠금 항목이 없습니다.", r.ref, ctx.evidence(ctx.read(lock, "lockfile")))
                reqs.append(r)
    for r in reqs:
        if r.ref not in matched:
            ctx.add(name=r.name, ecosystem="pypi", version=r.version, scope=r.scope, declared_spec=r.spec, direct=True,
                    version_source="manifest_pinned" if r.version else "manifest_range", discovered_by="requirements",
                    module="" if module == "." else module, evidence_ids=[r.ref], sources=[r.file], location=r.file)
