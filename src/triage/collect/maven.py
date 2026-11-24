"""POM의 기본 활성 모델을 정적으로 읽는다. 중앙 저장소에서는 POM만 받는다."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from xml.etree.ElementTree import Element, TreeBuilder
from xml.parsers import expat

import httpx

from .core import Document, SourceLine, safe_file

CACHE = Path(__file__).resolve().parents[3] / "data/cache/maven"
CENTRAL = "https://repo.maven.apache.org/maven2"
PROPERTY = re.compile(r"\$\{([^{}]+)\}")


@dataclass
class Pom:
    doc: Document
    root: Element
    lines: dict
    path: Path | None = None

    def ref(self, node):
        return SourceLine(self.doc, self.lines[node])

    @property
    def gav(self):
        return (self.root.findtext("groupId") or self.root.findtext("parent/groupId", ""),
                self.root.findtext("artifactId", ""),
                self.root.findtext("version") or self.root.findtext("parent/version", ""))


def parse(doc, path=None):
    builder = TreeBuilder()
    parser = expat.ParserCreate(namespace_separator=" ")
    lines = {}

    def start(tag, attrs):
        node = builder.start(tag.rsplit(" ", 1)[-1], {})
        lines[node] = parser.CurrentLineNumber

    def reject_dtd(*_):
        raise ValueError("POM DTD는 지원하지 않습니다.")

    parser.StartElementHandler = start
    parser.EndElementHandler = lambda tag: builder.end(tag.rsplit(" ", 1)[-1])
    parser.CharacterDataHandler = builder.data
    parser.StartDoctypeDeclHandler = reject_dtd
    parser.Parse(doc.text, True)
    root = builder.close()
    if root.tag != "project":
        raise ValueError("project 요소가 없습니다.")
    for node in root.iter():
        if node.text:
            node.text = node.text.strip()
    return Pom(doc, root, lines, path)


@dataclass
class Value:
    text: str
    refs: tuple = ()
    override: bool = False


def expand(raw, props, seen=frozenset()):
    refs = list(raw.refs)
    override = raw.override

    def replace(match):
        nonlocal override
        key = match[1]
        if key in seen or key not in props:
            return match[0]
        prop = expand(props[key], props, seen | {key})
        refs.extend(prop.refs)
        override |= prop.override
        return prop.text

    return Value(PROPERTY.sub(replace, raw.text), tuple(dict.fromkeys(refs)), override)


def field(pom, entry, key, props):
    node = entry.find(key)
    if node is None:
        return Value("")
    return expand(Value(node.text or "", (pom.ref(node),)), props)


def properties(chain):
    props = {}
    for pom in chain:
        for node in pom.root.findall("properties/*"):
            prev = props.get(node.tag)
            props[node.tag] = Value(node.text or "", (*prev.refs, pom.ref(node)) if prev else (pom.ref(node),),
                                    prev is not None)
        for key, text in zip(("groupId", "artifactId", "version"), pom.gav):
            node = pom.root.find(key)
            if node is None:
                node = pom.root.find("parent/" + key)
            if node is not None:
                props["project." + key] = props["pom." + key] = Value(text, (pom.ref(node),))
    return props


def valid_coord(gav):
    return all(re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.+-]*", part) and ".." not in part
               and not part.endswith(".") for part in gav)


def download(url):
    response = httpx.get(url, timeout=6.0)
    response.raise_for_status()
    return response.content.decode("utf-8-sig")


class Repository:
    def __init__(self, ctx, local):
        self.ctx = ctx
        self.local = {pom.gav: pom for pom in local}
        self.paths = {pom.path: pom for pom in local}
        self.external = {}

    def lookup(self, gav, ref):
        if gav in self.local:
            return self.local[gav]
        if gav in self.external:
            return self.external[gav]
        if not valid_coord(gav):
            self.ctx.anomaly("unresolved_pom", "부모 또는 BOM 좌표를 확인할 수 없습니다.", ref)
            return None
        group, artifact, version = gav
        rel = f"{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"
        url = CENTRAL + "/" + rel
        cache = CACHE / rel
        self.external[gav] = None
        try:
            if cache.is_file():
                text = cache.read_text(encoding="utf-8")
                cached = True
            else:
                self.ctx.event("maven.fetch", url=url)
                text = download(url)
                cached = False
            pom = parse(Document("data/cache/maven/" + rel, text, "manifest", url))
            if not cached:
                cache.parent.mkdir(parents=True, exist_ok=True)
                with NamedTemporaryFile(dir=cache.parent, mode="w", encoding="utf-8", delete=False) as tmp:
                    tmp.write(text)
                try:
                    os.replace(tmp.name, cache)
                finally:
                    Path(tmp.name).unlink(missing_ok=True)
            self.external[gav] = pom
            self.ctx.event("maven.resolved", url=url, cached=cached)
        except (httpx.HTTPError, OSError, ValueError, expat.ExpatError):
            self.ctx.anomaly("unresolved_pom", "부모 또는 BOM POM을 읽지 못했습니다.", ref)
        return self.external[gav]

    def lineage(self, pom):
        chain = []
        seen = set()
        while pom and pom.doc.file not in seen:
            seen.add(pom.doc.file)
            chain.append(pom)
            parent = pom.root.find("parent")
            if parent is None:
                break
            props = properties([pom])
            gav = tuple(field(pom, parent, k, props).text for k in ("groupId", "artifactId", "version"))
            local = None
            rel = parent.findtext("relativePath", "../pom.xml")
            if pom.path and rel:
                path = (pom.path.parent / rel).resolve()
                if path.is_dir():
                    path /= "pom.xml"
                candidate = self.paths.get(path)
                if candidate and candidate.gav == gav:
                    local = candidate
            pom = local or self.lookup(gav, pom.ref(parent))
            if pom and pom.doc.file in seen:
                self.ctx.anomaly("pom_cycle", "부모 POM 순환 참조입니다.", chain[-1].ref(parent))
        return chain[::-1]


def dependency_key(pom, entry, props):
    return tuple(field(pom, entry, k, props).text or default
                 for k, default in (("groupId", ""), ("artifactId", ""), ("type", "jar"), ("classifier", "")))


@dataclass
class Managed:
    version: Value
    scope: Value


def management(repo, chain, active):
    ctx = repo.ctx
    props = properties(chain)
    result = {}
    for pom in chain:
        imports = {}
        explicit = {}
        for dep in pom.root.findall("dependencyManagement/dependencies/dependency"):
            key = dependency_key(pom, dep, props)
            version = field(pom, dep, "version", props)
            scope = field(pom, dep, "scope", props)
            if key[2] == "pom" and scope.text == "import":
                ref = pom.ref(dep)
                bom = repo.lookup((*key[:2], version.text), ref)
                if bom and bom.doc.file not in active:
                    imported = management(repo, repo.lineage(bom), active | {bom.doc.file})
                    for coord, managed in imported.items():
                        source = managed.version
                        value = Value(source.text, (ref, *version.refs, *source.refs), source.override)
                        imports.setdefault(coord, Managed(value, managed.scope))
                elif bom:
                    ctx.anomaly("pom_cycle", "BOM 순환 참조입니다.", ref)
            else:
                explicit[key] = Managed(version, scope)
        for key, value in imports.items():
            result.setdefault(key, value)
        result.update(explicit)
    return result


def collect_maven(ctx, paths):
    poms = []
    pending = list(paths)
    seen = set()
    for path in pending:
        if path in seen:
            continue
        seen.add(path)
        doc = ctx.read(path, "manifest")
        try:
            pom = parse(doc, path)
        except (ValueError, expat.ExpatError):
            ctx.anomaly("invalid_pom", "POM XML을 해석할 수 없습니다.", ctx.evidence(doc))
            continue
        poms.append(pom)
        for module in pom.root.findall("modules/module"):
            target = (path.parent / (module.text or "")).resolve()
            if target.is_dir():
                target /= "pom.xml"
            if safe_file(ctx.root, target) and target.is_file():
                pending.append(target)
            else:
                ctx.anomaly("unresolved_module", "선언한 모듈의 POM을 확인할 수 없습니다.", pom.ref(module))
    repo = Repository(ctx, poms)
    for pom in poms:
        chain = repo.lineage(pom)
        props = properties(chain)
        managed = management(repo, chain, {pom.doc.file})
        dependencies = {}
        for owner in chain:
            for dep in owner.root.findall("dependencies/dependency"):
                key = dependency_key(owner, dep, props)
                dependencies[key] = (owner, dep)
        for key, (owner, dep) in dependencies.items():
            group, name, typ, classifier = key
            if not name or PROPERTY.search(name):
                ctx.anomaly("unresolved_dependency", "Maven 의존성 이름을 확인할 수 없습니다.", owner.ref(dep))
                continue
            explicit = field(owner, dep, "version", props)
            scope = field(owner, dep, "scope", props)
            version = explicit
            source = "manifest_pinned"
            if key in managed:
                if not version.text:
                    version = managed[key].version
                    source = "managed"
                if not scope.text:
                    scope = managed[key].scope
            if version.override:
                source = "property_override"
            actual = version.text
            if not actual or PROPERTY.search(actual) or actual in ("RELEASE", "LATEST"):
                actual, source = "", "unknown"
            elif actual.startswith(("[", "(")):
                actual, source = "", "manifest_range"
            module = pom.path.parent.relative_to(ctx.root).as_posix()
            refs = [owner.ref(dep), *field(owner, dep, "artifactId", props).refs,
                    *field(owner, dep, "groupId", props).refs, *version.refs, *scope.refs]
            refs.extend(p.ref(p.root.find("parent")) for p in chain if p.root.find("parent") is not None)
            scope_name = {"": "runtime", "compile": "runtime", "runtime": "runtime", "test": "test",
                          "provided": "build_only", "system": "build_only"}.get(scope.text, "unknown")
            optional = field(owner, dep, "optional", props)
            if optional.text == "true":
                refs.extend(optional.refs)
                scope_name = "optional"
            ctx.add(group="" if PROPERTY.search(group) else group, name=name, ecosystem="maven", version=actual,
                    version_source=source, declared_spec=dep.findtext("version", ""), direct=True, scope=scope_name,
                    module=pom.gav[1] if module == "." else module, discovered_by="maven", evidence_ids=refs,
                    sources=[owner.doc.file, pom.doc.file], location=f"{module}/{typ}" + (f"/{classifier}" if classifier else ""))
