"""npm packages 항목의 설치 경로와 선언 위치를 보존한다."""
from pathlib import Path, PurePosixPath

from semantic_version import NpmSpec, Version

from .core import LocatedJSON

MANIFEST = Path("package.json")
LOCKFILE = MANIFEST.with_stem(MANIFEST.stem + "-lock")

SECTIONS = (("dependencies", "runtime"), ("devDependencies", "dev"),
            ("peerDependencies", "unknown"), ("optionalDependencies", "optional"))


def declarations(data):
    result = {}
    for key, scope in SECTIONS:
        for name, spec in data.get(key, {}).items():
            if isinstance(spec, str):
                result[name] = key, spec, scope
    return result


def matches(version, spec):
    try:
        return NpmSpec(spec).match(Version(version.lstrip("v")))
    except ValueError:
        return None


def collect_npm(ctx, folder):
    manifest = folder / MANIFEST
    lock = folder / LOCKFILE
    prefix = folder.relative_to(ctx.root)
    declared = {}
    if manifest.is_file():
        doc = ctx.read(manifest, "manifest")
        try:
            meta = LocatedJSON(doc)
            declared = declarations(meta.data)
        except (ValueError, AttributeError):
            meta = None
            ctx.anomaly("invalid_manifest", "npm 명세를 해석할 수 없습니다.", ctx.evidence(doc))
    else:
        meta = None

    lock_entries = {}
    root_specs = {}
    if lock.is_file():
        locked = ctx.read(lock, "lockfile")
        try:
            tree = LocatedJSON(locked)
        except ValueError:
            tree = None
        packages = tree.data.get("packages") if tree else None
        if isinstance(packages, dict) and tree.data.get("lockfileVersion") in (2, 3):
            lock_entries = packages
            root_specs = declarations(packages.get("", {}))
        else:
            ctx.anomaly("unsupported_lockfile", "지원하는 npm packages 목록이 없습니다.", ctx.evidence(locked))

    installed = {}
    children = {}
    direct_names = set()
    for path, entry in lock_entries.items():
        if "node_modules/" not in path or not isinstance(entry, dict):
            continue
        key = path.rsplit("node_modules/", 1)[1]
        top = path == "node_modules/" + key
        declaration = declared.get(key) if top else None
        refs = [ctx.evidence(locked, tree.line("packages", path))]
        source_files = [locked.file]
        attrs = entry
        source_path = path
        if entry.get("link") and entry.get("resolved") in lock_entries:
            source_path = entry["resolved"]
            attrs = lock_entries[source_path]
        for prop in ("name", "version"):
            if prop in attrs:
                refs.append(ctx.evidence(locked, tree.line("packages", source_path, prop)))
        for prop in ("dev", "optional"):
            if prop in entry:
                refs.append(ctx.evidence(locked, tree.line("packages", path, prop)))
        spec = ""
        scope = "optional" if entry.get("optional") else "runtime"
        version = attrs.get("version", "")
        if declaration:
            section, spec, scope = declaration
            direct_names.add(key)
            refs.append(ctx.evidence(doc, meta.line(section, key)))
            source_files.append(doc.file)
            if matches(version, spec) is False:
                ctx.anomaly("lock_mismatch", f"{key} 명세 {spec}와 잠금 버전 {version}이 다릅니다.", *refs)
        if entry.get("dev") is True:
            scope = "dev"
        installed[path] = ctx.add(name=attrs.get("name", key), version=version, ecosystem="npm",
                                  direct=bool(declaration) if meta else None, scope=scope,
                                  declared_spec=spec, version_source="lockfile" if version else "unknown",
                                  discovered_by="npm", evidence_ids=refs, sources=source_files,
                                  location=(prefix / path).as_posix(), module=prefix.as_posix() if prefix.parts else "")
        children[path] = {name: decl for name, decl in declarations(attrs).items() if decl[0] != "devDependencies"}

    # Node resolves the closest installed copy, climbing ancestor node_modules directories.
    for path, deps in children.items():
        for name in deps:
            for ancestor in (PurePosixPath(path), *PurePosixPath(path).parents):
                candidate = (ancestor / "node_modules" / name).as_posix()
                if ancestor.name != "node_modules" and candidate in installed:
                    installed[path].depends_on.append(installed[candidate].id)
                    break

    if meta and "" in lock_entries:
        for key in sorted(declared.keys() | root_specs.keys()):
            current, saved = declared.get(key), root_specs.get(key)
            if current == saved:
                continue
            refs = [ctx.evidence(doc, meta.line(current[0], key) if current else 1),
                    ctx.evidence(locked, tree.line("packages", "", saved[0], key) if saved else tree.line("packages", ""))]
            ctx.anomaly("lock_mismatch", f"{key} 루트 선언과 잠금 파일의 명세가 다릅니다.", *refs)

    for key, (section, spec, scope) in declared.items():
        if key in direct_names:
            continue
        refs = [ctx.evidence(doc, meta.line(section, key))]
        if lock.is_file():
            refs.append(ctx.evidence(locked))
        ctx.anomaly("lock_mismatch" if lock.is_file() else "missing_lockfile",
                    f"{key} 설치 버전을 잠금 파일에서 확인할 수 없습니다.", *refs)
        ctx.add(name=key, ecosystem="npm", direct=True, scope=scope, declared_spec=spec,
                version_source="manifest_range", location=(prefix / "node_modules" / key).as_posix(),
                module="" if prefix.as_posix() == "." else prefix.as_posix(),
                discovered_by="npm", evidence_ids=refs, sources=[doc.file])
