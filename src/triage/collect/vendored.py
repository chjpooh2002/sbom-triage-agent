"""소스 배너와 JAR 안의 배포 메타데이터에서만 구성요소를 식별한다."""
import re
from zipfile import BadZipFile, ZipFile

from .core import Document

BANNER = re.compile(r"(?:^|[/!*|;]\s*|@preserve\s+)(@?[\w.-]+(?:/[\w.-]+)?)"
                    r"(?:\.js)?(?:\s+version\s*[:=]?|\s+v?|\s*@)\s*(\d+\.\d+(?:\.\d+)?(?:-[\w.-]+)?)\b", re.I)


def candidate(path):
    return path.name.endswith((".min.js", ".jar")) or (
        "vendor" in path.parts and path.suffix in {".js", ".css", ".py", ".java", ".c", ".h", ".cpp", ".ts"})


def report_undeclared(ctx):
    def coordinates(c):
        return c.ecosystem, c.group, c.name, c.version

    declared = {coordinates(c) for c in ctx.result.components if c.kind == "library" and c.discovered_by != "vendored"}
    for c in ctx.result.components:
        if c.discovered_by == "vendored" and coordinates(c) not in declared:
            ctx.anomaly("undeclared_bundle", f"명세·잠금 수집에서 확인되지 않은 내장 라이브러리 {c.display}를 추가했습니다.",
                        *c.evidence_ids)


def collect_vendor(ctx, path):
    file = path.relative_to(ctx.root).as_posix()
    if path.suffix == ".jar":
        found = False
        fallback = None
        try:
            with ZipFile(path) as jar:
                for info in sorted(jar.infolist(), key=lambda i: i.filename):
                    metadata = info.filename.startswith("META-INF/maven/") and info.filename.endswith("/pom.properties")
                    manifest = info.filename.upper() == "META-INF/MANIFEST.MF"
                    if not (metadata or manifest) or info.file_size > 1024 * 1024:
                        continue
                    with jar.open(info) as stream:
                        doc = Document(f"{file}!/{info.filename}", stream.read().decode("utf-8-sig"), "build")
                    fields = {}
                    for i, raw in enumerate(doc.lines, 1):
                        if manifest and not raw.strip():
                            break
                        key, sep, value = raw.partition("=" if metadata else ":")
                        if sep and value.strip():
                            fields[key.strip()] = value.strip(), i
                    keys = ("artifactId", "version") if metadata else ("Implementation-Title", "Implementation-Version")
                    if not all(k in fields for k in keys):
                        continue
                    name, version = (fields[k][0] for k in keys)
                    group = fields.get("groupId", ("",))[0]
                    refs = [ctx.evidence(doc, fields[k][1]) for k in (*keys, "groupId") if k in fields]
                    if manifest:
                        fallback = (name, version, refs)
                        continue
                    ctx.add(name=name, group=group, version=version, ecosystem="maven", version_source="vendored",
                            location=file, sources=[file], evidence_ids=refs, discovered_by="vendored")
                    found = True
                if not found and fallback:
                    name, version, refs = fallback
                    ctx.add(name=name, version=version, ecosystem="generic", version_source="vendored", location=file,
                            sources=[file], evidence_ids=refs, discovered_by="vendored")
                    found = True
        except (BadZipFile, UnicodeError):
            pass
        if not found:
            ctx.anomaly("unidentified_bundle", "JAR 구성요소를 식별할 메타데이터가 없습니다.",
                        ctx.evidence(Document(file, "", "build"), None))
        return
    doc = ctx.read(path, "code")
    for line, raw in enumerate(doc.lines, 1):
        if not raw.lstrip().startswith(("/*", "//", "*", "#")):
            continue
        match = BANNER.search(raw.lstrip("# ").split("*/", 1)[0][:600])
        if match:
            name, version = match.groups()
            ecosystem = {".js": "npm", ".ts": "npm", ".py": "pypi"}.get(path.suffix, "generic")
            ctx.add(name=name.removesuffix(".js"), version=version, ecosystem=ecosystem,
                    version_source="vendored", location=file, sources=[file], evidence_ids=[ctx.evidence(doc, line)],
                    discovered_by="vendored")
            return
    ctx.anomaly("unidentified_bundle", "배너에서 구성요소 이름과 버전을 확인할 수 없습니다.", ctx.evidence(doc))
