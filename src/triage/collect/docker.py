"""Dockerfile 전역 ARG 기본값과 FROM 참조를 정적으로 읽는다."""
import re

ARG = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
RUNTIMES = {"node": "node", "python": "python", "ruby": "ruby", "golang": "go", "nginx": "nginx",
            "openjdk": "java", "eclipse-temurin": "java", "amazoncorretto": "java", "maven": "maven"}


def collect_docker(ctx, path):
    doc = ctx.read(path, "build")
    aliases = set()
    args = {}
    global_args = True
    pending = ""
    for line, raw in enumerate(doc.lines, 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if not pending:
            start = line
        pending += value
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        words = pending.split()
        pending = ""
        if words[0].upper() == "ARG" and global_args and len(words) == 2:
            name, sep, default = words[1].partition("=")
            if sep:
                args[name] = (default, start)
        if words[0].upper() != "FROM":
            continue
        global_args = False
        operands = [w for w in words[1:] if not w.startswith("--")]
        if not operands:
            continue
        ref = operands[0]
        if ref.lower() in aliases:
            if len(operands) >= 3 and operands[1].lower() == "as":
                aliases.add(operands[2].lower())
            continue
        if len(operands) >= 3 and operands[1].lower() == "as":
            aliases.add(operands[2].lower())
        if ref == "scratch":
            continue
        refs = [ctx.evidence(doc, i) for i in range(start, line + 1)]

        def arg(match):
            name = match[1] or match[2]
            if name not in args:
                return match[0]
            default, n = args[name]
            refs.append(ctx.evidence(doc, n))
            return default

        ref = ARG.sub(arg, ref)
        image_tag, _, digest = ref.partition("@")
        image = image_tag
        tag = ""
        if ":" in image_tag.rsplit("/", 1)[-1]:
            image, tag = image_tag.rsplit(":", 1)
        if "$" in image:
            ctx.anomaly("unresolved_image", "FROM 이미지 이름을 확인할 수 없습니다.", *refs)
            continue
        concrete = tag if tag and "$" not in tag and tag != "latest" else ""
        ident = f"{doc.file}:{start}"
        ctx.add(name=image, version=concrete or (digest if "$" not in digest else ""), ecosystem="oci",
                kind="base-image", version_source="dockerfile", declared_spec=ref, location=ident, direct=True,
                discovered_by="dockerfile", evidence_ids=refs, sources=[doc.file])
        repo = image.removeprefix("docker.io/").removeprefix("library/")
        runtime = RUNTIMES.get(repo)
        if runtime:
            if runtime == "java":
                runtime = next((part for part in concrete.split("-") if part in {"jdk", "jre"}), runtime)
            match = re.match(r"^v?(\d+(?:\.\d+)*)(?:-|$)", concrete)
            ctx.add(name=runtime, version=match[1] if match else "", ecosystem="runtime", kind="runtime",
                    version_source="dockerfile", declared_spec=ref, location=ident, direct=True,
                    discovered_by="dockerfile", evidence_ids=refs, sources=[doc.file])
