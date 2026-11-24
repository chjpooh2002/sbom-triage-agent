"""등록된 정적 형식이 하나도 없을 때만 디렉터리를 Syft에 전달한다."""
import os
from pathlib import Path
import re
import shutil
import subprocess

from triage.ingest.common import parse_purl
from .core import Document, LocatedJSON, safe_file


def collect_syft(ctx):
    doc = Document(".", "", "tool")
    exe = shutil.which("syft")
    if not exe or Path(exe).resolve().is_relative_to(ctx.root):
        ctx.anomaly("syft_unavailable", "Syft 실행 파일을 찾을 수 없습니다.", ctx.evidence(doc, None, note="Syft 미설치"))
        ctx.event("syft.unavailable")
        return
    command = "syft scan dir:. -o syft-json"
    ctx.event("syft.start", command=command)
    try:
        proc = subprocess.run([exe, "scan", "dir:" + str(ctx.root), "-o", "syft-json"],
                              cwd=Path(exe).resolve().parent, capture_output=True, check=True,
                              encoding="utf-8", timeout=120,
                              env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false",
                                   "SYFT_JAVA_USE_NETWORK": "false", "SYFT_PYTHON_GUESS_UNPINNED_REQUIREMENTS": "false"})
        output = Document("syft:stdout", proc.stdout, "tool")
        tree = LocatedJSON(output)
        artifacts = tree.data["artifacts"]
        if not isinstance(artifacts, list):
            raise ValueError("Syft artifacts 목록 필요")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError):
        ctx.anomaly("syft_failed", "Syft가 유효한 스캔 결과를 반환하지 않았습니다.", ctx.evidence(doc, None, command=command))
        ctx.event("syft.failed")
        return
    for index, item in enumerate(artifacts):
        if not item.get("name"):
            continue
        purl = item.get("purl", "")
        parsed = parse_purl(purl)
        field = "version" if "version" in item else "name"
        refs = [ctx.evidence(output, tree.line("artifacts", index, field), command=command,
                             note=f"artifacts[{index}].{field}")]
        sources = []
        for loc in item.get("locations", []):
            relative = loc.get("path", "").replace("\\", "/").lstrip("/")
            path = ctx.root / relative
            if not relative or not safe_file(ctx.root, path):
                continue
            sources.append(relative)
            source = Document(relative, "", "tool")
            source_line = None
            version = item.get("version")
            if version and path.is_file() and path.stat().st_size <= 1024 * 1024:
                try:
                    source = ctx.read(path, "tool")
                except (OSError, UnicodeError):
                    pass
                else:
                    token = re.compile(r"(?<![\w.])" + re.escape(version) + r"(?![\w.])")
                    matches = [n for n, raw in enumerate(source.lines, 1) if token.search(raw)]
                    if len(matches) == 1:
                        source_line = matches[0]
            refs.append(ctx.evidence(source, source_line, command=command, note=f"Syft artifact {item.get('id', '')}"))
        ctx.add(name=item["name"], version=item.get("version", ""), group=parsed.get("group", ""),
                ecosystem=parsed.get("type") or item.get("type", ""), purl=purl, version_source="tool",
                discovered_by="tool:syft", evidence_ids=refs, sources=sources)
    ctx.event("syft.end", count=len(artifacts))
