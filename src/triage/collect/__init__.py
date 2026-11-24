"""소스 디렉터리에서 정적 어댑터를 자동 감지해 근거와 함께 수집한다."""
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .core import Collection, CollectResult, Document, project_files
from .docker import collect_docker
from .maven import collect_maven
from .npm import LOCKFILE, MANIFEST, collect_npm
from .python_deps import collect_python
from .syft import collect_syft
from .vendored import candidate, collect_vendor, report_undeclared


@dataclass(frozen=True)
class Adapter:
    name: str
    accepts: Callable[[Path], bool]
    run: Callable[[Collection, list[Path]], None]
    group: str = "file"  # file, folder, project


def folders_npm(ctx, paths):
    collect_npm(ctx, paths[0].parent)


def folders_python(ctx, paths):
    collect_python(ctx, paths[0].parent, paths)


ADAPTERS = {}


def register(adapter: Adapter):
    """새 형식은 감지 함수와 수집 함수를 한 번 등록한다."""
    if adapter.group not in {"file", "folder", "project"} or adapter.name in ADAPTERS:
        raise ValueError(f"잘못되거나 중복된 어댑터: {adapter.name}")
    ADAPTERS[adapter.name] = adapter


register(Adapter("npm", lambda p: p.name in {MANIFEST.name, LOCKFILE.name}, folders_npm, "folder"))
register(Adapter("pypi", lambda p: p.match("requirements*.txt") or p.name in {"poetry.lock", "Pipfile.lock"},
                 folders_python, "folder"))
register(Adapter("maven", lambda p: p.name == "pom.xml", collect_maven, "project"))
register(Adapter("dockerfile", lambda p: p.name.lower() == "dockerfile" or p.name.lower().endswith(".dockerfile")
                 or p.name.lower().startswith("dockerfile."), lambda ctx, paths: collect_docker(ctx, paths[0])))
register(Adapter("vendored", candidate, lambda ctx, paths: collect_vendor(ctx, paths[0])))


def collect(root: Path, log: Callable[..., None] | None = None, *, offline: bool = False) -> CollectResult:
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)
    ctx = Collection(root, log, offline=offline)
    files = sorted(project_files(root))
    detected = False
    for adapter in ADAPTERS.values():
        groups = defaultdict(list)
        for path in files:
            if adapter.accepts(path.relative_to(root)):
                key = {"file": path, "folder": path.parent, "project": root}[adapter.group]
                groups[key].append(path)
        for paths in groups.values():
            detected = True
            ctx.event("adapter.start", adapter=adapter.name, files=[p.relative_to(root).as_posix() for p in paths])
            try:
                adapter.run(ctx, paths)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as err:
                doc = Document(paths[0].relative_to(root).as_posix(), "", "manifest")
                ctx.anomaly("unreadable_input", f"{adapter.name} 입력을 해석할 수 없습니다 ({type(err).__name__}).",
                            ctx.evidence(doc, None))
            ctx.event("adapter.end", adapter=adapter.name)
    if not detected:
        collect_syft(ctx)
    else:
        report_undeclared(ctx)
    ctx.summarize_anomalies()
    ctx.event("end", components=len(ctx.result.components), anomalies=len(ctx.result.anomalies))
    return ctx.result


__all__ = ["collect", "CollectResult", "Adapter", "register"]
