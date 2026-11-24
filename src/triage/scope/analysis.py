"""최종 Docker 스테이지의 파일 출처와 설치 위치를 정적으로 추적한다."""
from __future__ import annotations

import json
import os
import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

from triage.models import Component, Evidence, SourceFileScope

from .docker import Instruction, Line, container_path, ignore_rules, ignored, instructions, matches, within, words
from .install import commands, normalized_name, omit_dev, options, requirements
from .maven import Reactor, reactor

_DOCKERFILE = "Dockerfile"
_DOCKER_IGNORE = ".dockerignore"
_NPM_MANIFEST = "package.json"


@dataclass
class ScopeResult:
    components: list[Component]
    files: list[SourceFileScope]
    evidence: list[Evidence]


@dataclass(frozen=True)
class Origin:
    path: str
    refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Install:
    kind: str
    ref: str
    anchor: str
    output: str
    refs: tuple[str, ...] = ()
    omit_dev: bool = False
    include_dev: bool = False
    npm_records: dict[str, dict] = field(default_factory=dict)
    entries: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    maven: Reactor | None = None
    maven_projects: frozenset[str] = frozenset()
    maven_inputs: tuple[Origin, ...] = ()


@dataclass
class Stage:
    image: str
    base_ref: str
    ref: str
    cwd: str = "/.scope-base-workdir"
    files: dict[str, Origin] = field(default_factory=dict)
    dirs: set[str] = field(default_factory=lambda: {"/", "/.scope-base-workdir"})
    installs: list[Install] = field(default_factory=list)
    uncertain: list[str] = field(default_factory=list)
    node_env: str = ""
    transfers: dict[str, str] = field(default_factory=dict)


class Build:
    def __init__(self, root: Path, paths: list[str]):
        self.root = root
        self.paths = set(paths)
        self.evidence: list[Evidence] = []
        self.refs: dict[tuple[str, str, Line | None, str], str] = {}
        self.excluded: dict[str, str] = {}
        self.base_images: list[tuple[str, str]] = []
        self.stages: dict[str, Stage] = {}
        self.context: dict[str, Origin] = {}
        self.text: dict[str, str | None] = {}
        self.final_files: dict[str, Origin] = {}
        self.maven_files: dict[str, tuple[str, ...]] = {}
        self.copy_refs: tuple[str, ...] = ()

    def cite(self, kind: str, path: str = "", line: Line | None = None, note: str = "") -> str:
        key = (kind, path, line, note)
        if key not in self.refs:
            ref = f"scope-{len(self.evidence) + 1:04d}"
            self.refs[key] = ref
            self.evidence.append(Evidence(id=ref, kind=kind, file=path, note=note,
                                          line_start=line.start if line else None,
                                          line_end=line.end if line else None,
                                          snippet=line.snippet if line else ""))
        return self.refs[key]

    def read(self, path: str) -> str | None:
        if path not in self.text:
            try:
                self.text[path] = (self.root / path).read_text(encoding="utf-8-sig") if path in self.paths else None
            except (OSError, UnicodeError):
                self.text[path] = None
        return self.text[path]

    def context_files(self) -> None:
        specific = _DOCKERFILE + _DOCKER_IGNORE
        self.ignore_file = specific if specific in self.paths else _DOCKER_IGNORE
        content = self.read(self.ignore_file)
        rules = ignore_rules(content or "")
        for path in sorted(self.paths):
            line = ignored(path, rules)
            if line:
                self.excluded[path] = self.cite("config", self.ignore_file, line, "빌드 컨텍스트 제외")
            elif path in {_DOCKERFILE, self.ignore_file}:
                self.excluded[path] = self.cite("build", path, note="Docker 빌드 제어 파일")
            else:
                self.context["/" + path] = Origin(path)

    def interpret(self, content: str) -> Stage | None:
        self.context_files()
        current: Stage | None = None
        index = 0
        for instruction in instructions(content):
            if instruction.op not in {"FROM", "COPY", "ADD", "WORKDIR", "RUN", "ENV", "ONBUILD", "SHELL"}:
                continue
            line = instruction.line
            if instruction.op == "ENV":
                line = replace(line, snippet="")
            ref = self.cite("build", _DOCKERFILE, line)
            try:
                if instruction.op == "FROM":
                    fields = _from_words(instruction.args)
                    image = fields[0]
                    parent = self.stages.get(image.lower())
                    if parent is None:
                        current = Stage(image, ref, ref)
                        if image == "scratch":
                            current.cwd = "/"
                            current.dirs = {"/"}
                        self.base_images.append((image, ref))
                    else:
                        current = replace(parent, ref=ref, files=parent.files.copy(), dirs=parent.dirs.copy(),
                                          installs=parent.installs.copy(),
                                          uncertain=parent.uncertain.copy(), transfers=parent.transfers.copy())
                    if "$" in image:
                        current.uncertain.append(ref)
                    self.stages[str(index)] = current
                    if len(fields) == 3:
                        self.stages[fields[2].lower()] = current
                    index += 1
                elif current is not None:
                    self.instruction(current, instruction, ref)
            except (ValueError, IndexError, re.error):
                if instruction.op == "FROM":
                    current = Stage("", ref, ref, uncertain=[ref])
                elif current is not None:
                    current.uncertain.append(ref)
        if current is not None and self.ignore_file in self.paths and self.read(self.ignore_file) is None:
            current.uncertain.append(self.cite("config", self.ignore_file, note="제외 규칙을 읽을 수 없음"))
        return current

    def instruction(self, stage: Stage, command: Instruction, ref: str) -> None:
        if command.op in {"COPY", "ADD"}:
            self.copy(stage, command, ref)
        elif command.op == "WORKDIR":
            args = words(command.args)
            if len(args) != 1 or "$" in args[0]:
                stage.uncertain.append(ref)
            else:
                stage.cwd = container_path(args[0], stage.cwd)
                stage.dirs.add(stage.cwd)
        elif command.op == "RUN":
            self.run(stage, command.args, ref)
        elif command.op == "ENV":
            args = words(command.args)
            if args and args[0] == "NODE_ENV":
                stage.node_env = " ".join(args[1:])
            else:
                for value in args:
                    if value.startswith("NODE_ENV="):
                        stage.node_env = value.split("=", 1)[1]
                    if value.lower().startswith("npm_config_"):
                        stage.uncertain.append(ref)
        elif command.op in {"ONBUILD", "SHELL"}:
            stage.uncertain.append(ref)

    def copy(self, stage: Stage, command: Instruction, ref: str) -> None:
        args = command.args
        source_stage = None
        while args.startswith("--"):
            flag, *rest = args.split(None, 1)
            args = rest[0] if rest else ""
            if flag.startswith("--from=") and command.op == "COPY":
                source_stage = self.stages.get(flag.split("=", 1)[1].lower())
                if source_stage is None or source_stage is stage:
                    raise ValueError("외부 또는 미확인 빌드 스테이지")
            elif not re.fullmatch(r"--(?:chown=\S+|chmod=\S+|link(?:=true|=false)?|checksum=\S+)", flag):
                raise ValueError("지원하지 않는 복사 옵션")
        *sources, dest = words(args)
        if not sources or any("$" in value or "<<" in value for value in (*sources, dest)):
            raise ValueError("동적 복사 경로")
        dest_path = container_path(dest, stage.cwd)
        directory = dest.endswith("/") or dest_path in stage.dirs or len(sources) > 1
        files = self.context if source_stage is None else source_stage.files
        if source_stage is not None:
            stage.uncertain.extend(source_stage.uncertain)
            stage.transfers[source_stage.base_ref] = ref
            stage.transfers.update(source_stage.transfers)
            if any(within(path, Stage.cwd) for path in (*source_stage.files, *(i.output for i in source_stage.installs))):
                stage.uncertain.append(ref)
        for source in sources:
            if source.startswith(("http://", "https://", "git@")):
                raise ValueError("원격 ADD")
            pattern = container_path(source)
            matched = list(matches(files, pattern))
            to_dir = directory or len({anchor for anchor, _ in matched}) > 1
            for anchor, path in matched:
                if command.op == "ADD" and source_stage is None and _tar(self.root / files[path].path):
                    stage.uncertain.append(ref)
                    continue
                target = _destination(dest_path, to_dir, anchor, path)
                origin = files[path]
                stage.files[target] = replace(origin, refs=(*origin.refs, ref))
                stage.installs = [item for item in stage.installs if item.kind != "maven" or item.output != target]
                stage.dirs.update(str(parent) for parent in PurePosixPath(target).parents)
            if source_stage is not None:
                self.copy_installs(stage, source_stage, pattern, dest_path, to_dir, ref)

    def copy_installs(self, stage: Stage, source: Stage, pattern: str, dest: str, directory: bool, ref: str) -> None:
        for install in source.installs:
            if not install.output:
                # 기본 pip 설치 위치는 이미지의 파이썬 환경에 따라 달라진다.
                continue
            for anchor, path in matches({install.output: None}, pattern):
                if install.kind != "maven" and anchor == install.output:
                    target = dest
                else:
                    target = _destination(dest, directory, anchor, path)
                if install.kind == "maven":
                    stage.files.pop(target, None)
                    stage.installs = [item for item in stage.installs if item.output != target]
                stage.installs.append(replace(install, output=target, refs=(*install.refs, ref)))
                break

    def run(self, stage: Stage, args: str, ref: str) -> None:
        cwd = stage.cwd
        for argv in commands(args):
            node_env = stage.node_env
            if len(argv) > 1 and argv[0].startswith("NODE_ENV="):
                node_env = argv.pop(0).split("=", 1)[1]
            command = posixpath.basename(argv[0])
            args = argv[1:]
            if command == "cd" and len(args) == 1:
                cwd = container_path(args[0], cwd)
                continue
            if command in {"echo", "true", "chmod", "chown", "set"}:
                continue
            if command == "mkdir" and all(not any(char in arg for char in "*?[") for arg in args):
                stage.dirs.update(container_path(arg, cwd) for arg in args if not arg.startswith("-"))
                continue
            if command == "npm" and args[:1] == ["ci"]:
                self.npm(stage, cwd, args[1:], node_env, ref)
            elif command == "mvn" or argv[0] == "./mvnw":
                self.maven(stage, cwd, args, ref)
            elif (re.fullmatch(r"pip(?:3(?:\.\d+)?)?", command) and args[:1] == ["install"]):
                self.pip(stage, cwd, args[1:], ref)
            elif re.fullmatch(r"python(?:3(?:\.\d+)?)?", command) and args[:3] == ["-m", "pip", "install"]:
                self.pip(stage, cwd, args[3:], ref)
            elif command == "rm" and all(not any(char in arg for char in "*?[") for arg in args):
                for arg in args:
                    if not arg.startswith("-"):
                        path = container_path(arg, cwd)
                        stage.files = {name: origin for name, origin in stage.files.items() if not within(name, path)}
                        stage.dirs = {name for name in stage.dirs if not within(name, path)}
                        stage.installs = [item for item in stage.installs if not within(item.output, path)]
                        if any(within(path, item.output) for item in stage.installs):
                            stage.uncertain.append(ref)
            else:
                stage.uncertain.append(ref)

    def npm(self, stage: Stage, cwd: str, args: list[str], node_env: str, ref: str) -> None:
        if any(value.startswith(("--workspace", "-w", "--global", "-g")) for value in args):
            raise ValueError("지원하지 않는 npm 설치 범위")
        prefixes = options(args, "--prefix", "--prefix")
        if prefixes:
            cwd = container_path(prefixes[-1], cwd)
        default_lock = f"{PurePosixPath(_NPM_MANIFEST).stem}-lock.json"
        lock = next((stage.files[path] for name in ("npm-shrinkwrap.json", default_lock)
                     if (path := container_path(name, cwd)) in stage.files), None)
        if lock is None:
            raise ValueError("설치 명세를 찾을 수 없음")
        content = self.read(lock.path)
        if content is None:
            raise ValueError("설치 명세를 읽을 수 없음")
        manifest = json.loads(content)
        if not isinstance(manifest, dict) or not isinstance(manifest.get("packages"), dict):
            raise ValueError("지원하지 않는 잠금 파일")
        if any(item.get("link") for item in manifest["packages"].values() if isinstance(item, dict)):
            raise ValueError("심볼릭 링크 기반 npm 작업 공간")
        output = container_path("node_modules", cwd)
        stage.files = {path: origin for path, origin in stage.files.items() if not within(path, output)}
        stage.installs = [item for item in stage.installs if item.output != output]
        omit = omit_dev(args)
        include = "dev" in options(args, "--include", "--include")
        stage.installs.append(Install("npm", ref, lock.path, output, lock.refs,
                                      omit_dev=omit or (node_env == "production" and not include),
                                      include_dev=include or (node_env == "development" and not omit),
                                      npm_records=manifest["packages"]))

    def pip(self, stage: Stage, cwd: str, args: list[str], ref: str) -> None:
        targets = options(args, "-t", "--target")
        if any(value.startswith(("--root", "--prefix", "--user", "--dry-run")) for value in args):
            raise ValueError("지원하지 않는 pip 설치 위치")

        def read(path: str) -> tuple[str, str, tuple[str, ...]] | None:
            origin = stage.files.get(path)
            if origin and (content := self.read(origin.path)) is not None:
                return origin.path, content, origin.refs
            return None

        def cite_line(path: str, content: str, start: int, end: int) -> str:
            snippet = "\n".join(content.splitlines()[start - 1:end])[:600]
            return self.cite("manifest", path, Line(start, end, snippet))

        specs = options(args, "-r", "--requirement")
        if not specs:
            raise ValueError("pip 요구사항 파일 지정 없음")
        for spec in specs:
            path = container_path(spec, cwd)
            output = container_path(targets[-1], cwd) if targets else ""
            stage.installs.append(Install("pypi", ref, "", output,
                                          entries=requirements(path, read, cite_line)))

    def maven(self, stage: Stage, cwd: str, args: list[str], ref: str) -> None:
        selectors = options(args, "-pl", "--projects")
        goals = {"package", "verify", "install", "deploy"}
        if (not selectors or goals.isdisjoint(args) or any(arg.startswith(("-P", "--activate-profiles", "-N", "--non-recursive"))
                                                            for arg in args)):
            raise ValueError("지원하지 않는 Maven 빌드")
        poms = options(args, "-f", "--file")
        pom = container_path(poms[-1] if poms else "pom.xml", cwd)
        if pom not in stage.files:
            pom = container_path("pom.xml", pom)

        def read(path: str) -> tuple[str, str, tuple[str, ...]] | None:
            origin = stage.files.get(path)
            if origin and (content := self.read(origin.path)) is not None:
                return origin.path, content, (self.cite("manifest", origin.path), *origin.refs)
            return None

        graph = reactor(pom, selectors[-1].split(","), read, "-am" in args or "--also-make" in args)
        if graph is None or not graph.complete:
            raise ValueError("Maven 리액터를 확정할 수 없음")
        archives = [module for module in graph.modules if module.path in graph.selected
                    and module.archive and module.packaging in {"jar", "war", "ear"}]
        modules_by_directory = {posixpath.dirname(module.path): module for module in archives}
        main_inputs: dict[str, list[Origin]] = {}
        for path, origin in stage.files.items():
            directory, separator, _ = path.partition("/src/main/")
            if separator and (owner := modules_by_directory.get(directory or "/")):
                main_inputs.setdefault(owner.path, []).append(replace(origin, refs=(*origin.refs, *owner.evidence)))
        for module in archives:
            output = container_path(f"target/{module.archive}", posixpath.dirname(module.path))
            build_modules = graph.closure({module.path}) & graph.selected
            inputs = tuple(origin for path, origins in main_inputs.items() if path in build_modules for origin in origins)
            stage.files.pop(output, None)
            stage.installs = [item for item in stage.installs if item.output != output]
            stage.installs.append(Install("maven", ref, "", output, maven=graph,
                                          maven_projects=frozenset({module.path}), maven_inputs=inputs))


def _from_words(value: str) -> list[str]:
    fields = [token for token in words(value) if not token.startswith("--platform=")]
    if len(fields) != 1 and (len(fields) != 3 or fields[1].lower() != "as"):
        raise ValueError("잘못된 FROM")
    return fields


def _destination(dest: str, directory: bool, anchor: str, path: str) -> str:
    if anchor != path:
        return container_path(posixpath.relpath(path, anchor), dest)
    return container_path(posixpath.basename(path), dest) if directory else dest


def _tar(path: Path) -> bool:
    # Docker는 확장자가 아니라 파일 내용을 보고 로컬 tar를 푼다.
    try:
        with path.open("rb") as file:
            header = file.read(512)
    except OSError:
        return True
    return header[257:262] == b"ustar" or header.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00"))


Decision = tuple[str, str, tuple[str, ...]]
_UNKNOWN_BUILD = "Dockerfile의 동적 경로 또는 명령 때문에 최종 스테이지 내용을 확정할 수 없음"


def _source_paths(component: Component, root: Path) -> set[str]:
    paths = set()
    for value in component.sources:
        candidate = Path(value)
        if candidate.is_absolute():
            try:
                candidate = candidate.relative_to(root)
            except ValueError:
                continue
        path = posixpath.normpath(candidate.as_posix().replace("\\", "/"))
        if path != ".." and not path.startswith(("../", "/")):
            paths.add(path)
    return paths


def _npm_decision(component: Component, install: Install, stage: Stage, build: Build) -> Decision | None:
    sources = _source_paths(component, build.root)
    package = posixpath.join(posixpath.dirname(install.anchor), _NPM_MANIFEST)
    if sources and sources.isdisjoint({install.anchor, package}):
        return None
    lock_path = component.id.partition("#")[2]
    records = [record for path, record in install.npm_records.items()
               if isinstance(record, dict) and (not lock_path or path == lock_path)
               and "node_modules/" in path and record.get("version") == component.version
               and record.get("name", path.rsplit("node_modules/", 1)[-1]) == component.name]
    refs = (*install.refs, install.ref, build.cite("lockfile", install.anchor))
    if not records:
        return None
    if any(within(path, install.output) for path in stage.files):
        return "unknown", "별도 COPY로 npm 설치 디렉터리의 내용이 바뀔 수 있음", refs
    if install.omit_dev and all(record.get("dev") is True and not record.get("devOptional") for record in records):
        return "no", "npm ci의 개발 의존성 제외 옵션과 잠금 파일에서 제외 확인", refs
    if any((not record.get("dev") or install.include_dev) and not record.get("optional") and not record.get("devOptional")
           for record in records):
        return "yes", "최종 스테이지에 포함된 npm ci 설치와 잠금 파일에서 확인", refs
    return "unknown", "npm의 개발·선택 의존성 설치 여부를 확정할 수 없음", refs


def _maven_decision(component: Component, installs: list[Install], build: Build) -> Decision | None:
    graph = installs[0].maven
    if graph is None:
        return None
    sources = _source_paths(component, build.root)
    by_source = [module for module in graph.modules if module.source in sources]
    name = component.module.replace("\\", "/").removeprefix("./").rstrip("/")
    # 상속 의존성의 POM 출처와 의존성이 적용되는 모듈은 다를 수 있다.
    modules = [module for module in graph.modules if name in module.aliases or name == module.artifact] if name else by_source
    if len(modules) > 1 and by_source:
        modules = [module for module in modules if module in by_source]
    if len(modules) != 1:
        return None
    deployed_roots = set().union(*(item.maven_projects if item.refs else item.maven_projects & graph.projects
                                   for item in installs))
    selected = graph.closure(deployed_roots, runtime=True) & graph.selected
    refs = tuple(dict.fromkeys(ref for item in installs for ref in (item.ref, *item.refs))) + tuple(
        ref for module in graph.modules for ref in module.evidence
    )
    if modules[0].path not in selected:
        return "no", "Maven 배포 대상과 리액터 의존 모듈에 포함되지 않음", refs
    if component.scope in {"test", "dev", "build_only", "provided"}:
        return "no", "선택된 Maven 모듈의 배포 전용 범위에서 제외되는 의존성", refs
    if component.scope == "runtime":
        return "yes", "Maven 배포 산출물에서 선택된 모듈의 런타임 범위에 포함됨", refs
    return "unknown", "선택된 Maven 모듈에서 구성요소의 런타임 범위를 확인할 수 없음", refs


def _image_matches(component: Component, image: str) -> bool:
    repository, _, digest = image.partition("@")
    basename = repository.rsplit("/", 1)[-1]
    name, separator, tag = basename.partition(":")
    version = digest or (tag if separator else "")
    component_name = component.name.lower()
    if component_name in {name.lower(), repository.removesuffix(":" + tag).lower()}:
        return not component.version or component.version == version or bool(
            re.match(re.escape(component.version) + r"[.\-]", version)
        )
    return (component_name in {"java", "jdk", "jre", "openjdk"}
            and name in {"eclipse-temurin", "openjdk", "amazoncorretto"} and bool(component.version)
            and (version == component.version or bool(re.match(re.escape(component.version) + r"[.\-]", version))))


def _component_decision(component: Component, stage: Stage, build: Build) -> Decision:
    if component.kind == "base-image" and stage.image and "$" not in stage.image:
        if _image_matches(component, stage.image):
            return "yes", "최종 스테이지가 사용하는 기반 이미지에서 확인", (stage.ref, stage.base_ref)
        build_refs = tuple(ref for image, ref in build.base_images if _image_matches(component, image))
        if build_refs:
            return "no", "빌드 전용 기반 이미지로 사용됨", (stage.ref, *build_refs)
    if stage.uncertain:
        return "unknown", _UNKNOWN_BUILD, (stage.ref, *stage.uncertain)
    if component.kind in {"runtime", "base-image", "server"} and component.version_source == "dockerfile":
        if _image_matches(component, stage.image):
            return "yes", "최종 스테이지가 사용하는 기반 이미지에서 확인", (stage.ref, stage.base_ref)
        for image, ref in build.base_images:
            if _image_matches(component, image):
                if ref in stage.transfers:
                    return "unknown", "빌드 스테이지에서 복사한 산출물의 런타임 포함 여부를 확인할 수 없음", (stage.ref, ref, stage.transfers[ref])
                return "no", "최종 스테이지에 상속되거나 복사되지 않는 빌드 이미지에서만 확인", (stage.ref, ref)
    if component.version_source == "vendored":
        sources = _source_paths(component, build.root) & build.paths
        if sources:
            decisions = [_file_decision(path, stage, build) for path in sorted(sources)]
            return next((item for item in decisions if item[0] == "yes"), decisions[0])
    candidates: list[Decision] = []
    if component.ecosystem == "maven":
        groups: dict[str, list[Install]] = {}
        for install in stage.installs:
            if install.kind == "maven":
                groups.setdefault(install.ref, []).append(install)
        for installs in groups.values():
            if decision := _maven_decision(component, installs, build):
                candidates.append(decision)
    for install in stage.installs:
        if component.ecosystem == "npm" and install.kind == "npm":
            if decision := _npm_decision(component, install, stage, build):
                candidates.append(decision)
        if component.ecosystem == "pypi" and install.kind == "pypi":
            refs = tuple(ref for version, ref in install.entries.get(normalized_name(component.name), [])
                         if version == component.version)
            if refs:
                candidates.append(("yes", "pip install -r로 설치하는 요구사항의 고정 버전과 일치", (install.ref, *install.refs, *refs)))
    for state in ("yes", "unknown", "no"):
        for candidate in candidates:
            if candidate[0] == state:
                return candidate
    return "unknown", "최종 스테이지에서 이 구성요소의 설치 또는 복사 근거를 확인할 수 없음", (stage.ref,)


def _file_decision(path: str, stage: Stage, build: Build) -> Decision:
    if path in build.excluded:
        return "no", "Docker 빌드 컨텍스트에서 복사할 수 없는 파일", (build.excluded[path],)
    if stage.uncertain:
        return "unknown", _UNKNOWN_BUILD, (stage.ref, *stage.uncertain)
    if archived := build.maven_files.get(path):
        return "yes", "Maven 빌드 산출물로 포함", (stage.ref, *archived)
    copied = build.final_files.get(path)
    if copied:
        return "yes", "최종 Docker 스테이지에 파일이 복사됨", (stage.ref, *copied.refs)
    return "no", "최종 Docker 스테이지에 원본 파일이 남는 경로가 없음", (stage.ref, *build.copy_refs)


def _classify(root: Path, path: str) -> tuple[str, Line | None]:
    parts = PurePosixPath(path.lower()).parts
    name = parts[-1]
    try:
        with (root / path).open("rb") as file:
            header = file.read(8192).decode("utf-8-sig", errors="replace")
    except OSError:
        header = ""
    for offset, value in enumerate(header.splitlines()[:12], 1):
        if "auto-generated" in value.lower():
            return "generated", Line(offset, offset, value[:600])
    if "generated" in parts[:-1]:
        return "generated", None
    if ".min." in name or "vendor" in parts[:-1] or name.endswith(".jar"):
        return "vendored_bundle", None
    if name.endswith((".js", ".css", ".mjs", ".cjs")):
        for offset, value in enumerate(header.splitlines(), 1):
            if len(value) >= 1500:
                return "vendored_bundle", Line(offset, offset, value[:600])
    if any(part in {"test", "tests", "__tests__", "spec", "specs"} for part in parts[:-1]) or re.search(
        r"(?:^(?:test|spec)[_.-]|(?:[_.-](?:test|spec)|(?:test|spec)(?:case|suite)?)\.(?:py|[cm]?[jt]sx?|java)$)", name
    ):
        return "test", None
    if "legacy" in parts[:-1] or name.startswith(("legacy_", "legacy-")):
        return "legacy", None
    if any(part in {"script", "scripts", "bin"} for part in parts[:-1]) or name.endswith((".sh", ".ps1", ".bat", ".cmd")):
        return "script", None
    if (name == "dockerfile" or name.endswith(".dockerignore") or name.startswith(".env")
            or name.endswith((".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties"))
            or name == "pom.xml" or any(part in {"config", "configs"} for part in parts[:-1])):
        return "config", None
    return "app", None


def apply_scope(root: Path, components: list[Component], log: Callable[..., None] | None = None) -> ScopeResult:
    """새 구성요소 목록, 파일 분류, 그리고 scope 단계에서 발급한 근거를 반환한다."""
    root = root.resolve()
    paths = []
    for directory, subdirs, names in os.walk(root):
        folder = Path(directory)
        subdirs[:] = [name for name in subdirs if name != ".git" and not (folder / name).is_symlink()]
        paths.extend((folder / name).relative_to(root).as_posix() for name in names
                     if name != ".git" and not (folder / name).is_symlink() and (folder / name).is_file())
    paths.sort()
    build = Build(root, paths)
    content = build.read(_DOCKERFILE)
    stage = build.interpret(content) if content is not None else None
    if stage is None:
        reason = "Dockerfile이 없어 배포 여부를 판단할 수 없음" if not (root / _DOCKERFILE).exists() else "Dockerfile에서 유효한 빌드 스테이지를 확인할 수 없음"
        fallback: Decision = ("unknown", reason, (build.cite("build", note=reason),))
    else:
        build.final_files = {origin.path: origin for origin in stage.files.values()}
        for artifact in stage.installs:
            if artifact.kind == "maven" and artifact.refs:
                for origin in artifact.maven_inputs:
                    build.maven_files.setdefault(origin.path, (*origin.refs, artifact.ref, *artifact.refs))
        build.copy_refs = tuple(ref for (_, path, line, _), ref in build.refs.items()
                                if path == _DOCKERFILE and line and re.match(r"\s*(?:COPY|ADD|RUN)\s", line.snippet, re.I))
    updated = []
    for component in components:
        status, reason, refs = _component_decision(component, stage, build) if stage else fallback
        existing = [ref for ref in component.evidence_ids if not ref.startswith("scope-")]
        updated.append(component.model_copy(update={"deployed": status, "deployed_reason": reason,
                                                     "evidence_ids": list(dict.fromkeys([*existing, *refs]))}))
    files = []
    for path in paths:
        status, reason, refs = _file_decision(path, stage, build) if stage else fallback
        category, line = _classify(root, path)
        ref = build.cite("config" if category == "config" else "code", path, line, f"파일 분류: {category}")
        files.append(SourceFileScope(path=path, deployed=status, category=category, reason=reason,
                                     evidence_ids=list(dict.fromkeys([*refs, ref]))))
    if log is not None:
        log("scope", "complete", components=len(updated), files=len(files), evidence=len(build.evidence))
    return ScopeResult(updated, files, build.evidence)
