"""복사된 POM에서 Maven 리액터의 모듈 선택과 의존 관계를 읽는다."""
from __future__ import annotations

import posixpath
from collections.abc import Callable
from dataclasses import dataclass, field
from xml.etree import ElementTree

from .docker import container_path


@dataclass
class Module:
    path: str
    group: str
    artifact: str
    requirements: list[tuple[str, str]]
    runtime_requirements: list[tuple[str, str]]
    source: str
    evidence: tuple[str, ...]
    packaging: str
    archive: str
    aliases: set[str] = field(default_factory=set)


@dataclass
class Reactor:
    modules: list[Module]
    selected: set[str]
    projects: set[str]
    complete: bool

    def closure(self, projects: set[str], *, runtime: bool = False) -> set[str]:
        modules = {module.path: module for module in self.modules}
        by_name = {(module.group, module.artifact): module.path for module in self.modules}
        selected = projects.copy()
        pending = list(selected)
        while pending:
            module = modules[pending.pop()]
            for requirement in module.runtime_requirements if runtime else module.requirements:
                dependency = by_name.get(requirement)
                if dependency and dependency not in selected:
                    selected.add(dependency)
                    pending.append(dependency)
        return selected


def reactor(pom: str, selectors: list[str], read: Callable, also_make: bool) -> Reactor | None:
    modules: dict[str, Module] = {}
    complete = True

    def visit(path: str) -> None:
        nonlocal complete
        if path in modules:
            return
        source = read(path)
        if source is None:
            complete = False
            return
        origin, content, evidence = source
        try:
            xml = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            complete = False
            return
        for element in xml.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]
        if xml.tag != "project":
            complete = False
            return
        directory = posixpath.dirname(path)
        artifact = xml.findtext("artifactId", "").strip()
        group = xml.findtext("groupId", xml.findtext("parent/groupId", "")).strip()
        version = xml.findtext("version", xml.findtext("parent/version", "")).strip()
        packaging = xml.findtext("packaging", "jar").strip()
        final_name = xml.findtext("build/finalName", f"{artifact}-{version}").strip()
        final_name = final_name.replace("${project.artifactId}", artifact).replace("${project.version}", version)
        properties = {"${project.groupId}": group, "${pom.groupId}": group}
        def coordinates(node: ElementTree.Element) -> tuple[str, str]:
            values = [node.findtext(tag, "").strip() for tag in ("groupId", "artifactId")]
            return properties.get(values[0], values[0]), values[1]

        refs = [*xml.findall("dependencies/dependency"), *xml.findall("build/plugins/plugin"),
                *xml.findall("build/plugins/plugin/dependencies/dependency"),
                *xml.findall("build/extensions/extension"), *xml.findall("parent")]
        requirements = [coordinates(node) for node in refs]
        runtime_requirements = [coordinates(node) for node in xml.findall("dependencies/dependency")
                                if node.findtext("scope", "compile").strip() in {"compile", "runtime"}
                                and node.findtext("optional", "false").strip() != "true"]
        if any("${" in group_id or "${" in name for group_id, name in requirements):
            complete = False
        if xml.findall("profiles/profile") or not artifact or "${" in group:
            complete = False
        relative = posixpath.relpath(directory, posixpath.dirname(pom))
        aliases = {relative, relative.removeprefix("./"), path, f":{artifact}", f"{group}:{artifact}"}
        archive = f"{final_name}.{packaging}" if version and "${" not in final_name and "/" not in final_name else ""
        modules[path] = Module(path, group, artifact, requirements, runtime_requirements, origin,
                               evidence, packaging, archive, aliases)
        for child in xml.findall("modules/module"):
            name = (child.text or "").strip()
            if not name or "${" in name:
                complete = False
                continue
            visit(container_path(name if name.endswith(".xml") else name + "/pom.xml", directory))

    visit(pom)
    if pom not in modules:
        return None
    projects: set[str] = set()
    for selector in selectors:
        selector = selector.removeprefix("+").removeprefix("./").rstrip("/") or "."
        found = [module.path for module in modules.values() if selector in module.aliases]
        if len(found) != 1:
            complete = False
        else:
            projects.add(found[0])
    graph = Reactor(list(modules.values()), projects.copy(), projects, complete)
    if also_make:
        graph.selected = graph.closure(projects)
    return graph
