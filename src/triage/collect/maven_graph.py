"""모듈별 유효 버전을 너비 우선으로 선택하고, 제외 규칙은 경로마다 전파한다."""
from collections import deque
from dataclasses import dataclass

from triage.models import Component

from .core import SourceLine


@dataclass(frozen=True)
class Limits:
    max_depth: int
    max_states: int
    max_poms: int


Key = tuple[str, str, str, str]
Exclusions = frozenset[tuple[str, str]]
SCOPE = {"compile": "runtime", "runtime": "runtime", "test": "test", "provided": "build_only", "system": "build_only"}


@dataclass
class Dependency:
    key: Key
    version: str
    version_source: str
    declared: str
    scope: str
    optional: str
    exclusions: Exclusions
    refs: tuple[SourceLine, ...]


@dataclass
class Visit:
    component: Component
    depth: int
    excluded: Exclusions
    ancestors: frozenset[Key]
    scope: str
    ref: SourceLine


def is_excluded(key, excluded):
    group, artifact = key[:2]
    return any(pair in excluded for pair in ((group, artifact), ("*", artifact), (group, "*"), ("*", "*")))


def collect_module(repo, pom):
    ctx = repo.ctx
    model = repo.model(pom)
    module = pom.path.parent.relative_to(ctx.root).as_posix()
    selected = {}
    visited = set()
    queue = deque()

    def accept(dep, parent=None):
        group, name, typ, classifier = key = dep.key
        ref = dep.refs[0]
        if dep.optional == "true" or (parent and is_excluded(key, parent.excluded)):
            return
        unknown_scope = dep.scope not in SCOPE or dep.optional not in {"", "false"}
        if unknown_scope:
            ctx.anomaly("unresolved_dependency", f"{group}:{name}의 범위 또는 optional 값을 확인할 수 없습니다.", *dep.refs)
        if parent and (unknown_scope or dep.scope not in {"compile", "runtime"}):
            return
        if not group or not name or any("${" in part for part in key):
            ctx.anomaly("unresolved_dependency", "Maven 의존성 좌표를 확인할 수 없습니다.", *dep.refs)
            return
        if (parent and key in parent.ancestors) or (group, name) == pom.gav[:2]:
            ctx.anomaly("pom_cycle", f"{group}:{name}의 순환 의존 경로를 중단했습니다.", ref)
            return

        scope = parent.scope if parent else SCOPE.get(dep.scope, "unknown")
        excluded = dep.exclusions | parent.excluded if parent else dep.exclusions
        state = key, excluded, scope
        bounded = state not in visited and repo.graph_states >= repo.limits.max_states
        component = selected.get(key)
        if bounded:
            repo.limit("states", f"의존 경로 {repo.limits.max_states}개 상한에 도달해 일부 탐색을 생략했습니다.", ref)
            if parent and component is None:
                return
        if component is None:
            component = ctx.add(
                group=group, name=name, ecosystem="maven", version=dep.version, version_source=dep.version_source,
                declared_spec=dep.declared, direct=parent is None, scope=scope,
                module=pom.gav[1] if module == "." else module, discovered_by="maven", evidence_ids=dep.refs,
                sources=[ref.doc.file, pom.doc.file], location=f"{module}/{typ}" + (f"/{classifier}" if classifier else ""),
            )
            selected[key] = component
            if not dep.version:
                ctx.anomaly("unresolved_dependency", f"{group}:{name}의 버전을 확정할 수 없습니다.", *dep.refs)
        if parent:
            if component.id not in parent.component.depends_on:
                parent.component.depends_on.append(component.id)
            # 여러 경로가 같은 승자를 가리킬 때도 각 선언 POM의 위치를 남긴다.
            edge_ref = ctx.evidence(*ref)
            if edge_ref not in component.evidence_ids:
                component.evidence_ids.append(edge_ref)
            if dep.version != component.version:
                # 가까운 선언을 가리키는 간선만 남긴다. 탈락한 버전의 경로로 자식을 다시 열지 않는다.
                return
            if not component.direct and scope == "runtime":
                component.scope = scope

        if bounded or state in visited:
            return
        visited.add(state)
        repo.graph_states += 1
        if not component.version or unknown_scope:
            return
        if any(not part or "${" in part for pair in excluded for part in pair):
            ctx.anomaly("unresolved_dependency", f"{group}:{name}의 exclusion 좌표를 확정하지 못해 하위 탐색을 중단했습니다.", ref)
            return
        depth = parent.depth + 1 if parent else 1
        if depth >= repo.limits.max_depth:
            repo.limit("depth", f"직접 의존성을 1로 센 깊이 {repo.limits.max_depth}에서 하위 탐색을 중단했습니다.", ref)
            return
        ancestors = parent.ancestors | {key} if parent else frozenset({key})
        queue.append(Visit(component, depth, excluded, ancestors, scope, ref))

    for dep in model.dependencies(None):
        accept(dep)
    while queue:
        visit = queue.popleft()
        c = visit.component
        descriptor = repo.lookup((c.group, c.name, c.version), visit.ref)
        if descriptor:
            for dep in repo.model(descriptor).dependencies(model.managed):
                accept(dep, visit)
