"""의존성 그래프에서 직접 의존 여부와 루트→구성요소 경로를 구한다(SBOM 변환기 공용)."""
from __future__ import annotations

from collections import deque

MAX_PATHS = 3      # 구성요소마다 보관할 경로 수(보고서에 '어떤 경로로 들어왔나'를 보여 주는 용도)
MAX_DEPTH = 12


def annotate(components: dict, edges: dict[str, list[str]], roots: list[str]) -> None:
    """components: ref → Component. edges: ref → [ref]. roots: 루트 ref 목록(대상 앱 자신).

    루트 바로 아래면 direct=True, 더 깊은 곳에만 있으면 False. 그래프가 없으면 None 을 유지한다.
    """
    if not edges or not roots:
        return
    paths: dict[str, list[list[str]]] = {}
    q = deque([(r, [r]) for r in roots])
    while q:
        ref, path = q.popleft()
        if len(path) > MAX_DEPTH:
            continue
        for child in edges.get(ref, []):
            if child in path:
                continue
            new = path + [child]
            got = paths.setdefault(child, [])
            if len(got) < MAX_PATHS:
                got.append(new)
                q.append((child, new))
    root_set = set(roots)
    for ref, comp in components.items():
        if ref in root_set:
            continue
        ps = paths.get(ref)
        if not ps:
            continue
        comp.direct = any(len(p) == 2 for p in ps)
        comp.dependency_paths = [[components[r].id for r in p if r in components] for p in ps]
