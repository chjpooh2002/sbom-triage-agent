"""본선 정답 CSV와 CycloneDX 판정을 비교한다."""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from triage.lookup import CACHE_DIR

if __package__:
    from ._osv_cache import OsvCache
else:
    from _osv_cache import OsvCache


DEFAULT_GOLD = Path("eval/gold_finals.csv")
STATES = {"exploitable": "affected", "not_affected": "not_affected", "in_triage": "undetermined"}


@dataclass(frozen=True)
class Candidate:
    service: str
    vuln_id: str
    aliases: frozenset[str]
    component: str
    state: str
    missing_info: bool = False
    version: str = ""

    @property
    def names(self) -> set[str]:
        names = re.split(r"\s+/\s+", self.component)
        return {re.split(r"[:/]", name)[-1].strip().casefold() for name in names}

    @property
    def description(self) -> str:
        version = f" @ {self.version}" if self.version else ""
        return f"{self.service} / {self.vuln_id} / {self.component}{version}"


@dataclass(frozen=True)
class GoldCase(Candidate):
    scoring_set: str = ""
    component_aliases: tuple[str, ...] = ()

    @property
    def names(self) -> set[str]:
        return super().names.union(self.component_aliases)


@dataclass(frozen=True)
class Ratio:
    hits: int
    total: int

    def __str__(self) -> str:
        return f"{self.hits / self.total:.1%} ({self.hits}/{self.total})" if self.total else "— (0/0)"


@dataclass(frozen=True)
class ExtraCandidate:
    candidate: Candidate
    states: frozenset[str]

    @property
    def description(self) -> str:
        return f"{self.candidate.description} ({', '.join(sorted(self.states))})"


@dataclass(frozen=True)
class VersionExclusion:
    case: GoldCase
    advisories: tuple[str, ...]

    @property
    def description(self) -> str:
        return f"{self.case.description} (OSV {', '.join(self.advisories)})"


@dataclass(frozen=True)
class Score:
    accuracy: Ratio
    accuracy_with_exclusions: Ratio
    recall: Ratio
    precision: Ratio
    missed_affected: tuple[GoldCase, ...]
    false_positives: tuple[GoldCase, ...]
    missing_core: tuple[GoldCase, ...]
    version_exclusions: tuple[VersionExclusion, ...]
    extras: tuple[ExtraCandidate, ...]
    undetermined: int
    aux_undetermined: Ratio
    aux_missing_info: Ratio


def load_gold(path: Path, component_aliases: Iterable[str] = ()) -> list[GoldCase]:
    by_display: dict[str, list[str]] = {}
    for alias in component_aliases:
        display, sep, name = (part.strip().casefold() for part in alias.partition("="))
        if not (display and sep and name):
            raise ValueError("--component-alias에는 정답 이름=SBOM 이름 형식이 필요합니다")
        by_display.setdefault(display, []).append(name)
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        required = {"service", "vuln_id", "aliases", "component", "expected_state", "scoring_set"}
        if missing := required - set(reader.fieldnames or ()):
            raise ValueError(f"{path}: 필수 열 누락 ({', '.join(sorted(missing))})")

        cases = []
        for row in reader:
            service, vuln_id, aliases, component, state, scoring_set = (
                (row[key] or "").strip() for key in (
                    "service", "vuln_id", "aliases", "component", "expected_state", "scoring_set"
                )
            )
            if not (service and vuln_id and component and state in STATES.values()
                    and scoring_set in {"core", "aux"}):
                raise ValueError(f"{path}:{reader.line_num}: 정답 키, expected_state 또는 scoring_set 오류")
            cases.append(GoldCase(
                service, vuln_id, frozenset(re.split(r"[;,|\s]+", aliases)) - {""}, component, state,
                scoring_set=scoring_set, version=(row.get("version") or "").strip(),
                component_aliases=tuple(by_display.get(component.casefold(), ())),
            ))
    return cases


def _components(items: Iterable[dict]) -> Iterable[dict]:
    for item in items:
        yield item
        yield from _components(item.get("components", []))


def _has_missing_info(value: object) -> bool:
    if isinstance(value, str):
        value = value.strip()
        if value.startswith(("[", "{", '"')):
            try:
                return _has_missing_info(json.loads(value))
            except json.JSONDecodeError:
                return False
        return bool(value) and value.casefold() not in {"null", "none", "unknown", "n/a", "-"}
    if isinstance(value, list):
        return any(map(_has_missing_info, value))
    if isinstance(value, dict):
        return all(isinstance(value.get(key), str) and value[key].strip() for key in ("what", "where"))
    return False


def _predictions(path: Path, document: dict, service: str) -> list[Candidate]:
    project = document.get("metadata", {}).get("component")
    roots = [project, *document.get("components", [])] if project else document.get("components", [])
    components = {item["bom-ref"]: item for item in _components(roots) if item.get("bom-ref")}
    predictions = []
    for vuln in document.get("vulnerabilities", []):
        if not (vuln_id := vuln.get("id", "").strip()):
            raise ValueError(f"{path}: 취약점 ID 누락")
        properties = vuln.get("properties", [])
        aliases = {item["id"] for item in vuln.get("references", []) if item.get("id")}
        for item in properties:
            if item["name"] in {"triage:alias", "triage:aliases"}:
                aliases.update(re.split(r"[;,|\s]+", item["value"].strip()))
        analysis = vuln.get("analysis", {})
        state = STATES.get(analysis.get("state"), "unknown")
        missing_info = _has_missing_info(analysis.get("missing_info")) or any(
            _has_missing_info(item.get("value")) for item in properties if item["name"] == "triage:missing_info"
        )
        targets = vuln.get("affects", [])
        if not targets:
            raise ValueError(f"{path}: {vuln_id}의 affects 구성요소 누락")
        for target in targets:
            ref = target.get("ref")
            if ref not in components:
                raise ValueError(f"{path}: {vuln_id}의 구성요소 참조를 찾을 수 없습니다 ({ref})")
            component = components[ref]
            predictions.append(Candidate(service, vuln_id, frozenset(aliases - {""}),
                                         component["name"], state, missing_info,
                                         version=component.get("version", "").strip()))
    return predictions


def load_run(
    path: Path, gold: list[GoldCase], label: str, service: str | None = None,
) -> tuple[list[GoldCase], list[Candidate]]:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path}: CycloneDX JSON이 필요합니다")
    if service is None:
        project_name = document.get("metadata", {}).get("component", {}).get("name", "")
        known = {case.service.casefold() for case in gold}
        service = project_name if project_name.casefold() in known else label
    cases = [case for case in gold if case.service.casefold() == service.casefold()]
    if not cases:
        raise ValueError(f"{path}: 정답 서비스 {service!r}을 찾을 수 없습니다. --service를 확인하세요")
    return cases, _predictions(path, document, service)


def _groups(*runs: Iterable[Candidate]) -> Iterable[list[list[Candidate]]]:
    """서비스·이름 안에서 대표 ID와 별칭이 이어지는 후보를 묶는다."""
    parents: list[int] = []
    owners: dict[tuple[str, str, str], int] = {}
    entries = [(run, entry) for run, entries in enumerate(runs) for entry in entries]

    def root(index: int) -> int:
        while index != parents[index]:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for index, (_, entry) in enumerate(entries):
        parents.append(index)
        for name in entry.names:
            for identifier in entry.aliases | {entry.vuln_id}:
                key = (entry.service.casefold(), name, identifier.casefold())
                owner = owners.setdefault(key, index)
                parents[root(owner)] = index

    groups: dict[int, list[list[Candidate]]] = {}
    for index, (run, entry) in enumerate(entries):
        groups.setdefault(root(index), [[] for _ in runs])[run].append(entry)
    return groups.values()


def _gold_version(value: str) -> str:
    parts = value.split(maxsplit=1)
    return parts[0] if parts else ""


def _matched_groups(gold: Iterable[GoldCase], *runs: Iterable[Candidate]) -> Iterable[list[list[Candidate]]]:
    for group in _groups(gold, *runs):
        if len(group[0]) == 1:
            yield group
            continue

        by_version: dict[str, list[list[Candidate]]] = {}
        for index, entries in enumerate(group):
            for entry in entries:
                version = _gold_version(entry.version) if index == 0 else entry.version
                by_version.setdefault(version, [[] for _ in group])[index].append(entry)
        yield from by_version.values()


def _state(entries: list[Candidate]) -> str:
    states = {entry.state for entry in entries}
    if len(states) > 1:
        return "conflict"
    return next(iter(states), "absent")


def score(gold: list[GoldCase], predictions: list[Candidate], osv_cache: OsvCache | None = None) -> Score:
    exact = affected = detected = aux = aux_undetermined = aux_missing_info = core = 0
    exclusion_hits = undetermined = 0
    misses, false_positives, missing_core, version_exclusions, extras = [], [], [], [], []
    for cases, entries in _matched_groups(gold, predictions):
        state = _state(entries)
        undetermined += state == "undetermined"
        if not cases:
            extras.append(ExtraCandidate(entries[0], frozenset(entry.state for entry in entries)))
            continue
        for case in cases:
            advisories = ()
            if state == "absent" and osv_cache is not None:
                advisories = osv_cache.outside_advisories(case.aliases | {case.vuln_id},
                                                         case.component, _gold_version(case.version))
                if advisories:
                    version_exclusions.append(VersionExclusion(case, advisories))
            if case.scoring_set == "aux":
                aux += 1
                aux_undetermined += state == "undetermined"
                aux_missing_info += any(entry.missing_info for entry in entries)
                continue
            core += 1
            exact += state == case.state
            if state == "absent":
                if advisories:
                    exclusion_hits += case.state == "not_affected"
                else:
                    missing_core.append(case)
            if case.state == "affected":
                affected += 1
                if state == "affected":
                    detected += 1
                else:
                    misses.append(case)
            elif any(entry.state == "affected" for entry in entries):
                false_positives.append(case)
    extra_affected = sum("affected" in entry.states for entry in extras)
    return Score(
        accuracy=Ratio(exact, core),
        accuracy_with_exclusions=Ratio(exact + exclusion_hits, core),
        recall=Ratio(detected, affected),
        precision=Ratio(detected, detected + len(false_positives) + extra_affected),
        missed_affected=tuple(misses), false_positives=tuple(false_positives), missing_core=tuple(missing_core),
        version_exclusions=tuple(version_exclusions), extras=tuple(extras), undetermined=undetermined,
        aux_undetermined=Ratio(aux_undetermined, aux), aux_missing_info=Ratio(aux_missing_info, aux),
    )


def agreement(first: list[Candidate], second: list[Candidate], gold: Iterable[GoldCase] = ()) -> Ratio:
    hits = total = 0
    for _, left, right in _matched_groups(gold, first, second):
        if left or right:
            total += 1
            left_state = _state(left)
            hits += left_state in STATES.values() and left_state == _state(right)
    return Ratio(hits, total)


def render(label: str, result: Score, repeat: Ratio | None = None) -> str:
    metrics = [
        ("core 정확 일치율 (엄격)", result.accuracy),
        ("core 정확 일치율 (버전 제외 인정)", result.accuracy_with_exclusions),
        ("core 영향 있음 재현율", result.recall),
        ("core 영향 있음 정밀도", result.precision),
        ("core 후보 누락", len(result.missing_core)),
        ("버전 범위 밖 제외", len(result.version_exclusions)),
        ("정답에 없는 추가 후보", len(result.extras)),
        ("aux 판단 유보율", result.aux_undetermined),
        ("aux missing_info 기재율", result.aux_missing_info),
    ]
    if repeat is not None:
        metrics.append(("run1·run2 판정 일치율", repeat))
    lines = [f"# 본선 채점 ({label})", "", "| 지표 | 값 |", "| --- | ---: |"]
    lines.extend(f"| {name} | {value} |" for name, value in metrics)
    for title, entries in (
        ("놓친 영향 있음", result.missed_affected), ("오탐", result.false_positives),
        ("누락 후보 (core)", result.missing_core), ("추가 후보", result.extras),
        ("버전 범위 밖 제외", result.version_exclusions),
        ("정답지 밖 영향 있음 검토", tuple(entry for entry in result.extras if "affected" in entry.states)),
    ):
        lines.extend(["", f"## {title} ({len(entries)})", ""])
        lines.extend(f"- {entry.description}" for entry in sorted(entries, key=lambda entry: entry.description))
        if not entries:
            lines.append("없음")
    return "\n".join(lines) + "\n"


def add_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("label", help="산출물 파일명의 라벨")
    parser.add_argument("--gold", type=Path, default=DEFAULT_GOLD)
    parser.add_argument("--osv-cache", type=Path, default=CACHE_DIR, help="OSV 상세 권고 캐시 디렉터리")
    parser.add_argument("--service", help="정답 CSV의 서비스 이름")
    parser.add_argument("--component-alias", action="append", default=[], metavar="정답이름=SBOM이름",
                        help="정답지와 SBOM의 구성요소 표시명이 다른 경우에만 지정")
    parser.add_argument("--out", type=Path, default=Path("out"))


def checked_label(label: str) -> str:
    if not re.fullmatch(r"[\w-]+", label):
        raise ValueError("라벨에는 문자, 숫자, 밑줄, 하이픈만 쓸 수 있습니다")
    return label


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_inputs(parser)
    parser.add_argument("--sbom", type=Path, help="기본값은 <out>/sbom-<라벨>.json")
    parser.add_argument("--run2", type=Path, help="반복 비교용 두 번째 SBOM 경로")
    args = parser.parse_args()
    try:
        label = checked_label(args.label)
        gold = load_gold(args.gold, args.component_alias)
        first_path = args.sbom or args.out / f"sbom-{label}.json"
        cases, first = load_run(first_path, gold, label, args.service)
        repeat = None
        if args.run2:
            _, second = load_run(args.run2, gold, label, cases[0].service)
            repeat = agreement(first, second, cases)
        report = render(label, score(cases, first, OsvCache(args.osv_cache)), repeat)
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / f"score-{label}.md").write_text(report, encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(report, end="")


if __name__ == "__main__":
    main()
