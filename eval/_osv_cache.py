"""로컬 OSV 상세 권고로만 설치 버전의 영향 범위 밖 여부를 확인한다."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote

import httpx

from triage.lookup._advisory import exact_version
from triage.lookup._http import Responses
from triage.lookup._osv import API, ECOSYSTEMS, _canonical_name, _event_ranges, _range_match


_VERSION_ECOSYSTEMS = {name: key for key, name in ECOSYSTEMS.items() if key != "go"}


@dataclass(frozen=True)
class FetchResult:
    received: tuple[str, ...]
    failed: tuple[str, ...]


def _detail_ids(doc: object) -> set[str]:
    if not isinstance(doc, dict) or not isinstance(doc.get("id"), str) or not doc["id"]:
        return set()
    if not isinstance(doc.get("affected"), list) and not doc.get("withdrawn"):
        return set()
    aliases = doc.get("aliases")
    aliases = aliases if isinstance(aliases, list) else []
    return {item.casefold() for item in [doc["id"], *aliases] if isinstance(item, str) and item}


def _outside_ranges(entry: dict, version: str, ecosystem: str) -> bool:
    rules = entry.get("ranges")
    if not isinstance(rules, list) or not rules:
        return False
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") not in ("ECOSYSTEM", "SEMVER"):
            return False
        comparison = "npm" if rule["type"] == "SEMVER" else ecosystem
        events = rule.get("events")
        if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
            return False
        ranges, _, valid = _event_ranges(events)
        if not valid:
            return False
        for expr in ranges:
            lower, comma, upper = expr.partition(",")
            if comma and _range_match(lower[2:], upper, comparison) is not True:
                return False
            if _range_match(version, expr, comparison) is not False:
                return False

    # 명시적으로 영향 받는 버전 목록은 범위 해석과 충돌하는 경우 제외 판단을 막는다.
    listed = entry.get("versions") or []
    comparison = "npm" if all(rule["type"] == "SEMVER" for rule in rules) else ecosystem
    return isinstance(listed, list) and all(
        isinstance(item, str) and exact_version(item) and _range_match(version, f"=={item}", comparison) is False
        for item in listed
    )


class OsvCache:
    def __init__(self, root: Path):
        self.root = root

    @cached_property
    def _by_id(self) -> dict[str, list[dict]]:
        by_id = defaultdict(list)
        seen = set()
        paths = sorted(self.root.rglob("osv-vuln-*.json"),
                       key=lambda path: (path.parent != self.root / "eval", path), reverse=True)
        for path in paths:
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            names = _detail_ids(doc)
            if not names or doc["id"].casefold() in seen:
                continue
            seen.add(doc["id"].casefold())
            for name in names:
                by_id[name].append(doc)
        return by_id

    def _save_fetched(self, doc: dict) -> None:
        # 일반 조회의 GET 키와 평가용 권고문 키를 구분한다.
        target = self.root / "eval" / Responses.key("osv-vuln", doc["id"])
        target.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=target.parent) as temp:
            partial = Path(temp) / "advisory.json"
            partial.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            partial.replace(target)

    def fetch_missing(self, groups: Iterable[tuple[str, ...]], client: httpx.Client) -> FetchResult:
        received, failed, attempted = set(), [], set()
        not_found = set()
        for identifiers in groups:
            if any(identifier.casefold() in self._by_id for identifier in identifiers):
                continue
            for identifier in identifiers:
                normalized = identifier.casefold()
                if normalized in attempted:
                    if normalized in not_found:
                        continue
                    break
                attempted.add(normalized)
                try:
                    response = client.get(f"{API}/vulns/{quote(identifier, safe='')}")
                    if response.status_code == 404:
                        not_found.add(normalized)
                        failed.append(identifier)
                        continue
                    response.raise_for_status()
                    doc = response.json()
                    names = _detail_ids(doc)
                    if normalized not in names:
                        raise ValueError("요청 ID에 해당하는 OSV 상세 권고가 없습니다")
                    self._save_fetched(doc)
                except (httpx.HTTPError, OSError, ValueError):
                    failed.append(identifier)
                    break
                for name in names:
                    self._by_id[name].append(doc)
                received.add(doc["id"])
                break
        return FetchResult(tuple(sorted(received)), tuple(sorted(failed)))

    def outside_advisories(self, identifiers: Iterable[str], component: str, version: str) -> tuple[str, ...]:
        if not exact_version(version) or re.search(r"\.x(?:\.|$)", version, re.IGNORECASE):
            return ()
        docs = {doc["id"]: doc for value in identifiers for doc in self._by_id.get(value.casefold(), ())}
        names = re.split(r"\s+/\s+", component)
        checked = set()
        for identifier, doc in docs.items():
            if doc.get("withdrawn"):
                continue
            entries = doc.get("affected")
            if not isinstance(entries, list):
                continue
            for entry in entries:
                package = entry.get("package") if isinstance(entry, dict) else None
                if not isinstance(package, dict):
                    continue
                eco, name = package.get("ecosystem"), package.get("name")
                if not isinstance(eco, str) or not isinstance(name, str) or not name:
                    continue
                full_name = _canonical_name(name, eco)
                if not any(_canonical_name(value, eco) == full_name for value in names):
                    continue
                if not _outside_ranges(entry, version, _VERSION_ECOSYSTEMS.get(eco, "")):
                    return ()
                checked.add(identifier)
        return tuple(sorted(checked))
