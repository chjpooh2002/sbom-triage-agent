"""로컬 OSV 상세 권고로만 설치 버전의 영향 범위 밖 여부를 확인한다."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable
from functools import cached_property
from pathlib import Path

from triage.lookup._advisory import exact_version
from triage.lookup._osv import ECOSYSTEMS, _canonical_name, _event_ranges, _range_match


_VERSION_ECOSYSTEMS = {name: key for key, name in ECOSYSTEMS.items() if key != "go"}


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
        for path in sorted(self.root.rglob("osv-vuln-*.json"), reverse=True):
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            identifier = doc.get("id") if isinstance(doc, dict) else None
            if not isinstance(identifier, str) or not identifier or identifier.casefold() in seen:
                continue
            seen.add(identifier.casefold())
            if doc.get("withdrawn"):
                continue
            aliases = doc.get("aliases")
            aliases = aliases if isinstance(aliases, list) else []
            for name in {value.casefold() for value in [identifier, *aliases] if isinstance(value, str)}:
                by_id[name].append(doc)
        return by_id

    def outside_advisories(self, identifiers: Iterable[str], component: str, version: str) -> tuple[str, ...]:
        if not exact_version(version) or re.search(r"\.x(?:\.|$)", version, re.IGNORECASE):
            return ()
        docs = {doc["id"]: doc for value in identifiers for doc in self._by_id.get(value.casefold(), ())}
        names = re.split(r"\s+/\s+", component)
        checked = set()
        for identifier, doc in docs.items():
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
