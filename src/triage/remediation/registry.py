"""패키지 레지스트리에서 실제 배포된 버전 목록을 가져온다(캐시 우선, 오프라인이면 캐시만).

- maven: Maven Central maven-metadata.xml
- npm·pypi·golang·cargo·nuget: deps.dev API
가져오지 못하면 None(=모름). 이때 검증은 스캐너의 수정 버전 목록으로만 한다.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Optional
from urllib.parse import quote
from xml.etree import ElementTree

from ..intel.cache import cache_dir
from ..maven_repos import FetchError, MavenRepositories, download
from ..models import Component

DEPSDEV = {"npm": "npm", "pypi": "pypi", "golang": "go", "cargo": "cargo", "nuget": "nuget", "maven": "maven"}
MAX_AGE_H = 24 * 7


def _cache_file(c: Component) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{c.ecosystem}_{c.group}_{c.name}")
    return cache_dir() / "registry" / f"{safe}.json"


def _fetch(c: Component, timeout: float) -> Optional[list[str]]:
    import httpx

    if c.ecosystem == "maven" and c.group:
        path = f"{quote(c.group.replace('.', '/'), safe='/')}/{quote(c.name, safe='')}/maven-metadata.xml"

        def parse_metadata(text, _url):
            root = ElementTree.fromstring(text)
            if root.tag != "metadata":
                raise ValueError("Maven metadata 요소가 없습니다.")
            return [node.text for node in root.findall("versioning/versions/version") if node.text]

        try:
            return MavenRepositories().fetch(path, download, parse_metadata)
        except FetchError as error:
            if error.missing:
                return []
            raise
    system = DEPSDEV.get(c.ecosystem)
    if not system:
        return None
    name = f"{c.group}/{c.name}" if c.group and c.ecosystem == "npm" else c.name
    r = httpx.get(f"https://api.deps.dev/v3/systems/{system}/packages/{quote(name, safe='')}", timeout=timeout)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return [v["versionKey"]["version"] for v in r.json().get("versions", [])]


def list_versions(c: Component, offline: bool = False, timeout: float = 10.0) -> Optional[list[str]]:
    f = _cache_file(c)
    if f.exists():
        data = json.loads(f.read_text(encoding="utf-8"))
        if offline or time.time() - data.get("fetched", 0) < MAX_AGE_H * 3600:
            return data["versions"]
    if offline:
        return None
    try:
        versions = _fetch(c, timeout)
    except Exception:
        # 네트워크 실패: 오래된 캐시라도 있으면 쓴다
        return json.loads(f.read_text(encoding="utf-8"))["versions"] if f.exists() else None
    if versions is None:
        return None
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps({"fetched": time.time(), "versions": versions}), encoding="utf-8")
    return versions
