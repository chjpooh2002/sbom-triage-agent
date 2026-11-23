"""KEV·EPSS 전체 파일 내려받기와 캐시 읽기.

- 내려받기(`fetch_all`)만 네트워크를 쓴다. 보강(`enrich`)은 캐시 파일만 읽는다 → 현장 네트워크가 없어도 동작.
- 내려받기에 실패하면 기존 캐시를 지우지 않는다(임시 파일에 받은 뒤 교체).
- 캐시가 없으면 data/snapshot 의 발췌본으로 대체하고 경고를 남긴다.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from ..config import ROOT, load_yaml


def intel_config() -> dict:
    return load_yaml("intel.yaml")


def _dir(key: str) -> Path:
    p = Path(intel_config()[key])
    return p if p.is_absolute() else ROOT / p


def cache_dir() -> Path:
    return Path(os.environ.get("TRIAGE_CACHE_DIR", _dir("cache_dir")))


def snapshot_dir() -> Path:
    return _dir("snapshot_dir")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_manifest(d: Optional[Path] = None) -> dict:
    p = (d or cache_dir()) / "manifest.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _write_manifest(d: Path, m: dict) -> None:
    (d / "manifest.json").write_text(json.dumps(m, ensure_ascii=False, indent=1), encoding="utf-8")


def _download(urls: list[str], dest: Path, timeout: float) -> tuple[str, bytes]:
    import httpx

    errors = []
    for url in urls:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as c:
                r = c.get(url)
                r.raise_for_status()
                data = r.content
            tmp = dest.with_suffix(dest.suffix + ".part")
            tmp.write_bytes(data)
            tmp.replace(dest)
            return url, data
        except Exception as e:  # 다음 주소로
            errors.append(f"{url}: {e}")
    raise RuntimeError("모든 주소에서 내려받기 실패:\n  " + "\n  ".join(errors))


def fetch_all(which: Iterable[str] = ("kev", "epss"), d: Optional[Path] = None) -> dict:
    """KEV·EPSS 를 내려받아 캐시하고 manifest 를 갱신한다. 실패한 항목은 기존 캐시를 유지한다."""
    cfg = intel_config()
    d = d or cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    manifest = read_manifest(d)
    report = {}
    for name in which:
        c = cfg[name]
        try:
            url, data = _download(c["urls"], d / c["file"], cfg.get("timeout_seconds", 60))
        except RuntimeError as e:
            report[name] = {"ok": False, "error": str(e), "kept": name in manifest}
            continue
        entry = {"url": url, "file": c["file"], "fetched_at": _now(), "bytes": len(data),
                 "sha256": hashlib.sha256(data).hexdigest()}
        if name == "kev":
            doc = json.loads(data)
            entry.update(records=len(doc.get("vulnerabilities", [])), catalog_version=doc.get("catalogVersion", ""),
                         date_released=doc.get("dateReleased", ""))
        else:
            meta, n = _epss_meta_and_count(gzip.decompress(data).decode("utf-8"))
            entry.update(records=n, **meta)
        manifest[name] = entry
        report[name] = {"ok": True, **entry}
    _write_manifest(d, manifest)
    return report


def _epss_meta_and_count(text: str) -> tuple[dict, int]:
    first = text.split("\n", 1)[0]
    meta = {}
    if first.startswith("#"):
        for part in first.lstrip("#").split(","):
            k, _, v = part.partition(":")
            meta[k.strip()] = v.strip()
    return {"model_version": meta.get("model_version", ""), "score_date": meta.get("score_date", "")[:10]}, \
        max(text.count("\n") - 2, 0)


@dataclass
class IntelSource:
    """보강에 쓸 KEV·EPSS. 어디서 왔는지(origin)와 기준 시각을 함께 들고 다닌다."""

    kev: dict[str, dict] = field(default_factory=dict)       # CVE → KEV 항목
    epss: dict[str, tuple[float, float]] = field(default_factory=dict)   # CVE → (epss, percentile)
    kev_origin: str = ""
    epss_origin: str = ""
    epss_date: str = ""
    kev_date: str = ""
    warnings: list[str] = field(default_factory=list)


def _load_kev(path: Path) -> dict[str, dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return {v["cveID"].upper(): v for v in doc.get("vulnerabilities", []) if v.get("cveID")}


def _load_epss(path: Path, wanted: Optional[set[str]]) -> tuple[dict[str, tuple[float, float]], str]:
    opener = gzip.open if path.suffix == ".gz" else open
    out: dict[str, tuple[float, float]] = {}
    with opener(path, "rt", encoding="utf-8") as fh:
        first = fh.readline()
        meta, _ = _epss_meta_and_count(first + "\n")
        if not first.startswith("#"):
            fh = io.StringIO(first + fh.read())
        for row in csv.DictReader(fh):
            cve = (row.get("cve") or "").upper()
            if wanted is not None and cve not in wanted:
                continue
            try:
                out[cve] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, ValueError):
                continue
    return out, meta.get("score_date", "")


def _age_hours(iso: str) -> Optional[float]:
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds() / 3600
    except (TypeError, ValueError):
        return None


def load_intel(wanted: Optional[set[str]] = None, d: Optional[Path] = None) -> IntelSource:
    """캐시 → 발췌본 순으로 읽는다. 둘 다 없으면 빈 값(스캐너 보조값만 쓰게 됨)."""
    cfg = intel_config()
    d = d or cache_dir()
    manifest = read_manifest(d)
    src = IntelSource()
    max_age = cfg.get("max_age_hours", 48)
    for name in ("kev", "epss"):
        f = d / cfg[name]["file"]
        origin = "cache"
        if not f.exists():
            snap = snapshot_dir() / cfg[name]["file"]
            if snap.exists():
                f, origin = snap, "snapshot"
                src.warnings.append(f"{name.upper()} 캐시 없음 → 테스트용 발췌본 사용(일부 CVE만 있음). `triage fetch-intel` 로 내려받으세요")
            else:
                src.warnings.append(f"{name.upper()} 캐시·발췌본 모두 없음 → 스캐너 보조값만 사용")
                continue
        else:
            age = _age_hours((manifest.get(name) or {}).get("fetched_at", ""))
            if age is not None and age > max_age:
                src.warnings.append(f"{name.upper()} 캐시가 {age:.0f}시간 전 것(기준 {max_age}시간) → 그대로 사용, 가능하면 갱신")
        if name == "kev":
            src.kev = _load_kev(f)
            src.kev_origin = origin
            src.kev_date = (manifest.get("kev") or {}).get("date_released", "")[:10] if origin == "cache" else "발췌본"
        else:
            src.epss, src.epss_date = _load_epss(f, wanted)
            src.epss_origin = origin
    return src
