"""자산 목록(엑셀·CSV) → AssetContext. 열 이름은 config/ingest.yaml 의 별칭으로 맞춘다."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pandas as pd

from ..config import load_ingest_config
from ..models import AssetContext
from .registry import TABLE_SUFFIXES, ParsedInput, register


def _norm(s: Any) -> str:
    return re.sub(r"[\s_\-()/]", "", str(s)).lower()


def read_table(path: Path) -> pd.DataFrame:
    suf = path.suffix.lower()
    if suf in (".xlsx", ".xls"):
        return pd.read_excel(path, dtype=str)
    sep = "\t" if suf == ".tsv" else ","
    # 국내 CSV 는 cp949 인 경우가 많다
    for enc in ("utf-8-sig", "cp949"):
        try:
            return pd.read_csv(path, dtype=str, sep=sep, encoding=enc)
        except UnicodeDecodeError:
            continue
    raise ValueError(f"{path}: 인코딩을 알 수 없습니다(utf-8, cp949 모두 실패)")


def map_columns(columns: list[str], aliases: dict[str, list[str]]) -> dict[str, str]:
    """원본 열 이름 → 내부 필드. 먼저 정확히 같은 별칭, 없으면 포함 관계로 찾는다."""
    found: dict[str, str] = {}
    normed = {c: _norm(c) for c in columns}
    for field, names in aliases.items():
        cands = [_norm(n) for n in names]
        hit = next((c for c, n in normed.items() if n in cands and c not in found), None)
        if hit is None:
            hit = next((c for c, n in normed.items() if c not in found and any(x and x in n for x in cands if len(x) >= 2)), None)
        if hit is not None:
            found[hit] = field
    return found


def to_bool(v: Any, cfg: dict) -> bool | None:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    s = _norm(v)
    if s in {_norm(x) for x in cfg["true_values"]}:
        return True
    if s in {_norm(x) for x in cfg["false_values"]}:
        return False
    return None


def to_criticality(v: Any, cfg: dict) -> int | None:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    s = str(v).strip()
    try:
        n = int(float(s))
        return min(max(n, 1), 5)
    except ValueError:
        pass
    m = {_norm(k): int(x) for k, x in cfg["criticality_map"].items()}
    return m.get(_norm(s))


def _looks_like_assets(path: Path, raw) -> bool:
    if path.suffix.lower() not in TABLE_SUFFIXES:
        return False
    cfg = load_ingest_config()["assets"]
    try:
        cols = list(read_table(path).columns)
    except Exception:
        return False
    fields = set(map_columns(cols, cfg["columns"]).values())
    return bool(fields & {"service_name", "asset_id"}) and bool(fields & {"internet_exposed", "criticality"})


@register("assets-table", kind="assets", sniff=_looks_like_assets)
def parse(path: Path, raw=None) -> ParsedInput:
    cfg = load_ingest_config()["assets"]
    df = read_table(path)
    colmap = map_columns(list(df.columns), cfg["columns"])
    warnings = []
    missing = {"internet_exposed", "criticality"} - set(colmap.values())
    if missing:
        warnings.append(f"{path.name}: 자산 목록에 {sorted(missing)} 열을 찾지 못함 → 결측으로 처리")
    assets = []
    for i, row in df.iterrows():
        rec = {colmap[c]: row[c] for c in df.columns if c in colmap}
        extra = {str(c): (None if pd.isna(row[c]) else row[c]) for c in df.columns if c not in colmap}
        sid = rec.get("service_name")
        aid = rec.get("asset_id")
        aid = str(aid).strip() if aid is not None and not pd.isna(aid) else (str(sid).strip() if sid else f"asset-{i + 1}")
        match_raw = rec.get("match")
        match = [] if match_raw is None or pd.isna(match_raw) else [
            m.strip() for m in str(match_raw).split(cfg.get("match_separator", ";")) if m.strip()]
        exposed_raw, crit_raw = rec.get("internet_exposed"), rec.get("criticality")
        exposed, crit = to_bool(exposed_raw, cfg), to_criticality(crit_raw, cfg)
        if exposed is None and exposed_raw is not None and not pd.isna(exposed_raw):
            warnings.append(f"{aid}: 외부 노출 값 '{exposed_raw}'를 해석하지 못함 → ingest.yaml true/false_values 에 추가 필요")
        if crit is None and crit_raw is not None and not pd.isna(crit_raw):
            warnings.append(f"{aid}: 중요도 값 '{crit_raw}'를 해석하지 못함 → ingest.yaml criticality_map 에 추가 필요")
        assets.append(AssetContext(
            asset_id=aid, service_name="" if sid is None or pd.isna(sid) else str(sid).strip(),
            internet_exposed=exposed, criticality=crit,
            environment="" if pd.isna(rec.get("environment")) else str(rec.get("environment") or ""),
            owner="" if pd.isna(rec.get("owner")) else str(rec.get("owner") or ""),
            match=match, extra=extra))
    return ParsedInput(source=str(path), converter="assets-table", kind="assets", assets=assets, warnings=warnings)
