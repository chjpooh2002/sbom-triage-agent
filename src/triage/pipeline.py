"""전체 흐름 한 번에: 정규화 → 위협 정보 보강 → 우선순위 → 조치안 → 보고서."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Optional

from .ingest import ingest_paths
from .intel import enrich
from .models import TriageBundle
from .priority import Policy, load_policy, prioritize
from .remediation import Provider, get_provider, remediate
from .report import excel, markdown


@dataclass
class RunResult:
    bundle: TriageBundle
    policy: Policy
    report_md: str
    paths: dict[str, Path]


def run(inputs: list[str], out_dir: Optional[Path] = Path("out"), provider: Optional[Provider | str] = None,
        llm_limit: int = 20, offline: bool = False, as_of: Optional[date] = None,
        policy_path: Optional[Path] = None, fmt: Optional[str] = None) -> RunResult:
    pol = load_policy(policy_path)
    bundle = ingest_paths(inputs, fmt)
    enrich(bundle)
    prioritize(bundle, pol, as_of)
    p = provider if provider is not None and not isinstance(provider, str) else get_provider(provider)
    remediate(bundle, p, llm_limit, offline)
    md = markdown.render(bundle, pol)
    paths: dict[str, Path] = {}
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        paths = {"bundle": out_dir / "bundle.json", "md": out_dir / "report.md", "xlsx": out_dir / "report.xlsx"}
        paths["bundle"].write_text(bundle.model_dump_json(indent=1), encoding="utf-8")
        paths["md"].write_text(md, encoding="utf-8")
        excel.write(bundle, pol, paths["xlsx"])
    return RunResult(bundle, pol, md, paths)
