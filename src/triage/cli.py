"""명령행 진입점."""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Optional

import typer

from .models import TriageBundle

# 윈도우 콘솔 기본 인코딩(cp949)에서 한글이 깨지지 않게 한다
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

app = typer.Typer(help="SW 공급망 스캐닝 에이전트", no_args_is_help=True, add_completion=False)


@app.callback()
def main() -> None:
    """SW 공급망 스캐닝 에이전트."""


def save_bundle(bundle: TriageBundle, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(bundle.model_dump_json(indent=1), encoding="utf-8")


def load_bundle(path: Path) -> TriageBundle:
    return TriageBundle.model_validate_json(path.read_text(encoding="utf-8"))


@app.command()
def version() -> None:
    """버전 출력."""
    from importlib.metadata import version as v

    typer.echo(v("triage"))


@app.command()
def formats() -> None:
    """등록된 변환기 목록."""
    from .ingest import converters

    for c in converters():
        typer.echo(f"{c.kind:7s} {c.name}")


@app.command()
def ingest(
    inputs: list[str] = typer.Argument(..., help="입력 파일·폴더. 자산을 직접 지정하려면 '경로=자산ID'"),
    out: Path = typer.Option(Path("out/bundle.json"), "-o", "--out"),
    fmt: Optional[str] = typer.Option(None, "--format", help="자동 판별 대신 쓸 변환기 이름"),
) -> None:
    """입력을 하나의 내부 구조(bundle.json)로 정규화한다."""
    from .ingest import ingest_paths

    bundle = ingest_paths(inputs, fmt)
    save_bundle(bundle, out)
    for i in bundle.meta["inputs"]:
        typer.echo(f"  [{i['converter']}] {i['source']} → 자산 {i.get('asset_id', '-')} "
                   f"(구성요소 {i.get('components', 0)}, 취약점 {i.get('findings', 0)})")
    by_asset = Counter(f.asset_id or "-" for f in bundle.findings)
    typer.echo(f"구성요소 {len(bundle.components)}개, 취약점 {len(bundle.findings)}건 {dict(by_asset)}, 자산 {len(bundle.assets)}개")
    for w in bundle.meta.get("warnings", []):
        typer.secho(f"  경고: {w}", fg="yellow")
    typer.echo(f"저장: {out}")


def print_results(bundle: TriageBundle, top: int) -> None:
    by_key = {f.key: f for f in bundle.findings}
    typer.echo(f"{'순위':>4} {'등급':4} {'점수':>6} {'기한':10} {'계층':12} {'취약점':18} 구성요소 / 자산")
    for r in bundle.results[:top]:
        f = by_key[r.finding_key]
        typer.echo(f"{r.rank:>4} {r.tier.value:4} {r.score:6.3f} {r.due_date or '-':10} {r.layer:12} "
                   f"{f.vulnerability.id:18} {f.component.display} / {f.asset_id or '-'}")
    counts = Counter(r.tier.value for r in bundle.results)
    typer.echo("등급별: " + ", ".join(f"{t} {counts.get(t, 0)}" for t in ("P1", "P2", "P3", "P4")))


@app.command()
def prioritize(
    bundle_path: Path = typer.Argument(Path("out/bundle.json")),
    out: Optional[Path] = typer.Option(None, "-o", "--out", help="기본: 입력 파일에 덮어씀"),
    policy: Optional[Path] = typer.Option(None, "--policy", help="정책 파일(기본 config/policy.yaml)"),
    as_of: Optional[str] = typer.Option(None, "--as-of", help="기한 계산 기준일 YYYY-MM-DD(기본 오늘)"),
    top: int = typer.Option(20, "--top"),
) -> None:
    """결정적 규칙으로 우선순위·처리 기한·근거를 매긴다."""
    from datetime import date

    from .intel import apply_hints
    from .priority import load_policy, prioritize as run

    bundle = load_bundle(bundle_path)
    apply_hints(bundle)
    run(bundle, load_policy(policy), date.fromisoformat(as_of) if as_of else None)
    save_bundle(bundle, out or bundle_path)
    print_results(bundle, top)


if __name__ == "__main__":
    app()
