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


if __name__ == "__main__":
    app()
