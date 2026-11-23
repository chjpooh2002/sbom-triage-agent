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

    from .intel import enrich
    from .priority import load_policy, prioritize as run

    bundle = load_bundle(bundle_path)
    enrich(bundle)
    intel = bundle.meta["intel"]
    typer.echo(f"위협 정보: KEV {intel['kev']['origin']}({intel['kev']['date']}), "
               f"EPSS {intel['epss']['origin']}({intel['epss']['date']}), 스캐너 보조값 {intel['hints_used']}건")
    for w in intel["warnings"]:
        typer.secho(f"  경고: {w}", fg="yellow")
    run(bundle, load_policy(policy), date.fromisoformat(as_of) if as_of else None)
    save_bundle(bundle, out or bundle_path)
    print_results(bundle, top)


@app.command("eval")
def eval_cmd(
    gold: Path = typer.Option(Path("eval/gold.csv"), "--gold"),
    out: Optional[Path] = typer.Option(None, "-o", "--out", help="결과 마크다운(예: eval/results/2026-11-23.md)"),
    policy: Optional[Path] = typer.Option(None, "--policy"),
    check: bool = typer.Option(False, "--check", help="형식만 검증하고 채점하지 않음"),
    force: bool = typer.Option(False, "--force", help="기존 결과 파일 덮어쓰기"),
) -> None:
    """정답 사례와 비교해 정확도를 계산한다(규칙 엔진 vs CVSS 단독)."""
    from .evaluation import GoldError, load_gold, render_markdown, run_eval
    from .priority import load_policy

    try:
        cases = load_gold(gold)
    except GoldError as e:
        typer.secho(str(e), fg="red")
        raise typer.Exit(1)
    reviewed = sum(c.reviewed for c in cases)
    typer.echo(f"정답 {len(cases)}건 형식 확인 완료(사람 검증 {reviewed}건)")
    if check:
        return
    pol = load_policy(policy)
    scores, results = run_eval(cases, pol)
    md = render_markdown(str(gold), cases, scores, results, pol)
    typer.echo(md)
    if out:
        if out.exists() and not force:
            typer.secho(f"{out} 이 이미 있습니다. 기록을 보존하려면 다른 이름을 쓰고, 덮어쓰려면 --force", fg="red")
            raise typer.Exit(1)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        typer.echo(f"저장: {out}")


@app.command("fetch-intel")
def fetch_intel(
    only: Optional[str] = typer.Option(None, "--only", help="kev 또는 epss 만"),
) -> None:
    """CISA KEV 목록과 EPSS 전체 점수 파일을 내려받아 data/cache 에 저장한다."""
    from .intel import fetch_all
    from .intel.cache import cache_dir

    report = fetch_all([only] if only else ["kev", "epss"])
    ok = True
    for name, r in report.items():
        if r["ok"]:
            extra = r.get("date_released") or r.get("score_date") or ""
            typer.echo(f"  {name.upper()}: {r['records']:,}건, {r['bytes'] / 1e6:.1f}MB, 기준 {extra} ← {r['url']}")
        else:
            ok = False
            typer.secho(f"  {name.upper()}: 실패 (기존 캐시 {'유지' if r['kept'] else '없음'})", fg="red")
            typer.secho(f"  {r['error']}", fg="red")
    typer.echo(f"캐시 위치: {cache_dir()}")
    if not ok:
        raise typer.Exit(1)


@app.command()
def remediate(
    bundle_path: Path = typer.Argument(Path("out/bundle.json")),
    out: Optional[Path] = typer.Option(None, "-o", "--out"),
    provider: Optional[str] = typer.Option(None, "--provider", help="anthropic | openai | template (기본: .env 의 LLM_PROVIDER)"),
    llm_limit: int = typer.Option(20, "--llm-limit", help="모델을 부를 최대 묶음 수(급한 순). 나머지는 템플릿"),
    offline: bool = typer.Option(False, "--offline", help="레지스트리 조회 없이 캐시만 사용"),
) -> None:
    """(자산, 구성요소) 묶음별 조치안을 만들고 목표 버전을 규칙으로 재검증한다."""
    from .remediation import get_provider, remediate as run

    bundle = load_bundle(bundle_path)
    p = get_provider(provider)
    run(bundle, p, llm_limit, offline)
    save_bundle(bundle, out or bundle_path)
    m = bundle.meta["remediation"]
    for w in m["warnings"]:
        typer.secho(f"  경고: {w}", fg="yellow")
    typer.echo(f"공급자 {m['provider']}({m['model']}): 묶음 {m['groups']}개, 모델 호출 {m['llm_calls']}, 캐시 {m['llm_cache_hits']}, "
               f"대체 {m['fallbacks']}, 제안 기각 {m['rejected_targets']}, 레지스트리 확인 불가 {m['registry_unknown']}")
    seen = set()
    for r in bundle.remediations:
        f = bundle.finding(r.finding_key)
        k = (f.asset_id, f.component.id)
        if k in seen:
            continue
        seen.add(k)
        mark = "검증됨" if r.verified else "미검증"
        typer.echo(f"  {f.component.display} → {r.target_version or '-'} [{mark}] {r.verify_notes[-1] if r.verify_notes else ''}")


if __name__ == "__main__":
    app()
