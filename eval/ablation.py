"""같은 서비스의 단계별 판정·토큰·시간을 비교한다."""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from . import finals_score
else:
    import finals_score


@dataclass(frozen=True)
class Stage:
    key: str
    title: str
    judge: str = "on"
    verify: str = "off"
    escalate: str = "off"
    reference: bool = False

    def environment(self, base: dict[str, str]) -> dict[str, str]:
        env = dict(base, SBOMTRIAGE_JUDGE=self.judge, SBOMTRIAGE_VERIFY=self.verify,
                   SBOMTRIAGE_ESCALATE=self.escalate)
        if self.reference:
            model = env.get("SBOMTRIAGE_REFERENCE_MODEL", "").strip()
            if not model:
                raise ValueError("SBOMTRIAGE_REFERENCE_MODEL이 필요합니다")
            env["SBOMTRIAGE_MODEL"] = model
            env["SBOMTRIAGE_ESCALATE_MODEL"] = model
        return env


STAGES = (
    Stage("rules", "결정적 선판정", judge="off"),
    Stage("model", "+ 모델 판정"),
    Stage("verify", "+ 검증기", verify="on"),
    Stage("escalate", "+ 조건부 승급", verify="on", escalate="on"),
    Stage("reference", "참고 상한 모델", verify="on", escalate="on", reference=True),
)


@dataclass(frozen=True)
class Usage:
    tokens: int | str = "측정 불가"
    seconds: float | str = "측정 불가"
    reason: str = ""


def load_usage(path: Path, *, allow_missing: bool) -> Usage:
    if not path.is_file():
        if allow_missing:
            return Usage(reason="실행 로그 없음")
        raise FileNotFoundError(f"{path}: 실행 로그가 없습니다")
    last = ""
    with path.open(encoding="utf-8-sig") as source:
        for line in source:
            if line.strip():
                last = line
    if not last:
        raise ValueError(f"{path}: 실행 로그가 비어 있습니다")
    try:
        record = json.loads(last)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: 마지막 로그 줄이 JSON이 아닙니다") from exc
    if not isinstance(record, dict) or (record.get("stage"), record.get("event")) != ("run", "end"):
        raise ValueError(f"{path}: 마지막 로그 줄에 run.end가 필요합니다")
    data = record.get("data", {})
    if not isinstance(data, dict):
        raise ValueError(f"{path}: run.end의 data가 객체여야 합니다")
    if data.get("status") == "error":
        raise ValueError(f"{path}: 실행이 실패했습니다")
    tokens, seconds = data.get("total_tokens"), data.get("total_seconds")
    reason = data.get("total_tokens_reason", "")
    if not (type(tokens) is int and tokens >= 0 or tokens == "측정 불가" and reason):
        raise ValueError(f"{path}: run.end의 total_tokens 또는 측정 불가 사유를 확인하세요")
    if not (type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0):
        raise ValueError(f"{path}: run.end의 total_seconds를 확인하세요")
    return Usage(tokens, seconds, reason)


def render(label: str, results: list[tuple[Stage, finals_score.Score, Usage]]) -> str:
    lines = [
        f"# 단계별 판정 비교 ({label})", "",
        "| 단계 | core 정확도 | 영향 있음 재현율 | 오탐 | 총 토큰 | 총 시간(초) |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    notes = []
    for stage, score, usage in results:
        lines.append(f"| {stage.title} | {score.accuracy} | {score.recall} | {len(score.false_positives)} | "
                     f"{usage.tokens} | {usage.seconds} |")
        if usage.reason:
            notes.append(f"- {stage.title} — {usage.reason}")
    if notes:
        lines.extend(["", "## 측정 불가 사유", "", *notes])
    return "\n".join(lines) + "\n"


def run_live(label: str, root: Path, out: Path, stages: list[Stage], offline: bool) -> Path:
    if importlib.util.find_spec("triage.finals") is None:
        raise ValueError("triage.finals.run_scan을 사용할 수 없습니다. 저장된 산출물은 --saved로 비교하세요")
    if not root.is_dir():
        raise ValueError(f"{root}: 소스 디렉터리가 필요합니다")
    environments = [(stage, stage.environment(os.environ.copy())) for stage in stages]
    parent = out / "ablation-runs"
    parent.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix=f"{label}-", dir=parent))
    entrypoint = (
        "from pathlib import Path; import sys; from triage.finals import run_scan; "
        "run_scan(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), offline=sys.argv[4] == '1')"
    )
    for stage, env in environments:
        directory = run_dir / stage.key
        directory.mkdir()
        subprocess.run([sys.executable, "-c", entrypoint, label, str(root), str(directory),
                        str(int(offline))], env=env, check=True, stdout=sys.stderr)
    return run_dir


def compare(
    directory: Path, label: str, gold: list[finals_score.GoldCase], service: str | None,
    stages: list[Stage], *, allow_missing_logs: bool,
) -> list[tuple[Stage, finals_score.Score, Usage]]:
    results = []
    for stage in stages:
        stage_dir = directory / stage.key
        cases, entries = finals_score.load_run(stage_dir / f"sbom-{label}.json", gold, label, service)
        service = cases[0].service
        usage = load_usage(stage_dir / f"log-{label}-run1.jsonl", allow_missing=allow_missing_logs)
        results.append((stage, finals_score.score(cases, entries), usage))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    finals_score.add_inputs(parser)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--saved", type=Path, help="단계별 SBOM과 로그가 들어 있는 디렉터리")
    source.add_argument("--root", type=Path, help="본선 스캔에 사용할 소스 디렉터리")
    parser.add_argument("--offline", action="store_true", help="본선 스캔에 오프라인 옵션 전달")
    parser.add_argument("--stage", action="append", choices=[stage.key for stage in STAGES],
                        help="비교할 단계 선택. 기본값은 전체 단계")
    args = parser.parse_args()

    try:
        label = finals_score.checked_label(args.label)
        gold = finals_score.load_gold(args.gold, args.component_alias)
        stages = [stage for stage in STAGES if not args.stage or stage.key in args.stage]
        directory = args.saved or run_live(label, args.root, args.out, stages, args.offline)
        results = compare(directory, label, gold, args.service, stages, allow_missing_logs=args.saved is not None)
        report = render(label, results)
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "ablation.md").write_text(report, encoding="utf-8")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    print(report, end="")


if __name__ == "__main__":
    main()
