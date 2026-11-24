"""출력 형식 간에 공유하는 판정과 근거 처리."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from triage.models import Evidence, Finding, Status, TriageBundle


def finding_state(finding: Finding) -> str:
    if finding.verdict is not None:
        state = finding.verdict.state
        return state if state in {"affected", "not_affected"} else "undetermined"
    if finding.status == Status.not_affected:
        return "not_affected"
    return "undetermined"


def finding_evidence(finding: Finding) -> list[str]:
    ids = list(finding.component.evidence_ids)
    if finding.verdict:
        for item in finding.verdict.item_results:
            ids.extend(item.evidence_ids)
    return list(dict.fromkeys(ids))


def public_url(value: str) -> str:
    """권고문 등의 링크에서 HTTP(S) 주소만 허용한다."""
    try:
        parts = urlsplit(value)
        if parts.scheme in {"http", "https"} and parts.hostname and parts.username is None:
            return value
    except ValueError:
        pass
    return ""


def artifact_evidence(
    stage: str, out: Path, note: str, bundle: TriageBundle | None = None,
) -> Evidence:
    used = {item.id for item in bundle.evidence} if bundle else set()
    number = next(
        number for number in range(1, 10_000)
        if f"{stage}-{number:04d}" not in used
    )
    return Evidence(id=f"{stage}-{number:04d}", kind="tool", file=out.name, note=note)


def file_location(item: Evidence) -> str:
    if not item.file or item.line_start is None:
        return item.file
    lines = str(item.line_start)
    if item.line_end and item.line_end != item.line_start:
        lines += f"-{item.line_end}"
    return f"{item.file}:{lines}"


def write_artifact(out: Path, content: bytes) -> None:
    """완성된 산출물만 최종 경로에 둔다."""
    out.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=out.parent) as directory:
        temporary = Path(directory) / out.name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        # 생성 시점에 umask가 적용된다. 교체 전에는 비공개 임시 디렉터리에 둔다.
        with os.fdopen(os.open(temporary, flags, 0o644), "wb") as handle:
            handle.write(content)
        temporary.replace(out)
