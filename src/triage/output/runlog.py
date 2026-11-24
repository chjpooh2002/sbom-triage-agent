"""단계별 이벤트와 실행 요약을 UTF-8 JSONL로 기록한다."""
import json
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from triage.models import Evidence

from ._common import artifact_evidence
from ._redact import Redactor


def _count(value) -> int | None:
    return value if type(value) is int and value >= 0 else None


class RunLog:
    def __init__(self, path: Path, *, secrets: tuple[str, ...] = ()) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("w", encoding="utf-8", newline="\n")
        self._start = time.perf_counter()
        self._redact = Redactor(secrets)
        self._lock = Lock()
        self._total_tokens = 0
        self._reasoning_tokens: int | None = None
        self._usage_count = 0
        self._missing_usage = False
        self._evidence: Evidence | None = None

    def _write(self, stage: str, event: str, data: dict) -> None:
        record = self._redact.value({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage, "event": event, "data": data,
        })
        self._file.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
        self._file.flush()

    def emit(self, stage: str, event: str, **data) -> None:
        with self._lock:
            self._ensure_open()
            if (stage, event) == ("run", "end"):
                raise ValueError("run.end는 close()로 기록해야 합니다.")
            self._write(stage, event, data)

    def add_usage(
        self, usage=None, *, total_tokens: int | None = None,
        prompt_tokens: int | None = None, completion_tokens: int | None = None,
        reasoning_tokens: int | None = None,
    ) -> None:
        """모델 호출 한 건의 사용량을 더한다. 추론 토큰은 총 토큰에 다시 더하지 않는다."""
        def field(obj, key):
            return obj.get(key) if isinstance(obj, Mapping) else getattr(obj, key, None)

        total = _count(total_tokens)
        if total is None:
            total = _count(usage if isinstance(usage, int) else field(usage, "total_tokens"))
        if total is None:
            prompt = _count(prompt_tokens if prompt_tokens is not None else field(usage, "prompt_tokens"))
            completion = _count(
                completion_tokens if completion_tokens is not None else field(usage, "completion_tokens")
            )
            if prompt is not None and completion is not None:
                total = prompt + completion
        reasoning = _count(reasoning_tokens)
        if reasoning is None:
            reasoning = _count(field(field(usage, "completion_tokens_details"), "reasoning_tokens"))

        with self._lock:
            self._ensure_open()
            if total is None:
                self._missing_usage = True
            else:
                self._total_tokens += total
                self._usage_count += 1
            if reasoning is not None:
                self._reasoning_tokens = (self._reasoning_tokens or 0) + reasoning

    def _ensure_open(self) -> None:
        if self._file.closed:
            raise ValueError("종료된 실행 로그입니다.")

    def close(self, *, usage_reason: str | None = None, **data) -> list[Evidence]:
        """run.end를 마지막 줄에 기록하고 요약의 근거를 돌려준다."""
        with self._lock:
            if self._evidence is not None:
                return [self._evidence]
            evidence = artifact_evidence("runlog", self.path, "실행 시간과 모델 토큰 사용량 집계")
            data.update(total_seconds=round(time.perf_counter() - self._start, 6),
                        evidence_ids=[evidence.id])
            if self._missing_usage or not self._usage_count:
                reason = ("일부 또는 전체 모델 호출의 토큰 사용량이 누락되었습니다."
                          if self._missing_usage else "기록된 모델 토큰 사용량이 없습니다.")
                data.update(total_tokens="측정 불가", total_tokens_reason=usage_reason or reason)
            else:
                data["total_tokens"] = self._total_tokens
            if self._reasoning_tokens is not None:
                data["reported_reasoning_tokens"] = self._reasoning_tokens
            self._write("run", "end", data)
            self._file.close()
            self._evidence = evidence
            return [evidence]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close(status="error" if exc_type else "ok")
