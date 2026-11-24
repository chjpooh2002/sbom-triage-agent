"""모델 호출: Chat Completions + json_schema. 디스크 캐시, 재시도, 사용량 기록, 거절 처리.

판정 단계 밖에서는 모델을 부르지 않는다(AGENTS.md). 키·주소는 환경변수(OPENAI_API_KEY,
OPENAI_BASE_URL)에서만 읽고 로그·캐시에 남기지 않는다.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema

from .settings import Settings

Log = Callable[..., None] | None
PROMPTS = Path(__file__).parent / "prompts"


class ModelError(Exception):
    """정해진 횟수만큼 시도해도 쓸 수 있는 응답을 받지 못함."""


class TransientError(Exception):
    """다시 시도할 만한 오류(연결, 시간 초과, 요청 한도, 서버 오류)."""


@dataclass
class Raw:
    content: str
    refusal: str = ""
    finish_reason: str = ""
    usage: dict = field(default_factory=dict)


# (모델, 메시지, 스키마, 스키마 이름) -> Raw. 테스트는 가짜 함수를 넣는다.
Transport = Callable[[str, list[dict], dict, str], Raw]


@dataclass
class Reply:
    data: dict | None
    model: str
    refused: bool = False
    refusal: str = ""
    cached: bool = False
    usage: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Prompt:
    name: str
    text: str
    version: str


def load_prompt(name: str) -> Prompt:
    """프롬프트 파일을 읽는다. 버전은 내용 해시라서 사람이 고치면 캐시도 자동으로 갈린다."""
    text = (PROMPTS / f"{name}.md").read_text(encoding="utf-8")
    return Prompt(name, text, f"{name}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]}")


def usage_dict(usage) -> dict:
    def get(obj, key):
        if obj is None:
            return None
        return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)

    details = get(usage, "completion_tokens_details")
    values = dict(prompt_tokens=get(usage, "prompt_tokens"), completion_tokens=get(usage, "completion_tokens"),
                  total_tokens=get(usage, "total_tokens"), reasoning_tokens=get(details, "reasoning_tokens"))
    return {k: v for k, v in values.items() if type(v) is int and v >= 0}


def openai_transport(timeout: float) -> Transport:
    import openai

    sdk = openai.OpenAI(base_url=os.environ.get("OPENAI_BASE_URL") or None, timeout=timeout, max_retries=0)

    def call(model: str, messages: list[dict], schema: dict, name: str) -> Raw:
        try:
            r = sdk.chat.completions.create(
                model=model, messages=messages,
                response_format={"type": "json_schema",
                                 "json_schema": {"name": name, "strict": True, "schema": schema}})
        except (openai.APIConnectionError, openai.APITimeoutError, openai.RateLimitError,
                openai.InternalServerError) as e:
            raise TransientError(type(e).__name__) from e
        except openai.APIStatusError as e:
            if e.status_code >= 500 or e.status_code in (408, 409, 429):
                raise TransientError(f"HTTP {e.status_code}") from e
            raise ModelError(f"API 오류 HTTP {e.status_code}") from e
        choice = r.choices[0]
        return Raw(content=choice.message.content or "", refusal=getattr(choice.message, "refusal", None) or "",
                   finish_reason=choice.finish_reason or "", usage=usage_dict(r.usage))

    return call


def usage_sink(log: Log, usage: Callable[..., None] | None = None):
    """RunLog.emit 을 log 로 넘기면 같은 객체의 add_usage 로 토큰을 합산한다."""
    return usage or getattr(getattr(log, "__self__", None), "add_usage", None)


class LLMClient:
    def __init__(self, model: str, transport: Transport, settings: Settings, *, log: Log = None,
                 usage: Callable[..., None] | None = None, cache_dir: Path | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        if not model:
            raise ValueError("모델 이름이 비어 있음")
        self.model = model
        self.transport = transport
        self.settings = settings
        self.log = log
        self.usage = usage_sink(log, usage)
        self.cache_dir = Path(cache_dir or settings.cache_dir) / "llm"
        self.sleep = sleep

    @classmethod
    def from_env(cls, settings: Settings, model: str, **kwargs) -> "LLMClient | None":
        """모델 이름이나 키가 없으면 None(호출측이 판단 유보로 대체)."""
        if not model or not os.environ.get("OPENAI_API_KEY"):
            return None
        try:
            transport = openai_transport(settings.timeout_seconds)
        except ImportError:
            return None
        return cls(model, transport, settings, **kwargs)

    def _emit(self, event: str, **data) -> None:
        if self.log:
            self.log("judge", event, model=self.model, **data)

    def _record_usage(self, usage: dict) -> None:
        if self.usage is None:
            return
        if usage:
            self.usage(**{k: usage[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens",
                                                 "reasoning_tokens") if k in usage})
        else:
            self.usage()   # 사용량이 안 왔음을 알린다(실행 로그가 '측정 불가'로 표시)

    def cache_key(self, prompt_version: str, messages: list[dict], schema: dict, schema_name: str) -> str:
        blob = json.dumps(dict(model=self.model, prompt=prompt_version, schema_name=schema_name,
                               schema=schema, messages=messages), ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def complete(self, *, purpose: str, prompt_version: str, messages: list[dict], schema: dict,
                 schema_name: str = "answer", subject: str = "") -> Reply:
        key = self.cache_key(prompt_version, messages, schema, schema_name)
        path = self.cache_dir / key[:2] / f"{key}.json"
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            data = json.loads(doc["content"])
            jsonschema.validate(data, schema)
        except (OSError, ValueError, KeyError, TypeError, jsonschema.ValidationError):
            pass
        else:
            self._emit("llm.call", purpose=purpose, subject=subject, cached=True, attempt=0,
                       original_usage=doc.get("usage", {}))
            if self.usage is not None:
                self.usage(total_tokens=0)
            return Reply(data, self.model, cached=True, usage=doc.get("usage", {}))

        last = ""
        for attempt in range(1, self.settings.max_attempts + 1):
            started = time.monotonic()
            try:
                raw = self.transport(self.model, messages, schema, schema_name)
            except TransientError as e:
                last = str(e)
                self._emit("llm.retry", purpose=purpose, subject=subject, attempt=attempt, error=last)
                if attempt < self.settings.max_attempts:
                    self.sleep(self.settings.backoff_seconds * 2 ** (attempt - 1))
                continue
            except ModelError as e:
                self._emit("llm.error", purpose=purpose, subject=subject, attempt=attempt, error=str(e))
                raise
            seconds = round(time.monotonic() - started, 3)
            self._record_usage(raw.usage)
            self._emit("llm.call", purpose=purpose, subject=subject, cached=False, attempt=attempt,
                       seconds=seconds, finish_reason=raw.finish_reason, **raw.usage)
            if raw.refusal or raw.finish_reason == "content_filter":
                self._emit("llm.refusal", purpose=purpose, subject=subject)
                return Reply(None, self.model, refused=True, refusal=(raw.refusal or "content_filter")[:300],
                             usage=raw.usage)
            if raw.finish_reason == "length":
                last = "출력이 잘림(length)"
            else:
                try:
                    data = json.loads(raw.content)
                    jsonschema.validate(data, schema)
                except (ValueError, jsonschema.ValidationError) as e:
                    last = f"응답 형식 오류: {type(e).__name__}"
                else:
                    self._save(path, dict(model=self.model, prompt=prompt_version, purpose=purpose,
                                          content=raw.content, usage=raw.usage))
                    return Reply(data, self.model, usage=raw.usage)
            self._emit("llm.retry", purpose=purpose, subject=subject, attempt=attempt, error=last)
            if attempt < self.settings.max_attempts:
                self.sleep(self.settings.backoff_seconds * 2 ** (attempt - 1))
        raise ModelError(f"{self.settings.max_attempts}회 시도 실패: {last}")

    @staticmethod
    def _save(path: Path, doc: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.{time.monotonic_ns()}.tmp")
        tmp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
