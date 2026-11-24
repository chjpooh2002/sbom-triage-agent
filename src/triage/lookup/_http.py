"""조회 응답의 날짜별 스냅샷과 네트워크 재시도."""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections import deque
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import monotonic

import httpx

Log = Callable[..., None]
NVD_RATE_WINDOW = 30
NVD_PUBLIC_LIMIT = 5
NVD_KEYED_LIMIT = 50


def _nvd_rate_limited(response: httpx.Response, keyed: bool) -> bool:
    if response.status_code == 429:
        return True
    if response.status_code != 403:
        return False
    message = response.headers.get("message", "").lower()
    return (not keyed and not message) or any(
        term in message for term in (
            "rate limit", "request limit", "too many requests", "quota", "forbidden by administrative rules",
        )
    )


def _retry_after(response: httpx.Response) -> float:
    value = response.headers.get("Retry-After", "").strip()
    if value.isdecimal():
        return int(value)
    with suppress(TypeError, ValueError, OverflowError):
        retry_at = parsedate_to_datetime(value)
        return max((retry_at - datetime.now(timezone.utc)).total_seconds(), 0)
    return NVD_RATE_WINDOW


class Responses:
    def __init__(self, root: Path, client: httpx.Client | None, log: Log | None):
        self.root = root
        self.date = datetime.now(timezone.utc).date().isoformat()
        self.client = client
        self.log = log
        self.memo: dict[str, tuple[dict, str]] = {}
        self.nvd_key = os.environ.get("NVD_API_KEY", "").strip() if client is not None else ""
        self.nvd_attempts: deque[float] = deque()

    def emit(self, event: str, **data) -> None:
        if self.log is not None:
            self.log("lookup", event, **data)

    def _relative(self, path: Path) -> str:
        return f"data/cache/lookup/{path.relative_to(self.root).as_posix()}"

    def cached(self, key: str) -> tuple[dict | None, str]:
        if key in self.memo:
            return self.memo[key]
        if self.root.is_dir():
            for folder in sorted(self.root.iterdir(), reverse=True):
                path = folder / key
                try:
                    doc = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if isinstance(doc, dict):
                    return doc, self._relative(path)
        return None, ""

    def save(self, key: str, doc: dict) -> str:
        path = self.root / self.date / key
        relative = self._relative(path)
        self.memo[key] = doc, relative
        temp_path = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as temp:
                temp_path = Path(temp.name)
                json.dump(doc, temp, ensure_ascii=False)
            temp_path.replace(path)
        except OSError as exc:
            self.emit("cache_write_error", file=relative, error=type(exc).__name__)
            self.memo[key] = doc, ""
            return ""
        finally:
            if temp_path is not None:
                with suppress(OSError):
                    temp_path.unlink(missing_ok=True)
        return relative

    @staticmethod
    def key(label: str, value) -> str:
        payload = json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return f"{label}-{hashlib.sha256(payload).hexdigest()}.json"

    def _pace_nvd(self) -> None:
        limit = NVD_KEYED_LIMIT if self.nvd_key else NVD_PUBLIC_LIMIT
        now = monotonic()
        if len(self.nvd_attempts) == limit:
            delay = self.nvd_attempts.popleft() + NVD_RATE_WINDOW - now
            if delay > 0:
                self.emit("rate_limit_wait", source="nvd", reason="window", seconds=delay)
                time.sleep(delay)
                now = monotonic()
        self.nvd_attempts.append(now)

    def request(self, source: str, method: str, url: str, **kwargs) -> tuple[dict | None, str]:
        key = self.key(source, [method, url, kwargs])
        if key in self.memo:
            return self.memo[key]
        if self.client is not None:
            is_nvd = source == "nvd"
            if is_nvd and self.nvd_key:
                kwargs["headers"] = {"apiKey": self.nvd_key}
            for attempt in range(1, 5):
                if is_nvd:
                    self._pace_nvd()
                self.emit("attempt", source=source, method=method, url=url, attempt=attempt)
                try:
                    response = self.client.request(method, url, **kwargs)
                    response.raise_for_status()
                    doc = response.json()
                    if not isinstance(doc, dict):
                        raise ValueError("JSON 객체 응답이 필요합니다")
                except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as exc:
                    failed = exc.response if isinstance(exc, httpx.HTTPStatusError) else None
                    status = failed.status_code if failed is not None else None
                    rate_limited = is_nvd and failed is not None and _nvd_rate_limited(failed, bool(self.nvd_key))
                    transient = rate_limited or status is None or status in (408, 429) or status >= 500
                    retry = attempt < 4 and transient
                    delay = 2 ** (attempt - 1) if retry else 0
                    if retry and rate_limited:
                        delay = max(delay, _retry_after(failed))
                    self.emit("request_error", source=source, url=url, attempt=attempt,
                              status=status, error=type(exc).__name__, retry_in_seconds=delay)
                    if not transient:
                        return None, ""
                    if not retry:
                        break
                    if rate_limited:
                        self.emit("rate_limit_wait", source=source, reason="response", status=status, seconds=delay)
                    time.sleep(delay)
                else:
                    path = self.save(key, doc)
                    self.emit("response", source=source, url=url, attempt=attempt, status=response.status_code)
                    return doc, path
        doc, path = self.cached(key)
        self.emit("cache_hit" if doc is not None else "cache_miss", source=source, url=url, file=path)
        return doc, path
