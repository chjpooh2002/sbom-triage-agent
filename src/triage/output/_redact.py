"""로그와 보고서에서 자격 증명을 제거한다."""
import os
import re
from collections.abc import Mapping
from itertools import chain
from math import isfinite


_HIDDEN = "[REDACTED]"
_KEY = re.compile(
    r"(?:^|_)(?:api_?key|token|"
    r"password|passwd|secret|credentials?|authorization|private_?key|"
    r"client_?secret|cookie|set_?cookie)$"
)
_AUTH = re.compile(r"(?i)\b(Bearer|Basic)(\s+)[A-Za-z0-9._~+/-]+=*")
_ASSIGNMENT = re.compile(r"""(?P<key>[\w.-]+)["']?[ \t]*[:=][ \t]*""")
_VALUE = re.compile(r""""(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s&,;<>]+""")
_TOKEN = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|"
    r"github_pat_[A-Za-z0-9_]{12,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
_URL_LOGIN = re.compile(r"(://)[^\s/@]+@")


def _secret_key(key: str) -> bool:
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    normalized = re.sub(r"[. -]", "_", normalized).lower()
    return (
        normalized in {"access_key", "access_key_id", "proxy_authorization"}
        or bool(_KEY.search(normalized))
    )


class Redactor:
    def __init__(self, secrets: tuple[str, ...] = ()) -> None:
        configured = (value for key, value in os.environ.items() if _secret_key(key))
        self._secrets = sorted({value for value in chain(configured, secrets) if value},
                               key=len, reverse=True)

    def text(self, value: str) -> str:
        value = _PRIVATE_KEY.sub(_HIDDEN, value)
        value = _TOKEN.sub(_HIDDEN, value)
        value = _AUTH.sub(lambda m: m[1] + m[2] + _HIDDEN, value)
        value = _URL_LOGIN.sub(r"\1", value)
        parts = []
        start = 0
        for match in _ASSIGNMENT.finditer(value):
            if match.start() >= start and _secret_key(match["key"]):
                if secret := _VALUE.match(value, match.end()):
                    hidden = "redacted" if value[match.start() - 1:match.start()] in {"?", "&"} else _HIDDEN
                    parts.extend((value[start:secret.start()], hidden))
                    start = secret.end()
        parts.append(value[start:])
        value = "".join(parts)
        for secret in self._secrets:
            value = value.replace(secret, _HIDDEN)
        return value

    def value(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, Mapping):
            return {
                self.text(str(key)): _HIDDEN if _secret_key(str(key)) else self.value(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self.value(item) for item in value]
        if isinstance(value, float) and not isfinite(value):
            return None
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return self.text(str(value))
