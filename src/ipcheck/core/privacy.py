"""Defence in depth for output; collectors must avoid collecting secrets first."""

import re
from typing import TypeAlias

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]

_SECRET_KEY = re.compile(r"(?:api[_-]?key|(?:access|auth|refresh)?[_-]?token|password|secret|authorization|cookie)", re.I)
_KEY_VALUE = re.compile(r"(?i)\b((?:[\w-]*(?:api[_-]?key|token|password|secret|authorization))[\w-]*\s*[:=]\s*)[^\s,;]+")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_SK_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{10,}")
_URL_CREDENTIAL = re.compile(r"(https?://)[^\s/@]+:[^\s/@]+@", re.I)


def redact_text(value: str) -> str:
    # Provider data must not inject terminal control sequences or rewrite output lines.
    value = "".join(char if ord(char) >= 32 and ord(char) != 127 else " " for char in value)
    value = _URL_CREDENTIAL.sub(r"\1[redacted]@", value)
    value = _BEARER.sub("Bearer [redacted]", value)
    value = _SK_KEY.sub("[redacted]", value)
    return _KEY_VALUE.sub(r"\1[redacted]", value)


def redact(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return {key: "[redacted]" if _SECRET_KEY.search(key) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
