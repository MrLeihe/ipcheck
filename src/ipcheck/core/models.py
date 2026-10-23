from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from ipcheck.core.privacy import JsonValue, redact

Status = Literal["completed", "unknown", "unsupported", "skipped"]
Severity = Literal["info", "warning", "error"]


@dataclass(frozen=True)
class CheckResult:
    id: str
    group: str
    label: str
    status: Status
    severity: Severity
    summary: str
    evidence: tuple[str, ...] = ()
    data: dict[str, JsonValue] = field(default_factory=dict)
    source: str = "local"
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, JsonValue]:
        raw: dict[str, JsonValue] = {
            "id": self.id, "group": self.group, "label": self.label,
            "status": self.status, "severity": self.severity, "summary": self.summary,
            "evidence": list(self.evidence), "data": self.data,
            "source": self.source, "observed_at": self.observed_at,
        }
        cleaned = redact(raw)
        if not isinstance(cleaned, dict):
            raise TypeError("A check must serialize to an object")
        return cleaned


@dataclass
class Report:
    checks: list[CheckResult]
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, JsonValue]:
        from ipcheck.core.summary import summarize

        return {
            "schema_version": "1.0", "id": self.id, "created_at": self.created_at,
            "checks": [check.to_dict() for check in self.checks],
            "summary": summarize(self.checks),
        }
