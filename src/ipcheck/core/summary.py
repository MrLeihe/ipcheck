from collections.abc import Sequence

from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue


def summarize(checks: Sequence[CheckResult]) -> dict[str, JsonValue]:
    completed = sum(check.status == "completed" for check in checks)
    unknown = sum(check.status in ("unknown", "unsupported") for check in checks)
    skipped = sum(check.status == "skipped" for check in checks)
    issues = [check.id for check in checks if check.status == "completed" and check.severity in ("warning", "error")]
    if unknown:
        message = "检查不完整，请结合未验证项查看结果"
    elif issues:
        message = "发现需要核对的配置或观测结果"
    else:
        message = "已完成的检查未发现已定义问题"
    return {
        "completed": completed, "unknown": unknown, "skipped": skipped,
        "total": len(checks), "issue_ids": issues, "message": message,
    }
