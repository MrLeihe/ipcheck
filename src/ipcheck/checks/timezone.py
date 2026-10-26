import os
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue
from ipcheck.platforms.system import system_timezone


def offset_minutes(name: str | None) -> int | None:
    if not name:
        return None
    try:
        offset = datetime.now(ZoneInfo(name)).utcoffset()
        return int(offset.total_seconds() // 60) if offset is not None else None
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def check_timezone() -> list[CheckResult]:
    system_name = system_timezone()
    cli_name = os.environ.get("TZ") or system_name
    results: list[CheckResult] = []
    for check_id, label, name, source in (
        ("timezone.system", "系统时区", system_name, "系统时区文件"),
        ("timezone.cli", "CLI 时区", cli_name, "TZ / 系统时区"),
    ):
        offset = offset_minutes(name)
        results.append(CheckResult(check_id, "system", label,
                                   "completed" if offset is not None else "unknown", "info",
                                   name if offset is not None and name else "时区解析失败",
                                   data={"timezone": name if offset is not None else None, "offset_minutes": offset}, source=source))
    return results


def _exit_timezone(check_id: str, label: str, observation: CheckResult | None) -> CheckResult:
    data = observation.data if observation else {}
    name = data.get("timezone")
    offset = offset_minutes(name if isinstance(name, str) else None)
    valid = observation is not None and observation.status == "completed" and offset is not None
    reason = (data.get("location_summary") or observation.summary) if observation else "缺少对应出口观测"
    return CheckResult(check_id, "system", label, "completed" if valid else "unknown", "info",
                       str(name) if valid else f"未取得对应出口的归属时区：{reason}",
                       ("时区来自对应请求出口 IP 的地理归属，不是服务端时区或浏览器本地时区。",),
                       {"timezone": name if valid else None, "offset_minutes": offset if valid else None,
                        "ip": data.get("ip"), "host": data.get("host"), "lookup_route": data.get("lookup_route")},
                       f"{observation.source} / IP 归属" if observation else "IP 归属")


def _comparison_data(local: CheckResult | None, exit_zone: CheckResult) -> dict[str, JsonValue]:
    local_name = local.data.get("timezone") if local else None
    exit_name = exit_zone.data.get("timezone")
    left = offset_minutes(local_name if isinstance(local_name, str) else None)
    right = offset_minutes(exit_name if isinstance(exit_name, str) else None)
    valid_local = local is not None and local.status == "completed" and left is not None
    known = valid_local and exit_zone.status == "completed" and right is not None
    return {"same_iana": local_name == exit_name if known else None,
            "same_offset": left == right if known else None,
            "local_timezone": local_name, "exit_timezone": exit_name,
            "local_source": local.id if local else None,
            "local_valid": valid_local, "exit_valid": exit_zone.status == "completed" and right is not None}


def compare_timezone(checks: list[CheckResult]) -> list[CheckResult]:
    lookup = {check.id: check for check in checks}
    cli = lookup.get("timezone.cli")
    normal = _exit_timezone("timezone.egress", "检测出口时区", lookup.get("network.location"))
    results = [normal]
    comparisons: dict[str, JsonValue] = {"general": _comparison_data(cli, normal)}
    web_zone = _exit_timezone("timezone.claude_web", "Claude 网页时区", lookup.get("claude.web.egress"))
    for key in ("api", "web"):
        observation = lookup.get(f"claude.{key}.egress")
        if observation is not None:
            label = "Claude API 时区" if key == "api" else "Claude 网页时区"
            zone = _exit_timezone(f"timezone.claude_{key}", label, observation)
            results.append(zone)
            if key == "api":
                comparisons[key] = _comparison_data(cli, zone)
    local = lookup.get("timezone.system")
    web = _comparison_data(local, web_zone)
    comparisons["web"] = web
    known = web["same_iana"] is not None and web["same_offset"] is not None
    consistent = web["same_iana"] is True and web["same_offset"] is True
    subject = "系统"
    if not known:
        missing = f"{subject}时区" if not web["local_valid"] else "Claude 网页出口时区"
        summary = f"请核对{missing}，补全后再比较"
    elif consistent:
        summary = f"{subject}与 Claude 网页出口的 IANA 名称、当前偏移一致"
    else:
        summary = f"如需与 Claude 网页出口保持一致，可考虑使用 {web['exit_timezone']}"
    evidence = (
        "建议仅参考 Claude 网页出口；普通检测出口不作为修改系统时区的依据。",
        "普通 API 请求通常不携带本机 IANA 时区；自定义客户端可能上传，本检查未审计实际请求内容。",
        "当前偏移相同不代表 IANA 名称相同；差异只作为环境核对线索，不用于判断账号风险。",
        "本工具读取系统 IANA 时区；CLI 的 TZ 环境变量只在单独一行展示。",
        "网页出口来自 Python 对 claude.ai 的匿名探测；客户端代理规则不同时需另行核对。",
        "IP 地理归属可能不准确；仅在希望保持环境一致且出口稳定时考虑调整，不自动修改配置。",
    )
    results.append(CheckResult("timezone.advice", "system", "时区建议", "completed" if known else "unknown",
                               "info" if consistent else "warning", summary, evidence,
                               {**web, "comparisons": comparisons}, "时区观测汇总"))
    return results
