from ipcheck.checks.timezone import compare_timezone, offset_minutes
from ipcheck.core.models import CheckResult, Report
from ipcheck.core.privacy import JsonValue

ALLOWED_FONTS = frozenset({"PingFang SC", "PingFang TC", "Microsoft YaHei", "SimSun", "Noto Sans CJK SC", "Arial", "Helvetica", "Segoe UI"})
FIELDS = frozenset({"timezone", "offset_minutes", "locale", "languages", "user_agent", "platform", "fonts"})


def validate_snapshot(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("浏览器数据字段不完整或包含未支持字段")
    for field, limit in (("timezone", 100), ("locale", 80), ("user_agent", 512), ("platform", 100)):
        item = value[field]
        if not isinstance(item, str) or len(item) > limit or any(ord(char) < 32 for char in item):
            raise ValueError("浏览器文本字段无效")
    offset = value["offset_minutes"]
    if isinstance(offset, bool) or not isinstance(offset, int) or not -840 <= offset <= 840:
        raise ValueError("浏览器时区偏移无效")
    languages = value["languages"]
    if not isinstance(languages, list) or len(languages) > 20 or any(not isinstance(item, str) or not 1 <= len(item) <= 80 or any(ord(c) < 32 for c in item) for item in languages):
        raise ValueError("浏览器语言列表无效")
    fonts = value["fonts"]
    if fonts is not None and (not isinstance(fonts, list) or len(fonts) > len(ALLOWED_FONTS) or any(not isinstance(item, str) or item not in ALLOWED_FONTS for item in fonts)):
        raise ValueError("浏览器字体列表无效")
    return {key: value[key] for key in FIELDS}


def merge_browser(report: Report, snapshot: dict[str, JsonValue]) -> Report:
    checks = [check for check in report.checks if check.group != "browser"]
    source = "当前本地网页浏览器"
    checks.append(CheckResult("browser.environment", "browser", "浏览器语言与平台", "completed", "info", "已采集当前浏览器环境",
                              ("语言、操作系统和字体作为环境特征展示，不用于计算封号风险。",),
                              {key: snapshot[key] for key in ("languages", "locale", "user_agent", "platform")}, source))
    timezone = snapshot["timezone"]
    expected = offset_minutes(timezone if isinstance(timezone, str) else None)
    browser_offset = snapshot["offset_minutes"]
    consistent = expected is not None and expected == browser_offset
    checks.append(CheckResult("browser.timezone", "browser", "浏览器时区", "completed" if expected is not None else "unknown",
                              "warning" if expected is not None and not consistent else "info",
                              str(timezone) if consistent else "IANA 时区与浏览器偏移不同，需核对" if expected is not None else "无法解析浏览器 IANA 时区",
                              data={"timezone": timezone, "offset_minutes": browser_offset}, source=source))
    cli = next((check for check in checks if check.id == "timezone.cli"), None)
    cli_name = cli.data.get("timezone") if cli else None
    cli_offset = offset_minutes(cli_name if isinstance(cli_name, str) else None)
    checks.append(CheckResult("browser.comparison", "browser", "浏览器与 CLI 时区", "completed" if cli_offset is not None else "unknown",
                              "warning" if cli_offset is not None and cli_offset != browser_offset else "info",
                              "IANA 时区相同" if cli_offset is not None and cli_name == timezone else "IANA 名称不同，当前偏移相同" if cli_offset == browser_offset else "当前 UTC 偏移不同" if cli_offset is not None else "缺少可比较的 CLI 时区",
                              ("本项只比较当前浏览器和本地检测进程。",), source=source))
    fonts = snapshot["fonts"]
    checks.append(CheckResult("browser.fonts", "browser", "可选字体特征", "skipped" if fonts is None else "completed", "info",
                              "未启用字体检测" if fonts is None else "已完成有限字体的渲染宽度比较",
                              ("宽度比较是启发式观测；不枚举全部字体、不生成持久指纹。",), {"fonts": fonts}, source))
    # Recompute advice using the collected browser timezone, replacing system-only advice.
    existing_ids = {check.id for check in checks}
    derived = [check for check in compare_timezone(checks) if check.id in existing_ids]
    replaced_ids = {check.id for check in derived}
    checks = [check for check in checks if check.id not in replaced_ids]
    checks.extend(derived)
    return Report(checks, id=report.id, created_at=report.created_at)
