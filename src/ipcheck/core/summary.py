"""Rules that turn observations into a conclusion and structured recommendations.

Every item here is a suggestion about the observed environment. None of it is an
account-safety rating, and no rule may claim that a configuration prevents bans.
"""

from collections.abc import Sequence

from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue

PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}
CORE_CHECKS = frozenset({
    "claude.web.egress", "claude.api.egress", "claude.web.reputation", "claude.api.reputation",
    "claude.endpoint", "claude.region", "route.comparison",
    "timezone.system", "timezone.cli", "timezone.claude_web", "timezone.claude_api", "timezone.advice",
    "network.egress", "network.direct", "network.cloudflare", "network.ipv6",
    "dns.configuration", "ipv6.configuration", "ipv6.interfaces",
    "proxy.environment", "proxy.system", "proxy.tunnel",
    "claude.web.abuse", "claude.api.abuse",
})


def _advice(item_id: str, priority: str, category: str, text: str,
            check_ids: Sequence[str], kind: str = "review", value: str = "") -> dict[str, JsonValue]:
    return {"id": item_id, "priority": priority, "category": category, "text": text,
            "check_ids": list(check_ids), "action": {"kind": kind, "value": value}}


def _focus_ids(checks: Sequence[CheckResult], has_claude: bool) -> list[str]:
    focus: list[str] = []
    for check in checks:
        if check.status == "skipped" or check.id == "timezone.advice":
            continue
        if check.id in CORE_CHECKS or check.id.endswith(".execution"):
            focus.append(check.id)
        elif check.severity in ("warning", "error"):
            focus.append(check.id)
        elif not has_claude and check.group == "local":
            focus.append(check.id)
    lookup = {check.id: check for check in checks}
    for suffix in ("reputation", "abuse"):
        web, api = lookup.get(f"claude.web.{suffix}"), lookup.get(f"claude.api.{suffix}")
        if web and api and web.data.get("ip") and web.data == api.data:
            focus = [key for key in focus if key != f"claude.api.{suffix}"]
    return focus


def _assessment(checks: Sequence[CheckResult], network_expected: bool = True
                ) -> tuple[str, str, list[dict[str, JsonValue]], list[str]]:
    lookup = {check.id: check for check in checks}
    has_claude = any(check.id.startswith("claude.") for check in checks)
    focus = _focus_ids(checks, has_claude)

    if not network_expected:
        issues = [check.id for check in checks if check.status == "completed" and check.severity in ("warning", "error")]
        if issues:
            return "attention", "本地配置摘要存在需核对项", [
                _advice("local-review", "medium", "endpoint", "核对本地配置摘要中标记的项目。", issues)
            ], focus
        return "clear", "仅本地配置摘要，未检测 Claude 网络", [], focus

    if not has_claude:
        return "incomplete", "未检测 Claude 网络，无法给出使用环境结论", [
            _advice("run-network", "high", "egress", "运行 ipcheck 检测 Claude 出口、IP 信誉与时区。",
                    [], "command", "ipcheck")
        ], focus

    items: list[dict[str, JsonValue]] = []
    attention = ip_attention = high_ip_risk = missing = api_issue = zone_mismatch = False
    route_split = route_multi = region_unsupported = False
    low_ip_checks = 0
    warned_ips: set[str] = set()
    profiles = [lookup.get(f"claude.{key}.reputation") for key in ("web", "api")]
    reputation_disabled = bool(profiles) and all(
        item is not None and item.status == "skipped" for item in profiles)
    if reputation_disabled:
        missing = True
        items.append(_advice("reputation.disabled", "medium", "reputation",
                             "IP 类型与信誉查询已关闭（--no-reputation），结论不完整。",
                             [f"claude.{key}.reputation" for key in ("web", "api")], "command", "ipcheck"))

    for key, name in (("web", "Claude 网页"), ("api", "官方 API")):
        route = lookup.get(f"claude.{key}.egress")
        profile = lookup.get(f"claude.{key}.reputation")
        abuse = lookup.get(f"claude.{key}.abuse")
        if route is None or route.status != "completed" or not route.data.get("ip"):
            missing = True
            items.append(_advice(f"{key}.egress", "high", "egress",
                                 f"检查 {name} 的代理分流与连通性，重新探测出口 IP。",
                                 [f"claude.{key}.egress"]))
            continue
        address = str(route.data["ip"])
        if not reputation_disabled:
            if profile is None or profile.status != "completed" or profile.data.get("ip") != address:
                missing = True
                if address not in warned_ips:
                    items.append(_advice(f"{key}.reputation", "medium", "reputation",
                                         f"补查 {name} 出口 IP 类型与信誉（ipcheck --reputation）。",
                                         [f"claude.{key}.reputation"], "command", "ipcheck --reputation"))
            else:
                score = profile.data.get("score")
                valid_score = isinstance(score, int) and not isinstance(score, bool) and 0 <= score <= 100
                if not valid_score:
                    missing = True
                    if address not in warned_ips:
                        items.append(_advice(f"{key}.score", "medium", "reputation",
                                             f"补查 {name} 出口 IP 信誉评分。", [f"claude.{key}.reputation"]))
                if valid_score and score >= 30:
                    attention = ip_attention = True
                    high_ip_risk = high_ip_risk or score >= 66
                    if address not in warned_ips:
                        action = "建议更换为信誉更好的稳定出口" if score >= 66 else "建议核对出口信誉，避免频繁切换节点"
                        items.append(_advice(f"{key}.score", "high" if score >= 66 else "medium", "reputation",
                                             f"{name}出口 IP 评分 {score}/100（proxycheck.io）：{action}。",
                                             [f"claude.{key}.reputation"], "review", action))
                if profile.data.get("classification") in (None, "IP 类型未知"):
                    missing = True
                    if address not in warned_ips:
                        items.append(_advice(f"{key}.type", "medium", "reputation",
                                             f"{name}出口类型未知，不能判断是否为住宅或机房 IP。",
                                             [f"claude.{key}.reputation"]))
            if abuse is None or abuse.status != "completed" or abuse.data.get("ip") != address:
                missing = True
                if address not in warned_ips:
                    items.append(_advice(f"{key}.abuse", "medium", "abuse",
                                         f"补查 {name} 出口的公开举报记录。", [f"claude.{key}.abuse"]))
            elif abuse.data.get("listed") is True:
                attention = ip_attention = True
                if address not in warned_ips:
                    items.append(_advice(f"{key}.abuse", "high", "abuse",
                                         f"{name}出口有公开举报记录（StopForumSpam），建议更换出口。",
                                         [f"claude.{key}.abuse"], "review", "更换出口"))
            elif (abuse.data.get("listed") is False and profile is not None and profile.status == "completed"
                  and profile.data.get("ip") == address and isinstance(profile.data.get("score"), int)
                  and not isinstance(profile.data.get("score"), bool) and 0 <= profile.data["score"] < 30):
                low_ip_checks += 1
        warned_ips.add(address)

    route = lookup.get("route.comparison")
    if route is not None and route.data.get("claude_multi") is True:
        attention = route_multi = True
        items.append(_advice("route.multi", "high", "route",
                             "Claude 出口观测到多个 IP：核对域名分流规则与节点稳定性。",
                             ["route.comparison", "claude.web.egress", "claude.api.egress"],
                             "review", "核对域名分流规则"))
    elif route is not None and route.data.get("claude_consistent") is False:
        attention = route_split = True
        items.append(_advice("route.split", "high", "route",
                             "Claude 网页与官方 API 出口不同：统一 claude.ai 与 api.anthropic.com 的分流规则。",
                             ["route.comparison"], "review", "统一域名分流规则"))

    region = lookup.get("claude.region")
    if region is None or region.status != "completed":
        missing = True
        items.append(_advice("region.missing", "low", "region",
                             "补全 Claude 出口国家代码，再核对支持地区。", ["claude.region"]))
    else:
        region_routes = region.data.get("routes")
        if isinstance(region_routes, list) and any(
                isinstance(entry, dict) and entry.get("supported") is None for entry in region_routes):
            missing = True
            items.append(_advice("region.partial", "low", "region",
                                 "部分 Claude 出口未取得国家代码，支持地区未完整比对。", ["claude.region"]))
        if region.data.get("unsupported") is True:
            attention = region_unsupported = True
            countries = "、".join(str(entry.get("country_code")) for entry in region_routes
                                  if isinstance(entry, dict) and entry.get("supported") is False) if isinstance(region_routes, list) else ""
            items.append(_advice("region.unsupported", "high", "region",
                                 f"出口所在国家或地区（{countries or '未知'}）不在 Claude 支持地区列表内，建议更换出口地区。",
                                 ["claude.region"], "review", "更换到支持地区的出口"))

    zone = lookup.get("timezone.advice")
    if zone is None or zone.status != "completed":
        missing = True
        items.append(_advice("timezone.missing", "low", "timezone",
                             "补全本机与 Claude 网页出口时区，再核对环境一致性。", ["timezone.advice"]))
    elif zone.data.get("same_iana") is not True or zone.data.get("same_offset") is not True:
        attention = zone_mismatch = True
        target = zone.data.get("exit_timezone")
        offset = "（当前 UTC 偏移相同）" if zone.data.get("same_offset") is True else ""
        items.append(_advice("timezone.mismatch", "medium", "timezone",
                             f"如需保持环境一致，可将系统时区设为 {target}{offset}。",
                             ["timezone.advice"], "setting", f"将系统时区设为 {target}"))

    endpoint = lookup.get("claude.endpoint")
    if endpoint is None or endpoint.status != "completed":
        missing = True
        items.append(_advice("endpoint.unreadable", "medium", "endpoint",
                             "检查 Claude API 地址配置是否可读取。", ["claude.endpoint"]))
    else:
        entries = endpoint.data.get("endpoints")
        kinds = {entry.get("kind") for entry in entries if isinstance(entry, dict)} if isinstance(entries, list) else set()
        if kinds.intersection({"invalid", "insecure"}):
            attention = api_issue = True
            items.append(_advice("endpoint.invalid", "high", "endpoint",
                                 "修正 API 地址，使用 HTTPS 并移除 URL 中的凭据。",
                                 ["claude.endpoint"], "setting", "使用 HTTPS 且不含凭据的 API 地址"))
        if endpoint.data.get("conflict"):
            attention = api_issue = True
            items.append(_advice("endpoint.conflict", "high", "endpoint",
                                 "统一各处 API 地址，确认实际生效的配置。",
                                 ["claude.endpoint"], "review", "统一 API 地址配置"))
        if kinds.intersection({"provider", "custom"}):
            missing = True
            items.append(_advice("endpoint.third_party", "low", "endpoint",
                                 "确认第三方 API 服务商；官方 API 探测不代表该中转的实际路径。",
                                 ["claude.endpoint"]))
        if "local" in kinds:
            missing = True
            items.append(_advice("endpoint.local", "low", "endpoint",
                                 "检测到本地中转地址；官方 API 探测不代表该中转的实际路径。",
                                 ["claude.endpoint"]))
        if (endpoint.severity in ("warning", "error")
                and not kinds.intersection({"invalid", "insecure", "provider", "custom", "local"})
                and not endpoint.data.get("conflict")):
            missing = True
            items.append(_advice("endpoint.partial", "low", "endpoint",
                                 "核对未完整读取的 API 配置。", ["claude.endpoint"]))

    ipv6 = lookup.get("network.ipv6")
    if ipv6 is not None and ipv6.status == "completed" and ipv6.data.get("ip"):
        items.append(_advice("ipv6.egress", "low", "ipv6",
                             "检测到 IPv6 出口；若代理规则只覆盖 IPv4，IPv6 流量可能绕过分流。",
                             ["network.ipv6"], "review", "确认代理同时覆盖 IPv4 与 IPv6"))

    for check_id, text in (
        ("network.egress", "两个出口回显服务返回不同 IP，需核对本机分流与出口稳定性。"),
        ("network.direct", "两个直连来源返回不同 IP，直连出口可能不稳定。"),
        ("network.ipv6", "两个来源返回不同 IPv6 出口，需核对域名分流。"),
    ):
        check = lookup.get(check_id)
        if check is not None and check.status == "completed" and check.severity in ("warning", "error"):
            attention = True
            items.append(_advice(f"{check_id}.warning", "medium", "egress", text, [check_id]))

    # Any remaining completed warning must reach the conclusion and the exit code.
    covered = {check_id for item in items for check_id in item["check_ids"]}
    for check in checks:
        if (check.status == "completed" and check.severity in ("warning", "error")
                and check.id not in covered):
            attention = True
            category = "local" if check.group == "local" else "other"
            items.append(_advice(f"{check.id}.warning", "medium", category,
                                 f"{check.label or check.id}：{check.summary}", [check.id]))

    items.sort(key=lambda item: PRIORITY_ORDER.get(str(item["priority"]), 9))
    if attention:
        if high_ip_risk:
            message = "Claude 出口 IP 信誉风险较高"
        elif region_unsupported:
            message = "Claude 出口不在支持地区"
        elif route_multi:
            message = "Claude 出口观测到多个 IP"
        elif route_split:
            message = "Claude 网页与官方 API 出口不一致"
        elif ip_attention:
            message = "Claude 出口 IP 信誉需要核对"
        else:
            message = "存在需要调整或核对的配置"
        if missing:
            message += "；部分关键信息未取得"
        elif low_ip_checks == 2:
            note = ("API 配置需核对" if api_issue else "出口分流需核对" if route_split
                    else "支持地区需核对" if region_unsupported else "时区一致性需核对" if zone_mismatch
                    else "存在需核对项")
            message = f"Claude 出口 IP 信誉风险较低；{note}"
        level = "attention"
    elif missing:
        message, level = "关键信息不完整，暂无法给出完整结论", "incomplete"
    else:
        message, level = "Claude 出口 IP 信誉风险较低，已检配置未见明显异常", "clear"
    return level, message, items, focus


def summarize(checks: Sequence[CheckResult], network_expected: bool = True) -> dict[str, JsonValue]:
    completed = sum(check.status == "completed" for check in checks)
    unknown = sum(check.status in ("unknown", "unsupported") for check in checks)
    skipped = sum(check.status == "skipped" for check in checks)
    issues = [check.id for check in checks if check.status == "completed" and check.severity in ("warning", "error")]
    level, message, advice, focus = _assessment(checks, network_expected)
    return {
        "completed": completed, "unknown": unknown, "skipped": skipped,
        "total": len(checks), "issue_ids": issues, "message": message,
        "level": level, "advice": advice, "focus_ids": focus,
    }
