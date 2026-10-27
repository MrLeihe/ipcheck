"""Readable terminal reports; JSON remains the machine-readable interface."""

import json
import unicodedata
from dataclasses import dataclass
from itertools import zip_longest

from ipcheck.core.models import Report
from ipcheck.core.privacy import JsonValue

EXTERNAL_URL = "https://ip.net.coffee/claude/"
CATEGORY_LABELS = {"egress": "出口连通", "reputation": "IP 信誉", "abuse": "举报记录",
                   "route": "域名分流", "region": "支持地区", "timezone": "时区",
                   "endpoint": "API 配置", "ipv6": "IPv6", "local": "本地配置",
                   "other": "其他", "none": "其他"}


@dataclass(frozen=True)
class Row:
    label: str
    value: str
    tone: str = ""


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2, allow_nan=False)


def _width(text: str) -> int:
    return sum(0 if unicodedata.category(char) in ("Mn", "Me", "Cf") else
               2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
               for char in text)


def _wrap(text: str, width: int, initial: str = "", subsequent: str | None = None) -> list[str]:
    """Wrap by terminal cells, keeping short ASCII words together when possible."""
    subsequent = initial if subsequent is None else subsequent
    output: list[str] = []
    for paragraph in text.splitlines() or [""]:
        remaining = paragraph.rstrip()
        while remaining:
            prefix = initial if not output else subsequent
            limit = max(1, width - _width(prefix))
            used, end = 0, 0
            for char in remaining:
                size = _width(char)
                if used + size > limit:
                    break
                used, end = used + size, end + 1
            end = max(end, 1)
            if end < len(remaining):
                space = remaining.rfind(" ", 0, end + 1)
                if space > end // 2:
                    end = space
            output.append(prefix + remaining[:end].rstrip())
            remaining = remaining[end:].lstrip()
        if not paragraph.strip():
            output.append(initial if not output else subsequent)
    return output


def _paint(text: str, code: str, color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if color and code else text


def _tone(item: dict[str, JsonValue]) -> str:
    if item["status"] == "skipped":
        return "90"
    if item["status"] != "completed":
        return "33"
    return {"warning": "33", "error": "31"}.get(str(item["severity"]), "")


def _mapping(value: JsonValue) -> dict[str, JsonValue]:
    return value if isinstance(value, dict) else {}


def _strings(value: JsonValue) -> list[str]:
    return [entry for entry in value if isinstance(entry, str)] if isinstance(value, list) else []


def _int(value: JsonValue) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _state_text(item: dict[str, JsonValue]) -> str:
    summary = str(item["summary"])
    summary = summary.replace("无法连接查询服务，可能与网络、代理或服务状态有关", "查询服务不可达")
    status = {"unknown": "未验证", "unsupported": "不支持", "skipped": "已跳过"}.get(str(item["status"]))
    if status:
        if summary == status or item["status"] == "unknown" and summary in ("检测失败", "读取失败", "无法确认"):
            return summary
        return f"{status} · {summary}"
    return ("需核对 · " if item["severity"] in ("warning", "error") else "") + summary


def _timezone(item: dict[str, JsonValue]) -> str:
    data = _mapping(item["data"])
    text = str(data.get("timezone") or item["summary"])
    offset = data.get("offset_minutes")
    if isinstance(offset, int) and not isinstance(offset, bool):
        hours, minutes = divmod(abs(offset), 60)
        text += f"  (UTC{'+' if offset >= 0 else '-'}{hours:02d}:{minutes:02d})"
    if item["severity"] in ("warning", "error"):
        text += " · 需核对"
    return text


_COUNTRIES = {"CN": "中国大陆", "TW": "台湾", "HK": "香港", "MO": "澳门", "US": "美国",
              "MY": "马来西亚", "SG": "新加坡", "JP": "日本", "KR": "韩国", "GB": "英国",
              "DE": "德国", "CA": "加拿大", "AU": "澳大利亚", "NL": "荷兰", "FR": "法国",
              "SE": "瑞典", "CH": "瑞士", "IE": "爱尔兰", "FI": "芬兰", "NO": "挪威",
              "PL": "波兰", "ES": "西班牙", "IT": "意大利", "BR": "巴西", "IN": "印度",
              "TR": "土耳其", "AE": "阿联酋", "IL": "以色列", "ZA": "南非", "VN": "越南",
              "TH": "泰国", "ID": "印度尼西亚", "PH": "菲律宾", "MX": "墨西哥", "AR": "阿根廷"}
_CITIES = {"Shenzhen": "深圳", "Taipei": "台北", "Taichung": "台中", "New Taipei": "新北",
           "Kaohsiung": "高雄", "Shanghai": "上海", "Beijing": "北京", "Guangzhou": "广州",
           "Hong Kong": "香港", "Singapore": "新加坡", "Kuala Lumpur": "吉隆坡", "Tokyo": "东京",
           "Osaka": "大阪", "Seoul": "首尔", "Los Angeles": "洛杉矶", "San Jose": "圣何塞",
           "San Francisco": "旧金山", "New York": "纽约", "Seattle": "西雅图", "Ashburn": "阿什本",
           "Frankfurt": "法兰克福", "Amsterdam": "阿姆斯特丹", "London": "伦敦", "Paris": "巴黎",
           "Tokyo": "东京", "Sydney": "悉尼", "Toronto": "多伦多", "Dallas": "达拉斯"}


def _ip_region(ip: str, data: dict[str, JsonValue], *, claude: bool = False) -> str:
    geo = data if claude else _mapping(_mapping(data.get("locations")).get(ip))
    prefix = "location_" if claude else ""
    code = geo.get("country_code") if claude else geo.get("country_code")
    country = _COUNTRIES.get(str(code), str(geo.get(prefix + "country") or code or ""))
    city = str(geo.get(prefix + "city") or geo.get(prefix + "region") or "")
    city = _CITIES.get(city, city)
    if city == country:
        city = ""
    region = country + (city if city and all(ord(c) > 127 for c in city) else " · " + city if city and country else city)
    return ip + "（" + (region or "归属未知") + "）"


def _egress_rows(item: dict[str, JsonValue]) -> list[Row]:
    observations = _mapping(item["data"]).get("observations")
    entries = [_mapping(entry) for entry in observations] if isinstance(observations, list) else []
    known = [entry for entry in entries if entry.get("ip")]
    addresses = list(dict.fromkeys(str(entry["ip"]) for entry in known))
    if not addresses:
        return [Row("代理出口 IP", _state_text(item), _tone(item))]
    if len(addresses) == 1:
        rows = [Row("代理出口 IP", _ip_region(addresses[0], _mapping(item["data"])), "1")]
    else:
        rows = [Row("代理出口 IP" if index == 0 else "", _ip_region(str(entry["ip"]), _mapping(item["data"])) + f"  ({entry.get('service', 'IPv4')})", "1")
                for index, entry in enumerate(known)]
    if item["status"] != "completed":
        note = (f"仅 {len(known)}/{len(entries)} 个来源返回地址，出口未验证" if len(known) < len(entries)
                else "出口校验未完成（未验证）")
        rows.append(Row("出口校验", note, "33"))
    elif len(addresses) > 1:
        rows.append(Row("出口校验", "不同服务观测到不同出口，需核对", "33"))
    elif len(known) > 1:
        rows.append(Row("出口校验", "两个服务观测一致", "32"))
    return rows


def _region_support(lookup: dict[str, dict[str, JsonValue]], key: str) -> tuple[str, str]:
    region = lookup.get("claude.region")
    if region is None:
        return "未比对", "90"
    routes = _mapping(region["data"]).get("routes")
    if not isinstance(routes, list):
        return "未比对", "90"
    for entry in routes:
        if isinstance(entry, dict) and entry.get("route") == key:
            if entry.get("supported") is True:
                parent = entry.get("territory_of")
                return (f"支持（{parent} 属地）" if parent else "支持"), "32"
            if entry.get("supported") is False:
                return "不支持", "31"
    return "未比对", "90"


def _policy_row(lookup: dict[str, dict[str, JsonValue]]) -> Row | None:
    region = lookup.get("claude.region")
    if region is None:
        return None
    policy = _mapping(_mapping(region["data"]).get("policy"))
    effective = policy.get("effective")
    if not isinstance(effective, str) or not effective:
        return None
    return Row("政策依据", f"Anthropic 支持地区政策 · {effective} 生效", "90")


def _exit_rows(key: str, label: str, item: dict[str, JsonValue],
               lookup: dict[str, dict[str, JsonValue]]) -> list[Row]:
    if item["status"] != "completed":
        return [Row(label, _state_text(item), _tone(item))]
    data = _mapping(item["data"])
    address = str(data.get("ip") or "")
    rows = [Row(label, _ip_region(address, data, claude=True) if address else str(item["summary"]), "1")]
    if data.get("location_status") == "completed":
        country = " / ".join(str(data[field]) for field in ("location_country", "location_region") if data.get(field))
        rows.append(Row("国家 / 地区", country or str(data.get("country_code") or "服务未提供")))
        for name, field in (("城市", "location_city"), ("运营商", "location_isp"), ("IP 归属", "location_org")):
            value = data.get(field)
            rows.append(Row(name, str(value) if value else "服务未提供", "" if value else "90"))
        if data.get("location_asn") is not None:
            rows.append(Row("ASN", f"AS{data['location_asn']}"))
    else:
        if data.get("country_code"):
            rows.append(Row("国家 / 地区", str(data["country_code"])))
        rows.append(Row("出口归属查询", "未取得归属数据", "33"))
    support, support_tone = _region_support(lookup, key)
    rows.append(Row("支持地区", support, support_tone))
    policy_row = _policy_row(lookup)
    if policy_row is not None:
        rows.append(policy_row)
    zone = lookup.get(f"timezone.claude_{key}")
    if zone is not None and zone["status"] == "completed":
        rows.append(Row("出口时区", _timezone(zone)))
    elif data.get("timezone"):
        rows.append(Row("出口时区", str(data["timezone"])))
    latency = _int(data.get("latency_ms"))
    if latency is not None:
        rows.append(Row("响应耗时", f"{latency} ms（DNS/TLS/首字节）"))
    return rows


def _shared_route(lookup: dict[str, dict[str, JsonValue]]) -> bool:
    web, api = lookup.get("claude.web.egress"), lookup.get("claude.api.egress")
    return bool(web and api and web["status"] == api["status"] == "completed"
                and _mapping(web["data"]).get("ip")
                and _mapping(web["data"]).get("ip") == _mapping(api["data"]).get("ip"))


def _claude_sections(lookup: dict[str, dict[str, JsonValue]]) -> list[list[Row]]:
    web, api = lookup.get("claude.web.egress"), lookup.get("claude.api.egress")
    if web is None and api is None:
        return []
    if _shared_route(lookup):
        return [_exit_rows("web", "Claude 网页/API 出口", web, lookup)]
    sections = []
    for key, label, item in (("web", "Claude 网页出口", web), ("api", "官方 API 出口", api)):
        if item is not None:
            sections.append(_exit_rows(key, label, item, lookup))
    return sections


def _flag_text(value: JsonValue) -> str | None:
    return {True: "是", False: "否"}.get(value) if isinstance(value, bool) else None


def _security_rows(lookup: dict[str, dict[str, JsonValue]]) -> list[Row]:
    web_profile, api_profile = lookup.get("claude.web.reputation"), lookup.get("claude.api.reputation")
    shared = bool(web_profile and api_profile and web_profile["status"] == api_profile["status"] == "completed"
                  and _mapping(web_profile["data"]).get("ip")
                  and _mapping(web_profile["data"]).get("ip") == _mapping(api_profile["data"]).get("ip"))
    pairs = (("web", "", ("web", "api")),) if shared else (("web", "网页 ", ("web",)), ("api", "API ", ("api",)))
    rows: list[Row] = []
    for key, prefix, _ in pairs:
        profile = lookup.get(f"claude.{key}.reputation")
        abuse = lookup.get(f"claude.{key}.abuse")
        if profile is None:
            continue
        data = _mapping(profile["data"])
        if profile["status"] == "skipped":
            rows.append(Row(prefix + "IP 类型与信誉", "未查询（--no-reputation）", "90"))
        else:
            rows.append(Row(prefix + "IP 类型", str(data.get("classification") or "类型未取得"),
                            "90" if not data.get("classification") else ""))
            score = _int(data.get("score"))
            if profile["status"] != "completed" or score is None:
                rows.append(Row(prefix + "IP 信誉评分", _state_text(profile), "33"))
            else:
                grade, tone = ("高", "31") if score >= 66 else ("中", "33") if score >= 30 else ("低", "32")
                rows.append(Row(prefix + "IP 信誉评分", f"{score}/100 · {grade}风险（proxycheck.io）", tone))
            proxy = _flag_text(data.get("proxy"))
            if proxy is not None:
                rows.append(Row(prefix + "代理标记", "已标记代理" if data.get("proxy") else "未标记代理",
                                "33" if data.get("proxy") else "32"))
            flags = [(name, _flag_text(data.get(field))) for name, field in
                     (("VPN", "vpn"), ("Tor", "tor"), ("爬虫", "crawler"))]
            flags = [(name, value) for name, value in flags if value is not None]
            if flags:
                rows.append(Row(prefix + "VPN/Tor/爬虫", " · ".join(f"{name}：{value}" for name, value in flags),
                                "33" if any(value == "是" for _, value in flags) else "32"))
        if abuse is not None:
            abuse_data = _mapping(abuse["data"])
            if abuse["status"] == "completed" and isinstance(abuse_data.get("listed"), bool):
                rows.append(Row(prefix + "公开举报记录",
                                "已收录（StopForumSpam）" if abuse_data["listed"] else "未收录（StopForumSpam）",
                                "33" if abuse_data["listed"] else "32"))
            elif abuse["status"] != "skipped":
                rows.append(Row(prefix + "公开举报记录", _state_text(abuse), "33"))
    return rows


def _observed_ips(check: dict[str, JsonValue] | None) -> list[str]:
    if check is None:
        return []
    data = _mapping(check["data"])
    found: list[JsonValue] = []
    addresses = data.get("addresses")
    if isinstance(addresses, list):
        found.extend(addresses)
    observations = data.get("observations")
    if isinstance(observations, list):
        found.extend(entry.get("ip") for entry in observations if isinstance(entry, dict))
    found.append(data.get("ip"))
    return list(dict.fromkeys(value for value in found if isinstance(value, str)))


def _joined_regions(ips: list[str], check: dict[str, JsonValue]) -> str:
    data = _mapping(check["data"])
    return "、".join(_ip_region(ip, data) for ip in ips)


def _comparison_rows(lookup: dict[str, dict[str, JsonValue]]) -> list[Row]:
    rows: list[Row] = []
    for source, label in (("network.direct", "本机直连公网 IP"), ("network.egress", "代理出口 IP"),
                          ("network.cloudflare", "Cloudflare 出口 IP")):
        check = lookup.get(source)
        if check is None:
            continue
        ips = _observed_ips(check)
        if ips:
            rows.append(Row(label, _joined_regions(ips, check), "33" if source == "network.direct" and len(ips) > 1 else "1"))
            if source == "network.direct":
                if len(ips) > 1:
                    rows.append(Row("直连校验", "不同来源返回不同 IP", "33"))
                elif check["status"] != "completed":
                    rows.append(Row("直连校验", "单源结果，未完成交叉验证", "33"))
        else:
            rows.append(Row(label, _state_text(check), "90"))
        if source == "network.egress":
            if check["status"] != "completed":
                data = _mapping(check["data"])
                observations = data.get("observations")
                total = len(observations) if isinstance(observations, list) else 0
                rows.append(Row("代理出口校验", f"仅 {len(ips)}/{total} 个来源返回地址，出口未验证", "33"))
            elif check["severity"] in ("warning", "error"):
                rows.append(Row("代理出口校验", _state_text(check), "33"))
    direct, tunnel = lookup.get("network.direct"), lookup.get("proxy.tunnel")
    if direct is not None and _observed_ips(direct) and (tunnel is None or _mapping(tunnel["data"]).get("state") != "off"):
        rows.append(Row("直连范围", "已绕过系统和环境代理；仍可能经过 TUN/VPN", "33"))
    comparison = lookup.get("route.comparison")
    if comparison is not None:
        tone = "33" if comparison["severity"] in ("warning", "error") else "32" if comparison["status"] == "completed" else "90"
        rows.append(Row("出口一致性", str(comparison["summary"]), tone))
    return rows if any(_observed_ips(lookup.get(source)) for source in
                       ("network.direct", "network.egress", "network.cloudflare")) or comparison else []


def _ipv6_hint(lookup: dict[str, dict[str, JsonValue]]) -> Row | None:
    egress = lookup.get("network.ipv6")
    if egress is not None and egress["status"] == "completed" and _mapping(egress["data"]).get("ip"):
        return Row("IPv6 提示", "检测到 IPv6 出口；若代理规则只覆盖 IPv4，IPv6 可能绕过分流", "33")
    configuration = lookup.get("ipv6.configuration")
    interfaces = lookup.get("ipv6.interfaces")
    if (configuration is not None and _mapping(configuration["data"]).get("mode") not in (None, "off")
            and interfaces is not None and interfaces["status"] == "completed"
            and _mapping(interfaces["data"]).get("global_count") == 0):
        return Row("IPv6 提示", "配置未关闭，但未发现公网 IPv6 地址", "90")
    return None


def _local_rows(lookup: dict[str, dict[str, JsonValue]]) -> list[Row]:
    rows: list[Row] = []
    for key in ("proxy.environment", "proxy.system", "proxy.tunnel"):
        item = lookup.get(key)
        if item is not None:
            rows.extend(_check_rows(item))
    dns = lookup.get("dns.configuration")
    if dns is not None:
        rows.extend(_check_rows(dns))
    configuration_item = lookup.get("ipv6.configuration")
    if configuration_item is not None:
        rows.extend(_check_rows(configuration_item))
    egress = lookup.get("network.ipv6")
    if egress is not None and (egress["status"] == "completed" or egress["severity"] in ("warning", "error")):
        rows.extend(_check_rows(egress))
    hint = _ipv6_hint(lookup)
    if hint is not None:
        rows.append(hint)
    return rows


def _timezone_rows(lookup: dict[str, dict[str, JsonValue]]) -> list[Row]:
    rows: list[Row] = []
    for key in ("timezone.system", "timezone.cli", "timezone.claude_web"):
        item = lookup.get(key)
        if item is not None:
            rows.extend(_check_rows(item))
    comparison = lookup.get("timezone.advice")
    if comparison is not None:
        data = _mapping(comparison["data"])
        if comparison["status"] != "completed":
            text, tone = "未完成比较", "33"
        elif data.get("same_iana") is True and data.get("same_offset") is True:
            text, tone = "IANA 名称、UTC 偏移一致", "32"
        elif data.get("same_offset") is True:
            text, tone = "IANA 名称不同，UTC 偏移一致", "33"
        else:
            text, tone = "本机与 Claude 网页出口时区不同", "33"
        rows.append(Row("时区一致性", text, tone))
    return rows


def _endpoint_rows(lookup: dict[str, dict[str, JsonValue]]) -> list[Row]:
    item = lookup.get("claude.endpoint")
    return _check_rows(item) if item is not None else []


def _advice_items(summary: dict[str, JsonValue]) -> list[dict[str, JsonValue]]:
    value = summary.get("advice")
    return [item for item in value if isinstance(item, dict) and isinstance(item.get("text"), str)] \
        if isinstance(value, list) else []


def _conclusion_rows(summary: dict[str, JsonValue]) -> list[Row]:
    items = _advice_items(summary)
    priorities = {item.get("priority") for item in items}
    if summary.get("level") == "clear":
        tone = "32"
    elif "high" in priorities:
        tone = "31"
    else:
        tone = "33"
    if items:
        categories: list[str] = []
        for item in items:
            label = CATEGORY_LABELS.get(str(item.get("category")), "其他")
            if label not in categories:
                categories.append(label)
        count = f"{len(items)} 项：" + "、".join(categories[:3]) + (" 等" if len(categories) > 3 else "")
        count_tone = "31" if "high" in priorities else "33"
    else:
        count, count_tone = "无", "32"
    return [Row("综合结论", str(summary.get("message", "")), tone),
            Row("需要确认", count, count_tone)]


def _advice_rows(summary: dict[str, JsonValue]) -> list[Row]:
    items = _advice_items(summary)
    if not items:
        return [Row("检测建议", "暂无需要调整的已检项目。", "32")]
    rows: list[Row] = []
    for index, item in enumerate(items):
        tone = {"high": "31", "medium": "33"}.get(str(item.get("priority")), "")
        rows.append(Row("检测建议" if index == 0 else "", f"{index + 1}. {item['text']}", tone))
    return rows


def _check_rows(item: dict[str, JsonValue]) -> list[Row]:
    check_id = item["id"]
    data = _mapping(item["data"])
    labels = {
        "network.ipv6": "IPv6 出口探测", "network.location": "IP 归属查询",
        "network.cloudflare": "Cloudflare 出口", "route.comparison": "出口路径对比",
        "claude.region": "Claude 支持地区",
        "timezone.system": "系统时区", "timezone.cli": "CLI 时区",
        "timezone.egress": "检测出口时区", "timezone.claude_web": "Claude 网页时区",
        "timezone.claude_api": "Claude API 时区", "timezone.advice": "时区建议",
        "dns.configuration": "本地 DNS", "dns.active": "主动 DNS 验证",
        "network.reputation": "IP 信誉查询", "network.abuse": "公开举报记录",
        "proxy.environment": "环境变量代理", "proxy.system": "系统代理", "proxy.tunnel": "TUN / VPN",
        "claude.endpoint": "Claude API 配置",
        "claude.web.reputation": "网页 IP 类型与信誉", "claude.api.reputation": "API IP 类型与信誉",
        "claude.api.egress": "官方 API 出口", "claude.web.egress": "Claude 网页出口",
    }
    label = labels.get(str(check_id), str(item["label"]))
    tone = _tone(item)
    if check_id == "network.direct":
        addresses = _strings(data.get("addresses"))
        if not addresses:
            return [Row("本机直连公网 IP", str(item["summary"]), "33")]
        rows = [Row("本机直连公网 IP" if index == 0 else "", _ip_region(address, data), "1") for index, address in enumerate(addresses)]
        if len(addresses) > 1:
            rows.append(Row("直连校验", "不同来源返回不同 IP", "33"))
        return rows
    if check_id in ("timezone.advice", "route.comparison"):
        return [Row(label, str(item["summary"]), "32" if item["status"] == "completed" and item["severity"] == "info" else tone)]
    if check_id == "claude.region":
        routes = data.get("routes")
        rows = []
        for entry in routes if isinstance(routes, list) else []:
            if isinstance(entry, dict):
                state = {True: "支持", False: "不支持"}.get(entry.get("supported"), "未比对")
                parent = entry.get("territory_of")
                code = str(entry.get("country_code") or "未知") + (f"（{parent} 属地）" if parent else "")
                rows.append(Row(str(entry.get("label") or ""), f"{code} · {state}",
                                "31" if entry.get("supported") is False else "32" if entry.get("supported") is True else "90"))
        policy_row = _policy_row({"claude.region": item})
        if policy_row is not None:
            rows.append(policy_row)
        return rows or [Row(label, _state_text(item), tone)]
    if str(check_id).endswith(".reputation") and data.get("classification"):
        score = _int(data.get("score"))
        rating = f"{score}/100（proxycheck.io）" if score is not None else "评分未取得"
        return [Row(label, str(data["classification"]) + " · " + rating, tone)]
    if check_id == "network.egress":
        return _egress_rows(item)
    if check_id == "network.cloudflare" and data.get("ip"):
        return [Row(label, _ip_region(str(data["ip"]), data), "1")]
    if item["status"] != "completed":
        if check_id == "network.reputation" and item["status"] == "skipped":
            return [Row(label, "已跳过 · 用 --reputation 启用", tone)]
        if check_id == "dns.active" and item["status"] == "skipped":
            return [Row(label, "已跳过 · 未配置主动检测服务", tone)]
        return [Row(label, _state_text(item), tone)]
    if check_id == "network.ipv6" and (data.get("addresses") or data.get("ip")):
        addresses = _strings(data.get("addresses")) or [str(data["ip"])]
        rows = [Row(label if index == 0 else "", _ip_region(address, data), "1") for index, address in enumerate(addresses)]
        total, successful = _int(data.get("total_sources")), _int(data.get("successful_sources"))
        if total is not None and successful is not None:
            if successful < total:
                observations = data.get("observations")
                failures = [f"{entry.get('service')}：{entry.get('reason')}" for entry in observations
                            if isinstance(entry, dict) and entry.get("status") != "completed"] if isinstance(observations, list) else []
                note = "；".join(failures) or "其余来源未完成"
                rows.append(Row("IPv6 探测来源", f"{successful}/{total} 个来源返回 IPv6；{note}", "33"))
            elif total > 1 and data.get("same_ip") is True:
                rows.append(Row("IPv6 探测来源", "两个来源返回相同 IPv6", "32"))
            elif total > 1:
                rows.append(Row("IPv6 探测来源", "不同来源返回不同 IPv6，请核对域名分流", "33"))
        return rows
    if check_id == "dns.configuration":
        servers = _strings(data.get("servers"))
        if servers:
            return [Row(label if index == 0 else "", value) for index, value in enumerate(servers)]
    if check_id == "network.location":
        country = " / ".join(str(data[key]) for key in ("country", "region") if data.get(key))
        fields = [("国家 / 地区", country), ("城市", data.get("city")), ("运营商", data.get("isp")),
                  ("IP 归属", data.get("org"))]
        if data.get("asn") is not None:
            fields.insert(4, ("ASN", f"AS{data['asn']}"))
        return [Row(name, str(value) if value else "服务未提供", "" if value else "90") for name, value in fields]
    if check_id == "proxy.environment":
        names = _strings(data.get("names"))
        return [Row(label, "已设置  " + " / ".join(names), "32")] if names else [Row(label, "未设置")]
    if check_id == "proxy.system":
        kinds = _strings(data.get("kinds"))
        return [Row(label, "已开启  " + " / ".join(kinds), "32")] if kinds else [Row(label, "未开启")]
    if check_id == "proxy.tunnel":
        text = str(item["summary"])
        interfaces = _strings(data.get("interfaces"))
        if data.get("state") == "on" and interfaces:
            text += "  " + " / ".join(interfaces)
        return [Row(label, text, "32" if data.get("state") == "on" else tone)]
    if check_id in ("timezone.system", "timezone.cli", "timezone.egress", "timezone.claude_api", "timezone.claude_web"):
        return [Row(label, _timezone(item), tone)]
    if check_id in ("claude.api.egress", "claude.web.egress"):
        return [Row(label, _ip_region(str(data["ip"]), data, claude=True) if data.get("ip") else str(item["summary"]), "1")]
    if check_id == "claude.endpoint":
        endpoints = data.get("endpoints")
        entries = [_mapping(entry) for entry in endpoints] if isinstance(endpoints, list) else []
        hosts = list(dict.fromkeys(str(entry["host"]) for entry in entries if entry.get("host")))
        if hosts:
            return [Row(label, " / ".join(hosts), tone or "1"), Row("", _state_text(item), tone)]
    return [Row(label, _state_text(item), tone)]


def _section(item: dict[str, JsonValue]) -> str:
    check_id = str(item["id"])
    if check_id.startswith("claude.") and check_id != "claude.endpoint":
        return "claude_network"
    if check_id in ("network.direct", "network.egress", "network.ipv6", "network.cloudflare",
                    "route.comparison", "ipv6.configuration", "ipv6.interfaces", "dns.configuration", "dns.active"):
        return "connection"
    if check_id == "network.location":
        return "location"
    if check_id.startswith("proxy.") or check_id in ("network.reputation", "network.abuse"):
        return "proxy"
    if check_id.startswith("timezone."):
        return "timezone"
    return str(item["group"])


def _table(sections: list[list[Row]], width: int, color: bool) -> list[str]:
    """Render grouped label/value rows in a double-border table.

    Text is wrapped before styling so injected/own ANSI sequences cannot affect
    column widths.
    """
    dual = width >= 56
    label_width = 20
    value_width = width - label_width - 9 if dual else width - 6

    def border(left: str, middle: str, right: str) -> str:
        inside = "═" * (label_width + 2) + middle if dual else ""
        return _paint("  " + left + inside + "═" * (value_width + 2) + right, "90", color)

    def cell(text: str, size: int, tone: str = "") -> str:
        return _paint(text, tone, color) + " " * (size - _width(text))

    lines = [border("╔", "╤", "╗")]
    edge, split = _paint("║", "90", color), _paint("│", "90", color)
    for index, section in enumerate(sections):
        if index:
            lines.append(border("╠", "╪", "╣"))
        for row in section:
            if dual:
                for label, value in zip_longest(_wrap(row.label, label_width), _wrap(row.value, value_width), fillvalue=""):
                    lines.append(f"  {edge} {cell(label, label_width)} {split} {cell(value, value_width, row.tone)} {edge}")
            else:
                if row.label:
                    for label in _wrap(row.label, value_width):
                        lines.append(f"  {edge} {cell(label, value_width, '1')} {edge}")
                for value in _wrap(row.value, value_width):
                    lines.append(f"  {edge} {cell(value, value_width, row.tone)} {edge}")
    lines.append(border("╚", "╧", "╝"))
    return lines


def _detailed_sections(checks: list[dict[str, JsonValue]]) -> list[list[Row]]:
    order = ("claude_network", "timezone", "claude", "connection", "location", "proxy", "local")
    groups: dict[str, list[dict[str, JsonValue]]] = {}
    for item in checks:
        groups.setdefault(_section(item), []).append(item)
    sections: list[list[Row]] = []
    for key in (*order, *(group for group in groups if group not in order)):
        rows: list[Row] = []
        items = groups.get(key, [])
        if key == "claude_network":
            route_order = ("claude.web.egress", "claude.web.reputation", "claude.web.abuse", "claude.region",
                           "claude.api.egress", "claude.api.reputation", "claude.api.abuse")
            items = sorted(items, key=lambda item: route_order.index(str(item["id"])) if str(item["id"]) in route_order else len(route_order))
        elif key == "connection":
            connection_order = ("network.direct", "network.egress", "network.cloudflare", "route.comparison",
                                "ipv6.configuration", "ipv6.interfaces", "network.ipv6", "dns.configuration", "dns.active")
            items = sorted(items, key=lambda item: connection_order.index(str(item["id"])) if str(item["id"]) in connection_order else len(connection_order))
        elif key == "proxy":
            items = sorted(items, key=lambda item: str(item["id"]).startswith("network."))
        elif key == "timezone":
            zone_order = ("timezone.system", "timezone.cli", "timezone.egress", "timezone.claude_api", "timezone.claude_web",
                          "timezone.advice")
            items = sorted(items, key=lambda item: zone_order.index(str(item["id"])) if str(item["id"]) in zone_order else len(zone_order))
        for item in items:
            rows.extend(_check_rows(item))
            rows.append(Row("", f"来源：{item['source']}", "90"))
            evidence = item.get("evidence")
            if isinstance(evidence, list):
                rows.extend(Row("", f"说明：{entry}", "90") for entry in evidence)
            if item["data"]:
                raw = json.dumps(item["data"], ensure_ascii=False, indent=2, allow_nan=False)
                rows.extend(Row("", line, "90") for line in raw.splitlines())
        if rows:
            sections.append(rows)
    return sections


def render_text(report: Report, *, details: bool = False, color: bool = False, width: int = 100) -> str:
    # Render only the redacted serialization, including in detailed mode.
    data = report.to_dict()
    checks = [entry for entry in data["checks"] if isinstance(entry, dict)] if isinstance(data["checks"], list) else []
    summary = _mapping(data["summary"])
    lookup = {str(item["id"]): item for item in checks}
    width = max(24, min(width, 92))
    if details:
        sections = [_conclusion_rows(summary)]
        sections.extend(_detailed_sections(checks))
    else:
        sections = [_conclusion_rows(summary)]
        sections.extend(_claude_sections(lookup))
        security = _security_rows(lookup)
        if security:
            sections.append(security)
        comparison = _comparison_rows(lookup)
        if comparison:
            sections.append(comparison)
        local = _local_rows(lookup)
        if local:
            sections.append(local)
        zones = _timezone_rows(lookup)
        if zones:
            sections.append(zones)
        endpoint = _endpoint_rows(lookup)
        if endpoint:
            sections.append(endpoint)
        local_checks = [row for item in checks if item["group"] == "local"
                        and item["status"] != "skipped" and not str(item["id"]).endswith(".execution")
                        for row in _check_rows(item)]
        if local_checks:
            sections.append(local_checks)
        failures = [row for item in checks if str(item["id"]).endswith(".execution") for row in _check_rows(item)]
        if failures:
            sections.append(failures)
    sections.append(_advice_rows(summary))
    lines = [""]
    lines.extend(_paint(line, "1", color) for line in _wrap("ipcheck · Claude AI IP 风险检测", width, "  "))
    lines.append("")
    lines.extend(_table(sections, width, color))
    lines.append("")
    if not details:
        lines.extend(_paint(line, "90", color) for line in _wrap("--details 查看全部检测与证据   --json 导出报告", width, "  "))
    lines.extend(_paint(line, "90", color) for line in _wrap(f"浏览器指纹 / WebRTC / DNS 泄露请访问 {EXTERNAL_URL}", width, "  "))
    lines.extend(_paint(line, "90", color) for line in _wrap("结论基于公开网络信号，非 Claude 账号风控评级。", width, "  "))
    return "\n".join(lines)
