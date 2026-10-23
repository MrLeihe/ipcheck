"""Readable terminal reports; JSON remains the machine-readable interface."""

import json
import unicodedata
from dataclasses import dataclass
from itertools import zip_longest

from ipcheck.core.models import Report
from ipcheck.core.privacy import JsonValue

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


def _state_text(item: dict[str, JsonValue]) -> str:
    summary = str(item["summary"])
    summary = summary.replace("无法连接查询服务，可能与网络、代理或服务状态有关", "查询服务不可达")
    status = {"unknown": "未验证", "unsupported": "不支持", "skipped": "已跳过"}.get(str(item["status"]))
    if status:
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


def _egress_rows(item: dict[str, JsonValue]) -> list[Row]:
    observations = _mapping(item["data"]).get("observations")
    entries = [_mapping(entry) for entry in observations] if isinstance(observations, list) else []
    known = [entry for entry in entries if entry.get("ip")]
    addresses = list(dict.fromkeys(str(entry["ip"]) for entry in known))
    if not addresses:
        return [Row("检测出口 IP", _state_text(item), _tone(item))]
    if len(addresses) == 1:
        rows = [Row("检测出口 IP", addresses[0], "1")]
    else:
        rows = [Row("检测出口 IP" if index == 0 else "", f"{entry['ip']}  ({entry.get('service', 'IPv4')})", "1")
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


def _check_rows(item: dict[str, JsonValue]) -> list[Row]:
    check_id = item["id"]
    data = _mapping(item["data"])
    labels = {
        "network.ipv6": "IPv6 出口探测", "network.location": "IP 归属查询",
        "dns.configuration": "本地 DNS", "dns.active": "主动 DNS 验证",
        "network.reputation": "IP 信誉查询", "network.abuse": "公开举报记录",
        "proxy.environment": "环境变量代理", "proxy.system": "系统代理", "proxy.tunnel": "TUN / VPN",
        "claude.endpoint": "Claude 端点",
        "claude.api.egress": "Claude API 出口", "claude.web.egress": "Claude 网页出口",
    }
    label = labels.get(str(check_id), str(item["label"]))
    tone = _tone(item)
    if check_id == "timezone.advice":
        return [Row(label, str(item["summary"]), "32" if item["status"] == "completed" and data.get("same_iana") is True and data.get("same_offset") is True else "33")]
    if check_id == "network.egress":
        return _egress_rows(item)
    if item["status"] != "completed":
        if check_id == "network.reputation" and item["status"] == "skipped":
            return [Row(label, "已跳过 · 用 --reputation 启用", tone)]
        if check_id == "dns.active" and item["status"] == "skipped":
            return [Row(label, "已跳过 · 未配置主动检测服务", tone)]
        return [Row(label, _state_text(item), tone)]
    if check_id == "network.ipv6" and (data.get("addresses") or data.get("ip")):
        addresses = _strings(data.get("addresses")) or [str(data["ip"])]
        rows = [Row(label if index == 0 else "", address, "1") for index, address in enumerate(addresses)]
        total, successful = data.get("total_sources"), data.get("successful_sources")
        if isinstance(total, int) and isinstance(successful, int):
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
        return [Row(label, "已设置  " + " / ".join(names), "32")] if names else [Row(label, "未设置（当前进程）")]
    if check_id == "proxy.system":
        kinds = _strings(data.get("kinds"))
        return [Row(label, "已开启  " + " / ".join(kinds), "32")] if kinds else [Row(label, "未开启")]
    if check_id == "proxy.tunnel":
        interfaces = _strings(data.get("interfaces"))
        return [Row(label, "发现路由迹象  " + " / ".join(interfaces))] if interfaces else [Row(label, "未发现已识别的隧道路由")]
    if check_id in ("timezone.system", "timezone.cli", "timezone.egress", "timezone.claude_api", "timezone.claude_web", "browser.timezone"):
        return [Row(label, _timezone(item), tone)]
    if check_id in ("claude.api.egress", "claude.web.egress"):
        country = f"  ({data['country_code']})" if data.get("country_code") else ""
        return [Row(label, str(data.get("ip") or item["summary"]) + country, "1"),
                Row("探测域名", str(data.get("host") or ""), "90")]
    if check_id == "network.reputation" and data.get("score") is not None:
        note = " · 需核对" if item["severity"] in ("warning", "error") else ""
        return [Row(label, f"{data['score']}/100  (proxycheck.io){note}", tone)]
    if check_id == "claude.endpoint":
        endpoints = data.get("endpoints")
        entries = [_mapping(entry) for entry in endpoints] if isinstance(endpoints, list) else []
        hosts = list(dict.fromkeys(str(entry["host"]) for entry in entries if entry.get("host")))
        if hosts:
            return [Row(label, " / ".join(hosts), tone or "1"), Row("", _state_text(item), tone)]
    return [Row(label, _state_text(item), tone)]


def _section(item: dict[str, JsonValue]) -> str:
    check_id = str(item["id"])
    if check_id in ("network.egress", "network.ipv6", "ipv6.configuration", "ipv6.interfaces", "dns.configuration", "dns.active"):
        return "connection"
    if check_id == "network.location":
        return "location"
    if check_id.startswith("proxy.") or check_id in ("network.reputation", "network.abuse"):
        return "proxy"
    if check_id.startswith("timezone."):
        return "timezone"
    return str(item["group"])


def _table(sections: list[list[Row]], width: int, color: bool) -> list[str]:
    """Double borders and grouped label/value rows follow the upstream panel design.

    Text is wrapped before styling so injected/own ANSI sequences cannot affect
    column widths. See docs/upstream-sources.md for the reference and changes.
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


def render_text(report: Report, *, details: bool = False, color: bool = False, width: int = 100) -> str:
    # Render only the redacted serialization, including in detailed mode.
    data = report.to_dict()
    checks = [entry for entry in data["checks"] if isinstance(entry, dict)] if isinstance(data["checks"], list) else []
    summary = _mapping(data["summary"])
    width = max(24, min(width, 92))
    groups: dict[str, list[dict[str, JsonValue]]] = {}
    for item in checks:
        groups.setdefault(_section(item), []).append(item)
    order = ("connection", "location", "proxy", "timezone", "claude", "local", "browser")
    sections: list[list[Row]] = []
    for key in (*order, *(group for group in groups if group not in order)):
        rows: list[Row] = []
        items = groups.get(key, [])
        if key == "connection":
            connection_order = ("network.egress", "ipv6.configuration", "ipv6.interfaces", "network.ipv6", "dns.configuration", "dns.active")
            items = sorted(items, key=lambda item: connection_order.index(str(item["id"])) if str(item["id"]) in connection_order else len(connection_order))
        elif key == "proxy":
            items = sorted(items, key=lambda item: str(item["id"]).startswith("network."))
        elif key == "timezone":
            zone_order = ("timezone.system", "timezone.cli", "timezone.egress", "timezone.claude_api", "timezone.claude_web",
                          "timezone.advice")
            items = sorted(items, key=lambda item: zone_order.index(str(item["id"])) if str(item["id"]) in zone_order else len(zone_order))
        for item in items:
            rows.extend(_check_rows(item))
            if details:
                rows.append(Row("", f"来源：{item['source']}", "90"))
                evidence = item.get("evidence")
                if isinstance(evidence, list):
                    rows.extend(Row("", f"说明：{entry}", "90") for entry in evidence)
                if item["data"]:
                    raw = json.dumps(item["data"], ensure_ascii=False, indent=2, allow_nan=False)
                    rows.extend(Row("", line, "90") for line in raw.splitlines())
        if rows:
            sections.append(rows)
    issues = summary.get("issue_ids")
    count = len(issues) if isinstance(issues, list) else 0
    stats = (f"完成 {summary.get('completed', 0)}/{summary.get('total', 0)} · "
             f"待核对 {count} · 未验证 {summary.get('unknown', 0)} · 跳过 {summary.get('skipped', 0)}")
    message_tone = "33" if summary.get("unknown") or count else "32"
    sections.append([Row("检测概况", stats), Row("检测提示", str(summary.get("message", "")), message_tone)])
    lines = [""]
    lines.extend(_paint(line, "1", color) for line in _wrap("ipcheck · 本地环境诊断", width, "  "))
    lines.append("")
    lines.extend(_table(sections, width, color))
    lines.append("")
    if not details:
        lines.extend(_paint(line, "90", color) for line in _wrap("--details 查看证据   --json 导出报告", width, "  "))
    lines.extend(_paint(line, "90", color) for line in _wrap("配置与请求观测，不代表任何平台的账号安全判断。", width, "  "))
    return "\n".join(lines)
