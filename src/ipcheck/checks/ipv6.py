"""Local IPv6 configuration and addresses, separate from proxied HTTP observations."""

import ipaddress
import platform
import re

from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue
from ipcheck.platforms.system import command


def service_for_interface(text: str, interface: str) -> str | None:
    service = None
    for line in text.splitlines():
        entry = re.fullmatch(r"\((\d+|\*)\)\s+(.+)", line.strip())
        if entry:
            name = entry[2].strip()
            service = name if entry[1] != "*" and not name.startswith(("*", "-")) else None
        device = re.search(r"Device:\s*([^\s,)]+)\)", line)
        if device and device[1] == interface:
            return service
    return None


def configuration_mode(text: str) -> str | None:
    modes = {"off": "off", "automatic": "automatic", "manual": "manual",
             "link-local only": "link_local", "link-local": "link_local"}
    values = re.findall(r"^IPv6:\s*([^\r\n]+)", text, re.MULTILINE)
    return modes.get(values[0].strip().lower()) if len(values) == 1 else None


def address_inventory(text: str) -> dict[str, JsonValue]:
    """Keep counts and interface names, never raw IP or MAC addresses."""
    global_interfaces: set[str] = set()
    counts = {"global_count": 0, "ula_count": 0, "link_local_count": 0}
    blocks = re.split(r"(?=^[^\s:]+:\s+flags=)", text, flags=re.MULTILINE)
    recognized = False
    for block in blocks:
        header = re.match(r"([^\s:]+):\s+flags=[^<\n]*<([^>]+)>", block)
        if not header:
            continue
        recognized = True
        interface, flags = header.groups()
        if "UP" not in flags.split(",") or "LOOPBACK" in flags.split(",") or re.search(r"status:\s*inactive\b", block):
            continue
        for line in block.splitlines():
            match = re.match(r"\s+inet6\s+(\S+)", line)
            if not match or re.search(r"\b(?:tentative|duplicated|detached)\b", line):
                continue
            try:
                address = ipaddress.IPv6Address(match[1].split("%", 1)[0])
            except ValueError:
                continue
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                continue
            if address.is_global:
                counts["global_count"] += 1
                global_interfaces.add(interface)
            elif address in ipaddress.IPv6Network("fc00::/7"):
                counts["ula_count"] += 1
            elif address.is_link_local:
                counts["link_local_count"] += 1
    return {**counts, "global_interfaces": sorted(global_interfaces), "parsed": recognized}


def check_local_ipv6() -> list[CheckResult]:
    if platform.system() != "Darwin":
        return [CheckResult("ipv6.configuration", "network", "本机 IPv6 配置", "unsupported", "info",
                            "当前仅支持 macOS 网络服务配置检测", source="macOS networksetup")]
    route = command(["/sbin/route", "-n", "get", "default"])
    match = re.search(r"^\s*interface:\s*([a-zA-Z0-9_.-]+)\s*$", route or "", re.MULTILINE)
    interface = match[1] if match else None
    order = command(["/usr/sbin/networksetup", "-listnetworkserviceorder"]) if interface else None
    service = service_for_interface(order, interface) if order is not None and interface else None
    info = command(["/usr/sbin/networksetup", "-getinfo", service]) if service else None
    mode = configuration_mode(info) if info is not None else None
    labels = {"off": "已关闭", "automatic": "自动配置", "manual": "手动配置", "link_local": "仅本地链路"}
    summary = f"{labels[mode]} · {service} ({interface})" if mode else "未能确认当前网络服务的 IPv6 配置"
    results = [CheckResult("ipv6.configuration", "network", "本机 IPv6 配置", "completed" if mode else "unknown",
                           "info", summary,
                           ("只描述 IPv4 默认路由所对应的网络服务，不代表其他网卡、VPN 或远端代理。",
                            "关闭仅指该服务的 IPv6 配置；不会据此跳过代理路径上的 IPv6 出口探测。"),
                           {"interface": interface, "service": service, "mode": mode,
                            "scope": "ipv4_default_service"}, "route / networksetup")]
    interfaces = command(["/sbin/ifconfig"])
    inventory = address_inventory(interfaces or "")
    available = interfaces is not None and inventory["parsed"] is True
    if not available:
        message = "无法读取活动接口的 IPv6 地址状态"
    elif inventory["global_count"]:
        names = inventory["global_interfaces"]
        message = "发现公网 IPv6 地址 · " + " / ".join(names if isinstance(names, list) else [])
    else:
        message = "未发现活动公网 IPv6 地址"
    results.append(CheckResult("ipv6.interfaces", "network", "本机 IPv6 地址", "completed" if available else "unknown",
                               "info", message,
                               ("检查已启用、非 inactive 接口，忽略回环及尚未就绪的地址。",
                                "fe80:: 链路本地地址和 ULA 不等于公网 IPv6；没有公网地址也不能单独证明无法经代理或地址转换访问 IPv6。"),
                               inventory, "ifconfig"))
    return results
