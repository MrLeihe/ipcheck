import ipaddress
import os
import platform
import re
import subprocess
from pathlib import Path


def command(args: list[str], timeout: float = 3) -> str | None:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return result.stdout if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None


def system_timezone() -> str | None:
    try:
        resolved = str(Path("/etc/localtime").resolve())
        if "/zoneinfo/" in resolved:
            return resolved.split("/zoneinfo/", 1)[1]
        path = Path("/etc/timezone")
        if path.is_file():
            return path.read_text().strip() or None
    except OSError:
        pass
    return None


def dns_configuration() -> tuple[list[str], str, bool]:
    if platform.system() == "Darwin":
        text = command(["scutil", "--dns"])
        if text is not None:
            return parse_dns(text), "scutil --dns", True
    if platform.system() == "Windows":
        text = command(["powershell", "-NoProfile", "-Command", "Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses"])
        return parse_dns(text or ""), "Get-DnsClientServerAddress", text is not None
    try:
        return parse_dns(Path("/etc/resolv.conf").read_text()), "/etc/resolv.conf", True
    except OSError:
        return [], "system DNS configuration", False


def parse_dns(text: str) -> list[str]:
    servers: list[str] = []
    for line in text.splitlines():
        candidate = line.strip()
        if candidate.startswith("nameserver["):
            candidate = candidate.split(":", 1)[-1].strip()
        elif candidate.startswith("nameserver ") or candidate.startswith("nameserver\t"):
            candidate = candidate.split()[1]
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in servers:
            servers.append(candidate)
    return servers


_PROXY_SWITCHES = (("HTTP", "HTTPEnable"), ("HTTPS", "HTTPSEnable"), ("SOCKS", "SOCKSEnable"))
_PAC_SWITCH = "ProxyAutoConfigEnable"


def _scutil_settings(text: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            settings[key.strip()] = value.strip()
    return settings


def parse_macos_proxy(text: str) -> list[str]:
    """Return the enabled proxy kinds from `scutil --proxy`; never addresses or credentials."""
    settings = _scutil_settings(text)
    enabled = [label for label, switch in _PROXY_SWITCHES if settings.get(switch) == "1"]
    if settings.get(_PAC_SWITCH) == "1":
        enabled.append("PAC")
    return enabled


def system_proxy() -> tuple[list[str], bool]:
    if platform.system() != "Darwin":
        return [], False
    text = command(["scutil", "--proxy"])
    return parse_macos_proxy(text or ""), text is not None


def environment_proxy_names() -> list[str]:
    return [name for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy") if os.environ.get(name)]
