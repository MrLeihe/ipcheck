from ipcheck.core.models import CheckResult
from ipcheck.platforms.system import dns_configuration


def check_dns() -> list[CheckResult]:
    servers, source, available = dns_configuration()
    return [CheckResult(
        "dns.configuration", "network", "DNS 配置",
        "completed" if available and servers else "unknown", "info",
        f"发现 {len(servers)} 个配置的解析器" if servers else "未能确认 DNS 配置",
        ("配置不等于实际解析路径；VPN、DoH 和分流可能改变解析方式。",),
        {"servers": servers}, source,
    ), CheckResult(
        "dns.active", "network", "主动 DNS 泄露验证", "skipped", "info",
        "未提供受控的权威 DNS 检测服务，未执行主动验证",
    )]
