"""Anonymous same-host probes, separate from client credentials and settings."""

import re
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter

from ipcheck.checks.network import location_check, public_ip
from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue
from ipcheck.providers.http import HttpClient, ProviderError

TARGETS = (("api", "Claude API", "api.anthropic.com"), ("web", "Claude 网页", "claude.ai"))


def parse_trace(text: str, host: str) -> dict[str, JsonValue]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in ("ip", "h", "loc", "colo"):
            if key in fields:
                raise ProviderError("同域名 trace 返回了重复字段")
            fields[key] = value
    if fields.get("h", "").lower().rstrip(".") != host:
        raise ProviderError("同域名 trace 未确认预期探测主机")
    address = public_ip(fields.get("ip"))
    country = fields.get("loc", "")
    colo = fields.get("colo", "")
    # colo is the Cloudflare server location, not the caller's exit timezone.
    return {"host": host, "ip": address,
            "country_code": country if re.fullmatch(r"[A-Z]{2}", country) else None,
            "colo": colo if re.fullmatch(r"[A-Z]{3}", colo) else None}


def _observe(client: HttpClient, entry: tuple[str, str, str]) -> CheckResult:
    key, label, host = entry
    source = f"https://{host}/cdn-cgi/trace"
    evidence = (f"向 {host} 发起当前进程的匿名 HTTPS 探测；保留当前代理与域名分流。",
                "不调用模型、不发送 API Key、Cookie 或登录凭证。",
                "探测固定官方域名；自定义端点、进程规则及运行中会话可能使用不同路径。")
    started = perf_counter()
    try:
        data = parse_trace(client.text(source), host)
        data["latency_ms"] = max(0, round((perf_counter() - started) * 1000))
        return CheckResult(f"claude.{key}.egress", "claude", f"{label} 出口观测", "completed", "info",
                           str(data["ip"]), evidence, data, source)
    except ProviderError as exc:
        return CheckResult(f"claude.{key}.egress", "claude", f"{label} 出口观测", "unknown", "info",
                           str(exc), evidence, {"host": host}, source)


def check_claude_routes(client: HttpClient, location_fallback: HttpClient | None = None) -> list[CheckResult]:
    with ThreadPoolExecutor(max_workers=2) as pool:
        observed = list(pool.map(lambda entry: _observe(client, entry), TARGETS))
    locations: dict[str, CheckResult] = {}
    results: list[CheckResult] = []
    for check in observed:
        data = dict(check.data)
        ip = data.get("ip")
        evidence = check.evidence
        if isinstance(ip, str):
            if ip not in locations:
                locations[ip] = location_check(client, ip, location_fallback)
            location = locations[ip]
            data.update({"timezone": location.data.get("timezone"), "location_status": location.status,
                         "location_summary": location.summary, "lookup_route": location.data.get("lookup_route"),
                         "location_country": location.data.get("country"), "location_source": location.source})
            for field in ("region", "city", "isp", "org", "asn"):
                data[f"location_{field}"] = location.data.get(field)
            evidence += location.evidence
            if location.status != "completed":
                evidence += (f"已观测出口，但归属查询未完成：{location.summary}",)
        results.append(CheckResult(check.id, check.group, check.label, check.status, check.severity,
                                   check.summary, evidence, data, check.source, check.observed_at))
    return results
