"""Generic Cloudflare egress observation, separate from the Claude host probes."""

from time import perf_counter

from ipcheck.checks.claude_route import parse_trace
from ipcheck.core.models import CheckResult
from ipcheck.providers.http import HttpClient, ProviderError

TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
HOST = "www.cloudflare.com"


def check_cloudflare(client: HttpClient) -> list[CheckResult]:
    evidence = ("向 Cloudflare 的公开 trace 接口发起当前进程的匿名 HTTPS 请求。",
                "保留当前代理与域名分流；Claude 域名可能使用不同规则。",
                "colo 是 Cloudflare 服务节点位置，不是用户出口位置。")
    started = perf_counter()
    try:
        data = parse_trace(client.text(TRACE_URL), HOST)
    except ProviderError as exc:
        return [CheckResult("network.cloudflare", "network", "Cloudflare 出口", "unknown", "info",
                            str(exc), evidence, {"host": HOST}, TRACE_URL)]
    data["latency_ms"] = max(0, round((perf_counter() - started) * 1000))
    return [CheckResult("network.cloudflare", "network", "Cloudflare 出口", "completed", "info",
                        str(data["ip"]), evidence, data, TRACE_URL)]
