from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from ipcheck.checks.claude import check_claude
from ipcheck.checks.claude_route import check_claude_routes
from ipcheck.checks.dns import check_dns
from ipcheck.checks.local import check_local
from ipcheck.checks.ipv6 import check_local_ipv6
from ipcheck.checks.network import check_network
from ipcheck.checks.proxy import check_proxy
from ipcheck.checks.timezone import check_timezone, compare_timezone
from ipcheck.core.models import CheckResult, Report
from ipcheck.providers.http import HttpClient

Progress = Callable[[int, int], None]


@dataclass(frozen=True)
class Options:
    network: bool = True
    local: bool = False
    reputation: bool = False
    timeout: float = 4


def run_checks(options: Options, progress: Progress | None = None, home: Path | None = None) -> Report:
    tasks: list[tuple[str, Callable[[], list[CheckResult]]]] = []
    if options.network:
        tasks.extend([
            ("network", lambda: check_network(HttpClient(options.timeout), options.reputation,
                                               location_fallback=HttpClient(options.timeout, direct_location=True))),
            ("ipv6_local", check_local_ipv6),
            ("dns", check_dns), ("proxy", check_proxy), ("timezone", check_timezone),
            ("claude", lambda: check_claude(home)),
            ("claude_route", lambda: check_claude_routes(HttpClient(options.timeout),
                                                        HttpClient(options.timeout, direct_location=True))),
        ])
    if options.local:
        tasks.append(("local", lambda: check_local(home)))
    if progress:
        progress(0, len(tasks))
    output: dict[str, list[CheckResult]] = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(task): name for name, task in tasks}
        for completed, future in enumerate(as_completed(futures), 1):
            name = futures[future]
            try:
                output[name] = future.result()
            except Exception:
                # Never render exception messages: they may contain credentials or file contents.
                output[name] = [CheckResult(f"{name}.execution", name, f"{name} 检查", "unknown", "info", "检查未能完成，请核对运行环境")]
            if progress:
                progress(completed, len(tasks))
    checks = [check for name, _ in tasks for check in output.get(name, [])]
    if options.network:
        checks.extend(compare_timezone(checks))
    return Report(checks)
