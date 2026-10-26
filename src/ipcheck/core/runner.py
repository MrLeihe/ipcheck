from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from ipcheck.checks.claude import check_claude
from ipcheck.checks.claude_route import check_claude_routes
from ipcheck.checks.cloudflare import check_cloudflare
from ipcheck.checks.dns import check_dns
from ipcheck.checks.direct import check_direct_ip
from ipcheck.checks.local import check_local
from ipcheck.checks.locations import LocationClient, enrich_locations
from ipcheck.checks.ipv6 import check_local_ipv6
from ipcheck.checks.network import check_network
from ipcheck.checks.proxy import check_proxy
from ipcheck.checks.region import check_region
from ipcheck.checks.reputation import check_claude_reputation
from ipcheck.checks.route import compare_routes
from ipcheck.checks.timezone import check_timezone, compare_timezone
from ipcheck.core.models import CheckResult, Report
from ipcheck.providers.http import HttpClient

Progress = Callable[[int, int], None]
Activity = Callable[[tuple[str, ...]], None]


@dataclass(frozen=True)
class Options:
    network: bool = True
    local: bool = False
    reputation: bool = True
    timeout: float = 4


def run_checks(options: Options, progress: Progress | None = None, home: Path | None = None, *, activity: Activity | None = None) -> Report:
    client = LocationClient(options.timeout)
    fallback = LocationClient(options.timeout, direct_location=True)
    tasks: list[tuple[str, Callable[[], list[CheckResult]]]] = []
    if options.network:
        tasks.extend([
            ("network", lambda: check_network(client, False, location_fallback=fallback)),
            ("direct_ip", lambda: check_direct_ip(HttpClient(options.timeout, direct_ip=True))),
            ("ipv6_local", check_local_ipv6),
            ("dns", check_dns), ("proxy", check_proxy), ("timezone", check_timezone),
            ("claude", lambda: check_claude(home)),
            ("claude_route", lambda: check_claude_routes(client, fallback)),
            ("cloudflare", lambda: check_cloudflare(client)),
        ])
    if options.local:
        tasks.append(("local", lambda: check_local(home)))
    total = len(tasks) + (3 if options.network else 0)
    active: set[str] = set()
    activity_lock = Lock()

    def notify(name: str, started: bool) -> None:
        with activity_lock:
            if started:
                active.add(name)
            else:
                active.discard(name)
            if activity:
                activity(tuple(sorted(active)))

    def tracked(name: str, task: Callable[[], list[CheckResult]]) -> list[CheckResult]:
        notify(name, True)
        try:
            return task()
        finally:
            notify(name, False)

    if progress:
        progress(0, total)
    output: dict[str, list[CheckResult]] = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(tracked, name, task): name for name, task in tasks}
        for completed, future in enumerate(as_completed(futures), 1):
            name = futures[future]
            try:
                output[name] = future.result()
            except Exception:
                # Never render exception messages: they may contain credentials or file contents.
                output[name] = [CheckResult(f"{name}.execution", name, f"{name} 检查", "unknown", "info", "检查未能完成，请核对运行环境")]
            if progress:
                progress(completed, total)
    checks = [check for name, _ in tasks for check in output.get(name, [])]
    if options.network:
        # Generic detector exits may follow a different Clash rule from Claude.
        checks = [check for check in checks if check.id != "network.reputation"]
        notify("locations", True)
        try:
            checks = enrich_locations(checks, client, fallback)
        finally:
            notify("locations", False)
        if progress:
            progress(len(tasks) + 1, total)
        notify("reputation", True)
        try:
            checks.extend(check_claude_reputation(checks, HttpClient(options.timeout), options.reputation))
        except Exception:
            checks.append(CheckResult("claude.reputation.execution", "claude", "Claude IP 信誉", "unknown", "info", "IP 信誉检测失败"))
        finally:
            notify("reputation", False)
        if progress:
            progress(len(tasks) + 2, total)
        notify("assessment", True)
        try:
            checks.extend(check_region(checks))
            checks.extend(compare_routes(checks))
            checks.extend(compare_timezone(checks))
            report = Report(checks, network_enabled=True)
        finally:
            notify("assessment", False)
        if progress:
            progress(total, total)
        return report
    return Report(checks, network_enabled=False)
