"""Per-run IP geography reuse and explicit per-address results."""

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from threading import Lock

from ipcheck.checks.network import location_check
from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue
from ipcheck.providers.http import HttpClient


class LocationClient(HttpClient):
    def __init__(self, timeout: float, *, direct_location: bool = False):
        super().__init__(timeout, direct_location=direct_location)
        self.cache: dict[str, Future[dict[str, JsonValue]]] = {}
        self.lock = Lock()

    def json(self, url: str) -> dict[str, JsonValue]:
        if not url.startswith("https://ipwho.is/"):
            return super().json(url)
        with self.lock:
            owner = url not in self.cache
            if owner:
                self.cache[url] = Future()
            future = self.cache[url]
        if owner:
            try:
                future.set_result(super().json(url))
            except BaseException as exc:
                future.set_exception(exc)
        return future.result()


def enrich_locations(checks: list[CheckResult], client: HttpClient, fallback: HttpClient) -> list[CheckResult]:
    targets = {"network.direct", "network.egress", "network.ipv6", "network.cloudflare"}
    addresses: dict[str, list[str]] = {}
    for check in checks:
        if check.id not in targets:
            continue
        found = list(check.data.get("addresses") or [])
        observations = check.data.get("observations")
        if isinstance(observations, list):
            found.extend(item.get("ip") for item in observations if isinstance(item, dict))
        found.append(check.data.get("ip"))
        addresses[check.id] = list(dict.fromkeys(ip for ip in found if isinstance(ip, str)))
    unique = list(dict.fromkeys(ip for group in addresses.values() for ip in group))
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(zip(unique, pool.map(lambda ip: location_check(client, ip, fallback), unique)))
    output = []
    for check in checks:
        if check.id not in addresses:
            output.append(check)
            continue
        locations: dict[str, JsonValue] = {}
        for ip in addresses[check.id]:
            result = results[ip]
            locations[ip] = {**result.data, "status": result.status, "summary": result.summary,
                             "evidence": list(result.evidence)}
        output.append(replace(check, data={**check.data, "locations": locations}))
    return output
