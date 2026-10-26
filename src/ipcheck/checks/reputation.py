"""Query reputation for the observed Claude exits, never substitute a generic exit."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from ipcheck.checks.network import public_ip, reputation_checks
from ipcheck.core.models import CheckResult
from ipcheck.providers.http import HttpClient, ProviderError


def check_claude_reputation(checks: list[CheckResult], client: HttpClient, enabled: bool) -> list[CheckResult]:
    lookup = {check.id: check for check in checks}
    exits: dict[str, str] = {}
    for key in ('web', 'api'):
        observation = lookup.get(f'claude.{key}.egress')
        if observation is None or observation.status != 'completed':
            continue
        try:
            exits[key] = public_ip(observation.data.get('ip'))
        except ProviderError:
            continue
    cache: dict[str, list[CheckResult]] = {}
    if enabled:
        addresses = list(dict.fromkeys(exits.values()))
        with ThreadPoolExecutor(max_workers=2) as pool:
            cache = dict(zip(addresses, pool.map(lambda ip: reputation_checks(client, ip), addresses)))
    results: list[CheckResult] = []
    for key, name in (('web', '网页'), ('api', '官方 API')):
        address = exits.get(key)
        if enabled and address:
            for result in cache[address]:
                suffix = result.id.removeprefix('network.')
                results.append(replace(result, id=f'claude.{key}.{suffix}', group='claude',
                                       label=f'{name} IP 信誉' if suffix == 'reputation' else f'{name} IP 举报'))
        else:
            results.append(CheckResult(f'claude.{key}.reputation', 'claude', f'{name} IP 信誉',
                                       'unknown' if enabled else 'skipped', 'info',
                                       '未取得对应出口 IP' if enabled else '未查询 IP 信誉',
                                       data={'ip': address}, source='proxycheck.io / StopForumSpam'))
    return results
