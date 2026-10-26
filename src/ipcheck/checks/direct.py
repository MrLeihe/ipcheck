"""Public IPv4 echo with explicit HTTP proxy bypass; never bypass system tunnels."""

import re
from concurrent.futures import ThreadPoolExecutor

from ipcheck.checks.network import public_ip
from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue
from ipcheck.providers.http import HttpClient, ProviderError

SOURCES = (("IPW", "https://4.ipw.cn/"), ("IPIP", "https://myip.ipip.net/"))


def _observe(client: HttpClient, source: tuple[str, str]) -> dict[str, JsonValue]:
    name, url = source
    try:
        text = client.text(url).strip()
        if name == 'IPIP':
            match = re.search(r'当前\s*IP\s*[：:]\s*([0-9.]+)', text)
            text = match[1] if match else ''
        return {'service': name, 'status': 'completed', 'ip': public_ip(text, 4)}
    except ProviderError as exc:
        return {'service': name, 'status': 'unknown', 'reason': str(exc)}


def check_direct_ip(client: HttpClient) -> list[CheckResult]:
    with ThreadPoolExecutor(max_workers=2) as pool:
        observations = list(pool.map(lambda source: _observe(client, source), SOURCES))
    addresses = list(dict.fromkeys(str(item['ip']) for item in observations if item.get('ip')))
    successful = sum(item['status'] == 'completed' for item in observations)
    if len(addresses) > 1:
        summary = '直连来源返回不同 IP，需核对出口'
    elif addresses:
        summary = addresses[0] + ('（单源结果）' if successful < len(SOURCES) else '')
    else:
        reasons = list(dict.fromkeys(str(item.get('reason') or '查询失败') for item in observations))
        summary = '查询失败：' + '；'.join(reasons)
    return [CheckResult('network.direct', 'network', '本机直连公网 IP',
                        'completed' if successful == len(SOURCES) else 'unknown',
                        'warning' if len(addresses) > 1 else 'info', summary,
                        ('明确绕过系统与环境 HTTP/HTTPS/SOCKS 代理，不修改系统设置。',
                         '遵循操作系统路由，不能绕过 TUN、VPN、透明网关或上游代理。',
                         '结果是该直连请求的公网出口，不能保证是运营商原始公网 IP；不代表局域网地址。',
                         '两项服务都会看到此次直连请求的公网来源 IP；失败不使用代理出口代替。'),
                        {'observations': observations, 'addresses': addresses, 'successful_sources': successful,
                         'total_sources': len(SOURCES), 'proxy_bypassed': True, 'tunnel_bypassed': False},
                        'IPW / IPIP（禁用 HTTP 代理）')]
