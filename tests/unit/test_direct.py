import unittest
import urllib.request
from unittest.mock import MagicMock, Mock, patch

from ipcheck.checks.direct import check_direct_ip
from ipcheck.core.models import CheckResult, Report
from ipcheck.core.runner import Options, run_checks
from ipcheck.output.render import render_text
from ipcheck.providers.http import DIRECT_IP_URLS, HttpClient, ProviderError, SafeRedirect


class Client:
    def __init__(self, values):
        self.values = values

    def text(self, url):
        value = self.values[0 if 'ipw.cn' in url else 1]
        if isinstance(value, Exception):
            raise value
        return value


class DirectIPTests(unittest.TestCase):
    def test_matching_sources_display_direct_ip_separately_from_proxy_exit(self):
        result = check_direct_ip(Client(['1.1.1.1', '当前 IP：1.1.1.1 来自于：示例地区']))[0]
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.data['addresses'], ['1.1.1.1'])
        proxy = CheckResult('network.egress', 'network', '', 'completed', 'info', '', data={'observations': [{'ip': '8.8.8.8'}]})
        text = render_text(Report([result, proxy]))
        self.assertLess(text.index('本机直连'), text.index('代理出口'))
        self.assertIn('1.1.1.1', text)
        self.assertIn('8.8.8.8', text)
        self.assertFalse(result.data['tunnel_bypassed'])

    def test_partial_conflicting_failed_and_invalid_results_are_not_substituted(self):
        partial = check_direct_ip(Client(['1.1.1.1', ProviderError('查询超时')]))[0]
        self.assertEqual(partial.status, 'unknown')
        text = render_text(Report([partial]))
        self.assertIn('1.1.1.1（归属未知）', text)
        self.assertIn('单源结果，未完成交叉验证', text)
        self.assertIn('查询超时', render_text(Report([partial]), details=True))
        different = check_direct_ip(Client(['1.1.1.1', '当前 IP: 8.8.8.8']))[0]
        self.assertEqual(different.severity, 'warning')
        self.assertEqual(len(different.data['addresses']), 2)
        for values in ([ProviderError('查询超时'), ProviderError('查询超时')],
                       ['127.0.0.1', '当前 IP：192.168.1.2'], ['::1', '<html>1.1.1.1</html>']):
            result = check_direct_ip(Client(values))[0]
            self.assertEqual(result.status, 'unknown')
            self.assertEqual(result.data['addresses'], [])
            self.assertIn('查询失败', result.summary)

    def test_tunnel_scope_is_explicit_and_no_claim_of_isp_original_ip(self):
        result = check_direct_ip(Client(['1.1.1.1', '当前 IP: 1.1.1.1']))[0]
        for state in ('on', 'unknown', 'off'):
            tunnel = CheckResult('proxy.tunnel', 'system', 'TUN / VPN', 'completed', 'info', state, data={'state': state})
            text = render_text(Report([result, tunnel]))
            self.assertEqual('仍可能经过 TUN/VPN' in text, state != 'off')
            self.assertNotIn('本机真实 IP', text)

    def test_direct_transport_uses_empty_proxy_handler_and_fixed_targets(self):
        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.read.return_value = b'1.1.1.1'
        with patch.dict('os.environ', {'HTTPS_PROXY': 'http://synthetic.invalid:7890'}), \
             patch('ipcheck.providers.http.urllib.request.build_opener', return_value=opener) as build:
            self.assertEqual(HttpClient(direct_ip=True).text('https://4.ipw.cn/'), '1.1.1.1')
        handlers = build.call_args.args
        proxy = next(handler for handler in handlers if isinstance(handler, urllib.request.ProxyHandler))
        self.assertEqual(proxy.proxies, {})
        with patch('ipcheck.providers.http.urllib.request.build_opener', side_effect=AssertionError('must not connect')):
            for url in ('https://api.anthropic.com/cdn-cgi/trace', 'https://4.ipw.cn/?token=synthetic',
                        'https://ipwho.is/1.1.1.1', 'https://4.ipw.cn/other', 'http://4.ipw.cn/'):
                with self.assertRaises(ProviderError):
                    HttpClient(direct_ip=True).text(url)
        with self.assertRaises(ProviderError):
            SafeRedirect(DIRECT_IP_URLS).redirect_request(Mock(), None, 302, '', {}, 'https://4.ipw.cn/other')

    def test_local_only_never_queries_direct_services(self):
        with patch('ipcheck.core.runner.check_direct_ip', side_effect=AssertionError('must not connect')), \
             patch('ipcheck.core.runner.check_local', return_value=[]):
            run_checks(Options(network=False, local=True))
