import unittest
from unittest.mock import patch

from ipcheck.checks.network import IPV6_SOURCES, check_network, observe_ip
from ipcheck.core.models import Report
from ipcheck.output.render import render_json, render_text
from ipcheck.providers.http import HttpClient, ProviderError

V6 = '2606:4700::1111'
OTHER_V6 = '2001:4860::8888'


class ProbeClient:
    def __init__(self, primary=V6, secondary=V6):
        self.primary = primary
        self.secondary = secondary
        self.calls = []

    def response(self, name):
        value = getattr(self, name)
        if isinstance(value, ProviderError):
            raise value
        return value

    def json(self, url):
        self.calls.append(url)
        if 'api6.ipify.org' in url:
            return {'ip': self.response('primary')}
        if 'ipwho.is' in url:
            return {'success': True, 'ip': '1.1.1.1', 'connection': {}}
        return {'ip': '1.1.1.1'}

    def text(self, url):
        self.calls.append(url)
        return self.response('secondary') if 'icanhazip' in url else '1.1.1.1'


def check(client):
    return next(result for result in check_network(client) if result.id == 'network.ipv6')


class IPv6ProbeTests(unittest.TestCase):
    def test_both_sources_confirm_same_ipv6_and_remain_in_export(self):
        client = ProbeClient()
        result = check(client)
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.data['ip'], V6)
        self.assertTrue(result.data['same_ip'])
        self.assertEqual(result.data['successful_sources'], 2)
        for _, url in IPV6_SOURCES:
            self.assertIn(url, client.calls)
        self.assertIn('两个来源返回相同 IPv6', render_text(Report([result])))
        self.assertIn('icanhazip IPv6', render_json(Report([result])))
        self.assertEqual(result.data['route'], 'system_or_process_proxy')

    def test_one_success_proves_observed_exit_but_retains_other_failure(self):
        for primary, secondary in ((ProviderError('查询超时'), V6), (V6, ProviderError('DNS 无法解析查询服务域名'))):
            with self.subTest(primary=primary):
                result = check(ProbeClient(primary, secondary))
                self.assertEqual(result.status, 'completed')
                self.assertEqual(result.data['ip'], V6)
                self.assertIsNone(result.data['same_ip'])
                text = render_text(Report([result]))
                self.assertIn('1/2 个来源返回 IPv6', text)
                self.assertIn('查询超时' if isinstance(primary, ProviderError) else 'DNS 无法解析', text)
                self.assertEqual(len(result.data['observations']), 2)

    def test_all_timeouts_show_actual_cause_instead_of_generic_unknown(self):
        result = check(ProbeClient(ProviderError('查询超时'), ProviderError('查询超时')))
        self.assertEqual(result.status, 'unknown')
        self.assertIn('探测超时', result.summary)
        self.assertIn('2 个来源', result.summary)
        text = render_text(Report([result]))
        for value in ('未验证', '探测超时', '当前请求路径'):
            self.assertIn(value, text)
        self.assertNotIn('已关闭', text)
        self.assertNotIn('已禁用', text)

    def test_dns_and_tls_errors_remain_distinguishable(self):
        result = check(ProbeClient(ProviderError('DNS 无法解析查询服务域名'), ProviderError('DNS 无法解析查询服务域名')))
        self.assertIn('DNS 解析失败', result.summary)
        result = check(ProbeClient(ProviderError('查询超时'), ProviderError('TLS 证书验证失败')))
        text = render_text(Report([result]), width=92)
        self.assertIn('ipify IPv6', result.summary)
        self.assertIn('icanhazip IPv6', result.summary)
        self.assertIn('TLS 证书验证失败', text)
        self.assertEqual(result.status, 'unknown')

    def test_different_valid_addresses_are_preserved_without_claiming_a_leak(self):
        result = check(ProbeClient(V6, OTHER_V6))
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.severity, 'warning')
        self.assertNotIn('ip', result.data)
        self.assertFalse(result.data['same_ip'])
        text = render_text(Report([result]))
        for address in (V6, OTHER_V6):
            self.assertIn(address, text)
        self.assertIn('域名分流', text)
        self.assertNotIn('IPv6 泄露', text)

    def test_ipv4_private_and_malformed_responses_cannot_be_success(self):
        for response in ('1.1.1.1', 'fd00::1', 'fe80::1', '::1', '', '<html>challenge</html>'):
            for name, url in IPV6_SOURCES:
                with self.subTest(response=response, source=name):
                    result = observe_ip(ProbeClient(response, response), name, url, 6)
                    self.assertEqual(result['status'], 'unknown')
                    self.assertNotIn('ip', result)

    def test_backup_transport_is_restricted_and_never_used_as_location_direct_fallback(self):
        with patch('ipcheck.providers.http.urllib.request.build_opener', side_effect=AssertionError('must not connect')):
            for url in ('http://ipv6.icanhazip.com/', 'https://ipv6.icanhazip.com/other',
                        'https://ipv6.icanhazip.com/?token=synthetic', 'https://ipv6.icanhazip.com/#fragment'):
                with self.subTest(url=url), self.assertRaises(ProviderError):
                    HttpClient().text(url)
            with self.assertRaises(ProviderError):
                HttpClient(direct_location=True).text('https://ipv6.icanhazip.com/')
