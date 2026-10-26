import socket
import ssl
import unittest
import urllib.error
from unittest.mock import Mock, patch

from ipcheck.checks.claude_route import check_claude_routes, parse_trace
from ipcheck.checks.network import location_check
from ipcheck.checks.timezone import compare_timezone
from ipcheck.core.models import CheckResult, Report
from ipcheck.output.render import render_text
from ipcheck.providers.http import HttpClient, ProviderError


class TraceClient:
    def __init__(self, fail_host=None, fail_location=False):
        self.fail_host, self.fail_location = fail_host, fail_location
        self.location_queries = []

    def text(self, url):
        host = url.split('/')[2]
        if host == self.fail_host:
            raise ProviderError('查询超时')
        return f'h={host}\nip=2.2.2.2\nloc=TW\ncolo=SIN\n'

    def json(self, url):
        self.location_queries.append(url)
        if self.fail_location:
            raise ProviderError('TLS 握手失败或连接被提前关闭')
        return {'success': True, 'ip': url.rsplit('/', 1)[1], 'country': 'Fixture country',
                'timezone': {'id': 'Asia/Taipei'}, 'connection': {}}


class RouteTests(unittest.TestCase):
    def test_trace_validates_exact_host_public_ip_and_duplicate_fields(self):
        for text in ('<html>challenge</html>', 'h=claude.ai\nip=2.2.2.2',
                     'h=api.anthropic.com\nip=127.0.0.1',
                     'h=api.anthropic.com\nip=2.2.2.2\nip=1.1.1.1'):
            with self.subTest(text=text), self.assertRaises(ProviderError):
                parse_trace(text, 'api.anthropic.com')

    def test_matching_routes_reuse_location_and_ignore_cloudflare_server_colo(self):
        client = TraceClient()
        results = check_claude_routes(client)
        self.assertEqual(client.location_queries, ['https://ipwho.is/2.2.2.2'])
        self.assertEqual({result.id for result in results}, {'claude.api.egress', 'claude.web.egress'})
        for result in results:
            self.assertEqual(result.status, 'completed')
            self.assertEqual(result.data['timezone'], 'Asia/Taipei')
            # colo is retained as an observation but never used as the exit timezone.
            self.assertEqual(result.data['colo'], 'SIN')
            self.assertIsInstance(result.data['latency_ms'], int)

    def test_failed_api_does_not_borrow_web_or_general_exit(self):
        routes = check_claude_routes(TraceClient(fail_host='api.anthropic.com'))
        checks = [CheckResult('timezone.cli', 'system', '', 'completed', 'info', '', data={'timezone': 'Asia/Shanghai'}),
                  CheckResult('network.location', 'network', '', 'completed', 'info', '', data={'timezone': 'Asia/Kuala_Lumpur'})]
        results = {result.id: result for result in compare_timezone(checks + routes)}
        self.assertEqual(results['timezone.claude_api'].status, 'unknown')
        self.assertIsNone(results['timezone.claude_api'].data['timezone'])
        self.assertEqual(results['timezone.claude_web'].data['timezone'], 'Asia/Taipei')
        self.assertEqual(results['timezone.egress'].data['timezone'], 'Asia/Kuala_Lumpur')

    def test_geolocation_failure_keeps_observed_ip_but_timezone_unknown(self):
        routes = check_claude_routes(TraceClient(fail_location=True))
        self.assertTrue(all(result.status == 'completed' for result in routes))
        zones = {result.id: result for result in compare_timezone(routes)}
        self.assertEqual(zones['timezone.claude_api'].status, 'unknown')
        self.assertEqual(zones['timezone.claude_api'].data['ip'], '2.2.2.2')
        self.assertIsNone(zones['timezone.claude_api'].data['timezone'])

    def test_lookup_fallback_keeps_original_ip_and_records_lookup_path(self):
        primary, fallback = TraceClient(fail_location=True), TraceClient()
        result = location_check(primary, '1.1.1.1', fallback)
        self.assertEqual(primary.location_queries, ['https://ipwho.is/1.1.1.1'])
        self.assertEqual(fallback.location_queries, primary.location_queries)
        self.assertEqual(result.data['ip'], '1.1.1.1')
        self.assertEqual(result.data['lookup_route'], 'direct')
        self.assertIn('默认路径', result.evidence[0])
        mismatch = Mock()
        mismatch.json.return_value = {'success': True, 'ip': '2.2.2.2'}
        self.assertEqual(location_check(primary, '1.1.1.1', mismatch).status, 'unknown')

    def test_transport_limits_direct_fallback_and_anonymous_trace_urls(self):
        with patch('ipcheck.providers.http.urllib.request.build_opener', side_effect=AssertionError('must not connect')):
            for url in ('https://api.ipify.org?format=json', 'https://ipwho.is/', 'https://ipwho.is/127.0.0.1',
                        'https://api.anthropic.com/cdn-cgi/trace'):
                with self.subTest(url=url), self.assertRaises(ProviderError):
                    HttpClient(direct_location=True).text(url)
            for url in ('https://api.anthropic.com/v1/messages', 'https://claude.ai/cdn-cgi/trace?key=synthetic'):
                with self.subTest(url=url), self.assertRaises(ProviderError):
                    HttpClient().text(url)

    def test_connection_errors_are_classified_without_raw_exception_text(self):
        reasons = [(socket.gaierror(8, 'synthetic-private-error'), 'DNS'),
                   (ssl.SSLEOFError(8, 'synthetic-private-error'), 'TLS 握手'),
                   (ssl.SSLCertVerificationError(1, 'synthetic-private-error'), 'TLS 证书'),
                   (TimeoutError('synthetic-private-error'), '查询超时')]
        for reason, label in reasons:
            opener = Mock()
            opener.open.side_effect = urllib.error.URLError(reason)
            with self.subTest(reason=type(reason).__name__), patch('ipcheck.providers.http.urllib.request.build_opener', return_value=opener):
                with self.assertRaises(ProviderError) as raised:
                    HttpClient().text('https://api.ipify.org?format=json')
                self.assertIn(label, str(raised.exception))
                self.assertNotIn('synthetic-private-error', str(raised.exception))

    def test_timezone_section_separates_general_and_claude_routes(self):
        routes = check_claude_routes(TraceClient())
        baseline = [CheckResult('timezone.cli', 'system', 'CLI 时区', 'completed', 'info', 'Asia/Shanghai', data={'timezone': 'Asia/Shanghai'}),
                    CheckResult('network.location', 'network', '', 'completed', 'info', '', data={'timezone': 'Asia/Kuala_Lumpur'})]
        comparisons = compare_timezone(baseline + routes)
        zones = {result.id: result for result in comparisons}
        self.assertTrue(zones['timezone.advice'].data['comparisons']['api']['same_offset'])
        self.assertFalse(zones['timezone.advice'].data['comparisons']['api']['same_iana'])
        text = render_text(Report(baseline + routes + comparisons), details=True)
        for value in ('检测出口时区', 'Claude API 时区', 'Claude 网页时区', 'Asia/Kuala_Lumpur', 'Asia/Taipei', 'UTC+08:00'):
            self.assertIn(value, text)
