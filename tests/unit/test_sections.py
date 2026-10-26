import re
import unittest

from ipcheck.checks.claude_route import check_claude_routes
from ipcheck.core.models import CheckResult, Report
from ipcheck.output.render import render_text
from tests.unit.test_assessment import baseline, changed
from tests.unit.test_render import cell_width
from tests.unit.test_routes import TraceClient


def observations():
    checks = baseline()
    for key in ('web', 'api'):
        checks = changed(checks, f'claude.{key}.egress', data={
            'ip': '1.1.1.1', 'timezone': 'Asia/Taipei', 'latency_ms': 123,
            'location_status': 'completed', 'location_country': 'Fixture country',
            'location_region': 'Fixture region', 'location_city': '示例城市',
            'location_isp': 'Fixture ISP', 'location_org': 'Fixture Org', 'location_asn': 64500})
        checks = changed(checks, f'claude.{key}.reputation', data={'ip': '1.1.1.1', 'classification': '疑似住宅 IP',
                                                                   'score': 5, 'proxy': False})
    checks += [
        CheckResult('network.egress', 'network', '', 'completed', 'info', '', data={'observations': [
            {'ip': '203.0.113.10', 'service': 'fixture', 'status': 'completed'}]}),
        CheckResult('ipv6.configuration', 'network', '本机 IPv6 配置', 'completed', 'info', '已关闭 · 示例服务 (en0)', data={'mode': 'off'}),
        CheckResult('dns.configuration', 'network', 'DNS', 'completed', 'info', '', data={'servers': ['192.0.2.53']}),
        CheckResult('dns.active', 'network', '主动 DNS 验证', 'skipped', 'info', '未配置'),
        CheckResult('proxy.environment', 'system', '', 'completed', 'info', '未设置', data={'names': []}),
        CheckResult('proxy.system', 'system', '', 'completed', 'info', '已开启', data={'kinds': ['HTTP', 'HTTPS']}),
        CheckResult('proxy.tunnel', 'system', '', 'completed', 'info', '未开启', data={'state': 'off'}),
        CheckResult('timezone.cli', 'system', 'CLI 时区', 'completed', 'info', 'Asia/Taipei', data={'timezone': 'Asia/Taipei', 'offset_minutes': 480}),
    ]
    return checks


class SectionTests(unittest.TestCase):
    def test_default_layout_puts_conclusion_first_and_advice_last(self):
        text = render_text(Report(observations()))
        labels = ('综合结论', '需要确认', 'Claude 网页/API 出口', '国家 / 地区', '城市', '运营商',
                  'IP 归属', 'ASN', '支持地区', '出口时区', '响应耗时', 'IP 类型', 'IP 信誉评分',
                  '公开举报记录', '代理出口 IP', '环境变量代理', '系统代理', 'TUN / VPN', '本地 DNS',
                  '本机 IPv6 配置', '系统时区', 'CLI 时区', '时区一致性', 'Claude API 配置', '检测建议')
        for label in labels:
            self.assertIn(label, text)
        self.assertLess(text.index('综合结论'), text.index('Claude 网页/API 出口'))
        self.assertGreater(text.index('检测建议'), text.index('Claude API 配置'))
        self.assertNotIn('主动 DNS 验证', text)
        self.assertNotIn('本机真实', text)
        self.assertNotIn('Anthropic 147', text)
        self.assertEqual(text.count('1.1.1.1'), 1)
        self.assertEqual(text.count('IP 信誉评分'), 1)
        self.assertIn('未收录（StopForumSpam）', text)
        self.assertIn('123 ms', text)

    def test_datacenter_type_is_not_colored_as_a_warning(self):
        checks = changed(observations(), 'claude.web.reputation',
                         data={'ip': '1.1.1.1', 'classification': '疑似机房 IP', 'score': 5, 'proxy': False})
        text = render_text(Report(checks), color=True)
        line = next(item for item in text.splitlines() if 'IP 类型' in item)
        self.assertIn('疑似机房 IP', line)
        self.assertNotIn('\x1b[33m', line)

    def test_split_routes_show_separate_geography_and_reputation_without_borrowing_data(self):
        checks = changed(observations(), 'claude.api.egress', data={'ip': '8.8.8.8', 'country_code': 'JP', 'location_status': 'unknown'})
        checks = changed(checks, 'claude.api.reputation', data={'ip': '8.8.8.8', 'classification': '疑似机房 IP', 'score': 72})
        checks = changed(checks, 'claude.api.abuse', data={'ip': '8.8.8.8', 'listed': True})
        text = render_text(Report(checks))
        self.assertIn('Claude 网页出口', text)
        self.assertIn('官方 API 出口', text)
        self.assertIn('网页 IP 信誉评分', text)
        self.assertIn('API IP 信誉评分', text)
        api_block = text[text.index('官方 API 出口'):text.index('代理出口 IP')]
        self.assertNotIn('Fixture ISP', api_block)
        self.assertIn('未取得归属数据', api_block)
        self.assertIn('72/100 · 高风险', text)

    def test_completed_egress_warning_is_visible_in_the_compact_view(self):
        checks = [item for item in observations() if item.id != 'network.egress']
        checks.append(CheckResult('network.egress', 'network', '', 'completed', 'warning',
                                  '不同服务观测到了不同出口',
                                  data={'observations': [{'ip': '203.0.113.10'}, {'ip': '203.0.113.11'}]}))
        text = render_text(Report(checks))
        self.assertIn('代理出口校验', text)
        self.assertIn('不同服务观测到了不同出口', text)

    def test_proxy_flags_survive_a_missing_score(self):
        checks = changed(observations(), 'claude.web.reputation', status='unknown', summary='评分未取得',
                         data={'ip': '1.1.1.1', 'classification': '疑似机房 IP', 'score': None,
                               'proxy': True, 'vpn': True, 'tor': False, 'crawler': None})
        text = render_text(Report(checks))
        self.assertIn('已标记代理', text)
        self.assertIn('VPN：是 · Tor：否', text)

    def test_failed_queries_and_partial_types_never_become_off_or_low_risk(self):
        checks = changed(observations(), 'claude.web.reputation', status='unknown', summary='查询超时',
                         data={'ip': '1.1.1.1', 'classification': '疑似住宅 IP', 'score': None})
        checks = changed(checks, 'proxy.tunnel', status='unknown', summary='检测失败', data={'state': 'unknown'})
        text = render_text(Report(checks))
        self.assertIn('疑似住宅 IP', text)
        self.assertIn('查询超时', text)
        tunnel_line = next(line for line in text.splitlines() if 'TUN / VPN' in line)
        self.assertIn('检测失败', tunnel_line)
        self.assertNotIn('未开启', tunnel_line)
        self.assertIn('关键信息不完整', text)

    def test_all_section_borders_and_colors_fit_cjk_widths(self):
        for width in (24, 40, 56, 80, 100):
            for color in (False, True):
                text = render_text(Report(observations()), width=width, color=color)
                plain = re.sub(r'\x1b\[[0-9;]+m', '', text)
                for line in plain.splitlines():
                    self.assertLessEqual(cell_width(line), width)
                    if line.lstrip().startswith(('╔', '╠', '╚', '║')):
                        self.assertEqual(cell_width(line), min(width, 92))

    def test_claude_route_keeps_location_fields_from_its_own_lookup(self):
        class Client(TraceClient):
            def json(self, url):
                raw = super().json(url)
                raw.update({'region': 'Fixture region', 'city': '示例城市',
                            'connection': {'isp': 'Fixture ISP', 'org': 'Fixture Org', 'asn': 64500}})
                return raw
        client = Client()
        routes = check_claude_routes(client)
        self.assertEqual(len(client.location_queries), 1)
        for route in routes:
            self.assertEqual(route.data['location_isp'], 'Fixture ISP')
            self.assertEqual(route.data['location_asn'], 64500)
