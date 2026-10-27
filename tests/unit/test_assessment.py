import unittest
from dataclasses import replace
from unittest.mock import patch

from ipcheck.checks.network import reputation_checks
from ipcheck.checks.reputation import check_claude_reputation
from ipcheck.checks.timezone import compare_timezone
from ipcheck.core.models import CheckResult, Report
from ipcheck.core.runner import Options, run_checks
from ipcheck.core.summary import summarize
from ipcheck.output.render import render_text
from ipcheck.providers.http import ProviderError


def check(key, data=None, status='completed', severity='info'):
    return CheckResult(key, 'claude' if key.startswith('claude.') else 'system', key, status, severity, 'synthetic', data=data or {})


def baseline():
    results = [check('timezone.system', {'timezone': 'Asia/Taipei'}), check('claude.endpoint'),
               check('claude.region', {
                   'routes': [{'route': 'web', 'label': '网页', 'country_code': 'US', 'supported': True},
                              {'route': 'api', 'label': '官方 API', 'country_code': 'US', 'supported': True}],
                   'unsupported': False,
                   'policy': {'policy': 'Anthropic Supported Regions Policy', 'effective': '2026-11-12'}}),
               check('route.comparison', {'claude_consistent': True, 'claude_multi': False})]
    for key in ('web', 'api'):
        results += [check(f'claude.{key}.egress', {'ip': '1.1.1.1', 'timezone': 'Asia/Taipei'}),
                    check(f'claude.{key}.reputation', {'ip': '1.1.1.1', 'classification': '疑似住宅 IP', 'score': 5}),
                    check(f'claude.{key}.abuse', {'ip': '1.1.1.1', 'listed': False})]
    return results + compare_timezone(results)


def changed(checks, key, **kwargs):
    return [replace(item, **kwargs) if item.id == key else item for item in checks]


class Client:
    def __init__(self, kind='Residential', score=5, fail=False):
        self.kind, self.score, self.fail = kind, score, fail
        self.urls = []

    def json(self, url):
        self.urls.append(url)
        if self.fail:
            raise ProviderError('查询超时')
        if 'proxycheck' in url:
            return {'status': 'ok', '1.1.1.1': {'risk': self.score, 'type': self.kind}}
        return {'success': 1, 'ip': {'appears': 0}}


class AssessmentTests(unittest.TestCase):
    def test_clear_requires_key_evidence_and_never_claims_account_safety(self):
        summary = summarize(baseline())
        self.assertEqual(summary['level'], 'clear')
        self.assertIn('未见明显异常', summary['message'])
        for label in ('低风险', '账号安全', '封号概率'):
            self.assertNotIn(label, summary['message'])
        self.assertEqual(summary['advice'], [])

    def test_missing_disabled_or_mismatched_reputation_cannot_be_clear(self):
        for kwargs in ({'status': 'unknown'}, {'status': 'skipped'},
                       {'data': {'ip': '8.8.8.8', 'classification': '疑似住宅 IP', 'score': 5}},
                       {'data': {'ip': '1.1.1.1', 'classification': 'IP 类型未知', 'score': 5}},
                       {'data': {'ip': '1.1.1.1', 'classification': '疑似住宅 IP', 'score': None}}):
            with self.subTest(kwargs=kwargs):
                summary = summarize(changed(baseline(), 'claude.web.reputation', **kwargs))
                self.assertEqual(summary['level'], 'incomplete')

    def test_high_score_and_abuse_give_actions_without_a_claude_risk_probability(self):
        checks = changed(baseline(), 'claude.web.reputation', severity='warning',
                         data={'ip': '1.1.1.1', 'classification': '疑似机房 IP', 'score': 85})
        summary = summarize(checks)
        self.assertIn('信誉风险较高', summary['message'])
        text = ' '.join(item['text'] for item in summary['advice'])
        self.assertIn('更换', text)
        self.assertIn('proxycheck.io', text)
        checks = changed(baseline(), 'claude.web.abuse', severity='warning', data={'ip': '1.1.1.1', 'listed': True})
        self.assertIn('举报', ' '.join(item['text'] for item in summarize(checks)['advice']))

    def test_timezone_difference_is_consistency_advice_not_account_risk(self):
        checks = [item for item in baseline() if not item.id.startswith('timezone.')]
        checks.append(check('timezone.system', {'timezone': 'Asia/Shanghai'}))
        checks += compare_timezone(checks)
        summary = summarize(checks)
        self.assertEqual(summary['level'], 'attention')
        text = ' '.join(item['text'] for item in summary['advice'])
        self.assertIn('Asia/Taipei', text)
        self.assertIn('UTC 偏移相同', text)
        self.assertNotIn('高风险', summary['message'])

    def test_third_party_endpoint_cannot_use_official_probe_as_its_evidence(self):
        checks = changed(baseline(), 'claude.endpoint', data={'endpoints': [{'kind': 'custom', 'host': 'relay.example'}]})
        summary = summarize(checks)
        self.assertEqual(summary['level'], 'incomplete')
        self.assertIn('不代表该中转', ' '.join(item['text'] for item in summary['advice']))

    def test_auxiliary_failures_do_not_change_risk_and_skipped_items_stay_in_details(self):
        noise = [replace(check(key, status='skipped' if key == 'dns.active' else 'unknown'), source=key) for key in (
            'dns.active', 'dns.configuration', 'network.ipv6', 'network.cloudflare', 'proxy.environment')]
        report = Report(baseline() + noise)
        summary = report.to_dict()['summary']
        self.assertEqual(summary['level'], 'clear')
        compact, detailed = render_text(report), render_text(report, details=True)
        for item in noise:
            self.assertNotIn(item.id, compact)
            self.assertIn(item.id, detailed)
        self.assertIn('本地 DNS', compact)
        self.assertIn('环境变量代理', compact)
        self.assertNotIn('主动 DNS 验证', compact)
        self.assertNotIn('IPv6 出口探测', compact)
        self.assertNotIn('检测概况', compact)
        self.assertNotIn('检测提示', compact)
        self.assertIn('综合结论', compact)
        self.assertIn('检测建议', compact)
        self.assertNotIn('claude.api.reputation', summary['focus_ids'])

    def test_route_split_and_unsupported_region_are_high_priority_advice(self):
        checks = changed(baseline(), 'route.comparison', data={'claude_consistent': False, 'claude_multi': False})
        checks = changed(checks, 'claude.region', data={'unsupported': True, 'routes': [
            {'route': 'web', 'label': '网页', 'country_code': 'HK', 'supported': False}]})
        summary = summarize(checks)
        self.assertEqual(summary['level'], 'attention')
        ids = {item['id'] for item in summary['advice']}
        self.assertIn('route.split', ids)
        self.assertIn('region.unsupported', ids)
        self.assertEqual(summary['advice'][0]['priority'], 'high')
        for item in summary['advice']:
            self.assertEqual(set(item), {'id', 'priority', 'category', 'text', 'check_ids', 'action'})

    def test_disabled_reputation_gives_one_explicit_advice_not_per_route_noise(self):
        checks = [item for item in baseline() if not item.id.endswith('.abuse')]
        checks = [replace(item, status='skipped', data={}) if item.id.endswith('.reputation') else item
                  for item in checks]
        summary = summarize(checks)
        ids = [item['id'] for item in summary['advice']]
        self.assertEqual(ids.count('reputation.disabled'), 1)
        self.assertNotIn('claude.web.abuse', str(summary['advice']))
        self.assertEqual(summary['level'], 'incomplete')

    def test_local_relay_is_incomplete_without_a_plaintext_warning(self):
        checks = changed(baseline(), 'claude.endpoint', data={
            'endpoints': [{'source': '当前进程环境变量', 'kind': 'local', 'host': '127.0.0.1'}]})
        summary = summarize(checks)
        self.assertEqual(summary['level'], 'incomplete')
        ids = {item['id'] for item in summary['advice']}
        self.assertIn('endpoint.local', ids)
        self.assertNotIn('endpoint.invalid', ids)

    def test_auxiliary_network_warning_changes_level_and_gets_advice(self):
        checks = baseline() + [check('network.egress', {
            'observations': [{'ip': '1.1.1.1'}, {'ip': '2.2.2.2'}]}, severity='warning')]
        summary = summarize(checks)
        self.assertEqual(summary['level'], 'attention')
        self.assertTrue(summary['issue_ids'])
        ids = {check_id for item in summary['advice'] for check_id in item['check_ids']}
        self.assertIn('network.egress', ids)

    def test_any_completed_warning_prevents_a_clear_level(self):
        checks = baseline() + [check('local.identity', {'different_account_backups': 1}, severity='warning')]
        summary = summarize(checks)
        self.assertEqual(summary['level'], 'attention')
        self.assertTrue(summary['issue_ids'])

    def test_partial_region_evidence_is_incomplete(self):
        checks = changed(baseline(), 'claude.region', data={'unsupported': False, 'routes': [
            {'route': 'web', 'label': '网页', 'country_code': 'XX', 'supported': None},
            {'route': 'api', 'label': '官方 API', 'country_code': 'US', 'supported': True}]})
        summary = summarize(checks)
        self.assertEqual(summary['level'], 'incomplete')
        self.assertIn('region.partial', {item['id'] for item in summary['advice']})

    def test_missing_region_evidence_is_incomplete(self):
        checks = [item for item in baseline() if item.id != 'claude.region']
        summary = summarize(checks)
        self.assertEqual(summary['level'], 'incomplete')
        self.assertIn('region.missing', {item['id'] for item in summary['advice']})

    def test_local_only_run_is_not_reported_as_incomplete(self):
        summary = summarize([check('local.shell')], network_expected=False)
        self.assertEqual(summary['level'], 'clear')
        self.assertIn('仅本地配置摘要', summary['message'])

    def test_summary_also_redacts_values_from_advice(self):
        checks = baseline()
        checks = changed(checks, 'timezone.advice', data={'same_iana': False, 'same_offset': False,
                         'exit_timezone': 'Bearer synthetic-private-token'})
        self.assertNotIn('synthetic-private-token', str(Report(checks).to_dict()))

    def test_type_and_score_are_independent_and_business_is_not_residential(self):
        for kind, label in (('Residential', '疑似住宅 IP'), ('Hosting', '疑似机房 IP'),
                            ('Business', '商业网络（住宅属性未知）'), ('new-type', 'IP 类型未知')):
            result = reputation_checks(Client(kind=kind), '1.1.1.1')[0]
            self.assertEqual(result.data['classification'], label)
        result = reputation_checks(Client(score=None), '1.1.1.1')[0]
        self.assertEqual(result.status, 'unknown')
        self.assertEqual(result.data['classification'], '疑似住宅 IP')
        for score in (-1, 101, True, 4.5, 'oops', '9' * 5000):
            self.assertEqual(reputation_checks(Client(score=score), '1.1.1.1')[0].status, 'unknown')

    def test_actual_claude_ips_are_used_and_shared_addresses_are_queried_once(self):
        client = Client()
        results = check_claude_reputation(baseline() + [check('network.location', {'ip': '8.8.8.8'})], client, True)
        self.assertEqual(len(client.urls), 2)
        self.assertTrue(all('1.1.1.1' in url and '8.8.8.8' not in url for url in client.urls))
        self.assertEqual(len(results), 4)
        client = Client()
        results = check_claude_reputation([check('claude.web.egress', status='unknown')], client, True)
        self.assertEqual(client.urls, [])
        self.assertTrue(all(result.status == 'unknown' for result in results))

    def test_distinct_claude_exits_are_not_collapsed(self):
        checks = changed(baseline(), 'claude.api.egress', data={'ip': '8.8.8.8'})
        with patch('ipcheck.checks.reputation.reputation_checks', side_effect=lambda client, ip: [
            check('network.reputation', {'ip': ip, 'classification': '疑似机房 IP', 'score': 70}),
            check('network.abuse', {'ip': ip, 'listed': False})]) as query:
            results = check_claude_reputation(checks, Client(), True)
        self.assertEqual({call.args[1] for call in query.call_args_list}, {'1.1.1.1', '8.8.8.8'})
        by_id = {item.id: item for item in results}
        self.assertEqual(by_id['claude.web.reputation'].data['ip'], '1.1.1.1')
        self.assertEqual(by_id['claude.api.reputation'].data['ip'], '8.8.8.8')

    def test_disabling_reputation_does_not_contact_providers(self):
        client = Client(fail=True)
        results = check_claude_reputation(baseline(), client, False)
        self.assertEqual(client.urls, [])
        self.assertTrue(all(item.status == 'skipped' for item in results))

    def test_runner_uses_claude_profiles_instead_of_generic_profiles(self):
        with patch('ipcheck.core.runner.check_network', return_value=[check('network.reputation', status='skipped')]), \
             patch('ipcheck.core.runner.check_claude_routes', return_value=baseline()), \
             patch('ipcheck.core.runner.check_claude_reputation', return_value=[]) as profiles, \
             patch('ipcheck.core.runner.check_direct_ip', return_value=[]), \
             patch('ipcheck.core.runner.check_cloudflare', return_value=[]), \
             patch('ipcheck.core.runner.check_local_ipv6', return_value=[]), \
             patch('ipcheck.core.runner.check_dns', return_value=[]), \
             patch('ipcheck.core.runner.check_proxy', return_value=[]), \
             patch('ipcheck.core.runner.check_timezone', return_value=[]), \
             patch('ipcheck.core.runner.check_claude', return_value=[]):
            report = run_checks(Options())
        self.assertNotIn('network.reputation', [item.id for item in report.checks])
        self.assertTrue(profiles.call_args.args[2])
