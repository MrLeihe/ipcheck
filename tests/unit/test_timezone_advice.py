import unittest
from unittest.mock import patch

from ipcheck.checks.timezone import compare_timezone
from ipcheck.core.models import CheckResult, Report
from ipcheck.output.render import render_text
from ipcheck.server.browser import merge_browser


def zone(check_id, name, status='completed', **extra):
    return CheckResult(check_id, 'system', check_id, status, 'info', '',
                       data={'timezone': name, **extra})


def baseline(system='Asia/Shanghai', cli='Asia/Shanghai', target='Asia/Taipei'):
    return [zone('timezone.system', system), zone('timezone.cli', cli),
            zone('network.location', 'Asia/Kuala_Lumpur'),
            zone('claude.api.egress', target), zone('claude.web.egress', target)]


def derived(checks):
    return {check.id: check for check in compare_timezone(checks)}


class TimezoneAdviceTests(unittest.TestCase):
    def test_same_offset_different_names_prompts_browser_check_without_claiming_risk(self):
        results = derived(baseline())
        web = results['timezone.advice']
        self.assertTrue(web.data['same_offset'])
        self.assertFalse(web.data['same_iana'])
        self.assertEqual(web.data['local_source'], 'timezone.system')
        self.assertEqual(web.severity, 'warning')
        for text in ('核对浏览器', 'Asia/Taipei'):
            self.assertIn(text, web.summary)
        self.assertIn('不用于判断账号风险', ' '.join(web.evidence))
        output = render_text(Report(baseline() + list(results.values())), color=True)
        self.assertEqual(output.count('时区建议'), 1)
        for obsolete in ('检测出口说明', 'API 时区建议', '网页时区建议', '无需'):
            self.assertNotIn(obsolete, output)
        advice_only = render_text(Report([web]), color=True)
        advice_line = next(line for line in advice_only.splitlines() if '时区建议' in line)
        self.assertIn('\x1b[33m', advice_line)
        self.assertNotIn('CLI / Claude', output)

    def test_cli_tz_override_is_not_treated_as_browser_timezone(self):
        web = derived(baseline(cli='America/New_York'))['timezone.advice']
        self.assertEqual(web.data['local_timezone'], 'Asia/Shanghai')
        self.assertTrue(web.data['same_offset'])

    def test_api_and_general_egress_do_not_require_system_timezone_changes(self):
        with patch('ipcheck.checks.timezone.offset_minutes', side_effect=lambda name: {
            'Asia/Shanghai': 480, 'Asia/Kuala_Lumpur': 480, 'America/New_York': -240}.get(name)):
            results = derived(baseline(target='America/New_York'))
        advice = results['timezone.advice']
        comparisons = advice.data['comparisons']
        self.assertFalse(comparisons['api']['same_offset'])
        self.assertIn('America/New_York', advice.summary)
        self.assertNotIn('无需', advice.summary)
        self.assertTrue(all('comparison' not in check_id for check_id in results))

    def test_equal_names_and_offsets_always_show_one_green_advice(self):
        results = derived(baseline(system='Asia/Taipei', cli='Asia/Taipei'))
        advice = results['timezone.advice']
        self.assertEqual(advice.status, 'completed')
        self.assertEqual(advice.severity, 'info')
        self.assertIn('一致', advice.summary)
        line = next(line for line in render_text(Report(list(results.values())), color=True).splitlines()
                    if '时区建议' in line)
        self.assertIn('\x1b[32m', line)

    def test_missing_egress_never_suggests_a_replacement_timezone(self):
        checks = baseline()
        checks[-1] = zone('claude.web.egress', None, 'unknown')
        advice = derived(checks)['timezone.advice']
        self.assertEqual(advice.status, 'unknown')
        self.assertIsNone(advice.data['same_iana'])
        self.assertNotIn('考虑使用', advice.summary)

    def test_browser_sampling_refreshes_advice_and_removes_stale_warning(self):
        checks = baseline()
        report = Report(checks + compare_timezone(checks))
        snapshot = {'timezone': 'Asia/Shanghai', 'offset_minutes': 480, 'locale': 'zh-CN',
                    'languages': ['zh-CN'], 'user_agent': 'Fixture', 'platform': 'Fixture', 'fonts': None}
        report = merge_browser(report, snapshot)
        web = next(check for check in report.checks if check.id == 'timezone.advice')
        self.assertEqual(web.severity, 'warning')
        self.assertEqual(web.data['local_source'], 'browser.timezone')
        self.assertIn('Asia/Taipei', web.summary)
        report = merge_browser(report, {**snapshot, 'timezone': 'Asia/Taipei'})
        matches = [check for check in report.checks if check.id == web.id]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, 'info')
        self.assertIn('一致', matches[0].summary)
        self.assertTrue(matches[0].data['same_iana'])

    def test_invalid_browser_timezone_does_not_fall_back_to_system_as_success(self):
        checks = baseline()
        for name, offset in (('Invalid/Fixture', 480), ('Asia/Taipei', 0)):
            with self.subTest(name=name):
                browser = zone('browser.timezone', name, offset_minutes=offset)
                advice = derived(checks + [browser])['timezone.advice']
                self.assertEqual(advice.status, 'unknown')
                self.assertIsNone(advice.data['same_iana'])

    def test_browser_sampling_of_local_only_report_does_not_add_egress_checks(self):
        snapshot = {'timezone': 'Asia/Shanghai', 'offset_minutes': 480, 'locale': 'zh-CN',
                    'languages': ['zh-CN'], 'user_agent': 'Fixture', 'platform': 'Fixture', 'fonts': None}
        report = merge_browser(Report([]), snapshot)
        self.assertTrue(all(check.group == 'browser' for check in report.checks))
