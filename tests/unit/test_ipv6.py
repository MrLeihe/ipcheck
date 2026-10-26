import unittest
from unittest.mock import patch

from ipcheck.checks.ipv6 import address_inventory, check_local_ipv6, configuration_mode, service_for_interface
from ipcheck.core.models import CheckResult, Report
from ipcheck.output.render import render_text

ORDER = '(1) Ethernet\n(Hardware Port: Ethernet, Device: en0)\n(2) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en1)'
IFCONFIG = '''lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384
    inet6 ::1 prefixlen 128
utun0: flags=8051<UP,POINTOPOINT,RUNNING> mtu 1500
    inet6 fe80::1%utun0 prefixlen 64
    inet6 fd00::1 prefixlen 64
en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
    status: active
'''


class IPv6Tests(unittest.TestCase):
    def test_maps_only_the_default_interface_service_and_recognizes_explicit_off(self):
        self.assertEqual(service_for_interface(ORDER, 'en0'), 'Ethernet')
        self.assertEqual(service_for_interface(ORDER, 'en1'), 'Wi-Fi')
        self.assertIsNone(service_for_interface(ORDER, 'utun0'))
        self.assertIsNone(service_for_interface('(1) *Ethernet\n(Hardware Port: Ethernet, Device: en0)', 'en0'))
        for value, expected in (('Off', 'off'), ('Automatic', 'automatic'), ('Manual', 'manual'), ('Link-local only', 'link_local')):
            self.assertEqual(configuration_mode('IPv6: ' + value), expected)
        for invalid in ('', 'IPv6: something else', 'IPv6: Off\nIPv6: Automatic'):
            self.assertIsNone(configuration_mode(invalid))

    def test_link_local_and_ula_are_not_reported_as_public_ipv6(self):
        data = address_inventory(IFCONFIG)
        self.assertTrue(data['parsed'])
        self.assertEqual(data['global_count'], 0)
        self.assertEqual(data['link_local_count'], 1)
        self.assertEqual(data['ula_count'], 1)
        for value in ('fe80::1', 'fd00::1', '::1'):
            self.assertNotIn(value, str(data))

    def test_ignores_down_inactive_and_unready_addresses(self):
        text = IFCONFIG + '''en1: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
    inet6 2606:4700::1111 prefixlen 64
    status: inactive
en2: flags=0<> mtu 1500
    inet6 2606:4700::1111 prefixlen 64
utun1: flags=8051<UP,POINTOPOINT,RUNNING> mtu 1500
    inet6 2606:4700::1111 prefixlen 64 tentative
utun2: flags=8051<UP,POINTOPOINT,RUNNING> mtu 1500
    inet6 2606:4700::1111 prefixlen 64
'''
        data = address_inventory(text)
        self.assertEqual(data['global_count'], 1)
        self.assertEqual(data['global_interfaces'], ['utun2'])
        self.assertFalse(address_inventory('unrecognized output')['parsed'])

    def test_closed_local_service_does_not_hide_unknown_proxy_egress(self):
        outputs = ['  interface: en0\n', ORDER, 'IPv6: Off\n', IFCONFIG]
        with patch('ipcheck.checks.ipv6.platform.system', return_value='Darwin'), \
                patch('ipcheck.checks.ipv6.command', side_effect=outputs) as command:
            checks = check_local_ipv6()
        self.assertEqual(command.call_args_list[2].args[0], ['/usr/sbin/networksetup', '-getinfo', 'Ethernet'])
        self.assertEqual(checks[0].status, 'completed')
        self.assertEqual(checks[0].data['mode'], 'off')
        self.assertIn('已关闭', checks[0].summary)
        self.assertIn('无公网 IPv6 地址', checks[1].summary)
        probe = CheckResult('network.ipv6', 'network', '', 'unknown', 'info', 'probe failed')
        text = render_text(Report(checks + [probe]), details=True)
        for value in ('本机 IPv6 配置', '已关闭', 'IPv6 出口探测', '未验证'):
            self.assertIn(value, text)

    def test_command_failure_or_unmapped_tunnel_never_means_disabled(self):
        for outputs in ([None, None], ['interface: utun0\n', ORDER, IFCONFIG],
                        ['interface: en0\n', ORDER, None, IFCONFIG]):
            with self.subTest(outputs=outputs), patch('ipcheck.checks.ipv6.platform.system', return_value='Darwin'), \
                    patch('ipcheck.checks.ipv6.command', side_effect=outputs):
                result = check_local_ipv6()[0]
            self.assertEqual(result.status, 'unknown')
            self.assertIsNone(result.data['mode'])
            self.assertNotIn('已关闭', result.summary)

    def test_unsupported_platform_does_not_run_macos_commands(self):
        with patch('ipcheck.checks.ipv6.platform.system', return_value='Linux'), \
                patch('ipcheck.checks.ipv6.command', side_effect=AssertionError('must not run')):
            self.assertEqual(check_local_ipv6()[0].status, 'unsupported')
