import unittest
from unittest.mock import patch

from ipcheck.checks.proxy import check_proxy
from ipcheck.core.models import Report
from ipcheck.output.render import render_text
from ipcheck.platforms.tunnel import TunnelObservation, linux_routes, macos_routes, macos_vpn_states, tunnel_status

V4 = '''Routing tables
Internet:
Destination Gateway Flags Netif Expire
default 192.0.2.1 UGScg en0
'''
V6 = '''Routing tables
Internet6:
Destination Gateway Flags Netif Expire
default fe80::%utun0 UGcIg utun0
fe80::%utun0/64 fe80::1%utun0 UcI utun0
ff00::/8 fe80::1%utun0 UmCI utun0
'''
VPN = 'Available network connection services in the current set (*=enabled):\n'


def observed(outputs, system='Darwin'):
    commands = {'/usr/sbin/netstat': {'inet': outputs[0], 'inet6': outputs[1]},
                '/usr/sbin/scutil': outputs[2] if len(outputs) > 2 else None}

    def fake(args):
        if args[0] == '/usr/sbin/netstat':
            return commands[args[0]][args[-1]]
        if args[0] == '/usr/sbin/scutil':
            return commands[args[0]]
        return outputs[0] if '-4' in args else outputs[1]

    with patch('ipcheck.platforms.tunnel.platform.system', return_value=system), \
            patch('ipcheck.platforms.tunnel.command', side_effect=fake):
        return tunnel_status()


def proxy_results(observation):
    with patch('ipcheck.checks.proxy.platform.system', return_value='Darwin'), \
            patch('ipcheck.checks.proxy.environment_proxy_names', return_value=[]), \
            patch('ipcheck.checks.proxy.system_proxy', return_value=([], True)), \
            patch('ipcheck.checks.proxy.tunnel_status', return_value=observation):
        return check_proxy()


class ProxyStatusTests(unittest.TestCase):
    def test_idle_apple_utun_scoped_defaults_and_local_routes_are_off(self):
        result = observed((V4, V6, VPN))
        self.assertEqual(result.state, 'off')
        self.assertEqual(result.interfaces, ())
        text = render_text(Report(proxy_results(result)), details=True)
        self.assertIn('未开启', text)
        self.assertNotIn('迹象', text)
        self.assertNotIn('未发现已识别的隧道路由', text)

    def test_ipv4_split_tunnel_and_ipv6_tunnel_routes_are_on(self):
        for v4, v6, interface in ((V4 + '0/1 link#30 USc utun9\n', V6, 'utun9'),
                                  (V4, V6 + '::/1 fe80::1 UGSc utun8\n', 'utun8'),
                                  (V4 + '10/8 link#20 USc ppp0\n', V6, 'ppp0')):
            with self.subTest(interface=interface):
                result = observed((v4, v6, VPN))
                self.assertEqual(result.state, 'on')
                self.assertEqual(result.interfaces, (interface,))
                text = render_text(Report(proxy_results(result)), details=True)
                self.assertIn('已开启', text)
                self.assertNotIn('迹象', text)

    def test_connected_system_vpn_is_on_even_without_recognized_tunnel_name(self):
        result = observed((V4, V6, VPN + '* (Connected) synthetic-uuid (VPN) "synthetic-private-config"\n'))
        self.assertEqual(result.state, 'on')
        report = Report(proxy_results(result)).to_dict()
        self.assertNotIn('synthetic-uuid', str(report))
        self.assertNotIn('synthetic-private-config', str(report))
        self.assertEqual(report['checks'][-1]['summary'], '已开启')

    def test_only_complete_negative_checks_allow_off(self):
        for outputs in ((None, V6, VPN), (V4, None, VPN), (V4, V6, None),
                        ('unrecognized', V6, VPN), (V4, V6, 'unrecognized')):
            with self.subTest(outputs=outputs):
                observation = observed(outputs)
                self.assertEqual(observation.state, 'unknown')
                result = proxy_results(observation)[-1]
                self.assertEqual(result.status, 'unknown')
                self.assertEqual(result.summary, '检测失败')
                text = render_text(Report([result]), details=True)
                self.assertNotIn('未开启', text)
                self.assertNotIn('未验证 · 检测失败', text)

    def test_positive_connection_survives_failure_of_other_checks(self):
        self.assertEqual(observed((None, None, VPN + '* (Connected) synthetic\n')).state, 'on')
        self.assertEqual(observed((V4 + 'default link#30 UGSc utun9\n', None, None)).state, 'on')

    def test_transition_states_are_not_mislabeled_as_off(self):
        for native, expected, summary in (('Connecting', 'connecting', '连接中'), ('Disconnecting', 'disconnecting', '断开中')):
            observation = observed((V4, V6, VPN + f'* ({native}) synthetic\n'))
            self.assertEqual(observation.state, expected)
            self.assertEqual(proxy_results(observation)[-1].summary, summary)

    def test_disconnected_service_is_off_and_invalid_state_cannot_mean_off(self):
        self.assertEqual(observed((V4, V6, VPN + '* (Disconnected) synthetic\n')).state, 'off')
        self.assertEqual(observed((V4, V6, VPN + '* (UnexpectedState) synthetic\n')).state, 'unknown')
        self.assertEqual(macos_vpn_states(None), (set(), False))

    def test_reject_blackhole_down_multicast_and_link_local_routes(self):
        text = V6 + '''default link#9 UGB utun9
2001:db8::/32 link#9 GR utun9
ff02::/16 link#9 UGc utun9
fe90::/64 link#9 UGc utun9
'''
        self.assertEqual(macos_routes(text, 6), (set(), True))
        self.assertFalse(macos_routes('', 6)[1])

    def test_linux_routes_check_both_families_and_keep_failures_distinct(self):
        self.assertEqual(observed(('default via 192.0.2.1 dev eth0\n', 'default dev wg0\n'), 'Linux').state, 'on')
        self.assertEqual(observed(('', ''), 'Linux').state, 'off')
        self.assertEqual(observed(('', None), 'Linux').state, 'unknown')
        self.assertEqual(linux_routes('fe80::/64 dev tun0\nff00::/8 dev tun0\ndefault dev tun1 linkdown\n'), (set(), True))

    def test_unsupported_platform_is_not_off(self):
        with patch('ipcheck.platforms.tunnel.platform.system', return_value='Windows'), \
                patch('ipcheck.platforms.tunnel.command', side_effect=AssertionError('must not run')):
            self.assertEqual(tunnel_status().state, 'unsupported')
