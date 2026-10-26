import contextlib
import io
import json
import os
import re
import unittest
import unicodedata
from unittest.mock import patch

from ipcheck.cli import main
from ipcheck.core.models import CheckResult, Report
from ipcheck.output.render import render_json, render_text
from tests.unit.test_assessment import baseline


def cell_width(text: str) -> int:
    return sum(0 if unicodedata.category(char) in ("Mn", "Me", "Cf") else
               2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
               for char in text)


class RenderTests(unittest.TestCase):
    def test_compact_output_retains_addresses_without_raw_payload_or_evidence(self):
        report = Report([
            CheckResult("network.egress", "network", "HTTPS 出口观测", "completed", "info", "两个服务观测到相同 IPv4 出口",
                        ("fixture-evidence",), {"observations": [{"service": "fixture", "ip": "203.0.113.10"}]}),
            CheckResult("dns.configuration", "network", "DNS 配置", "completed", "info", "发现 1 个配置的解析器", data={"servers": ["192.0.2.53"]}),
        ])
        compact = render_text(report)
        self.assertIn("203.0.113.10", compact)
        self.assertIn("192.0.2.53", compact)
        self.assertIn("192.0.2.53", render_text(report, details=True))
        self.assertNotIn('"observations"', compact)
        self.assertNotIn("fixture-evidence", compact)
        self.assertIn("fixture-evidence", render_text(report, details=True))
        self.assertEqual(json.loads(render_json(report))["checks"][0]["data"]["observations"][0]["ip"], "203.0.113.10")

    def test_unfinished_skipped_and_attention_results_remain_distinct(self):
        report = Report([
            CheckResult("a", "system", "配置", "completed", "warning", "需要核对"),
            CheckResult("b", "system", "网络", "unknown", "info", "未知"),
            CheckResult("c", "system", "平台", "unsupported", "info", "不支持"),
            CheckResult("d", "system", "可选项", "skipped", "info", "未启用"),
        ])
        text = render_text(report, details=True)
        for state in ("需核对", "未验证", "不支持", "已跳过"):
            self.assertIn(state, text)
        self.assertNotIn("检测概况", text)
        self.assertNotIn("检测提示", text)
        self.assertIn("综合结论", text)
        self.assertIn("检测建议", text)

    def test_partial_egress_is_not_shown_as_verified_or_ipv6_disabled(self):
        report = Report([
            CheckResult("network.egress", "network", "HTTPS 出口观测", "unknown", "info", "出口观测不完整",
                        data={"observations": [{"service": "one", "status": "completed", "ip": "203.0.113.10"},
                                               {"service": "two", "status": "unknown", "reason": "fixture-timeout"}]}),
            CheckResult("network.ipv6", "network", "IPv6 HTTPS 观测", "unknown", "info", "未能完成 IPv6 出口验证"),
        ])
        text = render_text(report)
        self.assertIn("203.0.113.10", text)
        self.assertIn("仅 1/2 个来源返回地址，出口未验证", text)
        self.assertNotIn("观测一致", text)
        self.assertNotIn("已禁用", text)

    def test_geolocation_fields_and_cjk_table_borders_align_with_and_without_color(self):
        report = Report([CheckResult("network.location", "network", "IP 归属查询", "completed", "info", "Example Country / Example City",
                                     data={"country": "Example Country", "region": "Example Region", "city": "示例城市",
                                           "isp": "Example ISP", "org": "Example Org", "asn": 64500,
                                           "timezone": "Example/Timezone"})])
        for width in (24, 40, 56, 80, 100, 120):
            for color in (False, True):
                text = render_text(report, details=True, color=color, width=width)
                plain = re.sub(r"\x1b\[[0-9;]+m", "", text)
                for value in ("示例城市", "Example ISP", "Example Org", "AS64500"):
                    self.assertIn(value, plain)
                for line in plain.splitlines():
                    if line.lstrip().startswith(("╔", "╠", "╚", "║")):
                        self.assertEqual(cell_width(line), min(width, 92), line)

    def test_cjk_and_ascii_output_fit_narrow_and_wide_terminals(self):
        report = Report([CheckResult("test", "network", "IPv6 HTTPS 观测", "unknown", "info",
                                     "无法连接查询服务，可能与网络、代理或服务状态有关 e\u0301 example.test/long/path/for/check",
                                     ("详细说明 " * 12,), {"servers": ["2001:db8::1"]})])
        for width in (24, 40, 80, 100, 120):
            for details in (False, True):
                with self.subTest(width=width, details=details):
                    for line in render_text(report, width=width, details=details).splitlines():
                        self.assertLessEqual(cell_width(line), width, line)

    def test_detailed_output_redacts_secrets_and_escapes_injected_controls(self):
        report = Report([CheckResult("test", "network", "test\x1b[31m", "completed", "info", "Bearer synthetic-token-123",
                                     ("sk-ant-syntheticlongkey123456789",),
                                     {"api_key": "synthetic-secret", "untrusted\x1b[31m": "value"})])
        text = render_text(report, details=True)
        for secret in ("synthetic-token-123", "syntheticlongkey123456789", "synthetic-secret", "\x1b"):
            self.assertNotIn(secret, text)
        colored = render_text(report, details=True, color=True)
        without_styles = re.sub(r"\x1b\[[0-9;]+m", "", colored)
        self.assertEqual(without_styles, text)

    def test_cli_uses_color_only_for_tty_unless_disabled(self):
        report = Report(baseline())
        for tty, no_color, term, expected in ((False, False, "xterm", False), (True, False, "xterm", True),
                                               (True, True, "xterm", False), (True, False, "dumb", False)):
            with self.subTest(tty=tty, no_color=no_color, term=term):
                stream = io.StringIO()
                environment = {"TERM": term, **({"NO_COLOR": ""} if no_color else {})}
                with patch("ipcheck.cli.run_checks", return_value=report), patch.dict(os.environ, environment, clear=True), \
                        contextlib.redirect_stdout(stream), patch.object(stream, "isatty", return_value=tty):
                    self.assertEqual(main([]), 0)
                self.assertEqual("\x1b[" in stream.getvalue(), expected)
