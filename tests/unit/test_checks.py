import os
import unittest
from pathlib import Path
from unittest.mock import patch

from ipcheck.checks.claude import check_claude, classify_endpoint
from ipcheck.checks.network import check_network, reputation_checks
from ipcheck.checks.timezone import compare_timezone
from ipcheck.core.models import CheckResult
from ipcheck.core.summary import summarize
from ipcheck.platforms.system import parse_dns, parse_macos_proxy
from ipcheck.providers.http import HttpClient, ProviderError


class FakeClient(HttpClient):
    def __init__(self, fail=False, split=False):
        self.fail, self.split = fail, split

    def json(self, url):
        if self.fail:
            raise ProviderError("查询超时")
        if "api6" in url:
            raise ProviderError("查询超时")
        if "ipwho" in url:
            return {"success": True, "ip": "1.1.1.1", "country": "Test country", "timezone": {"id": "Asia/Kuala_Lumpur"}, "connection": {"asn": 1234}}
        if "proxycheck" in url:
            return {"status": "error", "message": "synthetic quota error"}
        if "stopforumspam" in url:
            return {"success": 0}
        return {"ip": "1.1.1.1"}

    def text(self, url):
        if self.fail:
            raise ProviderError("查询超时")
        return "8.8.8.8" if self.split else "1.1.1.1"


class ChecksTests(unittest.TestCase):
    def test_timeout_does_not_mean_disabled_or_clean(self):
        results = check_network(FakeClient(fail=True))
        self.assertEqual(next(item for item in results if item.id == "network.ipv6").status, "unknown")
        summary = summarize(results)
        self.assertGreater(summary["unknown"], 0)
        self.assertEqual(summary["level"], "incomplete")

    def test_different_egress_sources_require_attention(self):
        result = check_network(FakeClient(split=True))[0]
        self.assertEqual(result.severity, "warning")
        self.assertIn("不同出口", result.summary)

    def test_provider_errors_do_not_mean_unlisted(self):
        results = reputation_checks(FakeClient(), "1.1.1.1")
        self.assertTrue(all(item.status == "unknown" for item in results))

    def test_models_in_hostname_are_not_trusted(self):
        self.assertEqual(classify_endpoint("https://deepseek.evil.test")[0], "custom")
        self.assertEqual(classify_endpoint("https://api.deepseek.com")[0], "provider")
        self.assertEqual(classify_endpoint("https://api.anthropic.com.evil.test")[0], "custom")
        self.assertEqual(classify_endpoint("http://api.anthropic.com")[0], "insecure")
        self.assertEqual(classify_endpoint("https://api.anthropic.com:443/v1")[0], "official")

    def test_loopback_http_is_a_local_relay_not_a_plaintext_warning(self):
        for url in ("http://127.0.0.1:3456", "http://localhost:8080",
                    "http://[::1]:8080", "https://127.0.0.1:8443"):
            with self.subTest(url=url):
                self.assertEqual(classify_endpoint(url)[0], "local")
        for url in ("http://192.168.1.10:8080", "http://user:pass@127.0.0.1:8080"):
            with self.subTest(url=url):
                self.assertEqual(classify_endpoint(url)[0], "insecure")
        self.assertEqual(classify_endpoint("https://192.168.1.10:8443")[0], "custom")

    def test_loopback_endpoint_stays_informational(self):
        with patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "http://127.0.0.1:3456"}, clear=True):
            result = check_claude(Path("/nonexistent-ipcheck-home"))[0]
        self.assertEqual(result.data["endpoints"][0]["kind"], "local")
        self.assertNotEqual(result.severity, "warning")
        self.assertIn("本地", result.evidence[0])

    def test_offset_match_is_not_iana_match(self):
        checks = [CheckResult("timezone.system", "system", "", "completed", "info", "", data={"timezone": "Asia/Shanghai"}),
                  CheckResult("claude.web.egress", "claude", "", "completed", "info", "", data={"timezone": "Asia/Taipei"})]
        result = next(item for item in compare_timezone(checks) if item.id == "timezone.advice")
        self.assertFalse(result.data["same_iana"])
        self.assertTrue(result.data["same_offset"])
        self.assertEqual(result.severity, "warning")
        self.assertIn("Asia/Taipei", result.summary)

    def test_dns_parse_handles_ipv6_without_claiming_actual_path(self):
        text = "nameserver[0] : 1.1.1.1\nnameserver[1] : 2606:4700:4700::1111\nnameserver[2] : 1.1.1.1"
        self.assertEqual(parse_dns(text), ["1.1.1.1", "2606:4700:4700::1111"])

    def test_proxy_parse_does_not_return_addresses(self):
        self.assertEqual(parse_macos_proxy("HTTPEnable : 1\nHTTPProxy : user:synthetic-secret@host\nProxyAutoConfigEnable : 1"), ["HTTP", "PAC"])

    def test_http_transport_rejects_arbitrary_and_insecure_hosts(self):
        client = HttpClient()
        for url in ("http://api.ipify.org", "https://127.0.0.1", "https://api.ipify.org:444", "https://user:pass@api.ipify.org"):
            with self.assertRaises(ProviderError):
                client.text(url)
