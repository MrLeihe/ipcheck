import unittest

from ipcheck.checks.cloudflare import check_cloudflare
from ipcheck.checks.network import reputation_checks
from ipcheck.checks.region import check_region, load_policy
from ipcheck.checks.route import compare_routes
from ipcheck.core.models import CheckResult
from ipcheck.providers.http import ProviderError


def egress(check_id, ip=None, country=None, status="completed"):
    data = {} if ip is None else {"ip": ip}
    if country is not None:
        data["country_code"] = country
    return CheckResult(check_id, "claude", check_id, status, "info", "", data=data)


def network(check_id, data, status="completed"):
    return CheckResult(check_id, "network", check_id, status, "info", "", data=data)


class RegionTests(unittest.TestCase):
    def test_policy_file_contains_published_codes(self):
        policy = load_policy()
        self.assertIn("US", policy["country_codes"])
        self.assertIn("TW", policy["country_codes"])
        self.assertNotIn("CN", policy["country_codes"])
        self.assertNotIn("HK", policy["country_codes"])
        self.assertTrue(policy["source"].startswith("https://www.anthropic.com/"))

    def test_supported_and_unsupported_countries(self):
        supported = check_region([egress("claude.web.egress", "1.1.1.1", "US")])[0]
        self.assertEqual(supported.status, "completed")
        self.assertEqual(supported.severity, "info")
        self.assertFalse(supported.data["unsupported"])
        unsupported = check_region([egress("claude.web.egress", "1.1.1.1", "HK")])[0]
        self.assertEqual(unsupported.severity, "warning")
        self.assertTrue(unsupported.data["unsupported"])
        self.assertIn("HK", unsupported.summary)

    def test_missing_country_is_unknown_not_supported(self):
        result = check_region([egress("claude.web.egress", "1.1.1.1", None)])[0]
        self.assertEqual(result.status, "unknown")
        self.assertNotIn("supported", result.data)
        self.assertTrue(all(route["supported"] is None for route in result.data["routes"]))

    def test_territories_resolve_through_their_parent_country(self):
        for code, parent in (("PR", "US"), ("GG", "GB"), ("RE", "FR"), ("GL", "DK")):
            with self.subTest(code=code):
                result = check_region([egress("claude.web.egress", "1.1.1.1", code)])[0]
                self.assertEqual(result.status, "completed")
                self.assertEqual(result.severity, "info")
                self.assertEqual(result.data["routes"][0]["territory_of"], parent)
                self.assertIn(f"{parent} 属地", result.summary)

    def test_unavailable_policy_is_unknown_not_unsupported(self):
        from unittest.mock import patch
        with patch("ipcheck.checks.region.load_policy", return_value={}):
            result = check_region([egress("claude.web.egress", "1.1.1.1", "US")])[0]
        self.assertEqual(result.status, "unknown")
        self.assertNotIn("unsupported", result.data)
        self.assertIn("数据不可用", result.summary)

    def test_placeholder_codes_are_unknown_not_unsupported(self):
        for code in ("XX", "T1"):
            with self.subTest(code=code):
                result = check_region([egress("claude.web.egress", "1.1.1.1", code)])[0]
                self.assertEqual(result.status, "unknown")
                self.assertIsNone(result.data["routes"][0]["supported"])

    def test_partial_unknown_route_is_named_in_the_summary(self):
        result = check_region([egress("claude.web.egress", "1.1.1.1", "XX"),
                               egress("claude.api.egress", "1.1.1.1", "US")])[0]
        self.assertEqual(result.status, "completed")
        self.assertIn("网页国家代码未知", result.summary)


class RouteComparisonTests(unittest.TestCase):
    def test_split_claude_routes_are_a_warning(self):
        result = compare_routes([egress("claude.web.egress", "1.1.1.1", "US"),
                                 egress("claude.api.egress", "8.8.8.8", "US")])[0]
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.severity, "warning")
        self.assertFalse(result.data["claude_consistent"])

    def test_direct_path_difference_is_expected_and_not_a_warning(self):
        result = compare_routes([
            egress("claude.web.egress", "1.1.1.1", "US"), egress("claude.api.egress", "1.1.1.1", "US"),
            network("network.direct", {"addresses": ["203.0.113.9"]}),
            network("network.egress", {"ip": "1.1.1.1", "observations": [{"ip": "1.1.1.1"}]}),
        ])[0]
        self.assertEqual(result.severity, "info")
        self.assertTrue(result.data["claude_consistent"])
        self.assertIn("本机直连", result.summary)
        self.assertEqual(result.data["different_paths"], ["本机直连"])

    def test_missing_claude_exit_is_unknown_not_consistent(self):
        result = compare_routes([network("network.direct", {"addresses": ["203.0.113.9"]})])[0]
        self.assertEqual(result.status, "unknown")
        self.assertIsNone(result.data["claude_consistent"])

    def test_multiple_addresses_are_never_collapsed_into_full_consistency(self):
        result = compare_routes([
            egress("claude.web.egress", "1.1.1.1", "US"), egress("claude.api.egress", "1.1.1.1", "US"),
            network("network.direct", {"addresses": ["1.1.1.1", "2.2.2.2"]}),
        ])[0]
        self.assertIs(result.data["all_consistent"], False)
        self.assertEqual(result.data["paths"]["direct"]["addresses"], ["1.1.1.1", "2.2.2.2"])
        self.assertNotIn("各路径观测到相同出口", result.summary)

    def test_multiple_claude_addresses_are_a_warning(self):
        result = compare_routes([
            egress("claude.web.egress", "1.1.1.1", "US"),
            network("claude.api.egress", {"ip": "1.1.1.1", "addresses": ["1.1.1.1", "2.2.2.2"]}),
        ])[0]
        self.assertTrue(result.data["claude_multi"])
        self.assertEqual(result.severity, "warning")
        self.assertTrue(result.data["paths"]["claude_api"]["addresses"])

    def test_unverified_path_prevents_an_all_paths_consistent_claim(self):
        result = compare_routes([
            egress("claude.web.egress", "1.1.1.1", "US"), egress("claude.api.egress", "1.1.1.1", "US"),
            CheckResult("network.direct", "network", "", "unknown", "info", "", data={"addresses": ["2.2.2.2"]}),
        ])[0]
        self.assertFalse(result.data["paths"]["direct"]["verified"])
        self.assertIs(result.data["all_consistent"], False)
        self.assertNotIn("各路径观测到相同出口", result.summary)


class Client:
    def __init__(self, text=None, fail=False):
        self.value, self.fail, self.urls = text, fail, []

    def text(self, url):
        self.urls.append(url)
        if self.fail:
            raise ProviderError("查询超时")
        return self.value

    def json(self, url):
        self.urls.append(url)
        if self.fail:
            raise ProviderError("查询超时")
        if "proxycheck" in url:
            return {"status": "ok", "1.1.1.1": {"risk": "7", "type": "Residential",
                                                 "proxy": "no", "vpn": "no", "tor": "no", "crawler": "yes"}}
        return {"success": 1, "ip": {"appears": 0}}


class CloudflareTests(unittest.TestCase):
    def test_trace_keeps_country_latency_and_rejects_wrong_host(self):
        result = check_cloudflare(Client("h=www.cloudflare.com\nip=2.2.2.2\nloc=US\ncolo=LAX\n"))[0]
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.data["ip"], "2.2.2.2")
        self.assertEqual(result.data["country_code"], "US")
        self.assertEqual(result.data["colo"], "LAX")
        self.assertIsInstance(result.data["latency_ms"], int)
        failed = check_cloudflare(Client("h=example.com\nip=2.2.2.2\n"))[0]
        self.assertEqual(failed.status, "unknown")

    def test_transport_error_stays_unknown(self):
        result = check_cloudflare(Client(fail=True))[0]
        self.assertEqual(result.status, "unknown")
        self.assertIn("超时", result.summary)


class ReputationFlagTests(unittest.TestCase):
    def test_yes_no_flags_are_parsed_only_when_provided(self):
        profile = reputation_checks(Client(), "1.1.1.1")[0]
        self.assertEqual(profile.data["vpn"], False)
        self.assertEqual(profile.data["tor"], False)
        self.assertEqual(profile.data["crawler"], True)
        self.assertEqual(profile.data["score"], 7)

    def test_missing_flags_stay_unknown(self):
        class Bare(Client):
            def json(self, url):
                if "proxycheck" in url:
                    return {"status": "ok", "1.1.1.1": {"risk": 3, "type": "Residential"}}
                return {"success": 1, "ip": {"appears": 0}}
        profile = reputation_checks(Bare(), "1.1.1.1")[0]
        for field in ("vpn", "tor", "crawler", "proxy"):
            self.assertIsNone(profile.data[field], field)
