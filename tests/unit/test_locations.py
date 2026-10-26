import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from ipcheck.checks.locations import LocationClient, enrich_locations
from ipcheck.core.models import CheckResult, Report
from ipcheck.output.render import render_text
from ipcheck.providers.http import HttpClient, ProviderError


class LocationTests(unittest.TestCase):
    def test_concurrent_same_ip_uses_one_request_per_path(self):
        client = LocationClient(4)
        with patch.object(HttpClient, "json", return_value={"success": True}) as request:
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(client.json, ["https://ipwho.is/1.1.1.1"] * 8))
            self.assertEqual(request.call_count, 1)

    def test_failed_queries_are_also_reused(self):
        client = LocationClient(4)
        with patch.object(HttpClient, "json", side_effect=ProviderError("查询超时")) as request:
            for _ in range(2):
                with self.assertRaises(ProviderError):
                    client.json("https://ipwho.is/1.1.1.1")
            self.assertEqual(request.call_count, 1)

    def test_each_ip_keeps_its_own_geography(self):
        def lookup(client, ip, fallback):
            data = {"ip": ip, "country_code": "CN" if ip == "1.1.1.1" else "TW",
                    "city": "Shenzhen" if ip == "1.1.1.1" else "Taipei"}
            return CheckResult("network.location", "network", "", "completed", "info", "", data=data)
        direct = CheckResult("network.direct", "network", "", "unknown", "info", "",
                             data={"addresses": ["1.1.1.1"]})
        generic = CheckResult("network.egress", "network", "", "completed", "info", "",
                              data={"observations": [{"ip": "8.8.8.8"}, {"ip": "1.1.1.1"}]})
        with patch("ipcheck.checks.locations.location_check", side_effect=lookup) as request:
            checks = enrich_locations([direct, generic], HttpClient(), HttpClient())
        self.assertEqual(request.call_count, 2)
        text = render_text(Report(checks))
        self.assertIn("1.1.1.1（中国大陆深圳）", text)
        self.assertIn("8.8.8.8（台湾台北）", text)
        self.assertNotIn("单一来源", text)

    def test_claude_country_only_and_unknown_fallback(self):
        for fields, expected in (({"country_code": "TW"}, "台湾"), ({}, "归属未知")):
            check = CheckResult("claude.web.egress", "claude", "", "completed", "info", "",
                                data={"ip": "1.1.1.1", **fields})
            self.assertIn("1.1.1.1（" + expected + "）", render_text(Report([check])))
