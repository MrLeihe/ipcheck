import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ipcheck.core.models import CheckResult, Report
from ipcheck.server.app import LocalServer, State


def fake_runner(options, progress):
    if progress:
        progress(1, 1)
    return Report([CheckResult("test.observation", "system", "synthetic", "completed", "info", "synthetic observation")])


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        (cls.root / "index.html").write_text("<!doctype html><title>synthetic test</title>")
        cls.state = State(runner=fake_runner)
        cls.server = LocalServer(0, cls.state, cls.root)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.directory.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        raw = json.dumps(body) if body is not None else None
        combined = {"Authorization": f"Bearer {self.state.token}", "Origin": self.server.origin}
        if body is not None:
            combined["Content-Type"] = "application/json"
        combined.update(headers or {})
        connection.request(method, path, raw, combined)
        response = connection.getresponse()
        result = response.status, response.read(), dict(response.getheaders())
        connection.close()
        return result

    def test_api_requires_token(self):
        self.assertEqual(self.request("GET", "/api/report", headers={"Authorization": ""})[0], 401)

    def test_cross_origin_and_rebinding_are_blocked(self):
        self.assertEqual(self.request("POST", "/api/run", {"local": False, "reputation": False}, {"Origin": "https://example.test"})[0], 403)
        self.assertEqual(self.request("GET", "/api/session", headers={"Host": "example.test"})[0], 403)

    def test_static_traversal_is_blocked_and_csp_is_present(self):
        self.assertEqual(self.request("GET", "/%2e%2e/secret")[0], 404)
        status, _, headers = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_local_checks_require_startup_permission(self):
        self.assertEqual(self.request("POST", "/api/run", {"local": True, "reputation": False})[0], 403)

    def test_unknown_fields_and_oversized_requests_are_rejected(self):
        self.assertEqual(self.request("POST", "/api/run", {"local": False, "reputation": False, "url": "https://example.test"})[0], 400)
        self.assertEqual(self.request("POST", "/api/run", {"padding": "x" * 17000})[0], 413)

    def test_run_and_browser_merge_keep_one_report_identity(self):
        status, _, _ = self.request("POST", "/api/run", {"local": False, "reputation": False})
        self.assertEqual(status, 202)
        deadline = time.monotonic() + 2
        while self.state.running and time.monotonic() < deadline:
            threading.Event().wait(0.01)
        response = json.loads(self.request("GET", "/api/report")[1])
        report_id = response["report"]["id"]
        snapshot = json.loads((Path(__file__).parents[1] / "fixtures/browser.json").read_text())
        status, body, _ = self.request("POST", "/api/browser", {"report_id": report_id, "snapshot": snapshot})
        self.assertEqual(status, 200)
        merged = json.loads(body)["report"]
        self.assertEqual(merged["id"], report_id)
        self.assertTrue(any(check["id"] == "browser.environment" for check in merged["checks"]))
        self.assertEqual(self.request("POST", "/api/browser", {"report_id": "stale", "snapshot": snapshot})[0], 409)
