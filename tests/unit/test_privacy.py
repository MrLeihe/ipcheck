import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ipcheck.checks.claude import check_claude
from ipcheck.checks.local import check_local
from ipcheck.core.models import CheckResult, Report
from ipcheck.output.render import render_json, render_text


class PrivacyTests(unittest.TestCase):
    def test_provider_strings_cannot_inject_terminal_control_sequences(self):
        report = Report([CheckResult("test", "network", "test", "completed", "info", "country\x1b[31m\rforged")])
        text = render_text(report)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\r", text)

    def test_shell_config_never_enters_any_output(self):
        secret = "synthetic-secret-that-must-never-appear"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".zshrc").write_text(f'export ANTHROPIC_API_KEY="{secret}"\nalias claude="client --token {secret}"\n')
            report = Report(check_local(home))
            for text in (render_json(report), render_text(report, details=True)):
                self.assertNotIn(secret, text)
                self.assertNotIn("export ", text)
                self.assertIn("ANTHROPIC_API_KEY", text)

    def test_endpoint_drops_url_credentials_path_and_query(self):
        secret = "SYNTHETIC-PRIVATE-VALUE"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".claude").mkdir()
            (home / ".claude/settings.json").write_text(json.dumps({"env": {
                "ANTHROPIC_BASE_URL": f"https://user:{secret}@example.test/private/{secret}?key={secret}",
                "ANTHROPIC_API_KEY": secret,
            }}))
            with patch.dict(os.environ, {}, clear=True):
                text = render_json(Report(check_claude(home)))
            self.assertNotIn(secret, text)
            self.assertNotIn("/private", text)
            self.assertIn("example.test", text)

    def test_output_boundary_redacts_nested_values_and_headers(self):
        result = CheckResult("synthetic", "test", "test", "completed", "info",
                             "Bearer synthetic-token-123",
                             ("https://user:synthetic-password@example.test", "sk-ant-syntheticlongkey123456789"),
                             {"nested": [{"api_key": "synthetic-key-123"}]})
        text = render_json(Report([result]))
        for secret in ("synthetic-token-123", "synthetic-password", "syntheticlongkey123456789", "synthetic-key-123"):
            self.assertNotIn(secret, text)

    def test_identity_values_never_enter_report(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".claude/backups").mkdir(parents=True)
            (home / ".claude.json").write_text(json.dumps({"oauthAccount": {"accountUuid": "current-synthetic-account"}}))
            (home / ".claude/backups/.claude.json.backup1").write_text(json.dumps({"oauthAccount": {"accountUuid": "old-synthetic-account"}}))
            text = render_json(Report(check_local(home)))
            self.assertNotIn("current-synthetic-account", text)
            self.assertNotIn("old-synthetic-account", text)
            self.assertIn('"different_account_backups": 1', text)
