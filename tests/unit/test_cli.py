import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ipcheck.cli import main
from ipcheck.core.models import CheckResult, Report
from ipcheck.core.runner import Options, run_checks


class CliTests(unittest.TestCase):
    def test_local_only_never_schedules_network(self):
        with tempfile.TemporaryDirectory() as directory, patch("ipcheck.core.runner.check_network", side_effect=AssertionError("must not contact network")):
            report = run_checks(Options(network=False, local=True), home=Path(directory))
            self.assertTrue(report.checks)
            self.assertTrue(all(check.group == "local" for check in report.checks))

    def test_json_exit_code_preserves_incomplete_status(self):
        report = Report([CheckResult("test", "network", "test", "unknown", "info", "timeout")])
        stream = io.StringIO()
        with patch("ipcheck.cli.run_checks", return_value=report), contextlib.redirect_stdout(stream):
            code = main(["--json"])
        self.assertEqual(code, 2)
        self.assertIn('"unknown": 1', stream.getvalue())

    def test_exit_code_follows_level(self):
        for level, code in (("clear", 0), ("attention", 1), ("incomplete", 2)):
            with self.subTest(level=level), \
                    patch("ipcheck.cli.run_checks", return_value=Report([])), \
                    patch.object(Report, "to_dict", return_value={"summary": {"level": level}}), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--json"]), code)

    def test_export_does_not_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("existing user data")
            with patch("ipcheck.cli.run_checks", return_value=Report([])), contextlib.redirect_stderr(io.StringIO()):
                code = main(["--output", str(path)])
            self.assertEqual(code, 2)
            self.assertEqual(path.read_text(), "existing user data")

    def test_worker_exception_does_not_expose_error_contents(self):
        with patch("ipcheck.core.runner.check_local", side_effect=RuntimeError("synthetic-secret-exception")):
            report = run_checks(Options(network=False, local=True))
        self.assertNotIn("synthetic-secret-exception", str(report.to_dict()))
        self.assertEqual(report.checks[0].status, "unknown")
