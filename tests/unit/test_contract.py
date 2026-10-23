import json
import re
import unittest
from pathlib import Path
from typing import get_args

from ipcheck.core.models import CheckResult, Report, Severity, Status
from ipcheck.core.summary import summarize

ROOT = Path(__file__).parents[2]


class ContractTests(unittest.TestCase):
    def test_python_schema_and_typescript_have_same_fields_and_enums(self):
        schema = json.loads((ROOT / "schemas/report.schema.json").read_text())
        report = Report([CheckResult("test", "test", "test", "completed", "info", "test")]).to_dict()
        self.assertEqual(set(report), set(schema["required"]))
        self.assertEqual(set(report["checks"][0]), set(schema["$defs"]["check"]["required"]))
        self.assertEqual(set(report["summary"]), set(schema["$defs"]["summary"]["required"]))
        typescript = (ROOT / "web/src/types/report.ts").read_text()
        for name, enum, definition in (("Status", Status, "status"), ("Severity", Severity, "severity")):
            match = re.search(rf"export type {name} = ([^;]+);", typescript)
            self.assertIsNotNone(match)
            self.assertEqual(set(re.findall(r'"([^"]+)"', match.group(1))), set(get_args(enum)))
            self.assertEqual(set(get_args(enum)), set(schema["$defs"]["check"]["properties"][definition]["enum"]))

    def test_unknown_and_skipped_are_not_successes(self):
        checks = [CheckResult("u", "test", "", "unknown", "info", ""), CheckResult("s", "test", "", "skipped", "info", "")]
        summary = summarize(checks)
        self.assertEqual(summary["completed"], 0)
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertIn("不完整", summary["message"])
