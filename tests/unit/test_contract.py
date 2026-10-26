import json
import unittest
from pathlib import Path
from typing import get_args

from ipcheck.core.models import CheckResult, Report, Severity, Status
from ipcheck.core.summary import summarize

ROOT = Path(__file__).parents[2]


class ContractTests(unittest.TestCase):
    def test_python_schema_and_models_have_same_fields_and_enums(self):
        schema = json.loads((ROOT / "schemas/report.schema.json").read_text())
        report = Report([CheckResult("test", "test", "test", "completed", "info", "test")]).to_dict()
        self.assertEqual(set(report), set(schema["required"]))
        self.assertEqual(set(report["checks"][0]), set(schema["$defs"]["check"]["required"]))
        self.assertEqual(set(report["summary"]), set(schema["$defs"]["summary"]["required"]))
        self.assertEqual(set(report["summary"]["focus_ids"]), set())
        self.assertIn(report["summary"]["level"], schema["$defs"]["summary"]["properties"]["level"]["enum"])
        for enum, definition in ((Status, "status"), (Severity, "severity")):
            self.assertEqual(set(get_args(enum)), set(schema["$defs"]["check"]["properties"][definition]["enum"]))

    def test_advice_items_match_the_schema(self):
        schema = json.loads((ROOT / "schemas/report.schema.json").read_text())
        report = Report([CheckResult("claude.web.egress", "claude", "", "unknown", "info", "")]).to_dict()
        advice = report["summary"]["advice"]
        self.assertTrue(advice)
        allowed = set(schema["$defs"]["advice"]["required"])
        for item in advice:
            self.assertEqual(set(item), allowed)
            self.assertIn(item["priority"], schema["$defs"]["advice"]["properties"]["priority"]["enum"])
            self.assertEqual(set(item["action"]), set(schema["$defs"]["action"]["required"]))

    def test_unknown_and_skipped_are_not_successes(self):
        checks = [CheckResult("u", "test", "", "unknown", "info", ""), CheckResult("s", "test", "", "skipped", "info", "")]
        summary = summarize(checks)
        self.assertEqual(summary["completed"], 0)
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["level"], "incomplete")
