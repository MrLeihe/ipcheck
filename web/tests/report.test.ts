import assert from "node:assert/strict";
import test from "node:test";
import { isReport, parseRunState } from "../src/types/report.ts";

const report = {
  schema_version: "1.0",
  id: "synthetic-report",
  created_at: "2026-01-01T00:00:00Z",
  checks: [
    {
      id: "test",
      group: "test",
      label: "test",
      status: "unknown",
      severity: "info",
      summary: "unverified",
      evidence: [],
      data: {},
      source: "synthetic",
      observed_at: "2026-01-01T00:00:00Z",
    },
  ],
  summary: {
    completed: 0,
    unknown: 1,
    skipped: 0,
    total: 1,
    issue_ids: [],
    message: "incomplete",
  },
};

test("accepts a report with explicitly unknown observations", () => {
  assert.equal(isReport(report), true);
  assert.equal(
    parseRunState({
      running: false,
      failed: false,
      completed: 1,
      total: 1,
      report,
    }).report?.summary.unknown,
    1,
  );
});

test("rejects incompatible protocol versions and invalid progress", () => {
  assert.equal(isReport({ ...report, schema_version: "2.0" }), false);
  assert.throws(() =>
    parseRunState({
      running: true,
      failed: false,
      completed: 3,
      total: 2,
      report: null,
    }),
  );
});

test("rejects unsupported statuses rather than interpreting them as success", () => {
  assert.equal(
    isReport({ ...report, checks: [{ ...report.checks[0], status: "safe" }] }),
    false,
  );
});
