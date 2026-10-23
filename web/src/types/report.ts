export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };
export type Status = "completed" | "unknown" | "unsupported" | "skipped";
export type Severity = "info" | "warning" | "error";

export interface CheckResult {
  id: string;
  group: string;
  label: string;
  status: Status;
  severity: Severity;
  summary: string;
  evidence: string[];
  data: Record<string, JsonValue>;
  source: string;
  observed_at: string;
}

export interface Report {
  schema_version: "1.0";
  id: string;
  created_at: string;
  checks: CheckResult[];
  summary: {
    completed: number;
    unknown: number;
    skipped: number;
    total: number;
    issue_ids: string[];
    message: string;
  };
}

export interface RunState {
  running: boolean;
  failed: boolean;
  completed: number;
  total: number;
  report: Report | null;
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isJson(value: unknown): value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJson);
  return isObject(value) && Object.values(value).every(isJson);
}

function strings(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.every((item: unknown) => typeof item === "string")
  );
}

function nonnegative(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

export function isReport(value: unknown): value is Report {
  if (
    !isObject(value) ||
    value.schema_version !== "1.0" ||
    typeof value.id !== "string" ||
    typeof value.created_at !== "string" ||
    !Array.isArray(value.checks)
  )
    return false;
  const validChecks = value.checks.every(
    (check: unknown) =>
      isObject(check) &&
      ["id", "group", "label", "summary", "source", "observed_at"].every(
        (key) => typeof check[key] === "string",
      ) &&
      ["completed", "unknown", "unsupported", "skipped"].includes(
        String(check.status),
      ) &&
      ["info", "warning", "error"].includes(String(check.severity)) &&
      strings(check.evidence) &&
      isObject(check.data) &&
      isJson(check.data),
  );
  const summary = value.summary;
  return (
    validChecks &&
    isObject(summary) &&
    ["completed", "unknown", "skipped", "total"].every((key) =>
      nonnegative(summary[key]),
    ) &&
    strings(summary.issue_ids) &&
    typeof summary.message === "string" &&
    summary.total === value.checks.length
  );
}

export function parseRunState(value: unknown): RunState {
  if (
    !isObject(value) ||
    typeof value.running !== "boolean" ||
    typeof value.failed !== "boolean" ||
    !nonnegative(value.completed) ||
    !nonnegative(value.total) ||
    value.completed > value.total ||
    !(value.report === null || isReport(value.report))
  )
    throw new Error("本地服务返回的报告格式不受支持");
  return {
    running: value.running,
    failed: value.failed,
    completed: value.completed,
    total: value.total,
    report: value.report,
  };
}
