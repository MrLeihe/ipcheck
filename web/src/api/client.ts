import { isObject, isReport, parseRunState } from "../types/report.ts";
import type { Report, RunState } from "../types/report.ts";
import type { BrowserSnapshot } from "../detection/collect.ts";

export function sessionToken(): string {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const fresh = params.get("token");
  if (fresh) {
    sessionStorage.setItem("ipcheck.session", fresh);
    history.replaceState(null, "", window.location.pathname);
  }
  return fresh ?? sessionStorage.getItem("ipcheck.session") ?? "";
}

export function createClient(token: string) {
  async function request(path: string, body?: unknown): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await fetch(path, {
        method: body === undefined ? "GET" : "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
        credentials: "omit",
      });
      const data: unknown = await response.json();
      if (!response.ok)
        throw new Error(
          isObject(data) && typeof data.error === "string"
            ? data.error
            : "本地请求失败",
        );
      return data;
    } finally {
      clearTimeout(timer);
    }
  }
  return {
    async session(): Promise<{ allow_local: boolean }> {
      const result = await request("/api/session");
      if (!isObject(result) || typeof result.allow_local !== "boolean")
        throw new Error("会话信息格式无效");
      return { allow_local: result.allow_local };
    },
    async run(local: boolean, reputation: boolean): Promise<void> {
      await request("/api/run", { local, reputation });
    },
    async state(): Promise<RunState> {
      return parseRunState(await request("/api/report"));
    },
    async browser(
      reportId: string,
      snapshot: BrowserSnapshot,
    ): Promise<Report> {
      const result = await request("/api/browser", {
        report_id: reportId,
        snapshot,
      });
      if (!isObject(result) || !isReport(result.report))
        throw new Error("浏览器报告格式无效");
      return result.report;
    },
  };
}
