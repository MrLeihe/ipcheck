import { useEffect, useMemo, useState } from "react";
import { createClient, sessionToken } from "./api/client.ts";
import { CheckCard } from "./components/CheckCard.tsx";
import { collectBrowser } from "./detection/collect.ts";
import type { Report } from "./types/report.ts";

const groups = [
  {
    id: "network",
    name: "网络观测",
    description: "各查询服务看到的出口与配置",
  },
  {
    id: "system",
    name: "本机环境",
    description: "当前进程、系统配置与路由迹象",
  },
  { id: "claude", name: "CLI 端点", description: "用户配置中发现的服务主机" },
  {
    id: "browser",
    name: "浏览器环境",
    description: "当前网页可观察到的环境特征",
  },
  {
    id: "local",
    name: "本地配置摘要",
    description: "显式启用的文件存在性与身份比对",
  },
];

const delay = (milliseconds: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

export default function App() {
  const client = useMemo(() => createClient(sessionToken()), []);
  const [connected, setConnected] = useState(false);
  const [allowLocal, setAllowLocal] = useState(false);
  const [includeLocal, setIncludeLocal] = useState(false);
  const [includeFonts, setIncludeFonts] = useState(false);
  const [includeReputation, setIncludeReputation] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState({ completed: 0, total: 0 });
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    let disposed = false;
    void client
      .session()
      .then((session) => {
        if (!disposed) {
          setAllowLocal(session.allow_local);
          setConnected(true);
        }
      })
      .catch(() => {
        if (!disposed)
          setError(
            "无法建立本机会话。请使用 ipcheck web 输出的完整地址打开页面。",
          );
      });
    return () => {
      disposed = true;
    };
  }, [client]);

  async function run() {
    setRunning(true);
    setError("");
    setReport(null);
    setProgress({ completed: 0, total: 0 });
    try {
      await client.run(includeLocal, includeReputation);
      const deadline = Date.now() + 90_000;
      while (Date.now() < deadline) {
        const state = await client.state();
        setProgress({ completed: state.completed, total: state.total });
        if (state.failed)
          throw new Error("本地检测未能完成，请重试或查看命令行环境。");
        if (!state.running && state.report) {
          // Preserve the network report even if browser collection fails.
          setReport(state.report);
          const combined = await client.browser(
            state.report.id,
            collectBrowser(includeFonts),
          );
          setReport(combined);
          return;
        }
        await delay(500);
      }
      throw new Error("等待检测超时。后台可能仍在运行，请稍后重试。");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "检测未完成");
    } finally {
      setRunning(false);
    }
  }

  function download() {
    if (!report) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `ipcheck-${report.id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  const activeGroups = groups.filter(
    (group) => filter === "all" || filter === group.id,
  );
  const summary = report?.summary;
  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="ipcheck 首页">
          <span className="brand-symbol">
            i<span>p</span>
          </span>
          <span>
            ipcheck<span className="brand-version"> / 0.1</span>
          </span>
        </a>
        <div className="connection">
          <span
            className={connected ? "connection-dot online" : "connection-dot"}
          />
          {connected ? "本机会话已连接" : "等待本机连接"}
        </div>
      </header>

      <main>
        <section className="hero">
          <div className="hero-copy">
            <p className="eyebrow">LOCAL ENVIRONMENT OBSERVATORY</p>
            <h1>
              看清你的
              <br />
              网络与运行环境<span className="accent">。</span>
            </h1>
            <p className="hero-description">
              把出口、代理、端点和浏览器特征放在一起。
              <br />
              每项结论都有来源，未能验证的部分也会如实呈现。
            </p>
            <div className="hero-meta">
              <span>仅本机访问</span>
              <span>密钥始终隐藏</span>
              <span>无账号登录</span>
            </div>
          </div>
          <div className="control-panel">
            <div className="panel-heading">
              <span className="eyebrow">检测范围</span>
              <span className="scope-tag">网络 + 浏览器</span>
            </div>
            <p className="scope-description">
              基础检查会联系 HTTPS IP 查询服务，观测当前测试请求的出口。
            </p>
            <label className="option">
              <input
                type="checkbox"
                checked={includeReputation}
                onChange={(event) => setIncludeReputation(event.target.checked)}
                disabled={running}
              />
              <span>
                <strong>额外 IP 信誉查询</strong>
                <small>将观测 IP 发送至 proxycheck.io / StopForumSpam</small>
              </span>
            </label>
            <label className="option">
              <input
                type="checkbox"
                checked={includeFonts}
                onChange={(event) => setIncludeFonts(event.target.checked)}
                disabled={running}
              />
              <span>
                <strong>有限字体特征</strong>
                <small>在当前浏览器比较 8 种字体的渲染宽度</small>
              </span>
            </label>
            <label className={`option ${allowLocal ? "" : "disabled"}`}>
              <input
                type="checkbox"
                checked={includeLocal}
                onChange={(event) => setIncludeLocal(event.target.checked)}
                disabled={running || !allowLocal}
              />
              <span>
                <strong>本地配置摘要</strong>
                <small>
                  {allowLocal
                    ? "只显示存在性、变量名及比对数量"
                    : "使用 ipcheck web --allow-local 可启用"}
                </small>
              </span>
            </label>
            <button
              className="primary-button"
              onClick={() => {
                void run();
              }}
              disabled={running || !connected}
            >
              {running ? "正在采集观测…" : report ? "重新检测" : "开始环境检测"}
              <span aria-hidden="true">↗</span>
            </button>
            <p className="button-caption" role="status">
              {running
                ? `已完成 ${progress.completed}/${progress.total || "—"} 组本机检查`
                : "检测结果保留在当前本机会话，导出由你决定。"}
            </p>
          </div>
        </section>

        {error && (
          <div className="error-banner" role="alert">
            {error}
          </div>
        )}

        <section className="report-section" aria-label="检测报告">
          <div className="report-heading">
            <div>
              <p className="eyebrow">OBSERVATIONS</p>
              <h2>环境观测报告</h2>
            </div>
            <button
              className="secondary-button"
              onClick={download}
              disabled={!report || running}
            >
              导出 JSON <span aria-hidden="true">↓</span>
            </button>
          </div>
          <div className="summary-grid" aria-live="polite">
            <div className="metric">
              <span>已完成检查</span>
              <strong>
                {summary ? summary.completed.toString().padStart(2, "0") : "—"}
                <small>{summary ? ` / ${summary.total}` : ""}</small>
              </strong>
            </div>
            <div className="metric warning-metric">
              <span>需要核对</span>
              <strong>
                {summary
                  ? summary.issue_ids.length.toString().padStart(2, "0")
                  : "—"}
              </strong>
            </div>
            <div className="metric">
              <span>尚未验证</span>
              <strong>
                {summary ? summary.unknown.toString().padStart(2, "0") : "—"}
              </strong>
            </div>
            <div className="metric conclusion">
              <span>当前结论</span>
              <strong>{summary?.message ?? "等待一次新的观测"}</strong>
              <small>
                {summary
                  ? `另有 ${summary.skipped} 项明确跳过`
                  : "开始检测后在这里查看结果"}
              </small>
            </div>
          </div>
          <nav className="filters" aria-label="报告分类">
            <button
              className={filter === "all" ? "active" : ""}
              onClick={() => setFilter("all")}
            >
              全部观测
            </button>
            {groups.map((group) => (
              <button
                key={group.id}
                className={filter === group.id ? "active" : ""}
                onClick={() => setFilter(group.id)}
              >
                {group.name}
              </button>
            ))}
          </nav>
          {!report ? (
            <div className="empty-state">
              <div
                className={`observation-orbit ${running ? "scanning" : ""}`}
                aria-hidden="true"
              >
                <span>+</span>
              </div>
              <h3>{running ? "正在建立本次环境快照" : "从一次观测开始"}</h3>
              <p>
                {running
                  ? "各项检查独立执行，进度按实际完成的任务更新。"
                  : "选择检测范围，查看有证据支撑的结果与仍待确认的部分。"}
              </p>
            </div>
          ) : (
            activeGroups.map((group) => {
              const checks = report.checks.filter(
                (check) => check.group === group.id,
              );
              return checks.length > 0 ? (
                <section className="check-group" key={group.id}>
                  <div className="group-heading">
                    <h2>
                      {group.name}
                      <span>{checks.length.toString().padStart(2, "0")}</span>
                    </h2>
                    <p>{group.description}</p>
                  </div>
                  <div className="check-grid">
                    {checks.map((check) => (
                      <CheckCard key={check.id} check={check} />
                    ))}
                  </div>
                </section>
              ) : null;
            })
          )}
          <aside className="report-note">
            <span aria-hidden="true">ⓘ</span>
            <p>
              配置与观测反映的是检测时刻的环境。它们不能证明其他应用的实际请求路径，也不代表平台的账号安全或风控判断。
            </p>
          </aside>
        </section>
      </main>
      <footer className="site-footer">
        <span>ipcheck · 本地环境诊断</span>
        <span>
          参考{" "}
          <a
            href="https://github.com/stormzhang/ipcheck"
            target="_blank"
            rel="noreferrer"
          >
            stormzhang/ipcheck
          </a>{" "}
          与{" "}
          <a
            href="https://github.com/yacuo/check-cc"
            target="_blank"
            rel="noreferrer"
          >
            yacuo/check-cc
          </a>{" "}
          · 保留上游许可
        </span>
      </footer>
    </div>
  );
}
