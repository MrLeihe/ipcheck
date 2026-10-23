import type { CheckResult, JsonValue } from "../types/report.ts";

const statusNames = {
  completed: "已验证",
  unknown: "未验证",
  unsupported: "未覆盖",
  skipped: "已跳过",
};

function display(value: JsonValue): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

export function CheckCard({ check }: { check: CheckResult }) {
  const attention = check.status === "completed" && check.severity !== "info";
  const tone = attention
    ? "attention"
    : check.status === "completed"
      ? "complete"
      : "neutral";
  return (
    <article className={`check-card ${tone}`}>
      <div className="card-heading">
        <span className="card-label">{check.label}</span>
        <span className={`status ${tone}`}>
          <span className="status-dot" />
          {attention ? "需核对" : statusNames[check.status]}
        </span>
      </div>
      <h3>{check.summary}</h3>
      {check.evidence.length > 0 && (
        <ul className="evidence">
          {check.evidence.map((text, index) => (
            <li key={index}>{text}</li>
          ))}
        </ul>
      )}
      {Object.keys(check.data).length > 0 && (
        <details>
          <summary>查看观测数据</summary>
          <dl className="data-list">
            {Object.entries(check.data).map(([key, value]) => (
              <div key={key}>
                <dt>{key}</dt>
                <dd>
                  <pre>{display(value)}</pre>
                </dd>
              </div>
            ))}
          </dl>
        </details>
      )}
      <footer className="card-source">
        <span>{check.source}</span>
        <time dateTime={check.observed_at}>
          {new Date(check.observed_at).toLocaleTimeString("zh-CN", {
            hour: "2-digit",
            minute: "2-digit",
          })}
        </time>
      </footer>
    </article>
  );
}
