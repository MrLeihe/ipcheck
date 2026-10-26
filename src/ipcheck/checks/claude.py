import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue

# Exact registrable domains, not substring hints. Attribution: see docs/upstream-sources.md.
PROVIDERS = {"deepseek.com": "DeepSeek", "moonshot.cn": "Moonshot", "moonshot.ai": "Moonshot",
             "bigmodel.cn": "智谱", "minimax.io": "MiniMax", "minimaxi.com": "MiniMax",
             "dashscope.aliyuncs.com": "阿里云 DashScope"}


def classify_endpoint(url: str) -> tuple[str, str, str | None]:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
        if parsed.scheme not in ("https", "http") or not host:
            return "invalid", "地址格式无效", None
        if parsed.scheme != "https" or parsed.username or parsed.password:
            return "insecure", "端点使用明文 HTTP 或包含凭据，需核对", host
        if host == "api.anthropic.com" and port in (None, 443):
            return "official", "配置指向 Anthropic 官方 API 主机", host
        for domain, label in PROVIDERS.items():
            if host == domain or host.endswith("." + domain):
                return "provider", f"配置指向已识别服务商：{label}", host
        return "custom", "自定义 API，需确认服务商", host
    except ValueError:
        return "invalid", "地址格式无效", None


def check_claude(home: Path | None = None) -> list[CheckResult]:
    home = home or Path.home()
    config_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR") or home / ".claude")
    candidates: list[tuple[str, str]] = []
    unreadable = False
    env = os.environ.get("ANTHROPIC_BASE_URL")
    if env:
        candidates.append(("当前进程环境变量", env))
    for name in ("settings.json", "settings.local.json"):
        path = config_dir / name
        if not path.exists():
            continue
        try:
            if path.stat().st_size > 1024 * 1024:
                unreadable = True
                continue
            settings = json.loads(path.read_text())
            env_values = settings.get("env", {}) if isinstance(settings, dict) else {}
            url = env_values.get("ANTHROPIC_BASE_URL") if isinstance(env_values, dict) else None
            if isinstance(url, str) and url:
                candidates.append((f"用户配置 {name}", url))
        except (OSError, ValueError, UnicodeError):
            unreadable = True
    if not candidates:
        return [CheckResult("claude.endpoint", "claude", "Claude API 配置",
                            "unknown" if unreadable else "completed", "info",
                            "部分配置无法读取，无法确认" if unreadable else "未发现覆盖，默认使用官方 API",
                            ("仅检查当前进程环境变量和用户配置。",
                             "未检查项目配置、受管设置和运行中客户端，不能据此确认客户端使用官方 API。",))]
    evidence: list[str] = []
    descriptions: list[JsonValue] = []
    kinds: list[str] = []
    summaries: list[str] = []
    signatures: set[tuple[str, str | None]] = set()
    for source, url in candidates:
        kind, summary, host = classify_endpoint(url)
        kinds.append(kind)
        summaries.append(summary)
        signatures.add((kind, host))
        evidence.append(f"{source}：{summary}" + (f"（{host}）" if host else ""))
        descriptions.append({"source": source, "kind": kind, "host": host})
    conflict = len(signatures) > 1
    issue = conflict or unreadable or any(kind in ("custom", "insecure", "invalid") for kind in kinds)
    return [CheckResult("claude.endpoint", "claude", "Claude API 配置", "completed", "warning" if issue else "info",
                        "多个配置来源不同，需要核对生效设置" if conflict else summaries[0],
                        tuple(evidence + ["只展示主机和配置来源，不发送密钥、不探测账号，也不推断账号安全。"] + (["部分配置无法读取。"] if unreadable else [])),
                        {"endpoints": descriptions, "conflict": conflict})]
