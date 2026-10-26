"""Opt-in metadata inspection; never copy raw shell lines or credential values."""

import json
import re
from pathlib import Path

from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue

MAX_CONFIG_BYTES = 1024 * 1024


def check_local(home: Path | None = None) -> list[CheckResult]:
    home = home or Path.home()
    results: list[CheckResult] = []
    files: list[JsonValue] = []
    failed = False
    for name in (".zshrc", ".zprofile", ".bashrc", ".bash_profile"):
        path = home / name
        try:
            if not path.is_file():
                continue
            if path.stat().st_size > MAX_CONFIG_BYTES:
                failed = True
                continue
            hits: list[JsonValue] = []
            for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                # Only the variable NAME and line number may leave this function.
                if re.search(r"claude|anthropic", line, re.I):
                    match = re.search(r"\b(ANTHROPIC_[A-Z0-9_]+)\s*=", line)
                    hits.append({"line": number, "variable": match.group(1) if match else "Claude 相关配置"})
            if hits:
                files.append({"file": name, "entries": hits})
        except OSError:
            failed = True
    results.append(CheckResult("local.shell", "local", "Shell 配置摘要", "unknown" if failed else "completed", "info",
                               f"{len(files)} 个文件包含相关配置" + ("，部分文件未能检查" if failed else ""),
                               ("仅输出变量名及行号，配置内容和密钥值始终隐藏。",), {"files": files}))
    current_account: str | None = None
    identity_file = home / ".claude.json"
    identity_failed = False
    if identity_file.exists():
        try:
            if identity_file.stat().st_size > MAX_CONFIG_BYTES:
                raise ValueError("oversized")
            raw = json.loads(identity_file.read_text())
            account = raw.get("oauthAccount") if isinstance(raw, dict) else None
            value = account.get("accountUuid") if isinstance(account, dict) else None
            current_account = value if isinstance(value, str) else None
        except (OSError, ValueError, UnicodeError):
            identity_failed = True
    backup_count = 0
    different_count = 0
    backup_unknown = 0
    try:
        backups = list((home / ".claude/backups").glob("*.claude.json.backup*"))
        for path in backups[:100]:
            backup_count += 1
            try:
                if path.stat().st_size > MAX_CONFIG_BYTES:
                    raise ValueError("oversized")
                raw = json.loads(path.read_text())
                account = raw.get("oauthAccount") if isinstance(raw, dict) else None
                value = account.get("accountUuid") if isinstance(account, dict) else None
                if current_account and isinstance(value, str) and value != current_account:
                    different_count += 1
                elif not current_account or not isinstance(value, str):
                    backup_unknown += 1
            except (OSError, ValueError, UnicodeError):
                backup_unknown += 1
        backup_unknown += max(0, len(backups) - 100)
    except OSError:
        backup_unknown += 1
    results.append(CheckResult("local.identity", "local", "账号备份摘要",
                               "unknown" if identity_failed or backup_unknown else "completed",
                               "warning" if different_count else "info",
                               f"不同账号备份：{different_count} 份" if different_count else "无法比对账号备份" if identity_failed or backup_unknown else "无账号备份" if backup_count == 0 else "备份账号一致",
                               ("只在内存比对账号标识，报告不包含邮箱、UUID 或凭证；不能据此推断服务端关联。",),
                               {"current_config_exists": identity_file.exists(), "backups_checked": backup_count,
                                "different_account_backups": different_count, "unverified_backups": backup_unknown}))
    try:
        telemetry_count = sum(1 for _ in (home / ".claude/telemetry").glob("*.json"))
        results.append(CheckResult("local.telemetry", "local", "遥测文件存在性", "completed", "info",
                                   f"发现 {telemetry_count} 个 JSON 文件", ("未读取事件内容，无法据此判断是否会上传或关联账号。",),
                                   {"files": telemetry_count}))
    except OSError:
        results.append(CheckResult("local.telemetry", "local", "遥测文件存在性", "unknown", "info", "无法读取目录"))
    return results
