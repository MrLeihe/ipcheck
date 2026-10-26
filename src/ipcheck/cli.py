import argparse
import os
import shutil
import sys
from pathlib import Path

from ipcheck import __version__
from ipcheck.core.runner import Options, run_checks
from ipcheck.output.progress import TerminalProgress
from ipcheck.output.render import render_json, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Claude AI 出口 IP、代理、DNS 与时区风险检测；不会保证账号安全。")
    parser.add_argument("--version", action="version", version=f"ipcheck-local {__version__}")
    parser.add_argument("--json", action="store_true", help="输出脱敏 JSON")
    parser.add_argument("--details", action="store_true", help="展开检测证据与脱敏原始数据")
    parser.add_argument("--local", action="store_true", help="只运行本地配置摘要检查")
    parser.add_argument("--full", action="store_true", help="网络与本地摘要检查")
    reputation = parser.add_mutually_exclusive_group()
    reputation.add_argument("--reputation", dest="reputation", action="store_true", help="查询 Claude 出口 IP 类型与信誉（默认开启）")
    reputation.add_argument("--no-reputation", dest="reputation", action="store_false", help="不将 Claude 出口 IP 发送至信誉服务")
    parser.set_defaults(reputation=True)
    parser.add_argument("--timeout", type=float, default=4, help="单次网络超时秒数（1–15）")
    parser.add_argument("--output", type=Path, help="将脱敏 JSON 写入新文件（不覆盖已有文件）")
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 15:
        parser.error("--timeout 必须在 1–15 秒之间")
    try:
        interactive = (not args.json and not args.output and sys.stdout.isatty()
                       and sys.stderr.isatty() and os.environ.get("TERM") != "dumb")
        with TerminalProgress(interactive) as progress:
            report = run_checks(Options(network=not args.local or args.full, local=args.local or args.full,
                                        reputation=args.reputation, timeout=args.timeout),
                                progress=progress.update, activity=progress.set_active)
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(render_json(report) + "\n")
        color = sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ
        print(render_json(report) if args.json else render_text(
            report, details=args.details, color=color, width=shutil.get_terminal_size((100, 24)).columns))
        summary = report.to_dict()["summary"]
        level = summary.get("level") if isinstance(summary, dict) else None
        return {"clear": 0, "attention": 1, "incomplete": 2}.get(str(level), 2)
    except KeyboardInterrupt:
        print("检测已中止", file=sys.stderr)
        return 130
    except OSError:
        print("无法写入报告，请检查路径、权限或文件是否已存在。", file=sys.stderr)
        return 2
