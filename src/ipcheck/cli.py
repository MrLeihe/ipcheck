import argparse
import os
import shutil
import sys
from pathlib import Path

from ipcheck import __version__
from ipcheck.core.runner import Options, run_checks
from ipcheck.output.render import render_json, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="网络、本机配置与浏览器环境诊断；不会保证账号安全。")
    parser.add_argument("--version", action="version", version=f"ipcheck-local {__version__}")
    parser.add_argument("--json", action="store_true", help="输出脱敏 JSON")
    parser.add_argument("--details", action="store_true", help="展开检测证据与脱敏原始数据")
    parser.add_argument("--local", action="store_true", help="只运行本地配置摘要检查")
    parser.add_argument("--full", action="store_true", help="网络与本地摘要检查")
    parser.add_argument("--reputation", action="store_true", help="将观测 IP 发送至额外的信誉查询服务")
    parser.add_argument("--timeout", type=float, default=4, help="单次网络超时秒数（1–15）")
    parser.add_argument("--output", type=Path, help="将脱敏 JSON 写入新文件（不覆盖已有文件）")
    sub = parser.add_subparsers(dest="command")
    web = sub.add_parser("web", help="启动仅本机可访问的网页")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--no-browser", action="store_true")
    web.add_argument("--allow-local", action="store_true", help="允许网页显式启动本地摘要检查")
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 15:
        parser.error("--timeout 必须在 1–15 秒之间")
    if args.command == "web":
        from ipcheck.server.app import serve
        if not 0 <= args.port <= 65535:
            parser.error("端口必须在 0–65535 之间")
        return serve(args.port, args.no_browser, args.allow_local)
    try:
        report = run_checks(Options(network=not args.local or args.full, local=args.local or args.full,
                                    reputation=args.reputation, timeout=args.timeout))
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(render_json(report) + "\n")
        color = sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ
        print(render_json(report) if args.json else render_text(
            report, details=args.details, color=color, width=shutil.get_terminal_size((100, 24)).columns))
        summary = report.to_dict()["summary"]
        if isinstance(summary, dict):
            return 2 if summary["unknown"] else 1 if summary["issue_ids"] else 0
        return 2
    except KeyboardInterrupt:
        print("检测已中止", file=sys.stderr)
        return 130
    except OSError:
        print("无法写入报告，请检查路径、权限或文件是否已存在。", file=sys.stderr)
        return 2
