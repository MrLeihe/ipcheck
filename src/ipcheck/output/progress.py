"""Transient terminal activity; never writes into machine-readable reports."""

import shutil
import sys
import threading
import time
import unicodedata
from typing import TextIO

LABELS = {
    "network": "公网出口与归属", "direct_ip": "本机公网 IP",
    "ipv6_local": "IPv6 配置", "dns": "DNS 配置", "proxy": "代理与 TUN",
    "timezone": "系统时区", "claude": "Claude 配置",
    "claude_route": "Claude 出口与归属", "local": "本机配置",
    "locations": "出口 IP 地区", "reputation": "IP 类型与信誉", "assessment": "综合分析",
}


def fit(text: str, width: int) -> str:
    result = ""
    used = 0
    for char in text:
        size = 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        if used + size > width:
            break
        result += char
        used += size
    return result


class TerminalProgress:
    def __init__(self, enabled: bool, stream: TextIO | None = None):
        self.enabled = enabled
        self.stream = stream if stream is not None else sys.stderr
        self.completed = self.total = 0
        self.active: tuple[str, ...] = ()
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.started = 0.0
        self.drawn = False
        self.frame = 0

    def update(self, completed: int, total: int) -> None:
        with self.lock:
            self.completed, self.total = completed, total

    def set_active(self, active: tuple[str, ...]) -> None:
        with self.lock:
            self.active = active

    def draw(self) -> None:
        with self.lock:
            width = max(1, shutil.get_terminal_size((100, 24)).columns - 1)
            marker = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[self.frame % 10]
            self.frame += 1
            status = f"{marker} 检测中 · 已完成 {self.completed}/{self.total} · 耗时 {time.monotonic() - self.started:.1f} 秒"
            tasks = "、".join(LABELS.get(name, "检测项目") for name in self.active)
            detail = f"  正在检测：{tasks}" if tasks else "  正在调度检测项目…"
            prefix = "\x1b[1A\r" if self.drawn else "\r"
            self.stream.write(prefix + "\x1b[2K" + fit(status, width) + "\n\r\x1b[2K" + fit(detail, width))
            self.stream.flush()
            self.drawn = True

    def animate(self) -> None:
        while not self.stop.wait(0.1):
            self.draw()

    def __enter__(self) -> "TerminalProgress":
        if self.enabled:
            self.started = time.monotonic()
            self.draw()
            self.thread = threading.Thread(target=self.animate, daemon=True)
            self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        if self.thread:
            self.stop.set()
            self.thread.join()
        if self.drawn:
            self.stream.write("\r\x1b[2K\x1b[1A\r\x1b[2K")
            self.stream.flush()
