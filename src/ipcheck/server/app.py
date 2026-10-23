import hmac
import json
import mimetypes
import secrets
import threading
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ipcheck.core.models import Report
from ipcheck.core.privacy import JsonValue
from ipcheck.core.runner import Options, Progress, run_checks
from ipcheck.server.browser import merge_browser, validate_snapshot

RunFunction = Callable[[Options, Progress | None], Report]
MAX_BODY_BYTES = 16 * 1024


class APIError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message


class State:
    def __init__(self, allow_local: bool = False, runner: RunFunction = run_checks):
        self.token = secrets.token_urlsafe(32)
        self.allow_local = allow_local
        self.runner = runner
        self.lock = threading.Lock()
        self.running = False
        self.completed = 0
        self.total = 0
        self.report: Report | None = None
        self.failed = False

    def progress(self, completed: int, total: int) -> None:
        with self.lock:
            self.completed, self.total = completed, total

    def start(self, options: Options) -> None:
        with self.lock:
            if self.running:
                raise APIError(409, "已有检测正在运行")
            self.running, self.failed = True, False
            self.completed = self.total = 0
            self.report = None

        def execute() -> None:
            try:
                report = self.runner(options, self.progress)
                with self.lock:
                    self.report = report
            except Exception:
                with self.lock:
                    self.failed = True
            finally:
                with self.lock:
                    self.running = False

        threading.Thread(target=execute, daemon=True, name="ipcheck-run").start()

    def snapshot(self) -> dict[str, JsonValue]:
        with self.lock:
            return {"running": self.running, "failed": self.failed, "completed": self.completed,
                    "total": self.total, "report": self.report.to_dict() if self.report else None}


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, state: State, static_dir: Path):
        self.state = state
        self.static_dir = static_dir.resolve()
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"


class Handler(BaseHTTPRequestHandler):
    server: LocalServer
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: object) -> None:
        # Requests, fragments and credentials must never enter terminal logs.
        return

    def security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")

    def respond(self, status: int, value: dict[str, JsonValue]) -> None:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
        self.send_response(status)
        self.security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def guard(self, authenticated: bool) -> None:
        if self.headers.get("Host") != self.server.origin.removeprefix("http://"):
            raise APIError(403, "Host 不受支持")
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.server.origin:
            raise APIError(403, "Origin 不受支持")
        if authenticated:
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied.encode(), f"Bearer {self.server.state.token}".encode()):
                raise APIError(401, "需要当前本地会话的访问凭证")
            if self.command == "POST" and origin != self.server.origin:
                raise APIError(403, "修改请求需要同源 Origin")

    def body(self) -> dict[str, object]:
        if self.headers.get("Transfer-Encoding"):
            raise APIError(400, "不支持该请求传输格式")
        if self.headers.get_content_type() != "application/json":
            raise APIError(415, "请求必须为 application/json")
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise APIError(400, "请求长度无效") from None
        if size < 1 or size > MAX_BODY_BYTES:
            raise APIError(413, "请求大小超出限制")
        self.connection.settimeout(5)
        try:
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("incomplete")
            value = json.loads(raw)
        except (ValueError, UnicodeError, TimeoutError, RecursionError):
            raise APIError(400, "请求 JSON 无效") from None
        if not isinstance(value, dict):
            raise APIError(400, "请求必须为 JSON 对象")
        return value

    def do_GET(self) -> None:
        try:
            path = urlsplit(self.path).path
            self.guard(path.startswith("/api/"))
            if path == "/api/session":
                self.respond(200, {"allow_local": self.server.state.allow_local, "schema_version": "1.0"})
            elif path == "/api/report":
                self.respond(200, self.server.state.snapshot())
            elif path.startswith("/api/"):
                raise APIError(404, "接口不存在")
            else:
                self.static(path)
        except APIError as exc:
            self.respond(exc.status, {"error": exc.message})
        except (OSError, ValueError):
            self.close_connection = True

    def static(self, path: str) -> None:
        relative = "index.html" if path == "/" else unquote(path).lstrip("/")
        target = (self.server.static_dir / relative).resolve()
        if not target.is_relative_to(self.server.static_dir) or not target.is_file():
            raise APIError(404, "资源不存在")
        raw = target.read_bytes()
        self.send_response(200)
        self.security_headers()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        try:
            self.guard(True)
            path = urlsplit(self.path).path
            body = self.body()
            if path == "/api/run":
                if set(body) != {"local", "reputation"} or any(not isinstance(body[key], bool) for key in body):
                    raise APIError(400, "检测选项无效")
                local = body["local"] is True
                if local and not self.server.state.allow_local:
                    raise APIError(403, "启动服务时未允许本地摘要检查")
                self.server.state.start(Options(local=local, reputation=body["reputation"] is True))
                self.respond(202, {"started": True})
            elif path == "/api/browser":
                if set(body) != {"report_id", "snapshot"}:
                    raise APIError(400, "浏览器请求字段无效")
                try:
                    snapshot = validate_snapshot(body["snapshot"])
                except ValueError as exc:
                    raise APIError(400, str(exc)) from None
                state = self.server.state
                with state.lock:
                    if state.running or not state.report or state.report.id != body["report_id"]:
                        raise APIError(409, "报告已变化，请重新检测")
                    state.report = merge_browser(state.report, snapshot)
                    value = state.report.to_dict()
                self.respond(200, {"report": value})
            else:
                raise APIError(404, "接口不存在")
        except APIError as exc:
            self.respond(exc.status, {"error": exc.message})
        except (OSError, ValueError):
            self.close_connection = True


def serve(port: int, no_browser: bool, allow_local: bool) -> int:
    static_dir = Path(__file__).resolve().parents[1] / "static"
    if not (static_dir / "index.html").is_file():
        print("网页资源尚未生成。请在项目目录按 README 的网页构建说明准备资源。")
        return 2
    try:
        server = LocalServer(port, State(allow_local), static_dir)
    except OSError:
        print("无法绑定本地端口，请检查端口占用。")
        return 2
    url = f"{server.origin}/#token={server.state.token}"
    print(f"本地网页：{url}\n会话地址仅用于本机访问，请勿分享。按 Ctrl+C 退出。")
    if not no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n本地服务已停止。")
    finally:
        server.server_close()
    return 0
