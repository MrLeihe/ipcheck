import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from ipcheck import __version__
from ipcheck.core.privacy import JsonValue

TRACE_HOSTS = frozenset({"api.anthropic.com", "claude.ai"})
CLOUDFLARE_HOST = "www.cloudflare.com"
ALLOWED_HOSTS = frozenset({"api.ipify.org", "api6.ipify.org", "ipv6.icanhazip.com", "checkip.amazonaws.com", "ipwho.is", "proxycheck.io", "api.stopforumspam.org"}) | TRACE_HOSTS | {CLOUDFLARE_HOST}
DIRECT_IP_URLS = frozenset({"https://4.ipw.cn/", "https://myip.ipip.net/"})
ALLOWED_HOSTS |= frozenset(urlsplit(url).hostname for url in DIRECT_IP_URLS)
MAX_RESPONSE_BYTES = 256 * 1024


class ProviderError(Exception):
    """Only safe, fixed error messages may cross the collector boundary."""


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, fixed_urls: frozenset[str] | None = None):
        self.fixed_urls = fixed_urls

    def redirect_request(self, req: urllib.request.Request, fp: object, code: int, msg: str, headers: object, newurl: str) -> urllib.request.Request | None:
        if self.fixed_urls is not None and newurl not in self.fixed_urls:
            raise ProviderError("直连 IP 查询返回了不受支持的跳转")
        if urlsplit(newurl).scheme != "https" or urlsplit(newurl).hostname != urlsplit(req.full_url).hostname:
            raise ProviderError("查询服务返回了不受支持的跳转")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpClient:
    def __init__(self, timeout: float = 4, *, direct_location: bool = False, direct_ip: bool = False):
        if direct_location and direct_ip:
            raise ValueError("直连模式不能同时启用")
        self.timeout = timeout
        self.direct_location = direct_location
        self.direct_ip = direct_ip

    def text(self, url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise ProviderError("查询地址不在允许的 HTTPS 服务列表中")
        if parsed.hostname in TRACE_HOSTS and (parsed.path != "/cdn-cgi/trace" or parsed.query or parsed.fragment):
            raise ProviderError("Claude 探测仅允许公开的同域名 trace 接口")
        if parsed.hostname == CLOUDFLARE_HOST and (parsed.path != "/cdn-cgi/trace" or parsed.query or parsed.fragment):
            raise ProviderError("Cloudflare 探测仅允许固定的 trace 接口")
        if parsed.hostname == "ipv6.icanhazip.com" and (parsed.path != "/" or parsed.query or parsed.fragment):
            raise ProviderError("IPv6 备用探测仅允许固定的地址回显接口")
        if self.direct_ip and url not in DIRECT_IP_URLS:
            raise ProviderError("直连 IP 仅允许固定的公网地址回显服务")
        if self.direct_location:
            try:
                address = ipaddress.ip_address(parsed.path.removeprefix("/"))
            except ValueError:
                raise ProviderError("归属回退仅允许查询已观测的公网 IP") from None
            if parsed.hostname != "ipwho.is" or not address.is_global or parsed.query or parsed.fragment:
                raise ProviderError("归属回退仅允许查询已观测的公网 IP")
        request = urllib.request.Request(url, headers={"User-Agent": f"ipcheck/{__version__}", "Accept": "application/json,text/plain"})
        # urllib honours process/system proxy configuration; never attach application keys.
        handlers = [SafeRedirect(DIRECT_IP_URLS if self.direct_ip else None)]
        if self.direct_location or self.direct_ip:
            handlers.append(urllib.request.ProxyHandler({}))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ProviderError("查询响应超出大小限制")
                return raw.decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"查询服务返回 HTTP {exc.code}") from None
        except (TimeoutError, socket.timeout):
            raise ProviderError("查询超时") from None
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise ProviderError("TLS 证书验证失败") from None
            if isinstance(reason, ssl.SSLError):
                raise ProviderError("TLS 握手失败或连接被提前关闭") from None
            if isinstance(reason, socket.gaierror):
                raise ProviderError("DNS 无法解析查询服务域名") from None
            if isinstance(reason, (TimeoutError, socket.timeout)):
                raise ProviderError("查询超时") from None
            raise ProviderError("无法连接查询服务，可能与网络、代理或服务状态有关") from None
        except (UnicodeError, OSError, ValueError):
            raise ProviderError("查询响应无法读取") from None

    def json(self, url: str) -> dict[str, JsonValue]:
        try:
            data = json.loads(self.text(url))
        except (ValueError, RecursionError):
            raise ProviderError("查询服务返回了无效 JSON") from None
        if not isinstance(data, dict):
            raise ProviderError("查询服务返回的数据结构无效")
        return data
