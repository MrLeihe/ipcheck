import platform

from ipcheck.core.models import CheckResult
from ipcheck.platforms.system import environment_proxy_names, system_proxy, tunnel_routes


def check_proxy() -> list[CheckResult]:
    names = environment_proxy_names()
    kinds, system_available = system_proxy()
    tunnels, route_available = tunnel_routes()
    return [
        CheckResult("proxy.environment", "system", "进程代理变量", "completed", "info",
                    "已设置代理变量" if names else "当前进程未设置代理变量",
                    ("只检查变量是否存在，不读取或展示其中的凭据。",), {"names": names}),
        CheckResult("proxy.system", "system", "系统代理配置",
                    "completed" if system_available else ("unknown" if platform.system() == "Darwin" else "unsupported"),
                    "info", "已启用：" + "、".join(kinds) if kinds else ("未启用系统代理" if system_available else "当前平台或环境无法读取系统代理"),
                    ("配置状态不保证 CLI 或浏览器请求使用该代理。",), {"kinds": kinds}),
        CheckResult("proxy.tunnel", "system", "隧道路由迹象",
                    "completed" if route_available else "unknown", "info",
                    "存在隧道路由迹象" if tunnels else ("未发现已识别的隧道路由" if route_available else "无法读取路由表"),
                    ("隧道存在与否不作为账号风险或代理完整性的结论。",), {"interfaces": tunnels}),
    ]
