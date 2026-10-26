import platform

from ipcheck.core.models import CheckResult
from ipcheck.platforms.system import environment_proxy_names, system_proxy
from ipcheck.platforms.tunnel import tunnel_status


def check_proxy() -> list[CheckResult]:
    names = environment_proxy_names()
    kinds, system_available = system_proxy()
    tunnel = tunnel_status()
    labels = {"on": "已开启", "off": "未开启", "connecting": "连接中", "disconnecting": "断开中",
              "unknown": "检测失败", "unsupported": "不支持"}
    return [
        CheckResult("proxy.environment", "system", "进程代理变量", "completed", "info",
                    "已设置" if names else "未设置",
                    ("只检查变量是否存在，不读取或展示其中的凭据。",), {"names": names}),
        CheckResult("proxy.system", "system", "系统代理配置",
                    "completed" if system_available else ("unknown" if platform.system() == "Darwin" else "unsupported"),
                    "info", "已开启" if kinds else ("未开启" if system_available else "读取失败" if platform.system() == "Darwin" else "不支持"),
                    ("配置状态不保证 CLI 或浏览器请求使用该代理。",), {"kinds": kinds}),
        CheckResult("proxy.tunnel", "system", "TUN / VPN",
                    "unknown" if tunnel.state == "unknown" else "unsupported" if tunnel.state == "unsupported" else "completed",
                    "info", labels[tunnel.state],
                    ("检测系统 VPN 连接与 IPv4/IPv6 隧道路由；已开启不代表覆盖所有流量。",
                     "排除 macOS 接口限定默认路由、链路本地与多播路由，不把空闲 utun 接口当作已开启。",
                     "按常见隧道接口名称识别路由，不读取代理客户端控制凭证；未覆盖使用其他接口名且未注册系统 VPN 的客户端。"),
                    {"state": tunnel.state, "interfaces": list(tunnel.interfaces)}, tunnel.source),
    ]
