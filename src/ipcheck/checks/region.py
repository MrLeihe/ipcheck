"""Compare observed Claude exits with Anthropic's published supported regions.

The policy is a published availability list, not a risk model: an unsupported
country means the service is not offered there, and says nothing about bans.
Territories and dependencies of a listed country are supported by the policy,
so they are resolved through their parent country instead of being reported as
unsupported.
"""

import json
from importlib.resources import files

from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue

DATA_FILE = "data/claude_regions.json"
# Cloudflare trace uses non-ISO placeholders for unknown and Tor exits.
UNKNOWN_CODES = frozenset({"XX", "T1"})
# Territories and dependencies of listed countries (policy: supported).
TERRITORIES = {
    "PR": "US", "GU": "US", "VI": "US", "AS": "US", "MP": "US", "UM": "US",
    "GG": "GB", "JE": "GB", "IM": "GB", "GI": "GB", "BM": "GB", "KY": "GB", "VG": "GB",
    "TC": "GB", "AI": "GB", "MS": "GB", "FK": "GB", "SH": "GB", "IO": "GB", "PN": "GB", "GS": "GB",
    "GP": "FR", "MQ": "FR", "GF": "FR", "RE": "FR", "YT": "FR", "PM": "FR", "BL": "FR",
    "MF": "FR", "NC": "FR", "PF": "FR", "WF": "FR", "TF": "FR",
    "AW": "NL", "CW": "NL", "SX": "NL", "BQ": "NL",
    "GL": "DK", "FO": "DK",
    "AX": "FI",
    "SJ": "NO", "BV": "NO",
    "CX": "AU", "CC": "AU", "HM": "AU", "NF": "AU",
    "TK": "NZ", "NU": "NZ", "CK": "NZ",
}


def load_policy() -> dict[str, JsonValue]:
    try:
        path = files("ipcheck").joinpath(DATA_FILE)
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _status(code: str | None, supported: set[str]) -> tuple[bool | None, str | None]:
    if not code or code in UNKNOWN_CODES:
        return None, None
    if code in supported:
        return True, None
    parent = TERRITORIES.get(code)
    if parent is not None and parent in supported:
        return True, parent
    return False, None


def _route_text(route: dict[str, JsonValue]) -> str:
    text = f"{route['label']} {route['country_code']}"
    if route.get("territory_of"):
        text += f"（{route['territory_of']} 属地）"
    return text


def check_region(checks: list[CheckResult]) -> list[CheckResult]:
    policy = load_policy()
    codes = policy.get("country_codes")
    supported = {code for code in codes if isinstance(code, str)} if isinstance(codes, list) else set()
    lookup = {check.id: check for check in checks}
    routes: list[dict[str, JsonValue]] = []
    for key, label in (("web", "网页"), ("api", "官方 API")):
        observation = lookup.get(f"claude.{key}.egress")
        code = observation.data.get("country_code") if observation is not None and observation.status == "completed" else None
        code = code.upper()[:2] if isinstance(code, str) else None
        supported_flag, parent = _status(code, supported)
        routes.append({"route": key, "label": label, "country_code": code,
                       "supported": supported_flag, "territory_of": parent})
    known = [route for route in routes if route["supported"] is not None]
    policy_info: dict[str, JsonValue] = {key: policy.get(key)
                                         for key in ("source", "policy", "verified_at", "effective", "note")}
    evidence = ("支持地区来自 Anthropic 公布的 Supported Regions Policy，按出口 IP 的国家代码比对。",
                "已列国家的属地与依赖地区按政策视为支持，使用其母国代码判定。",
                "XX、T1 等非国家占位码保留为未知，不判定为不支持。",
                "未列出的国家或地区不受支持；这是服务可用范围，不是账号风险评级。",
                "出口国家来自 Cloudflare trace 的 loc 字段，可能被代理或中转改变。",
                f"政策生效日期 {policy.get('effective', '未知')}，数据核对日期 {policy.get('verified_at', '未知')}。")
    if not supported:
        return [CheckResult("claude.region", "claude", "Claude 支持地区", "unknown", "info",
                            "支持地区数据不可用，无法比对", evidence,
                            {"routes": [{**route, "supported": None} for route in routes], "policy": policy_info},
                            "Anthropic Supported Regions Policy")]
    if not known:
        return [CheckResult("claude.region", "claude", "Claude 支持地区", "unknown", "info",
                            "未取得出口国家代码，无法比对支持地区", evidence,
                            {"routes": routes, "policy": policy_info}, "Anthropic Supported Regions Policy")]
    unsupported = [route for route in known if route["supported"] is False]
    if unsupported:
        summary = "不在支持地区：" + "、".join(_route_text(route) for route in unsupported)
    else:
        summary = "在支持地区（" + "；".join(_route_text(route) for route in known) + "）"
    unknown_routes = [route for route in routes if route["supported"] is None]
    if unknown_routes:
        summary += "；" + "、".join(f"{route['label']}国家代码未知" for route in unknown_routes)
    return [CheckResult("claude.region", "claude", "Claude 支持地区", "completed",
                        "warning" if unsupported else "info", summary, evidence,
                        {"routes": routes, "policy": policy_info, "unsupported": bool(unsupported)},
                        "Anthropic Supported Regions Policy")]
