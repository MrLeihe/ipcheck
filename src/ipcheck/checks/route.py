"""Cross-path egress comparison.

A direct path differing from a proxied path is expected. The signal worth
flagging is the Claude web and API hosts diverging from each other, because
both are official domains covered by the same split-routing rule.

Every observed address is kept: a path that answered with two different
addresses must never be collapsed into a single "consistent" value.
"""

from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue

PATHS = (("direct", "本机直连", "network.direct"), ("generic", "代理出口", "network.egress"),
         ("cloudflare", "Cloudflare", "network.cloudflare"), ("claude_web", "Claude 网页", "claude.web.egress"),
         ("claude_api", "官方 API", "claude.api.egress"))


def _collect(check: CheckResult | None) -> list[str]:
    if check is None:
        return []
    data = check.data
    found: list[JsonValue] = []
    addresses = data.get("addresses")
    if isinstance(addresses, list):
        found.extend(addresses)
    observations = data.get("observations")
    if isinstance(observations, list):
        found.extend(entry.get("ip") for entry in observations if isinstance(entry, dict))
    found.append(data.get("ip"))
    return list(dict.fromkeys(value for value in found if isinstance(value, str)))


def compare_routes(checks: list[CheckResult]) -> list[CheckResult]:
    lookup = {check.id: check for check in checks}
    found = {name: _collect(lookup.get(source)) for name, _, source in PATHS}
    verified = {name: bool(lookup.get(source) is not None and lookup.get(source).status == "completed")
                for name, _, source in PATHS}
    paths: dict[str, JsonValue] = {
        name: {"label": label, "addresses": found[name], "ip": found[name][0] if len(found[name]) == 1 else None,
               "observed": bool(found[name]), "verified": verified[name]}
        for name, label, _ in PATHS
    }
    web, api = found["claude_web"], found["claude_api"]
    claude_multi = len(web) > 1 or len(api) > 1
    if claude_multi:
        claude_consistent: bool | None = False
    elif web and api:
        claude_consistent = web == api
    else:
        claude_consistent = None
    observed_paths = [name for name, _, _ in PATHS if found[name]]
    if len(observed_paths) >= 2:
        all_consistent = (all(verified[name] and len(found[name]) == 1 for name in observed_paths)
                          and len({found[name][0] for name in observed_paths}) == 1)
    else:
        all_consistent = None
    distinct = list(dict.fromkeys(value for name, _, _ in PATHS for value in found[name]))
    data: dict[str, JsonValue] = {"paths": paths, "distinct": distinct, "claude_multi": claude_multi,
                                  "claude_consistent": claude_consistent, "all_consistent": all_consistent}
    evidence = ("各路径使用各自固定的探测目标，代表的是到这些目标的请求路径。",
                "直连与代理路径不同属于预期；只有 Claude 网页与官方 API 互相不一致才提示核对分流。",
                "同一路径观测到多个地址时保留全部地址，不折叠成单一出口，也不会判定为一致。",
                "未取得或未完成验证的路径不参与一致性判断，也不被其他路径替代。")
    different_paths: list[str] = []
    if claude_consistent is True and web:
        for name, label, _ in PATHS[:3]:
            if verified[name] and len(found[name]) == 1 and found[name][0] != web[0]:
                different_paths.append(label)
        data["different_paths"] = different_paths
    if claude_multi:
        summary, severity = "Claude 出口观测到多个 IP，需核对域名分流规则", "warning"
    elif claude_consistent is False:
        summary, severity = "Claude 网页与官方 API 出口不同，需核对域名分流规则", "warning"
    elif claude_consistent is True and all_consistent is True:
        summary, severity = "各路径观测到相同出口", "info"
    elif claude_consistent is True and different_paths:
        summary, severity = "Claude 网页与官方 API 一致；与" + "、".join(different_paths) + "路径不同", "info"
    elif claude_consistent is True:
        summary, severity = "Claude 网页与官方 API 一致", "info"
    elif distinct:
        summary, severity = "部分路径未取得出口，无法完整比对", "info"
    else:
        summary, severity = "未取得任何出口，无法比对", "info"
    if not (web or api):
        return [CheckResult("route.comparison", "network", "出口路径对比", "unknown", "info",
                            summary, evidence, data, "本机多路径探测")]
    return [CheckResult("route.comparison", "network", "出口路径对比", "completed", severity,
                        summary, evidence, data, "本机多路径探测")]
