import ipaddress
from concurrent.futures import ThreadPoolExecutor

from ipcheck.core.models import CheckResult
from ipcheck.core.privacy import JsonValue
from ipcheck.providers.http import HttpClient, ProviderError

IPV4_SOURCES = (("ipify", "https://api.ipify.org?format=json"), ("AWS Check IP", "https://checkip.amazonaws.com/"))
IPV6_SOURCES = (("ipify IPv6", "https://api6.ipify.org?format=json"),
                ("icanhazip IPv6", "https://ipv6.icanhazip.com/"))


def public_ip(value: object, version: int | None = None) -> str:
    try:
        address = ipaddress.ip_address(value if isinstance(value, str) else "")
    except ValueError:
        raise ProviderError("回显服务未返回有效 IP 地址") from None
    if not address.is_global or (version is not None and address.version != version):
        raise ProviderError("回显地址不是预期类型的公网 IP")
    return str(address)


def observe_ip(client: HttpClient, name: str, url: str, version: int) -> dict[str, JsonValue]:
    try:
        value = client.json(url).get("ip") if "ipify" in url else client.text(url).strip()
        return {"service": name, "status": "completed", "ip": public_ip(value, version)}
    except ProviderError as exc:
        return {"service": name, "status": "unknown", "reason": str(exc)}


def ipv6_observation(observations: list[dict[str, JsonValue]]) -> CheckResult:
    addresses = list(dict.fromkeys(str(item["ip"]) for item in observations if item.get("status") == "completed" and item.get("ip")))
    known = bool(addresses)
    failures = [str(item.get("reason") or "查询未完成") for item in observations if item.get("status") != "completed"]
    if len(addresses) > 1:
        summary = "不同服务观测到不同 IPv6 出口，请核对域名分流"
    elif known:
        summary = f"观测到 IPv6 出口：{addresses[0]}"
    elif failures and len(set(failures)) == 1:
        reason = {"查询超时": "探测超时", "DNS 无法解析查询服务域名": "DNS 解析失败"}.get(failures[0], failures[0])
        summary = f"{reason}（{len(observations)} 个来源，当前请求路径）"
    else:
        summary = "；".join(f"{item['service']}：{item.get('reason') or '查询未完成'}" for item in observations)
        summary = f"当前请求路径探测未完成：{summary}"
    data: dict[str, JsonValue] = {"observations": observations, "addresses": addresses,
                                  "successful_sources": len(observations) - len(failures),
                                  "total_sources": len(observations), "route": "system_or_process_proxy",
                                  "same_ip": len(addresses) == 1 if len(failures) == 0 and known else None}
    if len(addresses) == 1:
        data["ip"] = addresses[0]
    evidence = tuple(f"{item['service']}：{item.get('ip') or item.get('reason')}" for item in observations)
    evidence += (
        "只接收公网 IPv6 回显；任一来源成功即可确认该次请求的 IPv6 出口，其余来源的失败仍单独保留。",
        "探测遵循当前系统/进程代理设置，不强制直连，也不能据此确认实际使用了代理。",
        "本机可以经 IPv4 连接代理，再由远端访问 IPv6 目标；成功不证明本机启用 IPv6，失败也不证明关闭。",
        "这些是到检测服务的请求；不能代替 Claude 请求的 IPv6 观测或直连/代理对照，不能单独判断泄露。",
    )
    return CheckResult("network.ipv6", "network", "IPv6 出口探测", "completed" if known else "unknown",
                       "warning" if len(addresses) > 1 else "info", summary, evidence, data,
                       " / ".join(name for name, _ in IPV6_SOURCES))


def _location_data(client: HttpClient, ip: str) -> dict[str, JsonValue]:
    raw = client.json(f"https://ipwho.is/{ip}")
    if raw.get("success") is not True or public_ip(raw.get("ip")) != ip:
        raise ProviderError("地理服务未确认该 IP 的有效数据")
    timezone = raw.get("timezone")
    connection = raw.get("connection")
    data: dict[str, JsonValue] = {"ip": ip}
    for key in ("country", "country_code", "region", "city"):
        value = raw.get(key)
        data[key] = value[:160] if isinstance(value, str) else None
    data["timezone"] = timezone.get("id") if isinstance(timezone, dict) and isinstance(timezone.get("id"), str) else None
    if isinstance(connection, dict):
        for key in ("asn", "isp", "org"):
            value = connection.get(key)
            data[key] = value[:160] if isinstance(value, str) else value if isinstance(value, int) and not isinstance(value, bool) else None
    return data


def location_check(client: HttpClient, ip: str, fallback: HttpClient | None = None) -> CheckResult:
    # Both paths query the same already observed IP, never the lookup request's IP.
    try:
        ip = public_ip(ip)
    except ProviderError as exc:
        return CheckResult("network.location", "network", "IP 归属查询", "unknown", "info", str(exc), source="ipwho.is")
    failures: list[str] = []
    paths = [("system", client)] + ([("direct", fallback)] if fallback is not None else [])
    for route, lookup in paths:
        try:
            data = _location_data(lookup, ip)
            data["lookup_route"] = route
            evidence = tuple(failures) + (f"查询已观测的 {ip}；地理数据库可能不准确。",
                                         "归属查询使用直连回退，未改变出口观测请求路径。" if route == "direct" else "归属查询遵循当前系统/进程代理配置。",
                                         "未将非机房标记直接认定为住宅 IP。")
            return CheckResult("network.location", "network", "检测出口归属", "completed", "info",
                               " / ".join(str(data.get(key)) for key in ("country", "city") if data.get(key)) or "已取得归属数据",
                               evidence, data, "ipwho.is")
        except ProviderError as exc:
            failures.append(f"{'默认路径' if route == 'system' else '归属直连'}：{exc}")
    return CheckResult("network.location", "network", "检测出口归属", "unknown", "info", failures[-1],
                       tuple(failures), {"ip": ip}, "ipwho.is")


def reputation_checks(client: HttpClient, ip: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    try:
        raw = client.json(f"https://proxycheck.io/v2/{ip}?risk=1&vpn=1&asn=1")
        item = raw.get(ip)
        score = item.get("risk") if isinstance(item, dict) else None
        if raw.get("status") not in ("ok", "warning") or isinstance(score, bool) or not isinstance(score, (int, str)):
            raise ProviderError("信誉服务没有提供有效评分（可能受配额限制）")
        try:
            score = int(score)
        except ValueError:
            raise ProviderError("信誉服务评分格式无效") from None
        if not 0 <= score <= 100:
            raise ProviderError("信誉服务评分超出范围")
        results.append(CheckResult("network.reputation", "network", "第三方 IP 评分", "completed", "warning" if score >= 30 else "info",
                                   f"proxycheck.io：{score}/100", ("第三方信誉分不代表账号封禁概率。",), {"ip": ip, "score": score}, "proxycheck.io"))
    except ProviderError as exc:
        results.append(CheckResult("network.reputation", "network", "第三方 IP 评分", "unknown", "info", str(exc), source="proxycheck.io"))
    try:
        raw = client.json(f"https://api.stopforumspam.org/api?json=1&ip={ip}")
        item = raw.get("ip")
        appears = item.get("appears") if isinstance(item, dict) else None
        if raw.get("success") not in (1, True) or not isinstance(appears, (bool, int)) or appears not in (0, 1):
            raise ProviderError("举报服务未返回有效查询状态")
        results.append(CheckResult("network.abuse", "network", "公开举报记录", "completed", "warning" if appears else "info",
                                   "该服务收录了举报记录" if appears else "该服务未收录举报记录",
                                   ("未收录不代表没有滥用或其他服务的风险记录。",), {"ip": ip, "listed": bool(appears)}, "StopForumSpam"))
    except ProviderError as exc:
        results.append(CheckResult("network.abuse", "network", "公开举报记录", "unknown", "info", str(exc), source="StopForumSpam"))
    return results


def check_network(client: HttpClient | None = None, reputation: bool = False, *, location_fallback: HttpClient | None = None) -> list[CheckResult]:
    client = client or HttpClient()
    with ThreadPoolExecutor(max_workers=4) as pool:
        ipv4_futures = [pool.submit(observe_ip, client, name, url, 4) for name, url in IPV4_SOURCES]
        ipv6_futures = [pool.submit(observe_ip, client, name, url, 6) for name, url in IPV6_SOURCES]
        observations = [future.result() for future in ipv4_futures]
        ipv6 = [future.result() for future in ipv6_futures]
    addresses = [item["ip"] for item in observations if isinstance(item.get("ip"), str)]
    distinct = set(addresses)
    complete = len(addresses) == len(IPV4_SOURCES)
    evidence = tuple(f"{item['service']}：{item.get('ip') or item.get('reason')}" for item in observations)
    results = [CheckResult("network.egress", "network", "检测服务出口观测", "completed" if complete else "unknown",
                           "warning" if len(distinct) > 1 else "info",
                           "不同服务观测到了不同出口" if len(distinct) > 1 else "两个服务观测到相同 IPv4 出口" if complete else "出口观测不完整",
                           evidence + ("这些是测试请求的出口，不能代替 Claude 实际请求的路径验证。",), {"observations": observations}, "ipify / AWS Check IP")]
    results.append(ipv6_observation(ipv6))
    selected = addresses[0] if addresses else None
    if isinstance(selected, str):
        results.append(location_check(client, selected, location_fallback))
        if reputation:
            results.extend(reputation_checks(client, selected))
    else:
        results.append(CheckResult("network.location", "network", "IP 归属查询", "unknown", "info", "没有有效观测 IP，无法查询"))
        if reputation:
            results.append(CheckResult("network.reputation", "network", "第三方 IP 评分", "unknown", "info", "没有有效观测 IP，无法查询"))
    if not reputation:
        results.append(CheckResult("network.reputation", "network", "第三方 IP 信誉", "skipped", "info", "未启用可选信誉查询"))
    return results
