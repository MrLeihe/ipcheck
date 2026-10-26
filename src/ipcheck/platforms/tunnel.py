"""Read system VPN connections and system-wide tunnel routes without client credentials."""

import ipaddress
import platform
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Literal

from ipcheck.platforms.system import command

TunnelState = Literal['on', 'off', 'connecting', 'disconnecting', 'unknown', 'unsupported']
TUNNEL_NAME = re.compile(r'(?:utun|tun|tap|wg|ppp|ipsec|vti|tailscale)[a-zA-Z0-9_.-]*')


@dataclass(frozen=True)
class TunnelObservation:
    state: TunnelState
    interfaces: tuple[str, ...] = ()
    source: str = 'system VPN / routes'


def _local_destination(destination: str) -> bool:
    if destination == 'default':
        return False
    try:
        # netstat can put an interface scope before the prefix length.
        address = ipaddress.ip_network(destination.split('%', 1)[0], strict=False).network_address
    except ValueError:
        return False  # macOS also prints abbreviated IPv4 prefixes such as 10/8.
    return address.is_link_local or address.is_multicast or address.is_loopback


def macos_routes(text: str | None, family: int) -> tuple[set[str], bool]:
    heading = 'Internet:' if family == 4 else 'Internet6:'
    if text is None or heading not in text or not re.search(r'Destination\s+Gateway\s+Flags\s+Netif', text):
        return set(), False
    interfaces: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4 or not TUNNEL_NAME.fullmatch(fields[3]):
            continue
        destination, _, flags, interface = fields[:4]
        # I means interface-scoped; idle Apple utun interfaces have these defaults.
        if 'U' not in flags or any(flag in flags for flag in 'IRB') or _local_destination(destination):
            continue
        interfaces.add(interface)
    return interfaces, True


def macos_vpn_states(text: str | None) -> tuple[set[str], bool]:
    if text is None or 'Available network connection services' not in text:
        return set(), False
    states: set[str] = set()
    for line in text.splitlines():
        if not line.lstrip().startswith(('(', '*')):
            continue
        match = re.match(r'\s*\*?\s*\((Connected|Disconnected|Connecting|Disconnecting)\)', line)
        if not match:
            return states, False
        states.add(match[1])
    return states, True


def linux_routes(text: str | None) -> tuple[set[str], bool]:
    if text is None:
        return set(), False
    interfaces: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        match = re.search(r'\bdev\s+(\S+)', line)
        if not fields or not match or not TUNNEL_NAME.fullmatch(match[1]):
            continue
        if 'linkdown' in fields or fields[0] in ('unreachable', 'blackhole', 'prohibit', 'throw', 'local'):
            continue
        if not _local_destination(fields[0]):
            interfaces.add(match[1])
    return interfaces, True


def tunnel_status() -> TunnelObservation:
    system = platform.system()
    if system == 'Darwin':
        commands = (["/usr/sbin/netstat", "-rn", "-f", "inet"],
                    ["/usr/sbin/netstat", "-rn", "-f", "inet6"],
                    ["/usr/sbin/scutil", "--nc", "list"])
        with ThreadPoolExecutor(max_workers=3) as pool:
            ipv4, ipv6, vpn = list(pool.map(command, commands))
        routes4, valid4 = macos_routes(ipv4, 4)
        routes6, valid6 = macos_routes(ipv6, 6)
        states, valid_vpn = macos_vpn_states(vpn)
        interfaces = tuple(sorted(routes4 | routes6))
        source = 'netstat IPv4/IPv6 / scutil --nc list'
        if interfaces or 'Connected' in states:
            state: TunnelState = 'on'
        elif not (valid4 and valid6 and valid_vpn):
            state = 'unknown'
        elif 'Connecting' in states:
            state = 'connecting'
        elif 'Disconnecting' in states:
            state = 'disconnecting'
        else:
            state = 'off'
        return TunnelObservation(state, interfaces, source)
    if system == 'Linux':
        with ThreadPoolExecutor(max_workers=2) as pool:
            texts = list(pool.map(command, (["ip", "-4", "route", "show", "table", "all"],
                                            ["ip", "-6", "route", "show", "table", "all"])))
        routes = [linux_routes(text) for text in texts]
        interfaces = tuple(sorted(set().union(*(names for names, _ in routes))))
        state = 'on' if interfaces else 'off' if all(valid for _, valid in routes) else 'unknown'
        return TunnelObservation(state, interfaces, 'ip IPv4/IPv6 route show table all')
    return TunnelObservation('unsupported')
