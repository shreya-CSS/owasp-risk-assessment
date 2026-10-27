"""Target and scan-configuration validation.

Enforces the authorization policy *before* any scanner runs:

* only http/https URLs, no embedded credentials, no non-standard IP notations;
* the hostname is resolved and EVERY resolved address must be permitted (fail closed);
* loopback is always permitted (local labs); RFC 1918 / ULA private ranges only when
  IVA_ALLOW_PRIVATE_NETWORKS=true; anything else only when the hostname, IP or CIDR is
  listed in IVA_ALLOWED_TARGETS;
* link-local (incl. cloud metadata 169.254.169.254), multicast, unspecified, reserved
  and broadcast addresses are always rejected, even when allow-listed.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlsplit, urlunsplit

from config.settings import Settings
from modules.models import ScanConfig

MAX_URL_LENGTH = 2048
SUPPORTED_SCHEMES = ("http", "https")
KNOWN_TOOLS = ("builtin", "zap", "nmap", "nikto")
MAX_NMAP_PORTS = 1000

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*\.?$")
_PORT_SPEC = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")

Resolver = Callable[[str], Iterable[str]]


class TargetValidationError(ValueError):
    """Raised when a target or configuration is rejected. Message is user-facing."""


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]
    policy_reason: str

    @property
    def scan_address(self) -> str:
        """The validated address that host-level tools (Nmap) should use, so a second
        DNS lookup cannot redirect the scan elsewhere."""
        return self.addresses[0]


def default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def _always_blocked(ip: ipaddress._BaseAddress) -> str | None:
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_link_local:
        return "link-local address (includes cloud metadata endpoints)"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    if isinstance(ip, ipaddress.IPv4Address) and ip == ipaddress.IPv4Address("255.255.255.255"):
        return "broadcast address"
    return None


def _in_allowlist(host: str, ip: ipaddress._BaseAddress, allowed: tuple[str, ...]) -> bool:
    for entry in allowed:
        if entry == host:
            return True
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def check_address(host: str, address: str, settings: Settings) -> str:
    """Return the reason an address is permitted, or raise TargetValidationError."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback:  # checked first: Python also classifies ::1 as "reserved"
        return "loopback (local lab)"
    blocked = _always_blocked(ip)
    if blocked:
        raise TargetValidationError(f"Target resolves to a {blocked} ({ip}); scanning it is not permitted.")
    if _in_allowlist(host, ip, settings.allowed_targets):
        return "explicitly authorized in IVA_ALLOWED_TARGETS"
    if any(ip in net for net in _PRIVATE_NETWORKS):
        if settings.allow_private_networks:
            return "private network (IVA_ALLOW_PRIVATE_NETWORKS=true)"
        raise TargetValidationError(
            f"{ip} is a private-network address. Enable IVA_ALLOW_PRIVATE_NETWORKS or add it to "
            "IVA_ALLOWED_TARGETS if you are authorized to test it."
        )
    raise TargetValidationError(
        f"{host} ({ip}) is not an authorized target. Only localhost is allowed by default; add hosts "
        "you have written permission to test to IVA_ALLOWED_TARGETS."
    )


def _normalise_host(raw_host: str) -> str:
    host = raw_host.strip().rstrip(".").lower()
    if not host:
        raise TargetValidationError("The URL has no hostname.")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if _NUMERIC_HOST.match(host):
        raise TargetValidationError("Non-standard numeric IP notation is not accepted; use a dotted-quad address.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetValidationError("The hostname is not valid.") from exc
    if len(host) > 253 or not all(_HOST_LABEL.match(label) for label in host.split(".")):
        raise TargetValidationError("The hostname contains invalid characters.")
    return host


def validate_target(url: str, settings: Settings, resolver: Resolver = default_resolver) -> ValidatedTarget:
    """Validate a user-supplied target URL against syntax rules and the authorization policy."""
    if not isinstance(url, str) or not url.strip():
        raise TargetValidationError("Enter a target URL, for example http://127.0.0.1:8000/")
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise TargetValidationError(f"The URL is longer than {MAX_URL_LENGTH} characters.")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise TargetValidationError("The URL must not contain spaces or control characters.")

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise TargetValidationError("Only http:// and https:// targets are supported.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise TargetValidationError("Credentials embedded in the URL are not allowed.")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise TargetValidationError("The port number is invalid.") from exc
    if not 1 <= port <= 65535:
        raise TargetValidationError("The port number is invalid.")
    host = _normalise_host(parts.hostname or "")

    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        try:
            addresses = list(resolver(host))
        except (OSError, UnicodeError) as exc:
            raise TargetValidationError(f"Could not resolve {host}; check the hostname.") from exc
        if not addresses:
            raise TargetValidationError(f"Could not resolve {host}; check the hostname.")

    reasons = {check_address(host, addr, settings) for addr in addresses}

    netloc_host = f"[{host}]" if ":" in host else host
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = netloc_host if default_port else f"{netloc_host}:{port}"
    normalised = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return ValidatedTarget(
        url=normalised,
        scheme=scheme,
        host=host,
        port=port,
        addresses=tuple(addresses),
        policy_reason="; ".join(sorted(reasons)),
    )


def count_ports(spec: str) -> int:
    total = 0
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        start, end = int(lo), int(hi or lo)
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise TargetValidationError(f"Invalid port or range: {part}")
        total += end - start + 1
    return total


def validate_scan_config(config: ScanConfig, settings: Settings) -> ScanConfig:
    """Validate scan options. Returns the config with the port list normalised."""
    if not config.tools:
        raise TargetValidationError("Select at least one assessment method.")
    unknown = [t for t in config.tools if t not in KNOWN_TOOLS]
    if unknown:
        raise TargetValidationError(f"Unknown assessment method(s): {', '.join(unknown)}")
    if len(set(config.tools)) != len(config.tools):
        raise TargetValidationError("Each assessment method can only be selected once.")
    if not 10 <= int(config.tool_timeout) <= settings.max_tool_timeout:
        raise TargetValidationError(f"Timeout must be between 10 and {settings.max_tool_timeout} seconds.")
    if config.asset_criticality not in ("low", "medium", "high"):
        raise TargetValidationError("Asset criticality must be low, medium or high.")
    if config.exposure not in ("lab", "internal", "internet"):
        raise TargetValidationError("Exposure must be lab, internal or internet.")
    if not 1 <= int(config.zap_max_children) <= 200:
        raise TargetValidationError("ZAP spider child limit must be between 1 and 200.")
    if "nmap" in config.tools:
        spec = (config.nmap_ports or "").replace(" ", "")
        if not _PORT_SPEC.match(spec):
            raise TargetValidationError("Ports must look like 80,443 or 8000-8100.")
        if count_ports(spec) > MAX_NMAP_PORTS:
            raise TargetValidationError(f"At most {MAX_NMAP_PORTS} ports may be scanned.")
        config.nmap_ports = spec
    if config.zap_active_scan:
        if "zap" not in config.tools:
            raise TargetValidationError("Active scanning requires the ZAP method to be selected.")
        if not settings.allow_active_scan:
            raise TargetValidationError(
                "Active scanning is disabled. Set IVA_ALLOW_ACTIVE_SCAN=true only for targets you are "
                "authorized to attack (e.g. a local vulnerable lab)."
            )
    return config
