"""SSRF protection: block non-public IPs and restrict outbound mail ports."""

from __future__ import annotations

import asyncio
import ipaddress

from app.dns.resolver import DNSResolver, DNSStatus, normalize_dns_name

ALLOWED_EMAIL_PORTS: frozenset[int] = frozenset({25, 465, 587})
_CGNAT_NET = ipaddress.IPv4Network("100.64.0.0/10")


class SSRFError(ValueError):
    """Raised when a target host, IP, or port fails outbound network safety rules."""


def is_public_ip(ip_str: str) -> bool:
    """Return True only if ip_str is a globally routable public IPv4 or IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NET:
        return False

    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return False

    return bool(addr.is_global)


def validate_public_ip(ip_str: str) -> str:
    """Validate that ip_str is a public IP address, returning its canonical string."""
    cleaned = ip_str.strip()
    if not is_public_ip(cleaned):
        raise SSRFError(f"Refused connection to non-public or reserved IP address: {cleaned}")
    return str(ipaddress.ip_address(cleaned))


def validate_email_port(port: int) -> int:
    """Allow only standard SMTP ports (25, 465, 587)."""
    if port not in ALLOWED_EMAIL_PORTS:
        raise SSRFError(f"Port {port} is not allowed; only ports 25, 465, and 587 are permitted.")
    return port


async def resolve_public_ips(
    host: str,
    resolver: DNSResolver,
    *,
    allow_private_for_tests: bool = False,
) -> list[str]:
    """Resolve host to IPs and refuse if any resolved address is private, loopback, or reserved."""
    cleaned = host.strip().rstrip(".")
    if not cleaned:
        raise SSRFError("Target hostname is empty.")

    # Direct IP literal check
    try:
        addr = ipaddress.ip_address(cleaned)
        if not allow_private_for_tests and not is_public_ip(str(addr)):
            raise SSRFError(f"Refused connection to non-public or reserved IP address: {addr}")
        return [str(addr)]
    except ValueError:
        pass

    norm_host = normalize_dns_name(cleaned)
    a_resp, aaaa_resp = await asyncio.gather(
        resolver.query(norm_host, "A"),
        resolver.query(norm_host, "AAAA"),
    )

    ips: list[str] = []
    if a_resp.status == DNSStatus.OK:
        ips.extend(a_resp.records)
    if aaaa_resp.status == DNSStatus.OK:
        ips.extend(aaaa_resp.records)

    if not ips:
        raise SSRFError(f"Could not resolve any IP address for {norm_host}.")

    validated: list[str] = []
    for ip_str in ips:
        if not allow_private_for_tests and not is_public_ip(ip_str):
            raise SSRFError(
                f"Host {norm_host} resolved to a non-public or reserved IP address ({ip_str})."
            )
        validated.append(str(ipaddress.ip_address(ip_str)))

    return validated
