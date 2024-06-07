"""Domain and IP DNSBL checks with strict error-code vs listing separation."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from app.dns.resolver import DNSResolver, DNSStatus, normalize_dns_name
from app.net_safety import is_public_ip

BlocklistStatus = Literal["clean", "listed", "could_not_check"]

_SPAMHAUS_COMMON_ERRORS: frozenset[str] = frozenset(
    {
        "127.255.255.252",  # typing error in DNSBL name
        "127.255.255.254",  # query via public/open resolver
        "127.255.255.255",  # excessive number of queries
    }
)
_SPAMHAUS_DBL_ERRORS: frozenset[str] = _SPAMHAUS_COMMON_ERRORS | {"127.0.1.255"}
_URI_BLOCKED_CODES: frozenset[str] = frozenset({"127.0.0.1"})

MAX_IPS_TO_CHECK = 5


@dataclass(frozen=True)
class BlocklistIssue:
    severity: str  # "pass", "warn", "fail", "info"
    title: str
    detail: str
    fix: str | None = None


@dataclass(frozen=True)
class BlocklistEntry:
    list_name: str
    zone: str
    target: str
    target_kind: Literal["domain", "ip"]
    status: BlocklistStatus
    return_codes: tuple[str, ...] = ()
    detail: str = ""
    delist_url: str | None = None


@dataclass(frozen=True)
class BlocklistCheckResult:
    domain: str
    status: str  # "pass", "warn", "fail"
    entries: tuple[BlocklistEntry, ...] = ()
    checked_ips: tuple[str, ...] = ()
    issues: tuple[BlocklistIssue, ...] = ()

    @property
    def listed_entries(self) -> tuple[BlocklistEntry, ...]:
        return tuple(e for e in self.entries if e.status == "listed")

    @property
    def unchecked_entries(self) -> tuple[BlocklistEntry, ...]:
        return tuple(e for e in self.entries if e.status == "could_not_check")


def _reverse_ip_for_dnsbl(ip_str: str) -> tuple[str, bool]:
    """Return (reversed_label, is_ipv6) for IPv4 or IPv6 DNSBL lookups."""
    addr = ipaddress.ip_address(ip_str)
    if isinstance(addr, ipaddress.IPv4Address):
        octets = str(addr).split(".")
        return ".".join(reversed(octets)), False
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)), True


def _explain_spamhaus_error(code: str) -> str:
    if code == "127.255.255.254":
        return "Spamhaus refused the query (public/open resolver blocked — use Unbound or DQS)."
    if code == "127.255.255.255":
        return "Spamhaus rate-limited the querying resolver (configure SPAMHAUS_DQS_KEY)."
    if code == "127.255.255.252":
        return "Spamhaus returned a DNSBL zone configuration error code."
    if code == "127.0.1.255":
        return "Spamhaus DBL rejected an IP query on a domain-only blocklist."
    return f"Spamhaus returned error code {code}."


def _classify_response(
    *,
    list_name: str,
    zone: str,
    target: str,
    target_kind: Literal["domain", "ip"],
    status: DNSStatus,
    records: tuple[str, ...],
    error_codes: frozenset[str],
    delist_url: str,
    error_message: str | None,
) -> BlocklistEntry:
    if status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
        return BlocklistEntry(
            list_name=list_name,
            zone=zone,
            target=target,
            target_kind=target_kind,
            status="could_not_check",
            detail=f"DNS lookup failed ({error_message or status.value}).",
            delist_url=delist_url,
        )

    if status in (DNSStatus.NXDOMAIN, DNSStatus.NO_ANSWER) or not records:
        return BlocklistEntry(
            list_name=list_name,
            zone=zone,
            target=target,
            target_kind=target_kind,
            status="clean",
            detail=f"Not listed on {list_name}.",
            delist_url=delist_url,
        )

    # Filter out any non-127.x.x.x garbage answers
    valid_codes = tuple(r for r in records if r.startswith("127."))
    if not valid_codes:
        return BlocklistEntry(
            list_name=list_name,
            zone=zone,
            target=target,
            target_kind=target_kind,
            status="could_not_check",
            return_codes=records,
            detail=f"Unexpected non-127.0.0.0/8 DNSBL response: {', '.join(records)}.",
            delist_url=delist_url,
        )

    # If ANY returned code is a provider error/refusal code, treat as could_not_check, NEVER listed
    matched_errors = [code for code in valid_codes if code in error_codes]
    if matched_errors:
        if "spamhaus" in list_name.lower():
            reason = _explain_spamhaus_error(matched_errors[0])
        else:
            reason = (
                f"{list_name} refused the query (returned {matched_errors[0]} — "
                "querying resolver may be rate-limited or blocked)."
            )
        return BlocklistEntry(
            list_name=list_name,
            zone=zone,
            target=target,
            target_kind=target_kind,
            status="could_not_check",
            return_codes=valid_codes,
            detail=reason,
            delist_url=delist_url,
        )

    # Extra clarity for Spamhaus PBL (127.0.0.10 / 127.0.0.11)
    if "zen" in list_name.lower() and all(c in ("127.0.0.10", "127.0.0.11") for c in valid_codes):
        detail = (
            f"Listed on Spamhaus PBL ({', '.join(valid_codes)} — dynamic/residential policy "
            "blocklist; outbound mail should not be sent directly from this IP)."
        )
    else:
        detail = f"Listed on {list_name} (return code: {', '.join(valid_codes)})."

    return BlocklistEntry(
        list_name=list_name,
        zone=zone,
        target=target,
        target_kind=target_kind,
        status="listed",
        return_codes=valid_codes,
        detail=detail,
        delist_url=delist_url,
    )


async def _query_single_dnsbl(
    *,
    qname: str,
    list_name: str,
    zone: str,
    target: str,
    target_kind: Literal["domain", "ip"],
    error_codes: frozenset[str],
    delist_url: str,
    resolver: DNSResolver,
) -> BlocklistEntry:
    resp = await resolver.query(qname, "A")
    return _classify_response(
        list_name=list_name,
        zone=zone,
        target=target,
        target_kind=target_kind,
        status=resp.status,
        records=resp.records,
        error_codes=error_codes,
        delist_url=delist_url,
        error_message=resp.error_message,
    )


async def check_blocklists(
    domain: str,
    resolver: DNSResolver,
    *,
    ips: Sequence[str] = (),
    spamhaus_dqs_key: str | None = None,
    enable_barracuda_brbl: bool = False,
) -> BlocklistCheckResult:
    """Query domain and IP DNSBLs via Unbound, never confusing error codes with listings."""
    norm_domain = normalize_dns_name(domain)
    dqs = (spamhaus_dqs_key or "").strip()

    dbl_zone = f"{dqs}.dbl.dq.spamhaus.net" if dqs else "dbl.spamhaus.org"
    zen_zone = f"{dqs}.zen.dq.spamhaus.net" if dqs else "zen.spamhaus.org"

    tasks: list[asyncio.Future[BlocklistEntry] | object] = []
    coros = [
        _query_single_dnsbl(
            qname=f"{norm_domain}.{dbl_zone}",
            list_name="Spamhaus DBL",
            zone="dbl.spamhaus.org",
            target=norm_domain,
            target_kind="domain",
            error_codes=_SPAMHAUS_DBL_ERRORS,
            delist_url="https://check.spamhaus.org/",
            resolver=resolver,
        ),
        _query_single_dnsbl(
            qname=f"{norm_domain}.multi.surbl.org",
            list_name="SURBL",
            zone="multi.surbl.org",
            target=norm_domain,
            target_kind="domain",
            error_codes=_URI_BLOCKED_CODES,
            delist_url="https://www.surbl.org/surbl-analysis",
            resolver=resolver,
        ),
        _query_single_dnsbl(
            qname=f"{norm_domain}.multi.uribl.com",
            list_name="URIBL",
            zone="multi.uribl.com",
            target=norm_domain,
            target_kind="domain",
            error_codes=_URI_BLOCKED_CODES,
            delist_url="https://admin.uribl.com/",
            resolver=resolver,
        ),
    ]
    del tasks

    # Deduplicate and keep only globally routable public IPs
    public_ips: list[str] = []
    seen_ips: set[str] = set()
    for raw_ip in ips:
        cleaned = raw_ip.strip()
        if not cleaned or not is_public_ip(cleaned):
            continue
        canonical = str(ipaddress.ip_address(cleaned))
        if canonical not in seen_ips:
            seen_ips.add(canonical)
            public_ips.append(canonical)
        if len(public_ips) >= MAX_IPS_TO_CHECK:
            break

    for ip_str in public_ips:
        reversed_ip, is_ipv6 = _reverse_ip_for_dnsbl(ip_str)
        # Spamhaus ZEN supports both IPv4 and IPv6
        coros.append(
            _query_single_dnsbl(
                qname=f"{reversed_ip}.{zen_zone}",
                list_name="Spamhaus ZEN",
                zone="zen.spamhaus.org",
                target=ip_str,
                target_kind="ip",
                error_codes=_SPAMHAUS_COMMON_ERRORS,
                delist_url="https://check.spamhaus.org/",
                resolver=resolver,
            )
        )
        # SpamCop and Barracuda BRBL are IPv4-only
        if not is_ipv6:
            coros.append(
                _query_single_dnsbl(
                    qname=f"{reversed_ip}.bl.spamcop.net",
                    list_name="SpamCop",
                    zone="bl.spamcop.net",
                    target=ip_str,
                    target_kind="ip",
                    error_codes=frozenset(),
                    delist_url="https://www.spamcop.net/bl.shtml",
                    resolver=resolver,
                )
            )
            if enable_barracuda_brbl:
                coros.append(
                    _query_single_dnsbl(
                        qname=f"{reversed_ip}.b.barracudacentral.org",
                        list_name="Barracuda BRBL",
                        zone="b.barracudacentral.org",
                        target=ip_str,
                        target_kind="ip",
                        error_codes=frozenset(),
                        delist_url="https://www.barracudacentral.org/lookups",
                        resolver=resolver,
                    )
                )

    entries = tuple(await asyncio.gather(*coros))

    issues: list[BlocklistIssue] = []
    listed = [e for e in entries if e.status == "listed"]
    unchecked = [e for e in entries if e.status == "could_not_check"]

    for item in listed:
        issues.append(
            BlocklistIssue(
                severity="fail",
                title=f"{item.target} is listed on {item.list_name}",
                detail=item.detail,
                fix=(
                    "Investigate compromised accounts or spam sources, then request delisting "
                    f"at {item.delist_url}."
                ),
            )
        )

    if unchecked:
        names = ", ".join(sorted({e.list_name for e in unchecked}))
        issues.append(
            BlocklistIssue(
                severity="info",
                title=f"Could not check some blocklists ({names})",
                detail=(
                    f"{len(unchecked)} lookup{'s' if len(unchecked) != 1 else ''} returned a "
                    "resolver error or rate-limit code (this does not mean your domain is listed)."
                ),
                fix=(
                    "Ensure DeliverCheck queries through its local Unbound resolver "
                    "(or set SPAMHAUS_DQS_KEY for high-volume live deployments)."
                ),
            )
        )

    if not listed:
        checked_count = sum(1 for e in entries if e.status == "clean")
        issues.insert(
            0,
            BlocklistIssue(
                severity="pass",
                title=f"No blocklist listings found ({checked_count} clean)",
                detail=(
                    f"{norm_domain} and its checked mail IPs are not listed on any responding "
                    "blocklist."
                ),
            ),
        )

    overall = "fail" if listed else "pass"
    return BlocklistCheckResult(
        domain=norm_domain,
        status=overall,
        entries=entries,
        checked_ips=tuple(public_ips),
        issues=tuple(issues),
    )
