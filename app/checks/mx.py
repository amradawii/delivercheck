"""MX record inspection and mailbox provider detection."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass

from app.dns.providers import (
    MailProvider,
    detect_mail_provider_from_mx,
    resolve_smtp_host_for_provider,
)
from app.dns.resolver import DNSResolver, DNSStatus, MXRecord, normalize_dns_name


@dataclass(frozen=True)
class MXIssue:
    severity: str  # "pass", "warn", "fail", "info"
    title: str
    detail: str
    fix: str | None = None
    record_value: str | None = None


@dataclass(frozen=True)
class MXHostInfo:
    priority: int
    exchange: str
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    is_bare_ip: bool = False
    is_cname: bool = False
    cname_target: str | None = None
    has_non_public_ip: bool = False

    @property
    def all_ips(self) -> tuple[str, ...]:
        return (*self.ipv4, *self.ipv6)

    @property
    def resolves(self) -> bool:
        return bool(self.ipv4 or self.ipv6)


@dataclass(frozen=True)
class MXCheckResult:
    domain: str
    status: str  # "pass", "warn", "fail", "error"
    hosts: tuple[MXHostInfo, ...] = ()
    is_null_mx: bool = False
    implicit_fallback_ips: tuple[str, ...] = ()
    provider: MailProvider | None = None
    suggested_smtp_host: str | None = None
    issues: tuple[MXIssue, ...] = ()


def _is_bare_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_non_public_ip(ip_str: str) -> bool:
    addr = ipaddress.ip_address(ip_str)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _uses_legacy_google_mx(hosts: tuple[MXHostInfo, ...]) -> bool:
    exchanges = [h.exchange.lower() for h in hosts]
    has_legacy = any(e.endswith("aspmx.l.google.com") or "googlemail.com" in e for e in exchanges)
    has_modern = "smtp.google.com" in exchanges
    return has_legacy and not has_modern


async def _inspect_mx_host(record: MXRecord, resolver: DNSResolver) -> MXHostInfo:
    if _is_bare_ip(record.exchange):
        return MXHostInfo(
            priority=record.priority,
            exchange=record.exchange,
            is_bare_ip=True,
        )

    try:
        cname_resp, a_resp, aaaa_resp = await asyncio.gather(
            resolver.query(record.exchange, "CNAME"),
            resolver.query(record.exchange, "A"),
            resolver.query(record.exchange, "AAAA"),
        )
    except Exception:
        return MXHostInfo(
            priority=record.priority,
            exchange=record.exchange,
        )

    is_cname = cname_resp.status == DNSStatus.OK and bool(cname_resp.records)
    cname_target: str | None = None
    if is_cname:
        cname_target = cname_resp.records[0]
    elif a_resp.cname_chain:
        is_cname = True
        cname_target = a_resp.cname_chain[0]
    elif aaaa_resp.cname_chain:
        is_cname = True
        cname_target = aaaa_resp.cname_chain[0]

    ipv4 = a_resp.records if a_resp.status == DNSStatus.OK else ()
    ipv6 = aaaa_resp.records if aaaa_resp.status == DNSStatus.OK else ()
    non_public = any(_is_non_public_ip(ip) for ip in (*ipv4, *ipv6))

    return MXHostInfo(
        priority=record.priority,
        exchange=record.exchange,
        ipv4=ipv4,
        ipv6=ipv6,
        is_bare_ip=False,
        is_cname=is_cname,
        cname_target=cname_target,
        has_non_public_ip=non_public,
    )


async def check_mx(domain: str, resolver: DNSResolver) -> MXCheckResult:
    """Inspect a domain's MX records, A/AAAA resolution, RFC validity, and mail provider."""
    norm_domain = normalize_dns_name(domain)
    mx_resp = await resolver.query(norm_domain, "MX")

    if mx_resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
        return MXCheckResult(
            domain=norm_domain,
            status="error",
            issues=(
                MXIssue(
                    severity="fail",
                    title="Could not look up MX records",
                    detail=(
                        f"DNS lookup for {norm_domain} MX records failed "
                        f"({mx_resp.error_message or mx_resp.status.value})."
                    ),
                    fix="Check that your domain's nameservers are reachable and try again.",
                ),
            ),
        )

    if mx_resp.status in (DNSStatus.NXDOMAIN, DNSStatus.NO_ANSWER) or not mx_resp.mx_records:
        # RFC 5321 section 5.1: senders fall back to A/AAAA when no MX exists
        a_resp, aaaa_resp = await asyncio.gather(
            resolver.query(norm_domain, "A"),
            resolver.query(norm_domain, "AAAA"),
        )
        fallback_ips = (
            *(a_resp.records if a_resp.status == DNSStatus.OK else ()),
            *(aaaa_resp.records if aaaa_resp.status == DNSStatus.OK else ()),
        )
        if fallback_ips:
            detail = (
                f"{norm_domain} has no MX record. Under RFC 5321, sending servers will fall back "
                f"to delivering mail directly to its A/AAAA address ({fallback_ips[0]}), "
                "which usually bounces if that server only hosts a website."
            )
            fix = (
                "Add MX records for your email provider (for example, priority 1 "
                "smtp.google.com for Google Workspace), or publish a Null MX record "
                "('0 .') if this domain should not receive email."
            )
        else:
            detail = (
                f"{norm_domain} has no MX record and no A/AAAA fallback address, "
                "so other servers cannot deliver email to it."
            )
            fix = (
                "Add MX records from your email provider, or publish a Null MX record "
                "('0 .') if this domain is send-only."
            )
        return MXCheckResult(
            domain=norm_domain,
            status="fail",
            implicit_fallback_ips=fallback_ips,
            issues=(
                MXIssue(
                    severity="fail",
                    title="No MX records found",
                    detail=detail,
                    fix=fix,
                ),
            ),
        )

    mx_records = mx_resp.mx_records

    # RFC 7505 Null MX handling: must be priority 0, target ".", and the sole MX record
    null_entries = [r for r in mx_records if r.exchange == "."]
    if null_entries:
        if len(mx_records) == 1 and null_entries[0].priority == 0:
            return MXCheckResult(
                domain=norm_domain,
                status="pass",
                is_null_mx=True,
                hosts=(MXHostInfo(priority=0, exchange="."),),
                issues=(
                    MXIssue(
                        severity="info",
                        title="Domain publishes a Null MX record",
                        detail=(
                            f"{norm_domain} explicitly declares it does not accept incoming email "
                            "(RFC 7505 Null MX: 0 .)."
                        ),
                        fix=(
                            "No action needed if this domain is send-only or parked; "
                            "replace '0 .' with your email provider's MX records to receive mail."
                        ),
                    ),
                ),
            )

        return MXCheckResult(
            domain=norm_domain,
            status="fail",
            is_null_mx=False,
            hosts=tuple(MXHostInfo(priority=r.priority, exchange=r.exchange) for r in mx_records),
            issues=(
                MXIssue(
                    severity="fail",
                    title="Invalid Null MX configuration",
                    detail=(
                        "A Null MX record ('0 .') must have priority 0 and be the only MX record "
                        "for the domain (RFC 7505)."
                    ),
                    fix=(
                        "Remove all other MX records if this domain should not receive email, "
                        "or delete the '.' MX record if you want to receive email."
                    ),
                ),
            ),
        )

    inspected = tuple(
        await asyncio.gather(*(_inspect_mx_host(rec, resolver) for rec in mx_records))
    )

    issues: list[MXIssue] = []
    has_fail = False
    has_warn = False
    valid_host_count = 0

    for host in inspected:
        if host.is_bare_ip:
            has_fail = True
            issues.append(
                MXIssue(
                    severity="fail",
                    title=f"MX record points to a bare IP address ({host.exchange})",
                    detail=(
                        "RFC 5321 requires MX records to point to a hostname, not a numeric IP "
                        "address, and many sending servers reject bare IPs."
                    ),
                    fix=(
                        "Create an A/AAAA record such as mail."
                        f"{norm_domain} pointing to {host.exchange}, then point your MX record to "
                        "that hostname."
                    ),
                )
            )
            continue

        if host.is_cname:
            has_fail = True
            target_note = f" (-> {host.cname_target})" if host.cname_target else ""
            issues.append(
                MXIssue(
                    severity="fail",
                    title=f"MX target {host.exchange} is a CNAME",
                    detail=(
                        f"MX record {host.exchange}{target_note} points to a CNAME alias, which "
                        "violates RFC 2181 and can cause delivery failures."
                    ),
                    fix=(
                        "Point the MX record directly to the canonical hostname"
                        f"{f' ({host.cname_target})' if host.cname_target else ''} "
                        "instead of a CNAME."
                    ),
                )
            )
            continue

        if not host.resolves:
            has_fail = True
            issues.append(
                MXIssue(
                    severity="fail",
                    title=f"MX host {host.exchange} has no A or AAAA record",
                    detail=(
                        f"Mail servers cannot connect to {host.exchange} because it does not "
                        "resolve to an IPv4 or IPv6 address."
                    ),
                    fix=(
                        "Fix the typo in your MX record or add an A/AAAA record for "
                        f"{host.exchange}."
                    ),
                )
            )
            continue

        if host.has_non_public_ip:
            has_fail = True
            issues.append(
                MXIssue(
                    severity="fail",
                    title=f"MX host {host.exchange} resolves to a non-public IP",
                    detail=(
                        f"{host.exchange} resolves to a private or reserved address "
                        f"({', '.join(host.all_ips)}), which external mail servers cannot reach."
                    ),
                    fix=f"Update the A/AAAA record for {host.exchange} to a public IP address.",
                )
            )
            continue

        valid_host_count += 1

    exchanges = [h.exchange for h in inspected]
    provider = detect_mail_provider_from_mx(exchanges)
    suggested_smtp_host = resolve_smtp_host_for_provider(provider, exchanges)

    if provider and provider.id == "google_workspace" and _uses_legacy_google_mx(inspected):
        has_warn = True
        issues.append(
            MXIssue(
                severity="info",
                title="Google Workspace uses legacy MX records",
                detail=(
                    "Your domain uses the older aspmx.l.google.com MX records. They still work, "
                    "though Google Workspace now recommends a single MX record."
                ),
                fix="Optional: for new or simplified setups, use priority 1 smtp.google.com.",
                record_value="1 smtp.google.com",
            )
        )

    if valid_host_count > 0 and not has_fail:
        provider_label = f" ({provider.name})" if provider else ""
        issues.insert(
            0,
            MXIssue(
                severity="pass",
                title=f"MX records are valid{provider_label}",
                detail=(
                    f"Found {valid_host_count} reachable mail server"
                    f"{'s' if valid_host_count != 1 else ''} for {norm_domain}."
                ),
            ),
        )

    if has_fail:
        overall = "fail" if valid_host_count == 0 else "warn"
    elif has_warn:
        overall = "pass"
    else:
        overall = "pass"

    return MXCheckResult(
        domain=norm_domain,
        status=overall,
        hosts=inspected,
        is_null_mx=False,
        provider=provider,
        suggested_smtp_host=suggested_smtp_host,
        issues=tuple(issues),
    )
