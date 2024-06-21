"""Ready-to-receive SMTP server diagnostic (port 25, STARTTLS, cert, PTR, relay, mailbox)."""

from __future__ import annotations

import asyncio
import secrets
import ssl
from dataclasses import dataclass
from typing import Literal

from app.checks.mx import check_mx
from app.dns.providers import MailProvider
from app.dns.resolver import DNSResolver, DNSStatus, normalize_dns_name, reverse_ip_for_ptr
from app.net_safety import SSRFError, resolve_public_ips
from app.smtp.session import (
    SMTPProtocolError,
    SMTPSession,
    parse_ehlo_capabilities,
    read_only_cert_probe,
)
from app.smtp.tls import CertificateInfo, create_verified_ssl_context, inspect_der_certificate

ReceiveVerdict = Literal["ready", "partly", "not_ready"]
MailboxStatus = Literal["accepted", "catch_all", "rejected", "greylisted", "refused", "not_tested"]
RelayStatus = Literal["rejected", "open_relay", "inconclusive", "not_tested"]

SLOW_BANNER_DEFAULT_MS = 3000.0
CERT_EXPIRY_WARN_DAYS = 30
MAX_MX_HOSTS_TO_TEST = 3

_BLOCK_HINTS = (
    "blocked",
    "blacklist",
    "blocklist",
    "spamhaus",
    "barracuda",
    "spamcop",
    "rbl",
    "dnsbl",
    "policy",
    "access denied",
    "client host",
    "reputation",
)


@dataclass(frozen=True)
class ReceiveIssue:
    severity: Literal["fail", "warn", "info", "pass"]
    title: str
    detail: str
    fix: str | None = None


@dataclass(frozen=True)
class MXReceiveResult:
    mx_host: str
    priority: int
    ip: str | None = None
    reachable: bool = False
    connect_ms: float | None = None
    banner: str | None = None
    banner_ms: float | None = None
    slow_banner: bool = False
    banner_hostname: str | None = None
    ptr_hostname: str | None = None
    fcrdns_valid: bool | None = None
    ehlo_capabilities: tuple[str, ...] = ()
    supports_starttls: bool = False
    tls_version: str | None = None
    certificate: CertificateInfo | None = None
    relay_status: RelayStatus = "not_tested"
    relay_response: str | None = None
    mailbox_status: MailboxStatus = "not_tested"
    mailbox_response: str | None = None
    transcript: str = ""
    error: str | None = None
    issues: tuple[ReceiveIssue, ...] = ()


@dataclass(frozen=True)
class ReceiveTestReport:
    email: str
    domain: str
    verdict: ReceiveVerdict
    verdict_label: str  # "Yes", "Partly", "No"
    verdict_summary: str
    provider: MailProvider | None = None
    suggested_smtp_host: str | None = None
    suggested_smtp_port: int = 587
    hosts: tuple[MXReceiveResult, ...] = ()
    issues: tuple[ReceiveIssue, ...] = ()


def _extract_banner_hostname(banner_line: str) -> str | None:
    tokens = banner_line.strip().split()
    if not tokens:
        return None
    candidate = tokens[0].strip("<>[]()").rstrip(".").lower()
    if "." in candidate and all(ch.isalnum() or ch in ".-" for ch in candidate):
        return candidate
    return None


async def _check_ptr_and_fcrdns(ip: str, resolver: DNSResolver) -> tuple[str | None, bool]:
    ptr_name = reverse_ip_for_ptr(ip)
    ptr_resp = await resolver.query(ptr_name, "PTR")
    if ptr_resp.status != DNSStatus.OK or not ptr_resp.records:
        return None, False

    ptr_host = normalize_dns_name(ptr_resp.records[0])
    a_resp, aaaa_resp = await asyncio.gather(
        resolver.query(ptr_host, "A"),
        resolver.query(ptr_host, "AAAA"),
    )
    forward_ips = {
        *(a_resp.records if a_resp.status == DNSStatus.OK else ()),
        *(aaaa_resp.records if aaaa_resp.status == DNSStatus.OK else ()),
    }
    return ptr_host, ip in forward_ips


def _looks_like_policy_block(response_text: str) -> bool:
    lower = response_text.lower()
    return any(hint in lower for hint in _BLOCK_HINTS)


async def test_mx_host_receive(
    *,
    mx_host: str,
    priority: int,
    target_email: str,
    domain: str,
    resolver: DNSResolver,
    port: int = 25,
    probe_from: str = "probe@delivercheck.invalid",
    ehlo_hostname: str = "delivercheck.local",
    connect_timeout: float = 8.0,
    command_timeout: float = 8.0,
    slow_banner_ms: float = SLOW_BANNER_DEFAULT_MS,
    cafile: str | None = None,
    allow_private_for_tests: bool = False,
) -> MXReceiveResult:
    """Connect to one MX host and run non-intrusive ready-to-receive checks (never sends DATA)."""
    issues: list[ReceiveIssue] = []

    try:
        ips = await resolve_public_ips(
            mx_host,
            resolver,
            allow_private_for_tests=allow_private_for_tests,
        )
    except SSRFError as exc:
        issues.append(
            ReceiveIssue(
                severity="fail",
                title=f"Refused to connect to {mx_host}",
                detail=str(exc),
                fix="Ensure the MX record points to a public, globally routable mail server IP.",
            )
        )
        return MXReceiveResult(
            mx_host=mx_host,
            priority=priority,
            reachable=False,
            error=str(exc),
            issues=tuple(issues),
        )

    ip = ips[0]
    ptr_task = asyncio.create_task(_check_ptr_and_fcrdns(ip, resolver))

    session = SMTPSession(
        ip=ip,
        port=port,
        server_hostname=mx_host,
        connect_timeout=connect_timeout,
        command_timeout=command_timeout,
        allow_custom_port_for_tests=allow_private_for_tests,
    )

    connect_ms: float | None = None
    banner_line: str | None = None
    banner_ms: float | None = None
    slow_banner = False
    banner_host: str | None = None
    ehlo_caps: dict[str, str] = {}
    supports_starttls = False
    cert_info: CertificateInfo | None = None
    tls_version: str | None = None
    relay_status: RelayStatus = "not_tested"
    relay_response: str | None = None
    mailbox_status: MailboxStatus = "not_tested"
    mailbox_response: str | None = None

    try:
        try:
            connect_ms, banner_resp = await session.connect()
        except TimeoutError:
            ptr_host, fcrdns = await ptr_task
            msg = (
                f"Connection to {mx_host} ({ip}:{port}) timed out after {connect_timeout:.0f}s. "
                "The server may be down, firewalled on port 25, or this host's network may block "
                "outbound port 25."
            )
            issues.append(
                ReceiveIssue(
                    severity="fail",
                    title=f"Could not connect to {mx_host} (timed out)",
                    detail=msg,
                    fix=(
                        "Verify port 25 is open on your mail server firewall (and if self-hosting "
                        "DeliverCheck, confirm outbound port 25 is allowed by your VPS provider)."
                    ),
                )
            )
            return MXReceiveResult(
                mx_host=mx_host,
                priority=priority,
                ip=ip,
                reachable=False,
                ptr_hostname=ptr_host,
                fcrdns_valid=fcrdns,
                transcript=session.format_transcript(),
                error=msg,
                issues=tuple(issues),
            )
        except OSError as exc:
            ptr_host, fcrdns = await ptr_task
            msg = (
                f"Connection to {mx_host} ({ip}:{port}) was refused or failed ({exc}). "
                "No SMTP service is listening on port 25 or a firewall rejected the connection."
            )
            issues.append(
                ReceiveIssue(
                    severity="fail",
                    title=f"Connection refused by {mx_host}",
                    detail=msg,
                    fix=(
                        "Ensure your mail server (Postfix/Exim/etc.) is running and "
                        "listening on port 25."
                    ),
                )
            )
            return MXReceiveResult(
                mx_host=mx_host,
                priority=priority,
                ip=ip,
                reachable=False,
                ptr_hostname=ptr_host,
                fcrdns_valid=fcrdns,
                transcript=session.format_transcript(),
                error=msg,
                issues=tuple(issues),
            )

        banner_ms = banner_resp.duration_ms
        banner_line = banner_resp.first_line
        banner_host = _extract_banner_hostname(banner_line)
        if banner_resp.code != 220:
            issues.append(
                ReceiveIssue(
                    severity="fail",
                    title=f"Unexpected SMTP greeting ({banner_resp.code}) from {mx_host}",
                    detail=(
                        f"Expected a 220 greeting banner, but received: "
                        f"{banner_resp.code} {banner_line}."
                    ),
                    fix="Check your mail server logs for connection rejections or IP blocks.",
                )
            )

        if banner_ms >= slow_banner_ms:
            slow_banner = True
            issues.append(
                ReceiveIssue(
                    severity="warn",
                    title=f"Slow SMTP banner ({banner_ms:.0f} ms) on {mx_host}",
                    detail=(
                        f"{mx_host} waited {banner_ms / 1000:.1f}s before sending its 220 greeting "
                        "(often caused by anti-spam tarpitting / greetdelay or heavy server load)."
                    ),
                    fix=(
                        "A short 1-2s greetdelay is normal, but long delays can cause some senders "
                        "to time out; check Postscreen/Exim delay settings."
                    ),
                )
            )

        # EHLO
        ehlo_resp = await session.send_command(f"EHLO {ehlo_hostname}")
        if ehlo_resp.code == 250:
            ehlo_caps = parse_ehlo_capabilities(ehlo_resp)
        else:
            await session.send_command(f"HELO {ehlo_hostname}")

        supports_starttls = "STARTTLS" in ehlo_caps
        if supports_starttls:
            verified_ctx = create_verified_ssl_context(cafile=cafile)
            try:
                tls_resp, der_bytes = await session.starttls(verified_ctx)
                if tls_resp.code == 220 and der_bytes:
                    tls_version = session.tls_version
                    cert_info = inspect_der_certificate(
                        der_bytes,
                        mx_host,
                        tls_version=session.tls_version,
                        cipher=session.tls_cipher,
                        verified=True,
                    )
                    # RFC 3207: re-issue EHLO after STARTTLS
                    post_tls_ehlo = await session.send_command(f"EHLO {ehlo_hostname}")
                    if post_tls_ehlo.code == 250:
                        ehlo_caps = parse_ehlo_capabilities(post_tls_ehlo)
                else:
                    issues.append(
                        ReceiveIssue(
                            severity="warn",
                            title=f"STARTTLS command rejected by {mx_host}",
                            detail=(
                                "Server advertised STARTTLS but returned "
                                f"{tls_resp.code} {tls_resp.first_line}."
                            ),
                            fix="Check your mail server TLS configuration and certificate files.",
                        )
                    )
            except ssl.SSLCertVerificationError as exc:
                err_msg = str(exc.verify_message or exc)
                session.add_note(f"TLS certificate verification failed: {err_msg}")
                await session.quit_and_close()

                # Read-only CERT_NONE probe ONLY to report expiry / SAN mismatch details
                cert_info = await read_only_cert_probe(
                    ip=ip,
                    port=port,
                    server_hostname=mx_host,
                    verify_error=err_msg,
                    use_implicit_tls=False,
                    ehlo_hostname=ehlo_hostname,
                    timeout=command_timeout,
                    allow_custom_port_for_tests=allow_private_for_tests,
                )
                if cert_info is None:
                    cert_info = CertificateInfo(
                        verified=False,
                        hostname_matches=False,
                        is_expired=False,
                        is_not_yet_valid=False,
                        is_self_signed=False,
                        error=err_msg,
                    )
                tls_version = cert_info.tls_version

                # Reconnect plain (no TLS, no credentials) solely to finish relay & mailbox probes
                session = SMTPSession(
                    ip=ip,
                    port=port,
                    server_hostname=mx_host,
                    connect_timeout=connect_timeout,
                    command_timeout=command_timeout,
                    allow_custom_port_for_tests=allow_private_for_tests,
                )
                session.add_note(
                    "Reconnected without TLS (read-only receive probes only; no credentials sent)"
                )
                await session.connect()
                await session.send_command(f"EHLO {ehlo_hostname}")
            except ssl.SSLError as exc:
                err_msg = str(exc)
                session.add_note(f"TLS handshake error: {err_msg}")
                issues.append(
                    ReceiveIssue(
                        severity="warn",
                        title=f"STARTTLS handshake failed on {mx_host}",
                        detail=f"TLS negotiation failed: {err_msg}.",
                        fix=(
                            "Ensure your mail server supports TLS 1.2 or TLS 1.3 with "
                            "modern ciphers."
                        ),
                    )
                )
                await session.quit_and_close()
                session = SMTPSession(
                    ip=ip,
                    port=port,
                    server_hostname=mx_host,
                    connect_timeout=connect_timeout,
                    command_timeout=command_timeout,
                    allow_custom_port_for_tests=allow_private_for_tests,
                )
                await session.connect()
                await session.send_command(f"EHLO {ehlo_hostname}")
        else:
            issues.append(
                ReceiveIssue(
                    severity="warn",
                    title=f"{mx_host} does not support STARTTLS",
                    detail=(
                        "Without STARTTLS, incoming email is transmitted in plain text and fails "
                        "modern TLS delivery expectations."
                    ),
                    fix=(
                        "Install a valid TLS certificate (e.g. Let's Encrypt) and "
                        "enable STARTTLS in your MTA."
                    ),
                )
            )

        # Evaluate certificate findings
        if cert_info is not None:
            if cert_info.is_expired:
                days_ago = abs(cert_info.days_until_expiry or 0)
                exp_str = (
                    cert_info.not_after.strftime("%Y-%m-%d")
                    if cert_info.not_after
                    else "unknown date"
                )
                issues.append(
                    ReceiveIssue(
                        severity="warn",
                        title=f"TLS certificate on {mx_host} is expired",
                        detail=(
                            f"The certificate expired on {exp_str} ({days_ago} days ago), so "
                            "strict senders and MTA-STS policies will reject encrypted delivery."
                        ),
                        fix=f"Renew the TLS certificate for {mx_host} and reload your mail server.",
                    )
                )
            elif not cert_info.hostname_matches:
                san_list = (
                    ", ".join(cert_info.san_dns_names[:3])
                    if cert_info.san_dns_names
                    else (cert_info.subject_cn or "none")
                )
                issues.append(
                    ReceiveIssue(
                        severity="warn",
                        title=f"TLS certificate hostname mismatch on {mx_host}",
                        detail=(
                            f"Certificate covers ({san_list}) and does not match the MX hostname "
                            f"{mx_host}."
                        ),
                        fix=f"Issue a TLS certificate that includes {mx_host} in its SAN list.",
                    )
                )
            elif not cert_info.verified:
                issues.append(
                    ReceiveIssue(
                        severity="warn",
                        title=f"TLS certificate chain on {mx_host} is not trusted",
                        detail=(
                            "Certificate verification failed "
                            f"({cert_info.error or 'untrusted CA'})."
                        ),
                        fix=(
                            "Use a certificate from a trusted CA (such as Let's Encrypt) and "
                            "serve the full intermediate certificate chain."
                        ),
                    )
                )
            elif (
                cert_info.days_until_expiry is not None
                and cert_info.days_until_expiry <= CERT_EXPIRY_WARN_DAYS
            ):
                exp_str = cert_info.not_after.strftime("%Y-%m-%d") if cert_info.not_after else ""
                issues.append(
                    ReceiveIssue(
                        severity="warn",
                        title=(
                            f"TLS certificate on {mx_host} expires in "
                            f"{cert_info.days_until_expiry} days"
                        ),
                        detail=f"The certificate expires on {exp_str}.",
                        fix="Renew the certificate soon and enable automated renewal.",
                    )
                )

        # Open relay check (reserved test domain example.com; NEVER sends DATA)
        mail_relay = await session.send_command(f"MAIL FROM:<{probe_from}>")
        if mail_relay.code == 250:
            rcpt_relay = await session.send_command("RCPT TO:<relay-test@example.com>")
            relay_response = f"{rcpt_relay.code} {rcpt_relay.first_line}"
            if 200 <= rcpt_relay.code < 300:
                relay_status = "open_relay"
                issues.append(
                    ReceiveIssue(
                        severity="fail",
                        title=f"CRITICAL: {mx_host} appears to be an open relay",
                        detail=(
                            f"{mx_host} accepted an unauthenticated RCPT TO for an unrelated "
                            f"domain (example.com): {relay_response}. Spammers abuse open relays "
                            "within hours and get your IP blocklisted."
                        ),
                        fix=(
                            "Restrict relaying immediately to authenticated users and your own "
                            "domains (e.g. reject_unauth_destination in Postfix)."
                        ),
                    )
                )
            else:
                relay_status = "rejected"
            await session.send_command("RSET")
        else:
            relay_status = "inconclusive"
            relay_response = f"{mail_relay.code} {mail_relay.first_line}"

        # Mailbox verification: probe the REAL address FIRST (never sends DATA)
        mail_box = await session.send_command(f"MAIL FROM:<{probe_from}>")
        if mail_box.code == 250:
            rcpt_real = await session.send_command(f"RCPT TO:<{target_email}>")
            mailbox_response = f"{rcpt_real.code} {rcpt_real.first_line}"
            if 200 <= rcpt_real.code < 300:
                # Real address accepted -> RSET and probe one random address to detect catch-all
                await session.send_command("RSET")
                random_local = f"delivercheck-probe-{secrets.token_hex(6)}"
                mail_rand = await session.send_command(f"MAIL FROM:<{probe_from}>")
                if mail_rand.code == 250:
                    rcpt_rand = await session.send_command(f"RCPT TO:<{random_local}@{domain}>")
                    if 200 <= rcpt_rand.code < 300:
                        mailbox_status = "catch_all"
                        issues.append(
                            ReceiveIssue(
                                severity="info",
                                title=f"{mx_host} accepts mail as a catch-all domain",
                                detail=(
                                    f"{mx_host} accepted both {target_email} and a random "
                                    "non-existent address, so it accepts any address here."
                                ),
                            )
                        )
                    else:
                        mailbox_status = "accepted"
                    await session.send_command("RSET")
                else:
                    mailbox_status = "accepted"
            elif 400 <= rcpt_real.code < 500:
                mailbox_status = "greylisted"
                issues.append(
                    ReceiveIssue(
                        severity="warn",
                        title=f"{mx_host} temporarily deferred {target_email} ({rcpt_real.code})",
                        detail=(
                            f"The server returned '{mailbox_response}', which usually means "
                            "greylisting or temporary rate limiting — real sending servers retry "
                            "automatically after a few minutes."
                        ),
                        fix=(
                            "No action needed if greylisting is intentional; otherwise check "
                            "server deferral logs."
                        ),
                    )
                )
            elif _looks_like_policy_block(mailbox_response):
                mailbox_status = "refused"
                issues.append(
                    ReceiveIssue(
                        severity="info",
                        title=f"{mx_host} refused mailbox verification",
                        detail=(
                            f"The server returned '{mailbox_response}' — some providers block "
                            "unauthenticated address checks or probes from hosting IPs."
                        ),
                        fix=(
                            "Use the 'Send a test email' tab if you want to confirm "
                            "end-to-end delivery."
                        ),
                    )
                )
            else:
                mailbox_status = "rejected"
                issues.append(
                    ReceiveIssue(
                        severity="fail",
                        title=(
                            f"Mailbox {target_email} was rejected by {mx_host} "
                            f"({rcpt_real.code})"
                        ),
                        detail=f"The server rejected the recipient with '{mailbox_response}'.",
                        fix=(
                            f"Verify that the mailbox or alias '{target_email}' exists in your "
                            "email provider and is enabled to receive mail."
                        ),
                    )
                )
            await session.send_command("RSET")
        else:
            mailbox_status = "refused"
            mailbox_response = f"{mail_box.code} {mail_box.first_line}"
            issues.append(
                ReceiveIssue(
                    severity="info",
                    title=f"{mx_host} refused recipient verification",
                    detail=(
                        f"Server declined MAIL FROM with '{mailbox_response}', so mailbox "
                        "existence could not be verified directly."
                    ),
                )
            )

    except (SMTPProtocolError, TimeoutError, OSError) as exc:
        session.add_note(f"Session ended early: {exc}")
        issues.append(
            ReceiveIssue(
                severity="warn",
                title=f"SMTP conversation with {mx_host} ended early",
                detail=f"Connection interrupted during testing: {exc}.",
                fix=(
                    "Some servers drop connections after probe commands; check your "
                    "mail server logs if mail fails."
                ),
            )
        )
    finally:
        await session.quit_and_close()

    ptr_host, fcrdns = await ptr_task
    if ptr_host is None:
        issues.append(
            ReceiveIssue(
                severity="warn",
                title=f"No reverse DNS (PTR) record for {ip}",
                detail=(
                    f"IP address {ip} has no PTR record; while receiving mail still works, "
                    "matching reverse DNS is expected for a healthy mail server."
                ),
                fix=f"Set a PTR record for {ip} pointing to {mx_host} in your hosting/VPS panel.",
            )
        )
    elif not fcrdns:
        issues.append(
            ReceiveIssue(
                severity="warn",
                title=f"Reverse DNS for {ip} is not forward-confirmed",
                detail=(f"PTR points to {ptr_host}, but {ptr_host} does not resolve back to {ip}."),
                fix=f"Ensure {ptr_host} has an A/AAAA record pointing back to {ip}.",
            )
        )
    elif banner_host and banner_host != ptr_host:
        issues.append(
            ReceiveIssue(
                severity="info",
                title=f"SMTP banner hostname ({banner_host}) differs from PTR ({ptr_host})",
                detail=(
                    "Banner hostname does not match the IP's reverse DNS; this is common on "
                    "hosted providers but worth aligning on dedicated mail servers."
                ),
            )
        )

    if not any(i.severity in ("fail", "warn") for i in issues):
        issues.insert(
            0,
            ReceiveIssue(
                severity="pass",
                title=f"{mx_host} is ready to receive email",
                detail=(
                    f"Connected in {connect_ms or 0:.0f} ms, verified {tls_version or 'TLS'}, "
                    f"rejected relaying, and accepted {target_email}."
                ),
            ),
        )

    return MXReceiveResult(
        mx_host=mx_host,
        priority=priority,
        ip=ip,
        reachable=True,
        connect_ms=connect_ms,
        banner=banner_line,
        banner_ms=banner_ms,
        slow_banner=slow_banner,
        banner_hostname=banner_host,
        ptr_hostname=ptr_host,
        fcrdns_valid=fcrdns,
        ehlo_capabilities=tuple(sorted(ehlo_caps.keys())),
        supports_starttls=supports_starttls,
        tls_version=tls_version,
        certificate=cert_info,
        relay_status=relay_status,
        relay_response=relay_response,
        mailbox_status=mailbox_status,
        mailbox_response=mailbox_response,
        transcript=session.format_transcript(),
        issues=tuple(issues),
    )


async def run_receive_test(
    email_address: str,
    resolver: DNSResolver,
    *,
    port: int = 25,
    probe_from: str = "probe@delivercheck.invalid",
    ehlo_hostname: str = "delivercheck.local",
    connect_timeout: float = 8.0,
    command_timeout: float = 8.0,
    slow_banner_ms: float = SLOW_BANNER_DEFAULT_MS,
    cafile: str | None = None,
    allow_private_for_tests: bool = False,
) -> ReceiveTestReport:
    """Test whether the mail servers for email_address are ready to receive email."""
    cleaned_email = email_address.strip()
    local_part, _, raw_domain = cleaned_email.partition("@")
    norm_domain = normalize_dns_name(raw_domain)
    norm_email = f"{local_part}@{norm_domain}"

    mx_result = await check_mx(norm_domain, resolver)
    provider = mx_result.provider
    suggested_smtp = mx_result.suggested_smtp_host
    suggested_port = provider.smtp_port if provider else 587

    if mx_result.is_null_mx:
        issue = ReceiveIssue(
            severity="fail",
            title="Domain publishes a Null MX record (0 .)",
            detail=f"{norm_domain} explicitly declares that it does not accept incoming email.",
            fix="Replace the Null MX record with your email provider's MX records to receive mail.",
        )
        return ReceiveTestReport(
            email=norm_email,
            domain=norm_domain,
            verdict="not_ready",
            verdict_label="No",
            verdict_summary=f"{norm_domain} publishes a Null MX record and does not accept email.",
            provider=provider,
            suggested_smtp_host=suggested_smtp,
            suggested_smtp_port=suggested_port,
            issues=(issue,),
        )

    valid_mx = [
        h for h in mx_result.hosts if h.exchange != "." and not h.is_bare_ip and not h.is_cname
    ]
    if not valid_mx:
        issue = ReceiveIssue(
            severity="fail",
            title="No valid MX hosts to test",
            detail=f"{norm_domain} has no valid, reachable MX records in DNS.",
            fix="Add valid MX records for your email provider before testing the mail server.",
        )
        return ReceiveTestReport(
            email=norm_email,
            domain=norm_domain,
            verdict="not_ready",
            verdict_label="No",
            verdict_summary=f"No valid MX servers found for {norm_domain}.",
            provider=provider,
            suggested_smtp_host=suggested_smtp,
            suggested_smtp_port=suggested_port,
            issues=(issue,),
        )

    targets = valid_mx[:MAX_MX_HOSTS_TO_TEST]
    host_results = tuple(
        await asyncio.gather(
            *(
                test_mx_host_receive(
                    mx_host=h.exchange,
                    priority=h.priority,
                    target_email=norm_email,
                    domain=norm_domain,
                    resolver=resolver,
                    port=port,
                    probe_from=probe_from,
                    ehlo_hostname=ehlo_hostname,
                    connect_timeout=connect_timeout,
                    command_timeout=command_timeout,
                    slow_banner_ms=slow_banner_ms,
                    cafile=cafile,
                    allow_private_for_tests=allow_private_for_tests,
                )
                for h in targets
            )
        )
    )

    all_issues: list[ReceiveIssue] = []
    for hr in host_results:
        all_issues.extend(hr.issues)

    severity_rank = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    sorted_issues = tuple(sorted(all_issues, key=lambda i: severity_rank[i.severity]))

    reachable_hosts = [h for h in host_results if h.reachable]
    any_open_relay = any(h.relay_status == "open_relay" for h in host_results)
    all_rejected_mailbox = bool(reachable_hosts) and all(
        h.mailbox_status == "rejected" for h in reachable_hosts
    )
    any_fail = any(i.severity == "fail" for i in sorted_issues)
    any_warn = any(i.severity == "warn" for i in sorted_issues)

    verdict: ReceiveVerdict
    if not reachable_hosts or any_open_relay or all_rejected_mailbox or any_fail:
        verdict = "not_ready"
        verdict_label = "No"
        if any_open_relay:
            summary = "Critical security problem: at least one mail server acts as an open relay."
        elif not reachable_hosts:
            summary = f"Could not reach any mail server for {norm_domain} on port {port}."
        elif all_rejected_mailbox:
            summary = f"The mail server rejected {norm_email} (mailbox unknown or disabled)."
        else:
            summary = f"Mail server check for {norm_email} found blocking problems."
    elif any_warn:
        verdict = "partly"
        verdict_label = "Partly"
        warn_count = sum(1 for i in sorted_issues if i.severity == "warn")
        noun = "warning" if warn_count == 1 else "warnings"
        summary = f"Mail server accepts mail for {norm_email}, with {warn_count} {noun} to fix."
    else:
        verdict = "ready"
        verdict_label = "Yes"
        summary = (
            f"Mail server for {norm_email} is reachable, encrypted with valid TLS, "
            "and ready to receive."
        )

    return ReceiveTestReport(
        email=norm_email,
        domain=norm_domain,
        verdict=verdict,
        verdict_label=verdict_label,
        verdict_summary=summary,
        provider=provider,
        suggested_smtp_host=suggested_smtp,
        suggested_smtp_port=suggested_port,
        hosts=host_results,
        issues=sorted_issues,
    )


def render_receive_report_text(report: ReceiveTestReport) -> str:
    """Render a plain-text mail server receive report for support tickets."""
    lines = [
        f"DeliverCheck Mail Server Report: {report.email}",
        "=" * (33 + len(report.email)),
        f"Ready to receive: {report.verdict_label}",
        f"Summary: {report.verdict_summary}",
        "",
    ]
    for host in report.hosts:
        lines.append(
            f"MX {host.priority} {host.mx_host} ({host.ip or 'unresolved'}) — "
            f"{'reachable' if host.reachable else 'unreachable'}"
        )
        if host.reachable:
            tls_yn = "yes" if host.supports_starttls else "no"
            fcrdns_ok = "ok" if host.fcrdns_valid else "no"
            lines.append(
                f"  Connect: {host.connect_ms or 0:.0f} ms | "
                f"Banner: {host.banner_ms or 0:.0f} ms | "
                f"STARTTLS: {tls_yn} ({host.tls_version or 'none'})"
            )
            lines.append(
                f"  PTR: {host.ptr_hostname or 'none'} (FCrDNS={fcrdns_ok}) | "
                f"Relay: {host.relay_status} | Mailbox: {host.mailbox_status}"
            )
        lines.append("")

    lines.append("Findings:")
    for issue in report.issues:
        lines.append(f"[{issue.severity.upper()}] {issue.title}")
        lines.append(f"  {issue.detail}")
        if issue.fix:
            lines.append(f"  Fix: {issue.fix}")
    return "\n".join(lines) + "\n"
