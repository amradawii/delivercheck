"""Optional SMTP submission (ready-to-send) test with strict TLS and credential masking."""

from __future__ import annotations

import asyncio
import base64
import email.utils
import secrets
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Literal

from app.dns.resolver import DNSResolver
from app.net_safety import SSRFError, resolve_public_ips, validate_email_port
from app.smtp.session import (
    SMTPProtocolError,
    SMTPSession,
    parse_ehlo_capabilities,
    read_only_cert_probe,
)
from app.smtp.tls import CertificateInfo, create_verified_ssl_context, inspect_der_certificate

SecurityMode = Literal["starttls", "implicit_tls"]
ALLOWED_SUBMISSION_PORTS: frozenset[int] = frozenset({465, 587})


@dataclass(frozen=True)
class SendIssue:
    severity: Literal["fail", "warn", "info", "pass"]
    title: str
    detail: str
    fix: str | None = None


@dataclass(frozen=True)
class SendTestReport:
    from_email: str
    smtp_host: str
    port: int
    security_mode: SecurityMode
    ready_to_send: bool
    verdict_label: Literal["Yes", "No"]
    verdict_summary: str
    ip: str | None = None
    connect_ms: float | None = None
    tls_version: str | None = None
    certificate: CertificateInfo | None = None
    auth_methods: tuple[str, ...] = ()
    login_succeeded: bool = False
    message_accepted: bool = False
    inbox_token: str | None = None
    inbox_address: str | None = None
    transcript: str = ""
    issues: tuple[SendIssue, ...] = ()


def _scrub_secrets(text: str, *, username: str, password: str) -> str:
    """Defense-in-depth scrub ensuring credentials or their base64 never leak into transcripts."""
    cleaned = text
    secrets_to_hide: list[str] = []
    if password:
        secrets_to_hide.append(password)
        secrets_to_hide.append(base64.b64encode(password.encode("utf-8")).decode("ascii"))
        plain_blob = f"\x00{username}\x00{password}".encode()
        secrets_to_hide.append(base64.b64encode(plain_blob).decode("ascii"))
    for secret in secrets_to_hide:
        if secret and secret in cleaned:
            cleaned = cleaned.replace(secret, "****")
    return cleaned


def _explain_auth_failure(smtp_host: str, code: int, message: str) -> tuple[str, str, str]:
    lower_host = smtp_host.lower()
    lower_msg = message.lower()

    if (
        "office365" in lower_host
        or "outlook" in lower_host
        or "5.7.139" in lower_msg
        or "5.7.30" in lower_msg
        or "smtpclientauthentication" in lower_msg
        or "basic authentication is not supported" in lower_msg
    ):
        return (
            "Microsoft 365 rejected SMTP login",
            (
                f"The server returned {code} ({message}). Microsoft 365 disables SMTP AUTH by "
                "default under Security Defaults."
            ),
            (
                "App passwords will not work while Security Defaults block SMTP AUTH. Ask a "
                "Microsoft 365 admin to enable authenticated SMTP for this mailbox (or use OAuth2)."
            ),
        )

    if (
        "gmail" in lower_host
        or "google" in lower_host
        or "application-specific" in lower_msg
        or "badcredentials" in lower_msg
        or "5.7.8" in lower_msg
        and "gmail" in lower_host
    ):
        return (
            "Gmail rejected SMTP login",
            (
                f"The server returned {code} ({message}). Google accounts with 2-Step Verification "
                "do not accept your regular password over SMTP."
            ),
            (
                "Create a 16-character App Password in your Google Account security settings "
                "and try again with that password."
            ),
        )

    if (
        code == 530
        or "starttls" in lower_msg
        or "encryption" in lower_msg
        or "must issue" in lower_msg
    ):
        return (
            "Server requires TLS before login",
            f"The server returned {code} ({message}) because encryption is required prior to AUTH.",
            "Use port 587 with STARTTLS or port 465 with Implicit TLS.",
        )

    return (
        f"SMTP login failed ({code})",
        f"The server rejected the username or password ({code} {message}).",
        (
            "Verify your full mailbox address as the username, check the password or app password, "
            "and confirm SMTP AUTH is enabled for this account."
        ),
    )


def _build_test_message(from_email: str, to_address: str, token: str) -> bytes:
    msg = EmailMessage()
    msg["From"] = from_email
    msg["To"] = to_address
    msg["Subject"] = "DeliverCheck SMTP sending test"
    msg["Date"] = email.utils.format_datetime(datetime.now(UTC))
    _, _, domain = from_email.partition("@")
    msg["Message-ID"] = f"<dc-{token}-{secrets.token_hex(4)}@{domain or 'delivercheck.local'}>"
    msg.set_content(
        "This single automated test message was sent at your request by DeliverCheck "
        "to verify SMTP submission, TLS, SPF, DKIM, and DMARC alignment.\n"
    )
    return msg.as_bytes()


async def run_send_test(
    *,
    from_email: str,
    smtp_host: str,
    port: int,
    security_mode: SecurityMode,
    username: str,
    password: str,
    target_inbox_token: str,
    target_inbox_address: str,
    resolver: DNSResolver,
    ehlo_hostname: str = "delivercheck.local",
    connect_timeout: float = 8.0,
    command_timeout: float = 10.0,
    total_timeout: float = 30.0,
    cafile: str | None = None,
    allow_private_for_tests: bool = False,
) -> SendTestReport:
    """Verify SMTP submission login over verified TLS and send ONE test message to our own inbox.

    Credentials are used once in memory, never logged or stored, never sent over unverified TLS,
    and masked as '****' in transcripts.
    """
    clean_host = smtp_host.strip().rstrip(".").lower()
    try:
        async with asyncio.timeout(total_timeout):
            return await _run_send_test_core(
                from_email=from_email,
                smtp_host=clean_host,
                port=port,
                security_mode=security_mode,
                username=username,
                password=password,
                target_inbox_token=target_inbox_token,
                target_inbox_address=target_inbox_address,
                resolver=resolver,
                ehlo_hostname=ehlo_hostname,
                connect_timeout=connect_timeout,
                command_timeout=command_timeout,
                cafile=cafile,
                allow_private_for_tests=allow_private_for_tests,
            )
    except TimeoutError:
        return SendTestReport(
            from_email=from_email,
            smtp_host=clean_host,
            port=port,
            security_mode=security_mode,
            ready_to_send=False,
            verdict_label="No",
            verdict_summary=(
                f"Sending test to {clean_host}:{port} timed out after {total_timeout:.0f} seconds."
            ),
            issues=(
                SendIssue(
                    severity="fail",
                    title=f"SMTP submission test timed out on {clean_host}:{port}",
                    detail=(
                        f"{clean_host}:{port} did not complete TLS login and submission within "
                        f"{total_timeout:.0f} seconds."
                    ),
                    fix=(
                        "Verify the SMTP hostname, port (587 or 465), and that outbound "
                        "connections to this server are not firewalled."
                    ),
                ),
            ),
        )
    except Exception as exc:
        safe_err = _scrub_secrets(str(exc), username=username, password=password)
        return SendTestReport(
            from_email=from_email,
            smtp_host=clean_host,
            port=port,
            security_mode=security_mode,
            ready_to_send=False,
            verdict_label="No",
            verdict_summary=f"Could not complete sending test to {clean_host}:{port}.",
            issues=(
                SendIssue(
                    severity="fail",
                    title=f"SMTP submission test failed on {clean_host}:{port}",
                    detail=f"An unexpected error interrupted submission ({safe_err}).",
                    fix="Verify your SMTP host, port, security mode, and try again.",
                ),
            ),
        )


async def _run_send_test_core(
    *,
    from_email: str,
    smtp_host: str,
    port: int,
    security_mode: SecurityMode,
    username: str,
    password: str,
    target_inbox_token: str,
    target_inbox_address: str,
    resolver: DNSResolver,
    ehlo_hostname: str = "delivercheck.local",
    connect_timeout: float = 8.0,
    command_timeout: float = 10.0,
    cafile: str | None = None,
    allow_private_for_tests: bool = False,
) -> SendTestReport:
    issues: list[SendIssue] = []
    clean_host = smtp_host.strip().rstrip(".").lower()

    if not allow_private_for_tests:
        try:
            validate_email_port(port)
        except SSRFError as exc:
            return SendTestReport(
                from_email=from_email,
                smtp_host=clean_host,
                port=port,
                security_mode=security_mode,
                ready_to_send=False,
                verdict_label="No",
                verdict_summary=str(exc),
                issues=(
                    SendIssue(
                        severity="fail",
                        title="Port not allowed for SMTP submission",
                        detail=str(exc),
                        fix="Use port 587 (STARTTLS) or port 465 (Implicit TLS).",
                    ),
                ),
            )
        if port not in ALLOWED_SUBMISSION_PORTS:
            msg = (
                f"Port {port} cannot be used for authenticated sending; DeliverCheck only "
                "submits credentials over encrypted port 587 (STARTTLS) or 465 (Implicit TLS)."
            )
            return SendTestReport(
                from_email=from_email,
                smtp_host=clean_host,
                port=port,
                security_mode=security_mode,
                ready_to_send=False,
                verdict_label="No",
                verdict_summary=msg,
                issues=(
                    SendIssue(
                        severity="fail",
                        title="Encrypted submission port required (587 or 465)",
                        detail=msg,
                        fix="Select port 587 (STARTTLS) or port 465 (Implicit TLS).",
                    ),
                ),
            )

    try:
        ips = await resolve_public_ips(
            clean_host,
            resolver,
            allow_private_for_tests=allow_private_for_tests,
        )
    except SSRFError as exc:
        return SendTestReport(
            from_email=from_email,
            smtp_host=clean_host,
            port=port,
            security_mode=security_mode,
            ready_to_send=False,
            verdict_label="No",
            verdict_summary=str(exc),
            issues=(
                SendIssue(
                    severity="fail",
                    title=f"Refused to connect to {clean_host}",
                    detail=str(exc),
                    fix="Enter a public outgoing SMTP hostname such as smtp.gmail.com.",
                ),
            ),
        )

    ip = ips[0]
    session = SMTPSession(
        ip=ip,
        port=port,
        server_hostname=clean_host,
        connect_timeout=connect_timeout,
        command_timeout=command_timeout,
        allow_custom_port_for_tests=allow_private_for_tests,
    )

    connect_ms: float | None = None
    cert_info: CertificateInfo | None = None
    tls_version: str | None = None
    auth_methods: tuple[str, ...] = ()
    login_succeeded = False
    message_accepted = False

    def _safe_transcript() -> str:
        return _scrub_secrets(session.format_transcript(), username=username, password=password)

    try:
        verified_ctx = create_verified_ssl_context(cafile=cafile)

        if security_mode == "implicit_tls":
            try:
                connect_ms, banner = await session.connect(ssl_context=verified_ctx)
            except ssl.SSLCertVerificationError as exc:
                err_msg = str(exc.verify_message or exc)
                cert_info = await read_only_cert_probe(
                    ip=ip,
                    port=port,
                    server_hostname=clean_host,
                    verify_error=err_msg,
                    use_implicit_tls=True,
                    ehlo_hostname=ehlo_hostname,
                    timeout=command_timeout,
                    allow_custom_port_for_tests=allow_private_for_tests,
                )
                issues.append(
                    SendIssue(
                        severity="fail",
                        title=f"TLS certificate verification failed for {clean_host}",
                        detail=(
                            f"Refused to send credentials over an unverified TLS connection "
                            f"({err_msg})."
                        ),
                        fix=(
                            f"Ensure {clean_host} presents a valid, non-expired certificate "
                            "matching its hostname."
                        ),
                    )
                )
                return SendTestReport(
                    from_email=from_email,
                    smtp_host=clean_host,
                    port=port,
                    security_mode=security_mode,
                    ready_to_send=False,
                    verdict_label="No",
                    verdict_summary=(
                        "Stopped before login because the server TLS certificate "
                        "failed verification."
                    ),
                    ip=ip,
                    certificate=cert_info,
                    transcript=_safe_transcript(),
                    issues=tuple(issues),
                )
            except ssl.SSLError as exc:
                err_str = str(exc)
                wrong_mode = "wrong_version" in err_str.lower() or "plain" in err_str.lower()
                title = (
                    f"Wrong security mode for {clean_host}:{port}"
                    if wrong_mode
                    else f"TLS handshake failed on {clean_host}:{port}"
                )
                detail = (
                    f"Implicit TLS failed on port {port} ({err_str}). This port likely expects "
                    "plain connect followed by STARTTLS."
                    if wrong_mode
                    else f"Could not negotiate implicit TLS with {clean_host}:{port}: {err_str}."
                )
                issues.append(
                    SendIssue(
                        severity="fail",
                        title=title,
                        detail=detail,
                        fix=(
                            "Try switching to port 587 with STARTTLS "
                            "(or verify port 465 supports implicit TLS)."
                        ),
                    )
                )
                return SendTestReport(
                    from_email=from_email,
                    smtp_host=clean_host,
                    port=port,
                    security_mode=security_mode,
                    ready_to_send=False,
                    verdict_label="No",
                    verdict_summary=detail,
                    ip=ip,
                    transcript=_safe_transcript(),
                    issues=tuple(issues),
                )

            tls_version = session.tls_version
            der = session.get_peer_der_cert()
            if der:
                cert_info = inspect_der_certificate(
                    der,
                    clean_host,
                    tls_version=session.tls_version,
                    cipher=session.tls_cipher,
                    verified=True,
                )
            if banner.code != 220:
                issues.append(
                    SendIssue(
                        severity="fail",
                        title=f"Unexpected greeting ({banner.code}) from {clean_host}",
                        detail=(
                            f"Expected 220 greeting, received: "
                            f"{banner.code} {banner.first_line}."
                        ),
                        fix="Verify the SMTP hostname and that your IP is allowed to connect.",
                    )
                )
                return SendTestReport(
                    from_email=from_email,
                    smtp_host=clean_host,
                    port=port,
                    security_mode=security_mode,
                    ready_to_send=False,
                    verdict_label="No",
                    verdict_summary="SMTP server rejected the connection at greeting.",
                    ip=ip,
                    connect_ms=connect_ms,
                    tls_version=tls_version,
                    certificate=cert_info,
                    transcript=_safe_transcript(),
                    issues=tuple(issues),
                )
            ehlo_resp = await session.send_command(f"EHLO {ehlo_hostname}")
            ehlo_caps = parse_ehlo_capabilities(ehlo_resp)
        else:
            # STARTTLS mode (typically port 587)
            try:
                connect_ms, banner = await session.connect()
            except (TimeoutError, SMTPProtocolError) as exc:
                detail = (
                    f"Did not receive a plain SMTP greeting on {clean_host}:{port} ({exc}). "
                    "If this port expects implicit TLS (such as port 465), switch security mode "
                    "to Implicit TLS."
                )
                issues.append(
                    SendIssue(
                        severity="fail",
                        title=f"Wrong security mode or no greeting on {clean_host}:{port}",
                        detail=detail,
                        fix="Use port 587 with STARTTLS or port 465 with Implicit TLS.",
                    )
                )
                return SendTestReport(
                    from_email=from_email,
                    smtp_host=clean_host,
                    port=port,
                    security_mode=security_mode,
                    ready_to_send=False,
                    verdict_label="No",
                    verdict_summary=detail,
                    ip=ip,
                    transcript=_safe_transcript(),
                    issues=tuple(issues),
                )

            ehlo_initial = await session.send_command(f"EHLO {ehlo_hostname}")
            initial_caps = parse_ehlo_capabilities(ehlo_initial)
            if "STARTTLS" not in initial_caps:
                issues.append(
                    SendIssue(
                        severity="fail",
                        title=f"TLS required before login ({clean_host} lacks STARTTLS)",
                        detail=(
                            f"{clean_host}:{port} did not advertise STARTTLS; DeliverCheck "
                            "refuses to send login credentials over an unencrypted connection."
                        ),
                        fix="Enable STARTTLS on port 587 or switch to port 465 (Implicit TLS).",
                    )
                )
                return SendTestReport(
                    from_email=from_email,
                    smtp_host=clean_host,
                    port=port,
                    security_mode=security_mode,
                    ready_to_send=False,
                    verdict_label="No",
                    verdict_summary="Refused to log in because STARTTLS is not supported.",
                    ip=ip,
                    connect_ms=connect_ms,
                    transcript=_safe_transcript(),
                    issues=tuple(issues),
                )

            try:
                tls_resp, der = await session.starttls(verified_ctx)
            except ssl.SSLCertVerificationError as exc:
                err_msg = str(exc.verify_message or exc)
                cert_info = await read_only_cert_probe(
                    ip=ip,
                    port=port,
                    server_hostname=clean_host,
                    verify_error=err_msg,
                    use_implicit_tls=False,
                    ehlo_hostname=ehlo_hostname,
                    timeout=command_timeout,
                    allow_custom_port_for_tests=allow_private_for_tests,
                )
                issues.append(
                    SendIssue(
                        severity="fail",
                        title=f"TLS certificate verification failed for {clean_host}",
                        detail=(
                            f"Refused to send credentials over an unverified TLS connection "
                            f"({err_msg})."
                        ),
                        fix=(
                            f"Fix the TLS certificate on {clean_host} before sending credentials."
                        ),
                    )
                )
                return SendTestReport(
                    from_email=from_email,
                    smtp_host=clean_host,
                    port=port,
                    security_mode=security_mode,
                    ready_to_send=False,
                    verdict_label="No",
                    verdict_summary=(
                        "Stopped before login because the server TLS certificate "
                        "failed verification."
                    ),
                    ip=ip,
                    connect_ms=connect_ms,
                    certificate=cert_info,
                    transcript=_safe_transcript(),
                    issues=tuple(issues),
                )

            if tls_resp.code != 220:
                issues.append(
                    SendIssue(
                        severity="fail",
                        title=f"STARTTLS rejected by {clean_host}",
                        detail=(
                            f"Server returned {tls_resp.code} "
                            f"{tls_resp.first_line} to STARTTLS."
                        ),
                        fix="Check TLS configuration on your outgoing SMTP server.",
                    )
                )
                return SendTestReport(
                    from_email=from_email,
                    smtp_host=clean_host,
                    port=port,
                    security_mode=security_mode,
                    ready_to_send=False,
                    verdict_label="No",
                    verdict_summary="Server rejected STARTTLS before login.",
                    ip=ip,
                    connect_ms=connect_ms,
                    transcript=_safe_transcript(),
                    issues=tuple(issues),
                )

            tls_version = session.tls_version
            if der:
                cert_info = inspect_der_certificate(
                    der,
                    clean_host,
                    tls_version=session.tls_version,
                    cipher=session.tls_cipher,
                    verified=True,
                )
            post_ehlo = await session.send_command(f"EHLO {ehlo_hostname}")
            ehlo_caps = parse_ehlo_capabilities(post_ehlo)

        # AUTH negotiation over verified TLS ONLY
        raw_auth = ehlo_caps.get("AUTH", "")
        auth_methods = tuple(m.upper() for m in raw_auth.split() if m.strip())
        if not auth_methods:
            issues.append(
                SendIssue(
                    severity="fail",
                    title=f"{clean_host} did not advertise SMTP AUTH",
                    detail="No AUTH methods were offered after establishing TLS.",
                    fix=(
                        "Ensure you connected to the submission host (port 587/465) "
                        "with SMTP AUTH enabled."
                    ),
                )
            )
            return SendTestReport(
                from_email=from_email,
                smtp_host=clean_host,
                port=port,
                security_mode=security_mode,
                ready_to_send=False,
                verdict_label="No",
                verdict_summary="Server does not offer SMTP AUTH login.",
                ip=ip,
                connect_ms=connect_ms,
                tls_version=tls_version,
                certificate=cert_info,
                auth_methods=auth_methods,
                transcript=_safe_transcript(),
                issues=tuple(issues),
            )

        if "PLAIN" in auth_methods:
            token_b64 = base64.b64encode(f"\x00{username}\x00{password}".encode()).decode("ascii")
            auth_resp = await session.send_command(
                f"AUTH PLAIN {token_b64}",
                mask_in_transcript="AUTH PLAIN ****",
            )
        elif "LOGIN" in auth_methods:
            step1 = await session.send_command("AUTH LOGIN")
            if step1.code != 334:
                auth_resp = step1
            else:
                user_b64 = base64.b64encode(username.encode("utf-8")).decode("ascii")
                step2 = await session.send_command(user_b64, mask_in_transcript="****")
                if step2.code != 334:
                    auth_resp = step2
                else:
                    pass_b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")
                    auth_resp = await session.send_command(pass_b64, mask_in_transcript="****")
        else:
            methods_str = ", ".join(auth_methods)
            issues.append(
                SendIssue(
                    severity="fail",
                    title=f"Unsupported AUTH methods ({methods_str})",
                    detail=(
                        f"{clean_host} only advertises {methods_str}; password-based PLAIN/LOGIN "
                        "authentication is disabled."
                    ),
                    fix=(
                        "If this is Microsoft 365 or Google Workspace, use OAuth2 in your app or "
                        "check whether SMTP AUTH is enabled."
                    ),
                )
            )
            return SendTestReport(
                from_email=from_email,
                smtp_host=clean_host,
                port=port,
                security_mode=security_mode,
                ready_to_send=False,
                verdict_label="No",
                verdict_summary=f"Server only offers {methods_str} (password login unavailable).",
                ip=ip,
                connect_ms=connect_ms,
                tls_version=tls_version,
                certificate=cert_info,
                auth_methods=auth_methods,
                transcript=_safe_transcript(),
                issues=tuple(issues),
            )

        if auth_resp.code != 235:
            safe_msg = _scrub_secrets(auth_resp.first_line, username=username, password=password)
            title, detail, fix = _explain_auth_failure(clean_host, auth_resp.code, safe_msg)
            issues.append(SendIssue(severity="fail", title=title, detail=detail, fix=fix))
            return SendTestReport(
                from_email=from_email,
                smtp_host=clean_host,
                port=port,
                security_mode=security_mode,
                ready_to_send=False,
                verdict_label="No",
                verdict_summary=detail,
                ip=ip,
                connect_ms=connect_ms,
                tls_version=tls_version,
                certificate=cert_info,
                auth_methods=auth_methods,
                login_succeeded=False,
                transcript=_safe_transcript(),
                issues=tuple(issues),
            )

        login_succeeded = True
        issues.append(
            SendIssue(
                severity="pass",
                title=f"Authenticated over {tls_version or 'TLS'} on {clean_host}:{port}",
                detail=f"TLS certificate verified and SMTP AUTH succeeded on {clean_host}.",
            )
        )

        # Send ONE test message to DeliverCheck's own test address ONLY
        mail_resp = await session.send_command(f"MAIL FROM:<{from_email}>")
        if not (200 <= mail_resp.code < 300):
            issues.append(
                SendIssue(
                    severity="fail",
                    title=f"Server rejected sender address ({from_email})",
                    detail=f"MAIL FROM returned {mail_resp.code} {mail_resp.first_line}.",
                    fix=(
                        "Ensure the From address matches the authenticated mailbox or an "
                        "authorized send-as alias."
                    ),
                )
            )
            return SendTestReport(
                from_email=from_email,
                smtp_host=clean_host,
                port=port,
                security_mode=security_mode,
                ready_to_send=False,
                verdict_label="No",
                verdict_summary=f"Login worked, but server rejected MAIL FROM:<{from_email}>.",
                ip=ip,
                connect_ms=connect_ms,
                tls_version=tls_version,
                certificate=cert_info,
                auth_methods=auth_methods,
                login_succeeded=True,
                message_accepted=False,
                transcript=_safe_transcript(),
                issues=tuple(issues),
            )

        rcpt_resp = await session.send_command(f"RCPT TO:<{target_inbox_address}>")
        if not (200 <= rcpt_resp.code < 300):
            issues.append(
                SendIssue(
                    severity="fail",
                    title="Server rejected the DeliverCheck test recipient",
                    detail=f"RCPT TO returned {rcpt_resp.code} {rcpt_resp.first_line}.",
                    fix=(
                        "Check whether this SMTP server restricts outgoing recipients or "
                        "whether DeliverCheck is running with a local test domain."
                    ),
                )
            )
            return SendTestReport(
                from_email=from_email,
                smtp_host=clean_host,
                port=port,
                security_mode=security_mode,
                ready_to_send=False,
                verdict_label="No",
                verdict_summary="Login worked, but server rejected the test recipient.",
                ip=ip,
                connect_ms=connect_ms,
                tls_version=tls_version,
                certificate=cert_info,
                auth_methods=auth_methods,
                login_succeeded=True,
                message_accepted=False,
                transcript=_safe_transcript(),
                issues=tuple(issues),
            )

        data_cmd = await session.send_command("DATA")
        if data_cmd.code != 354:
            issues.append(
                SendIssue(
                    severity="fail",
                    title="Server rejected DATA command",
                    detail=f"DATA returned {data_cmd.code} {data_cmd.first_line}.",
                    fix="Check outgoing sending limits or account permissions.",
                )
            )
            return SendTestReport(
                from_email=from_email,
                smtp_host=clean_host,
                port=port,
                security_mode=security_mode,
                ready_to_send=False,
                verdict_label="No",
                verdict_summary="Login worked, but DATA submission was rejected.",
                ip=ip,
                connect_ms=connect_ms,
                tls_version=tls_version,
                certificate=cert_info,
                auth_methods=auth_methods,
                login_succeeded=True,
                message_accepted=False,
                transcript=_safe_transcript(),
                issues=tuple(issues),
            )

        msg_bytes = _build_test_message(from_email, target_inbox_address, target_inbox_token)
        data_done = await session.send_data(msg_bytes)
        if not (200 <= data_done.code < 300):
            issues.append(
                SendIssue(
                    severity="fail",
                    title="Test message was rejected after DATA",
                    detail=f"Server returned {data_done.code} {data_done.first_line}.",
                    fix="Check your outgoing provider's sending quota or content policy.",
                )
            )
            return SendTestReport(
                from_email=from_email,
                smtp_host=clean_host,
                port=port,
                security_mode=security_mode,
                ready_to_send=False,
                verdict_label="No",
                verdict_summary="Login worked, but the test message was rejected.",
                ip=ip,
                connect_ms=connect_ms,
                tls_version=tls_version,
                certificate=cert_info,
                auth_methods=auth_methods,
                login_succeeded=True,
                message_accepted=False,
                transcript=_safe_transcript(),
                issues=tuple(issues),
            )

        message_accepted = True
        issues.append(
            SendIssue(
                severity="pass",
                title="Test message accepted for delivery",
                detail=(
                    f"{clean_host} accepted one test message addressed to {target_inbox_address}."
                ),
            )
        )

    except (OSError, TimeoutError, SMTPProtocolError) as exc:
        safe_err = _scrub_secrets(str(exc), username=username, password=password)
        issues.append(
            SendIssue(
                severity="fail",
                title=f"Could not complete SMTP submission to {clean_host}:{port}",
                detail=f"Connection or protocol error: {safe_err}.",
                fix="Verify the SMTP hostname, port (587 or 465), and firewall rules.",
            )
        )
        return SendTestReport(
            from_email=from_email,
            smtp_host=clean_host,
            port=port,
            security_mode=security_mode,
            ready_to_send=False,
            verdict_label="No",
            verdict_summary=f"Could not connect or submit mail via {clean_host}:{port}.",
            ip=ip,
            connect_ms=connect_ms,
            tls_version=tls_version,
            certificate=cert_info,
            auth_methods=auth_methods,
            login_succeeded=login_succeeded,
            message_accepted=False,
            transcript=_safe_transcript(),
            issues=tuple(issues),
        )
    finally:
        await session.quit_and_close()

    return SendTestReport(
        from_email=from_email,
        smtp_host=clean_host,
        port=port,
        security_mode=security_mode,
        ready_to_send=True,
        verdict_label="Yes",
        verdict_summary=(
            f"Connected to {clean_host}:{port} over {tls_version or 'TLS'}, logged in, and "
            "submitted a real test message."
        ),
        ip=ip,
        connect_ms=connect_ms,
        tls_version=tls_version,
        certificate=cert_info,
        auth_methods=auth_methods,
        login_succeeded=login_succeeded,
        message_accepted=message_accepted,
        inbox_token=target_inbox_token,
        inbox_address=target_inbox_address,
        transcript=_safe_transcript(),
        issues=tuple(issues),
    )


def render_send_report_text(report: SendTestReport) -> str:
    """Render a plain-text SMTP sending test report (never contains credentials)."""
    lines = [
        f"DeliverCheck Outgoing SMTP Report: {report.smtp_host}:{report.port}",
        "=" * (37 + len(report.smtp_host)),
        f"Ready to send: {report.verdict_label}",
        f"Summary: {report.verdict_summary}",
        (
            f"From: {report.from_email} | Mode: {report.security_mode} | "
            f"TLS: {report.tls_version or 'none'}"
        ),
        f"AUTH methods: {', '.join(report.auth_methods) if report.auth_methods else 'none'} | "
        f"Login: {'ok' if report.login_succeeded else 'failed'} | "
        f"Message accepted: {'yes' if report.message_accepted else 'no'}",
        "",
        "Findings:",
    ]
    for issue in report.issues:
        lines.append(f"[{issue.severity.upper()}] {issue.title}")
        lines.append(f"  {issue.detail}")
        if issue.fix:
            lines.append(f"  Fix: {issue.fix}")
    return "\n".join(lines) + "\n"
