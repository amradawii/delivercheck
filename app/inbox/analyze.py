"""Independent analysis of a received test email (SPF, DKIM, DMARC, TLS, PTR, headers)."""

from __future__ import annotations

import asyncio
import email
import email.policy
import email.utils
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

import dkim

from app.checks.dmarc import DMARCCheckResult, check_dmarc, get_organizational_domain
from app.checks.spf import SPFEvalResult, evaluate_spf_for_ip
from app.dns.resolver import (
    CachedDNSResolver,
    DNSResolver,
    DNSStatus,
    normalize_dns_name,
    reverse_ip_for_ptr,
)


@dataclass(frozen=True)
class EmailIssue:
    severity: Literal["fail", "warn", "info", "pass"]
    title: str
    detail: str
    fix: str | None = None


@dataclass(frozen=True)
class DKIMSignatureReport:
    index: int
    domain: str | None
    selector: str | None
    algorithm: str | None
    verified: bool
    aligned_relaxed: bool
    aligned_strict: bool
    error: str | None = None


@dataclass(frozen=True)
class EmailAnalysisReport:
    received_at: datetime
    peer_ip: str
    helo_hostname: str
    ptr_hostname: str | None
    fcrdns_valid: bool
    tls_used: bool
    tls_version: str | None
    tls_cipher: str | None
    mail_from: str
    mail_from_domain: str | None
    from_header: str
    from_address: str | None
    from_domain: str | None
    subject: str
    message_id: str | None
    date_header: str | None
    date_valid: bool
    size_bytes: int
    has_text_plain: bool
    has_text_html: bool
    attachment_count: int
    list_unsubscribe: str | None
    list_unsubscribe_post: str | None
    one_click_unsubscribe_valid: bool
    spf: SPFEvalResult | None
    spf_aligned_relaxed: bool
    spf_aligned_strict: bool
    dkim_signatures: tuple[DKIMSignatureReport, ...]
    dmarc_result: Literal["pass", "fail", "none"]
    dmarc_policy: str | None
    dmarc_adkim: str
    dmarc_aspf: str
    verdict_status: Literal["pass", "warn", "fail"]
    verdict_line: str
    issues: tuple[EmailIssue, ...]


def _domains_align(
    from_domain: str | None,
    auth_domain: str | None,
) -> tuple[bool, bool]:
    """Return (relaxed_aligned, strict_aligned) using the offline Public Suffix List."""
    if not from_domain or not auth_domain:
        return False, False
    f_norm = normalize_dns_name(from_domain)
    a_norm = normalize_dns_name(auth_domain)
    strict = f_norm == a_norm
    relaxed = get_organizational_domain(f_norm) == get_organizational_domain(a_norm)
    return relaxed, strict


def _parse_dkim_sig_tags(header_value: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in header_value.split(";"):
        piece = part.strip()
        if not piece or "=" not in piece:
            continue
        k, v = piece.split("=", 1)
        tags[k.strip().lower()] = "".join(v.split())
    return tags


async def _check_ptr(peer_ip: str, resolver: DNSResolver) -> tuple[str | None, bool]:
    try:
        ptr_qname = reverse_ip_for_ptr(peer_ip)
    except ValueError:
        return None, False
    ptr_resp = await resolver.query(ptr_qname, "PTR")
    if ptr_resp.status != DNSStatus.OK or not ptr_resp.records:
        return None, False
    ptr_host = normalize_dns_name(ptr_resp.records[0])
    a_resp, aaaa_resp = await asyncio.gather(
        resolver.query(ptr_host, "A"),
        resolver.query(ptr_host, "AAAA"),
    )
    ips = {
        *(a_resp.records if a_resp.status == DNSStatus.OK else ()),
        *(aaaa_resp.records if aaaa_resp.status == DNSStatus.OK else ()),
    }
    return ptr_host, peer_ip in ips


async def _verify_all_dkim_signatures(
    raw_bytes: bytes,
    raw_sig_headers: list[str],
    from_domain: str | None,
    resolver: DNSResolver,
) -> tuple[DKIMSignatureReport, ...]:
    """Independently verify every DKIM-Signature header using dkimpy and our DNSResolver."""
    if not raw_sig_headers:
        return ()

    parsed_tags = [_parse_dkim_sig_tags(hdr) for hdr in raw_sig_headers]

    # Pre-fetch all referenced DKIM TXT records asynchronously through our DNSResolver
    qnames: set[str] = set()
    for tags in parsed_tags:
        d_val = tags.get("d")
        s_val = tags.get("s")
        if d_val and s_val:
            qnames.add(normalize_dns_name(f"{s_val}._domainkey.{d_val}"))

    prefetched: dict[str, bytes | None] = {}
    if qnames:
        qname_list = sorted(qnames)
        responses = await asyncio.gather(*(resolver.query(q, "TXT") for q in qname_list))
        for q, resp in zip(qname_list, responses, strict=True):
            if resp.status == DNSStatus.OK and resp.records:
                prefetched[q] = resp.records[0].encode("utf-8")
            else:
                prefetched[q] = None

    def _sync_dnsfunc(qname: bytes, timeout: float = 5.0) -> bytes | None:
        key = normalize_dns_name(qname.decode("ascii", errors="ignore"))
        return prefetched.get(key)

    reports: list[DKIMSignatureReport] = []
    for idx, tags in enumerate(parsed_tags):
        sig_domain = tags.get("d")
        selector = tags.get("s")
        algorithm = tags.get("a")
        relaxed, strict = _domains_align(from_domain, sig_domain)

        verified = False
        err_msg: str | None = None
        try:
            verifier = dkim.DKIM(raw_bytes)
            verified = bool(verifier.verify(idx=idx, dnsfunc=_sync_dnsfunc))
            if not verified:
                err_msg = "Cryptographic signature check failed (body or signed headers modified)."
        except Exception as exc:
            verified = False
            err_msg = str(exc) or exc.__class__.__name__

        reports.append(
            DKIMSignatureReport(
                index=idx,
                domain=sig_domain,
                selector=selector,
                algorithm=algorithm,
                verified=verified,
                aligned_relaxed=relaxed,
                aligned_strict=strict,
                error=err_msg,
            )
        )

    return tuple(reports)


def _check_one_click_unsubscribe(
    list_unsub: str | None,
    list_unsub_post: str | None,
) -> bool:
    if not list_unsub or not list_unsub_post:
        return False
    has_https_uri = "https://" in list_unsub.lower()
    has_one_click_post = "list-unsubscribe=one-click" in list_unsub_post.lower()
    return has_https_uri and has_one_click_post


async def analyze_received_email(
    raw_bytes: bytes,
    *,
    peer_ip: str,
    mail_from: str,
    helo_hostname: str,
    tls_used: bool,
    tls_version: str | None,
    tls_cipher: str | None,
    resolver: DNSResolver,
    received_at: datetime | None = None,
) -> EmailAnalysisReport:
    """Analyze a received message without trusting any sender-supplied auth headers."""
    scoped = CachedDNSResolver(resolver)
    timestamp = received_at or datetime.now(UTC)

    # Parse headers and MIME structure (attachments are counted, never stored)
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    from_header = str(msg.get("From", "") or "").strip()
    _, parsed_from_addr = email.utils.parseaddr(from_header)
    from_address = parsed_from_addr.strip().lower() or None
    from_domain = (
        normalize_dns_name(from_address.split("@", 1)[1])
        if from_address and "@" in from_address
        else None
    )

    clean_mail_from = mail_from.strip().strip("<>").lower()
    mail_from_domain = (
        normalize_dns_name(clean_mail_from.split("@", 1)[1])
        if "@" in clean_mail_from and clean_mail_from.split("@", 1)[1]
        else None
    )

    subject = str(msg.get("Subject", "") or "").strip() or "(no subject)"
    message_id = str(msg.get("Message-ID", "") or "").strip() or None
    date_header = str(msg.get("Date", "") or "").strip() or None
    date_valid = False
    if date_header:
        try:
            date_valid = email.utils.parsedate_to_datetime(date_header) is not None
        except Exception:
            date_valid = False

    list_unsub = str(msg.get("List-Unsubscribe", "") or "").strip() or None
    list_unsub_post = str(msg.get("List-Unsubscribe-Post", "") or "").strip() or None
    one_click_valid = _check_one_click_unsubscribe(list_unsub, list_unsub_post)

    has_text_plain = False
    has_text_html = False
    attachment_count = 0
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disp = str(part.get_content_disposition() or "").lower()
            ctype = part.get_content_type().lower()
            if disp == "attachment" or part.get_filename():
                attachment_count += 1
            elif ctype == "text/plain":
                has_text_plain = True
            elif ctype == "text/html":
                has_text_html = True
    else:
        ctype = msg.get_content_type().lower()
        if ctype == "text/plain":
            has_text_plain = True
        elif ctype == "text/html":
            has_text_html = True

    raw_dkim_headers = [str(v) for v in (msg.get_all("DKIM-Signature") or [])]

    spf_domain = mail_from_domain or (
        normalize_dns_name(helo_hostname) if "." in helo_hostname else None
    )

    async def _run_spf() -> SPFEvalResult | None:
        if not spf_domain:
            return None
        try:
            return await evaluate_spf_for_ip(
                spf_domain,
                peer_ip,
                clean_mail_from or f"postmaster@{spf_domain}",
                scoped,
                helo=helo_hostname,
            )
        except ValueError:
            return None

    async def _run_dmarc() -> DMARCCheckResult | None:
        if not from_domain:
            return None
        return await check_dmarc(from_domain, scoped)

    ptr_res, spf_res, dkim_reports, dmarc_check = await asyncio.gather(
        _check_ptr(peer_ip, scoped),
        _run_spf(),
        _verify_all_dkim_signatures(raw_bytes, raw_dkim_headers, from_domain, scoped),
        _run_dmarc(),
    )
    ptr_host, fcrdns_valid = ptr_res

    spf_aligned_relaxed, spf_aligned_strict = _domains_align(from_domain, spf_domain)

    adkim = dmarc_check.parsed.adkim if (dmarc_check and dmarc_check.parsed) else "r"
    aspf = dmarc_check.parsed.aspf if (dmarc_check and dmarc_check.parsed) else "r"
    dmarc_policy = dmarc_check.effective_policy if dmarc_check else None

    spf_passes_dmarc = bool(
        spf_res is not None
        and spf_res.result == "pass"
        and (spf_aligned_strict if aspf == "s" else spf_aligned_relaxed)
    )
    dkim_passes_dmarc = any(
        sig.verified and (sig.aligned_strict if adkim == "s" else sig.aligned_relaxed)
        for sig in dkim_reports
    )

    dmarc_result: Literal["pass", "fail", "none"]
    if dmarc_check is None or dmarc_check.record is None or dmarc_policy is None:
        dmarc_result = "none"
    elif spf_passes_dmarc or dkim_passes_dmarc:
        dmarc_result = "pass"
    else:
        dmarc_result = "fail"

    issues: list[EmailIssue] = []

    # 1. SPF findings
    if spf_res is None:
        issues.append(
            EmailIssue(
                severity="warn",
                title="Could not evaluate SPF for this message",
                detail="No valid Return-Path domain or connecting IP was available for SPF.",
                fix="Configure your sending server with a valid envelope sender domain.",
            )
        )
    elif spf_res.result == "pass":
        if spf_aligned_relaxed:
            issues.append(
                EmailIssue(
                    severity="pass",
                    title=f"SPF passed and aligned ({spf_res.domain})",
                    detail=(
                        f"Connecting IP {peer_ip} is authorized by {spf_res.domain} "
                        f"({spf_res.dns_lookups}/10 lookups) and aligns with From: {from_domain}."
                    ),
                )
            )
        else:
            issues.append(
                EmailIssue(
                    severity="warn",
                    title="SPF passed, but Return-Path does not align with From:",
                    detail=(
                        f"SPF passed for {spf_res.domain}, which does not share an organizational "
                        f"domain with From: {from_domain or 'unknown'}."
                    ),
                    fix=(
                        "Set a custom return-path / bounce domain under your own domain so SPF "
                        "can satisfy DMARC alignment."
                    ),
                )
            )
    else:
        issues.append(
            EmailIssue(
                severity="fail",
                title=f"SPF {spf_res.result} for IP {peer_ip}",
                detail=(
                    f"SPF evaluation for {spf_res.domain} returned '{spf_res.result}'"
                    f"{f' ({spf_res.explanation})' if spf_res.explanation else ''}."
                ),
                fix=(
                    f"Authorize sending IP {peer_ip} (or your mail provider's include) in "
                    f"{spf_res.domain}'s SPF TXT record."
                ),
            )
        )

    # 2. DKIM findings
    if not dkim_reports:
        issues.append(
            EmailIssue(
                severity="fail",
                title="Email is not signed with DKIM",
                detail="No DKIM-Signature header was present on this message.",
                fix="Enable DKIM signing in your email provider and publish the DNS key.",
            )
        )
    else:
        any_valid_dkim = any(sig.verified for sig in dkim_reports)
        any_aligned_dkim = any(
            sig.verified and (sig.aligned_strict if adkim == "s" else sig.aligned_relaxed)
            for sig in dkim_reports
        )
        for sig in dkim_reports:
            label = f"d={sig.domain or '?'}, s={sig.selector or '?'}"
            if not sig.verified:
                issues.append(
                    EmailIssue(
                        severity="fail",
                        title=f"DKIM signature failed ({label})",
                        detail=sig.error or "DKIM signature verification failed.",
                        fix=(
                            "Confirm the published DNS public key matches the signing private key "
                            "and that no relay modifies the message body after signing."
                        ),
                    )
                )
            elif sig.algorithm and "sha1" in sig.algorithm.lower():
                issues.append(
                    EmailIssue(
                        severity="warn",
                        title=f"DKIM uses deprecated SHA-1 ({label})",
                        detail="SHA-1 DKIM signatures are deprecated by RFC 8301.",
                        fix="Switch DKIM signing to rsa-sha256 or ed25519-sha256.",
                    )
                )
        if any_valid_dkim and any_aligned_dkim:
            issues.append(
                EmailIssue(
                    severity="pass",
                    title="DKIM signature passed and aligned",
                    detail=(
                        f"Verified cryptographic DKIM signature aligned with From: {from_domain}."
                    ),
                )
            )
        elif any_valid_dkim:
            issues.append(
                EmailIssue(
                    severity="warn",
                    title="DKIM signature verified, but signing domain does not align with From:",
                    detail=(
                        f"DKIM verified for {dkim_reports[0].domain}, which does not align with "
                        f"From: {from_domain}."
                    ),
                    fix=(
                        f"Configure your email provider to sign with d={from_domain} instead of "
                        "its shared provider domain."
                    ),
                )
            )

    # 3. DMARC findings
    if dmarc_result == "pass":
        issues.append(
            EmailIssue(
                severity="pass",
                title=f"DMARC passed (p={dmarc_policy})",
                detail=(
                    f"Message satisfied DMARC alignment for {from_domain} "
                    f"(SPF aligned={'yes' if spf_passes_dmarc else 'no'}, "
                    f"DKIM aligned={'yes' if dkim_passes_dmarc else 'no'})."
                ),
            )
        )
    elif dmarc_result == "none":
        issues.append(
            EmailIssue(
                severity="warn",
                title="No DMARC policy published for From: domain",
                detail=(
                    f"No DMARC record exists for {from_domain or 'the sender domain'}; Gmail and "
                    "Yahoo require at least p=none for bulk senders."
                ),
                fix=f"Publish a DMARC TXT record at _dmarc.{from_domain or 'yourdomain.com'}.",
            )
        )
    else:
        issues.append(
            EmailIssue(
                severity="fail",
                title=f"DMARC failed (policy p={dmarc_policy})",
                detail=(
                    f"Neither SPF nor DKIM both passed and aligned with From: {from_domain}, "
                    f"so receivers apply policy '{dmarc_policy}'."
                ),
                fix=(
                    "Fix SPF and/or DKIM signing so at least one passes and aligns with "
                    "your From: domain."
                ),
            )
        )

    # 4. Transport TLS & reverse DNS
    if tls_used:
        issues.append(
            EmailIssue(
                severity="pass",
                title=f"Delivered over TLS ({tls_version or 'encrypted'})",
                detail=(
                    "The sending server encrypted this delivery using "
                    f"{tls_version or 'STARTTLS'}."
                ),
            )
        )
    else:
        issues.append(
            EmailIssue(
                severity="warn",
                title="Email arrived without TLS encryption",
                detail=(
                    "The sending connection did not use STARTTLS; Gmail and Yahoo require TLS "
                    "for delivering email."
                ),
                fix="Enable outbound opportunistic TLS on your sending mail server.",
            )
        )

    if ptr_host and fcrdns_valid:
        issues.append(
            EmailIssue(
                severity="pass",
                title=f"Valid reverse DNS ({ptr_host})",
                detail=f"Connecting IP {peer_ip} resolves to {ptr_host} and back to {peer_ip}.",
            )
        )
    else:
        issues.append(
            EmailIssue(
                severity="warn",
                title=f"Missing or unconfirmed reverse DNS for {peer_ip}",
                detail=(
                    f"Connecting IP {peer_ip} does not have valid forward-confirmed reverse DNS "
                    "(required by Gmail and Yahoo for all senders)."
                ),
                fix="Set a PTR record on the sending IP whose hostname resolves back to that IP.",
            )
        )

    # 5. Headers & one-click unsubscribe
    if one_click_valid:
        issues.append(
            EmailIssue(
                severity="pass",
                title="One-click unsubscribe headers present (RFC 8058)",
                detail=(
                    "Both List-Unsubscribe (HTTPS) and List-Unsubscribe-Post headers are valid."
                ),
            )
        )
    else:
        issues.append(
            EmailIssue(
                severity="info",
                title="No RFC 8058 one-click unsubscribe headers found",
                detail=(
                    "Required for bulk promotional/subscribed emails since June 1, 2024; "
                    "transactional emails (receipts, password resets) do not need this."
                ),
                fix=(
                    "For newsletters/marketing mail, include both List-Unsubscribe: <https://...> "
                    "and List-Unsubscribe-Post: List-Unsubscribe=One-Click."
                ),
            )
        )

    if not message_id:
        issues.append(
            EmailIssue(
                severity="warn",
                title="Missing Message-ID header",
                detail=(
                    "RFC 5322 recommends a unique Message-ID header; spam filters penalize "
                    "missing IDs."
                ),
                fix=(
                    "Configure your mailer or app library to generate a standard "
                    "Message-ID header."
                ),
            )
        )

    if not date_valid:
        issues.append(
            EmailIssue(
                severity="warn",
                title="Missing or invalid Date header",
                detail="Every email should include a valid RFC 5322 Date header.",
                fix="Ensure your sending client sets a valid Date header.",
            )
        )

    if has_text_html and not has_text_plain:
        issues.append(
            EmailIssue(
                severity="info",
                title="HTML email has no plain-text part (tip)",
                detail=(
                    "Sending multipart/alternative with both text/plain and text/html improves "
                    "accessibility and spam-filter compatibility."
                ),
                fix="Include a plain-text fallback alongside your HTML email body.",
            )
        )

    severity_rank = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    sorted_issues = tuple(sorted(issues, key=lambda i: severity_rank[i.severity]))

    fail_count = sum(1 for i in sorted_issues if i.severity == "fail")
    warn_count = sum(1 for i in sorted_issues if i.severity == "warn")
    verdict_status: Literal["pass", "warn", "fail"]
    if fail_count > 0:
        verdict_status = "fail"
        noun = "problem" if fail_count == 1 else "problems"
        verdict_line = f"This email failed authentication checks. {fail_count} {noun} to fix."
    elif warn_count > 0:
        verdict_status = "warn"
        noun = "improvement" if warn_count == 1 else "improvements"
        verdict_line = f"This email passed core checks, with {warn_count} recommended {noun}."
    else:
        verdict_status = "pass"
        verdict_line = "This email passed SPF, DKIM, DMARC, TLS, and reverse DNS checks."

    return EmailAnalysisReport(
        received_at=timestamp,
        peer_ip=peer_ip,
        helo_hostname=helo_hostname,
        ptr_hostname=ptr_host,
        fcrdns_valid=fcrdns_valid,
        tls_used=tls_used,
        tls_version=tls_version,
        tls_cipher=tls_cipher,
        mail_from=clean_mail_from,
        mail_from_domain=mail_from_domain,
        from_header=from_header,
        from_address=from_address,
        from_domain=from_domain,
        subject=subject,
        message_id=message_id,
        date_header=date_header,
        date_valid=date_valid,
        size_bytes=len(raw_bytes),
        has_text_plain=has_text_plain,
        has_text_html=has_text_html,
        attachment_count=attachment_count,
        list_unsubscribe=list_unsub,
        list_unsubscribe_post=list_unsub_post,
        one_click_unsubscribe_valid=one_click_valid,
        spf=spf_res,
        spf_aligned_relaxed=spf_aligned_relaxed,
        spf_aligned_strict=spf_aligned_strict,
        dkim_signatures=dkim_reports,
        dmarc_result=dmarc_result,
        dmarc_policy=dmarc_policy,
        dmarc_adkim=adkim,
        dmarc_aspf=aspf,
        verdict_status=verdict_status,
        verdict_line=verdict_line,
        issues=sorted_issues,
    )


def render_email_report_text(report: EmailAnalysisReport) -> str:
    """Render a plain-text summary of a received test email report."""
    lines = [
        f"DeliverCheck Test Email Report ({report.from_address or 'unknown sender'})",
        "=" * 54,
        f"Verdict: {report.verdict_line}",
        f"From: {report.from_header or '(missing)'}",
        f"Return-Path: {report.mail_from or '(empty)'}",
        f"Subject: {report.subject}",
        f"Connecting IP: {report.peer_ip} (PTR: {report.ptr_hostname or 'none'}, "
        f"FCrDNS={'ok' if report.fcrdns_valid else 'no'})",
        f"TLS: {report.tls_version if report.tls_used else 'none'} | "
        f"Size: {report.size_bytes} bytes",
        f"Auth: SPF={report.spf.result if report.spf else 'none'} | "
        f"DKIM={'pass' if any(s.verified for s in report.dkim_signatures) else 'fail/none'} | "
        f"DMARC={report.dmarc_result} (p={report.dmarc_policy or 'none'})",
        "",
        "Findings:",
    ]
    for issue in report.issues:
        lines.append(f"[{issue.severity.upper()}] {issue.title}")
        lines.append(f"  {issue.detail}")
        if issue.fix:
            lines.append(f"  Fix: {issue.fix}")
    return "\n".join(lines) + "\n"
