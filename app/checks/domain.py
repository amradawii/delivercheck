"""End-to-end domain readiness orchestrator with per-check timeouts and partial-result safety."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Sequence

from app.checks.blocklists import BlocklistCheckResult, BlocklistIssue, check_blocklists
from app.checks.dkim import DKIMCheckResult, DKIMIssue, check_dkim
from app.checks.dmarc import (
    DMARCCheckResult,
    DMARCIssue,
    check_dmarc,
    get_organizational_domain,
)
from app.checks.extras import (
    ExtraIssue,
    ExtrasCheckResult,
    MTASTSResult,
    PolicyFetcher,
    check_extras,
)
from app.checks.fixes import suggest_dmarc_fix, suggest_spf_fix
from app.checks.mx import MXCheckResult, MXIssue, check_mx
from app.checks.requirements import evaluate_sender_requirements
from app.checks.spf import SPFCheckResult, SPFIssue, check_spf
from app.config import Settings
from app.dns.providers import (
    DNSHost,
    MailProvider,
    detect_dns_host_for_domain,
    detect_providers_from_txt,
)
from app.dns.resolver import (
    CachedDNSResolver,
    DNSResolver,
    DNSResponse,
    DNSStatus,
    normalize_dns_name,
)
from app.report.models import DomainReport, Finding, Severity, build_verdict, sort_findings

DEFAULT_CHECK_TIMEOUT_SECONDS = 12.0


def _as_severity(raw: str) -> Severity:
    if raw in ("fail", "warn", "info", "pass"):
        return raw  # type: ignore[return-value]
    return "info"


def _extract_single_spf_ips(ip4_nets: tuple[str, ...], ip6_nets: tuple[str, ...]) -> list[str]:
    """Return single-host IPs (/32 or /128) explicitly listed in SPF for IP blocklist checks."""
    out: list[str] = []
    for raw in ip4_nets:
        try:
            net4 = ipaddress.IPv4Network(raw, strict=False)
            if net4.prefixlen == 32:
                out.append(str(net4.network_address))
        except ValueError:
            continue
    for raw in ip6_nets:
        try:
            net6 = ipaddress.IPv6Network(raw, strict=False)
            if net6.prefixlen == 128:
                out.append(str(net6.network_address))
        except ValueError:
            continue
    return out


async def safe_check_mx(
    domain: str,
    resolver: DNSResolver,
    *,
    timeout_seconds: float = DEFAULT_CHECK_TIMEOUT_SECONDS,
) -> MXCheckResult:
    try:
        async with asyncio.timeout(timeout_seconds):
            return await check_mx(domain, resolver)
    except TimeoutError:
        return MXCheckResult(
            domain=domain,
            status="error",
            issues=(
                MXIssue(
                    severity="warn",
                    title="MX check timed out",
                    detail=(
                        f"DNS did not answer the MX query for {domain} within "
                        f"{timeout_seconds:.0f} seconds, while the rest of the report completed."
                    ),
                    fix="Run the check again in a moment or verify your authoritative DNS servers.",
                ),
            ),
        )
    except Exception:
        return MXCheckResult(
            domain=domain,
            status="error",
            issues=(
                MXIssue(
                    severity="warn",
                    title="MX check could not complete",
                    detail=(
                        f"An unexpected error interrupted the MX lookup for {domain}, "
                        "while the remaining checks still ran."
                    ),
                    fix="Try checking this domain again shortly.",
                ),
            ),
        )


async def safe_detect_dns_host(
    domain: str,
    resolver: DNSResolver,
    *,
    timeout_seconds: float = DEFAULT_CHECK_TIMEOUT_SECONDS,
) -> DNSHost | None:
    try:
        async with asyncio.timeout(timeout_seconds):
            return await detect_dns_host_for_domain(domain, resolver)
    except (TimeoutError, Exception):
        return None


async def safe_query_root_txt(
    domain: str,
    resolver: DNSResolver,
    *,
    timeout_seconds: float = DEFAULT_CHECK_TIMEOUT_SECONDS,
) -> DNSResponse:
    try:
        async with asyncio.timeout(timeout_seconds):
            return await resolver.query(domain, "TXT")
    except TimeoutError:
        return DNSResponse(
            qname=domain,
            rdtype="TXT",
            status=DNSStatus.TIMEOUT,
            error_message="DNS query timed out",
        )
    except Exception:
        return DNSResponse(
            qname=domain,
            rdtype="TXT",
            status=DNSStatus.ERROR,
            error_message="DNS query failed",
        )


async def safe_check_spf(
    domain: str,
    resolver: DNSResolver,
    *,
    detected_providers: Sequence[MailProvider] = (),
    timeout_seconds: float = DEFAULT_CHECK_TIMEOUT_SECONDS,
) -> SPFCheckResult:
    try:
        async with asyncio.timeout(timeout_seconds):
            return await check_spf(domain, resolver, detected_providers=detected_providers)
    except TimeoutError:
        return SPFCheckResult(
            domain=domain,
            status="error",
            issues=(
                SPFIssue(
                    severity="warn",
                    title="SPF check timed out",
                    detail=(
                        f"Evaluating the SPF record and includes for {domain} exceeded "
                        f"{timeout_seconds:.0f} seconds, while the rest of the report completed."
                    ),
                    fix="Run the check again or simplify slow third-party SPF include chains.",
                ),
            ),
        )
    except Exception:
        return SPFCheckResult(
            domain=domain,
            status="error",
            issues=(
                SPFIssue(
                    severity="warn",
                    title="SPF check could not complete",
                    detail=(
                        f"An unexpected error interrupted SPF evaluation for {domain}, "
                        "while the remaining checks still ran."
                    ),
                    fix="Try checking this domain again shortly.",
                ),
            ),
        )


async def safe_check_dmarc(
    domain: str,
    resolver: DNSResolver,
    *,
    timeout_seconds: float = DEFAULT_CHECK_TIMEOUT_SECONDS,
) -> DMARCCheckResult:
    org_domain = get_organizational_domain(domain) or domain
    try:
        async with asyncio.timeout(timeout_seconds):
            return await check_dmarc(domain, resolver)
    except TimeoutError:
        return DMARCCheckResult(
            domain=domain,
            organizational_domain=org_domain,
            status="error",
            issues=(
                DMARCIssue(
                    severity="warn",
                    title="DMARC check timed out",
                    detail=(
                        f"DNS did not answer the DMARC lookup for _dmarc.{domain} within "
                        f"{timeout_seconds:.0f} seconds, while the rest of the report completed."
                    ),
                    fix="Run the check again in a moment or verify your authoritative DNS servers.",
                ),
            ),
        )
    except Exception:
        return DMARCCheckResult(
            domain=domain,
            organizational_domain=org_domain,
            status="error",
            issues=(
                DMARCIssue(
                    severity="warn",
                    title="DMARC check could not complete",
                    detail=(
                        f"An unexpected error interrupted DMARC inspection for {domain}, "
                        "while the remaining checks still ran."
                    ),
                    fix="Try checking this domain again shortly.",
                ),
            ),
        )


async def safe_check_dkim(
    domain: str,
    resolver: DNSResolver,
    *,
    detected_providers: Sequence[MailProvider] = (),
    custom_selector: str | None = None,
    timeout_seconds: float = DEFAULT_CHECK_TIMEOUT_SECONDS,
) -> DKIMCheckResult:
    try:
        async with asyncio.timeout(timeout_seconds):
            return await check_dkim(
                domain,
                resolver,
                detected_providers=detected_providers,
                custom_selector=custom_selector,
            )
    except TimeoutError:
        return DKIMCheckResult(
            domain=domain,
            status="error",
            issues=(
                DKIMIssue(
                    severity="warn",
                    title="DKIM check timed out",
                    detail=(
                        f"Probing DKIM selectors for {domain} exceeded {timeout_seconds:.0f} "
                        "seconds, while the rest of the report completed."
                    ),
                    fix=(
                        "Run the check again or enter your exact DKIM selector in the optional "
                        "selector box."
                    ),
                ),
            ),
        )
    except Exception:
        return DKIMCheckResult(
            domain=domain,
            status="error",
            issues=(
                DKIMIssue(
                    severity="warn",
                    title="DKIM check could not complete",
                    detail=(
                        f"An unexpected error interrupted DKIM probing for {domain}, "
                        "while the remaining checks still ran."
                    ),
                    fix=(
                        "Try checking this domain again shortly or send a test email "
                        "to verify DKIM."
                    ),
                ),
            ),
        )


async def safe_check_blocklists(
    domain: str,
    resolver: DNSResolver,
    *,
    ips: Sequence[str] = (),
    spamhaus_dqs_key: str | None = None,
    enable_barracuda_brbl: bool = False,
    timeout_seconds: float = DEFAULT_CHECK_TIMEOUT_SECONDS,
) -> BlocklistCheckResult:
    try:
        async with asyncio.timeout(timeout_seconds):
            return await check_blocklists(
                domain,
                resolver,
                ips=ips,
                spamhaus_dqs_key=spamhaus_dqs_key,
                enable_barracuda_brbl=enable_barracuda_brbl,
            )
    except TimeoutError:
        return BlocklistCheckResult(
            domain=domain,
            status="warn",
            issues=(
                BlocklistIssue(
                    severity="warn",
                    title="Blocklist check timed out",
                    detail=(
                        f"DNS blocklist queries for {domain} did not finish within "
                        f"{timeout_seconds:.0f} seconds; this does not mean the domain is listed."
                    ),
                    fix="Run the check again in a moment to retry the blocklist lookups.",
                ),
            ),
        )
    except Exception:
        return BlocklistCheckResult(
            domain=domain,
            status="warn",
            issues=(
                BlocklistIssue(
                    severity="warn",
                    title="Blocklist check could not complete",
                    detail=(
                        f"An unexpected error interrupted blocklist lookups for {domain}; "
                        "this does not mean the domain is listed."
                    ),
                    fix="Try checking this domain again shortly.",
                ),
            ),
        )


async def safe_check_extras(
    domain: str,
    resolver: DNSResolver,
    *,
    mx_result: MXCheckResult,
    dmarc_result: DMARCCheckResult,
    policy_fetcher: PolicyFetcher | None = None,
    timeout_seconds: float = DEFAULT_CHECK_TIMEOUT_SECONDS,
) -> ExtrasCheckResult:
    try:
        async with asyncio.timeout(timeout_seconds):
            return await check_extras(
                domain,
                resolver,
                mx_result=mx_result,
                dmarc_result=dmarc_result,
                policy_fetcher=policy_fetcher,
            )
    except TimeoutError:
        return ExtrasCheckResult(
            domain=domain,
            mta_sts=MTASTSResult(error="Timed out"),
            issues=(
                ExtraIssue(
                    severity="info",
                    title="Optional extras check timed out",
                    detail=(
                        f"Checking MTA-STS, TLS-RPT, and BIMI for {domain} exceeded "
                        f"{timeout_seconds:.0f} seconds, while the core checks completed."
                    ),
                    fix="Run the check again if you want to verify optional MTA-STS or BIMI setup.",
                ),
            ),
        )
    except Exception:
        return ExtrasCheckResult(
            domain=domain,
            mta_sts=MTASTSResult(error="Unexpected error"),
            issues=(
                ExtraIssue(
                    severity="info",
                    title="Optional extras check could not complete",
                    detail=(
                        f"An unexpected error interrupted optional MTA-STS, TLS-RPT, and BIMI "
                        f"checks for {domain}, while the core checks completed."
                    ),
                    fix="Try checking this domain again shortly.",
                ),
            ),
        )


def assemble_domain_report(
    *,
    domain: str,
    mx_result: MXCheckResult,
    dns_host: DNSHost | None,
    spf_result: SPFCheckResult,
    dkim_result: DKIMCheckResult,
    dmarc_result: DMARCCheckResult,
    blocklist_result: BlocklistCheckResult,
    extras_result: ExtrasCheckResult,
    detected_providers: Sequence[MailProvider],
) -> DomainReport:
    """Assemble sorted findings, checklist, suggestions, and verdict from completed checks."""
    all_providers: list[MailProvider] = list(detected_providers)
    for p in dkim_result.detected_providers:
        if all(existing.id != p.id for existing in all_providers):
            all_providers.append(p)

    mailbox_provider = mx_result.provider
    sending_providers = tuple(
        p for p in all_providers if mailbox_provider is None or p.id != mailbox_provider.id
    )

    checklist = evaluate_sender_requirements(spf_result, dkim_result, dmarc_result)
    spf_suggestion = suggest_spf_fix(spf_result, all_providers)
    dmarc_suggestion = suggest_dmarc_fix(dmarc_result)

    findings: list[Finding] = []
    for mx_issue in mx_result.issues:
        findings.append(
            Finding(
                section="MX",
                severity=_as_severity(mx_issue.severity),
                title=mx_issue.title,
                summary=mx_issue.detail,
                fix=mx_issue.fix,
                record_value=mx_issue.record_value,
                record_host="@",
            )
        )
    for spf_issue in spf_result.issues:
        rec_val = spf_issue.record_value
        if (
            rec_val is None
            and spf_suggestion
            and spf_suggestion.record
            and spf_issue.severity == "fail"
        ):
            rec_val = spf_suggestion.record
        findings.append(
            Finding(
                section="SPF",
                severity=_as_severity(spf_issue.severity),
                title=spf_issue.title,
                summary=spf_issue.detail,
                fix=spf_issue.fix,
                record_value=rec_val,
                record_host="@",
            )
        )
    for dkim_issue in dkim_result.issues:
        findings.append(
            Finding(
                section="DKIM",
                severity=_as_severity(dkim_issue.severity),
                title=dkim_issue.title,
                summary=dkim_issue.detail,
                fix=dkim_issue.fix,
                record_value=dkim_issue.record_value,
            )
        )
    dmarc_host = f"_dmarc.{dmarc_result.record_domain or dmarc_result.organizational_domain}"
    for dmarc_issue in dmarc_result.issues:
        findings.append(
            Finding(
                section="DMARC",
                severity=_as_severity(dmarc_issue.severity),
                title=dmarc_issue.title,
                summary=dmarc_issue.detail,
                fix=dmarc_issue.fix,
                record_value=dmarc_issue.record_value,
                record_host=dmarc_host if dmarc_issue.record_value else None,
            )
        )
    for bl_issue in blocklist_result.issues:
        findings.append(
            Finding(
                section="Blocklists",
                severity=_as_severity(bl_issue.severity),
                title=bl_issue.title,
                summary=bl_issue.detail,
                fix=bl_issue.fix,
            )
        )
    for ex_issue in extras_result.issues:
        findings.append(
            Finding(
                section="Extras",
                severity=_as_severity(ex_issue.severity),
                title=ex_issue.title,
                summary=ex_issue.detail,
                fix=ex_issue.fix,
            )
        )

    sorted_findings = sort_findings(findings)
    verdict_status, verdict_line = build_verdict(
        sorted_findings,
        checklist,
        is_null_mx=mx_result.is_null_mx,
    )

    return DomainReport(
        domain=domain,
        verdict_status=verdict_status,
        verdict_line=verdict_line,
        mailbox_provider=mailbox_provider,
        sending_providers=sending_providers,
        dns_host=dns_host,
        checklist=checklist,
        mx=mx_result,
        spf=spf_result,
        dkim=dkim_result,
        dmarc=dmarc_result,
        blocklists=blocklist_result,
        extras=extras_result,
        spf_suggestion=spf_suggestion,
        dmarc_suggestion=dmarc_suggestion,
        findings=sorted_findings,
    )


async def run_domain_check(
    domain: str,
    resolver: DNSResolver,
    *,
    custom_selector: str | None = None,
    settings: Settings | None = None,
    policy_fetcher: PolicyFetcher | None = None,
    check_timeout_seconds: float | None = None,
) -> DomainReport:
    """Run all domain checks in parallel with per-check timeouts and partial-result safety."""
    norm_domain = normalize_dns_name(domain)
    scoped = CachedDNSResolver(resolver)
    cfg = settings or Settings()
    timeout = (
        check_timeout_seconds if check_timeout_seconds is not None else cfg.check_timeout_seconds
    )

    # Phase 1: MX, NS (DNS host), and root TXT (for early sender detection such as Klaviyo)
    mx_result, dns_host, root_txt_resp = await asyncio.gather(
        safe_check_mx(norm_domain, scoped, timeout_seconds=timeout),
        safe_detect_dns_host(norm_domain, scoped, timeout_seconds=timeout),
        safe_query_root_txt(norm_domain, scoped, timeout_seconds=timeout),
    )

    initial_providers: list[MailProvider] = []
    if mx_result.provider is not None:
        initial_providers.append(mx_result.provider)
    if root_txt_resp.status == DNSStatus.OK:
        for p in detect_providers_from_txt(root_txt_resp.records):
            if all(existing.id != p.id for existing in initial_providers):
                initial_providers.append(p)

    # Phase 2: SPF and DMARC in parallel
    spf_result, dmarc_result = await asyncio.gather(
        safe_check_spf(
            norm_domain,
            scoped,
            detected_providers=initial_providers,
            timeout_seconds=timeout,
        ),
        safe_check_dmarc(norm_domain, scoped, timeout_seconds=timeout),
    )

    all_providers: list[MailProvider] = list(initial_providers)
    for p in spf_result.detected_providers:
        if all(existing.id != p.id for existing in all_providers):
            all_providers.append(p)

    ips_to_check: list[str] = []
    for host in mx_result.hosts:
        ips_to_check.extend(host.all_ips)
    ips_to_check.extend(_extract_single_spf_ips(spf_result.ip4_networks, spf_result.ip6_networks))

    # Phase 3: DKIM, Blocklists, and Extras in parallel
    dkim_result, blocklist_result, extras_result = await asyncio.gather(
        safe_check_dkim(
            norm_domain,
            scoped,
            detected_providers=all_providers,
            custom_selector=custom_selector,
            timeout_seconds=timeout,
        ),
        safe_check_blocklists(
            norm_domain,
            scoped,
            ips=ips_to_check,
            spamhaus_dqs_key=cfg.spamhaus_dqs_key,
            enable_barracuda_brbl=cfg.enable_barracuda_brbl,
            timeout_seconds=timeout,
        ),
        safe_check_extras(
            norm_domain,
            scoped,
            mx_result=mx_result,
            dmarc_result=dmarc_result,
            policy_fetcher=policy_fetcher,
            timeout_seconds=timeout,
        ),
    )

    return assemble_domain_report(
        domain=norm_domain,
        mx_result=mx_result,
        dns_host=dns_host,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        blocklist_result=blocklist_result,
        extras_result=extras_result,
        detected_providers=all_providers,
    )
