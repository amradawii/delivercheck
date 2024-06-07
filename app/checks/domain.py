"""End-to-end domain readiness orchestrator running DNS checks in parallel."""

from __future__ import annotations

import asyncio
import ipaddress

from app.checks.blocklists import check_blocklists
from app.checks.dkim import check_dkim
from app.checks.dmarc import check_dmarc
from app.checks.extras import PolicyFetcher, check_extras
from app.checks.fixes import suggest_dmarc_fix, suggest_spf_fix
from app.checks.mx import check_mx
from app.checks.requirements import evaluate_sender_requirements
from app.checks.spf import check_spf
from app.config import Settings
from app.dns.providers import (
    MailProvider,
    detect_dns_host_for_domain,
    detect_providers_from_txt,
)
from app.dns.resolver import CachedDNSResolver, DNSResolver, DNSStatus, normalize_dns_name
from app.report.models import DomainReport, Finding, Severity, build_verdict, sort_findings


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


async def run_domain_check(
    domain: str,
    resolver: DNSResolver,
    *,
    custom_selector: str | None = None,
    settings: Settings | None = None,
    policy_fetcher: PolicyFetcher | None = None,
) -> DomainReport:
    """Run all domain checks in parallel and assemble a unified DomainReport."""
    norm_domain = normalize_dns_name(domain)
    scoped = CachedDNSResolver(resolver)
    cfg = settings or Settings()

    # Phase 1: MX, NS (DNS host), and root TXT (for early sender detection such as Klaviyo)
    mx_result, dns_host, root_txt_resp = await asyncio.gather(
        check_mx(norm_domain, scoped),
        detect_dns_host_for_domain(norm_domain, scoped),
        scoped.query(norm_domain, "TXT"),
    )

    initial_providers: list[MailProvider] = []
    if mx_result.provider is not None:
        initial_providers.append(mx_result.provider)
    if root_txt_resp.status == DNSStatus.OK:
        for p in detect_providers_from_txt(root_txt_resp.records):
            if all(existing.id != p.id for existing in initial_providers):
                initial_providers.append(p)

    # Phase 2: SPF and DMARC in parallel (SPF may uncover extra senders for DKIM selector probing)
    spf_result, dmarc_result = await asyncio.gather(
        check_spf(norm_domain, scoped, detected_providers=initial_providers),
        check_dmarc(norm_domain, scoped),
    )

    all_providers: list[MailProvider] = list(initial_providers)
    for p in spf_result.detected_providers:
        if all(existing.id != p.id for existing in all_providers):
            all_providers.append(p)

    # Collect MX IPs + explicit /32 or /128 SPF IPs for blocklist checks
    ips_to_check: list[str] = []
    for host in mx_result.hosts:
        ips_to_check.extend(host.all_ips)
    ips_to_check.extend(_extract_single_spf_ips(spf_result.ip4_networks, spf_result.ip6_networks))

    # Phase 3: DKIM, Blocklists, and Extras in parallel
    dkim_result, blocklist_result, extras_result = await asyncio.gather(
        check_dkim(
            norm_domain,
            scoped,
            detected_providers=all_providers,
            custom_selector=custom_selector,
        ),
        check_blocklists(
            norm_domain,
            scoped,
            ips=ips_to_check,
            spamhaus_dqs_key=cfg.spamhaus_dqs_key,
            enable_barracuda_brbl=cfg.enable_barracuda_brbl,
        ),
        check_extras(
            norm_domain,
            scoped,
            mx_result=mx_result,
            dmarc_result=dmarc_result,
            policy_fetcher=policy_fetcher,
        ),
    )

    # Include any additional providers discovered from DKIM CNAME targets
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
    for dmarc_issue in dmarc_result.issues:
        dmarc_host = f"_dmarc.{dmarc_result.record_domain or dmarc_result.organizational_domain}"
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
        domain=norm_domain,
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
