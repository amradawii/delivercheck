"""Plain-text report renderer for developers and hosting support tickets."""

from __future__ import annotations

from app.report.models import DomainReport, Finding

_STATUS_TAG = {
    "pass": "PASS",
    "warn": "WARN",
    "fail": "FAIL",
    "info": "INFO",
    "needs_test_email": "NEEDS TEST EMAIL",
}


def render_findings_text(findings: tuple[Finding, ...]) -> list[str]:
    lines: list[str] = []
    for finding in findings:
        tag = _STATUS_TAG.get(finding.severity, finding.severity.upper())
        lines.append(f"[{tag}] ({finding.section}) {finding.title}")
        lines.append(f"  {finding.summary}")
        if finding.fix:
            lines.append(f"  Fix: {finding.fix}")
        if finding.record_value:
            host_prefix = f"{finding.record_host}: " if finding.record_host else ""
            lines.append(f"  Record: {host_prefix}{finding.record_value}")
    return lines


def render_domain_report_text(report: DomainReport) -> str:
    """Render a clean plain-text summary suitable for copying into a support ticket."""
    lines: list[str] = [
        f"DeliverCheck Domain Report: {report.domain}",
        "=" * (28 + len(report.domain)),
        f"Verdict: {report.verdict_line}",
        "",
    ]

    detected_parts: list[str] = []
    if report.mailbox_provider:
        detected_parts.append(f"Email: {report.mailbox_provider.name}")
    if report.sending_providers:
        names = ", ".join(p.name for p in report.sending_providers)
        detected_parts.append(f"Also sending: {names}")
    if report.dns_host:
        detected_parts.append(f"DNS host: {report.dns_host.name}")
    if detected_parts:
        lines.append("Detected: " + " | ".join(detected_parts))
        if report.dns_host:
            lines.append(f"Where to add DNS records: {report.dns_host.guide_url}")
        lines.append("")

    lines.append("Gmail & Yahoo 2024 Sender Requirements:")
    for item in report.checklist.items:
        tag = _STATUS_TAG.get(item.status, item.status.upper())
        lines.append(f"  - [{tag}] {item.title}: {item.detail}")
    lines.append("")

    if report.spf_suggestion:
        lines.append("Suggested SPF Record:")
        lines.append(f"  {report.spf_suggestion.note}")
        if report.spf_suggestion.record:
            lines.append(
                f"  TXT {report.spf_suggestion.record_host}: {report.spf_suggestion.record}"
            )
        lines.append("")

    if report.dmarc_suggestion and report.dmarc_suggestion.record:
        lines.append("Suggested DMARC Record:")
        lines.append(f"  {report.dmarc_suggestion.next_step}")
        lines.append(
            f"  TXT {report.dmarc_suggestion.record_host}: {report.dmarc_suggestion.record}"
        )
        lines.append("")

    lines.append("Findings (worst first):")
    lines.extend(render_findings_text(report.findings))
    lines.append("")
    lines.append(
        f"Summary: MX={report.mx.status.upper()} | "
        f"SPF={report.spf.status.upper()} ({report.spf.dns_lookups}/10 lookups) | "
        f"DKIM={report.dkim.status.upper()} | "
        f"DMARC={report.dmarc.status.upper()} | "
        f"Blocklists={report.blocklists.status.upper()}"
    )
    return "\n".join(lines) + "\n"
