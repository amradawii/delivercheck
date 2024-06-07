"""Unified Finding and DomainReport models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.checks.blocklists import BlocklistCheckResult
from app.checks.dkim import DKIMCheckResult
from app.checks.dmarc import DMARCCheckResult
from app.checks.extras import ExtrasCheckResult
from app.checks.fixes import DMARCSuggestion, SPFSuggestion
from app.checks.mx import MXCheckResult
from app.checks.requirements import SenderChecklist
from app.checks.spf import SPFCheckResult
from app.dns.providers import DNSHost, MailProvider

Severity = Literal["fail", "warn", "info", "pass"]

_SEVERITY_ORDER: dict[Severity, int] = {
    "fail": 0,
    "warn": 1,
    "info": 2,
    "pass": 3,
}


@dataclass(frozen=True)
class Finding:
    section: str  # "MX", "SPF", "DKIM", "DMARC", "Blocklists", "Extras", "Server", "Email"
    severity: Severity
    title: str
    summary: str
    fix: str | None = None
    record_value: str | None = None
    record_host: str | None = None


@dataclass(frozen=True)
class DomainReport:
    domain: str
    verdict_status: Literal["pass", "warn", "fail"]
    verdict_line: str
    mailbox_provider: MailProvider | None
    sending_providers: tuple[MailProvider, ...]
    dns_host: DNSHost | None
    checklist: SenderChecklist
    mx: MXCheckResult
    spf: SPFCheckResult
    dkim: DKIMCheckResult
    dmarc: DMARCCheckResult
    blocklists: BlocklistCheckResult
    extras: ExtrasCheckResult
    spf_suggestion: SPFSuggestion | None
    dmarc_suggestion: DMARCSuggestion | None
    findings: tuple[Finding, ...]

    @property
    def fail_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "fail")

    @property
    def warn_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warn")


def sort_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    """Order findings worst-first (fail -> warn -> info -> pass), keeping section order stable."""
    return tuple(sorted(findings, key=lambda f: _SEVERITY_ORDER[f.severity]))


def build_verdict(
    findings: tuple[Finding, ...],
    checklist: SenderChecklist,
    *,
    is_null_mx: bool,
) -> tuple[Literal["pass", "warn", "fail"], str]:
    fails = [f for f in findings if f.severity == "fail"]
    warns = [f for f in findings if f.severity == "warn"]

    if fails:
        count = len(fails)
        noun = "problem" if count == 1 else "problems"
        if checklist.failed_count > 0:
            return (
                "fail",
                f"Gmail and Yahoo will likely reject or spam your emails. {count} {noun} to fix.",
            )
        return (
            "fail",
            f"Email delivery has serious issues. {count} {noun} to fix.",
        )

    if warns:
        count = len(warns)
        noun = "improvement" if count == 1 else "improvements"
        return (
            "warn",
            f"Email should deliver, with {count} recommended {noun} to strengthen trust.",
        )

    if is_null_mx:
        return (
            "pass",
            "This domain explicitly does not accept email (Null MX) and its policies look clean.",
        )

    return (
        "pass",
        "Your domain DNS records look ready to send and receive email.",
    )
