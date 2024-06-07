"""Gmail and Yahoo 2024 sender requirements checklist."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.checks.dkim import DKIMCheckResult
from app.checks.dmarc import DMARCCheckResult
from app.checks.spf import SPFCheckResult

RequirementStatus = Literal["pass", "fail", "warn", "needs_test_email", "info"]


@dataclass(frozen=True)
class SenderRequirementItem:
    id: str
    title: str
    scope: Literal["all", "bulk"]
    status: RequirementStatus
    detail: str
    fix: str | None = None


@dataclass(frozen=True)
class SenderChecklist:
    items: tuple[SenderRequirementItem, ...]
    timeline_note: str
    bulk_threshold_note: str

    @property
    def failed_count(self) -> int:
        return sum(1 for item in self.items if item.status == "fail")


def evaluate_sender_requirements(
    spf: SPFCheckResult,
    dkim: DKIMCheckResult,
    dmarc: DMARCCheckResult,
) -> SenderChecklist:
    """Evaluate Gmail and Yahoo 2024 sender requirements from DNS results."""
    spf_ok = spf.status in ("pass", "warn") and not spf.permerror and spf.record is not None
    if spf.all_qualifier == "+":
        spf_ok = False
    dkim_ok = dkim.has_active_key
    dkim_unknown = dkim.status == "unknown"
    dmarc_ok = (
        dmarc.record is not None
        and dmarc.status != "fail"
        and dmarc.effective_policy in ("none", "quarantine", "reject")
    )

    items: list[SenderRequirementItem] = []

    # 1. All senders: SPF or DKIM
    if spf_ok or dkim_ok:
        items.append(
            SenderRequirementItem(
                id="all_auth",
                title="SPF or DKIM authentication (all senders)",
                scope="all",
                status="pass",
                detail="At least one valid authentication method (SPF or DKIM) is published.",
            )
        )
    elif dkim_unknown:
        items.append(
            SenderRequirementItem(
                id="all_auth",
                title="SPF or DKIM authentication (all senders)",
                scope="all",
                status="needs_test_email",
                detail=(
                    "SPF is missing or invalid, and DKIM could not be confirmed automatically "
                    "from common selectors."
                ),
                fix="Publish a valid SPF record or send a test email to confirm DKIM signing.",
            )
        )
    else:
        items.append(
            SenderRequirementItem(
                id="all_auth",
                title="SPF or DKIM authentication (all senders)",
                scope="all",
                status="fail",
                detail="Neither SPF nor DKIM is validly configured for this domain.",
                fix="Publish a valid SPF record and enable DKIM signing in your email provider.",
            )
        )

    # 2. All senders: FCrDNS (needs test email / server IP)
    items.append(
        SenderRequirementItem(
            id="all_fcrdns",
            title="Valid forward and reverse DNS (all senders)",
            scope="all",
            status="needs_test_email",
            detail=(
                "The sending server's IP must have a PTR record that resolves back to the same IP."
            ),
            fix="Send a test email or run the mail server test to verify reverse DNS.",
        )
    )

    # 3. All senders: TLS transport
    items.append(
        SenderRequirementItem(
            id="all_tls",
            title="TLS encryption in transit (all senders)",
            scope="all",
            status="needs_test_email",
            detail="Gmail and Yahoo require TLS when transmitting email.",
            fix="Send a test email to verify your outgoing server uses TLS 1.2 or newer.",
        )
    )

    # 4. All senders: Spam complaint rate (informational only)
    items.append(
        SenderRequirementItem(
            id="all_spam_rate",
            title="Spam rate below 0.3% (target below 0.1%)",
            scope="all",
            status="info",
            detail=(
                "Spam complaint rates cannot be checked from DNS; monitor them in Google "
                "Postmaster Tools and Yahoo Sender Hub."
            ),
        )
    )

    # 5. Bulk senders: Both SPF AND DKIM
    if spf_ok and dkim_ok:
        items.append(
            SenderRequirementItem(
                id="bulk_spf_dkim",
                title="Both SPF and DKIM enabled (bulk senders)",
                scope="bulk",
                status="pass",
                detail="Both SPF and an active DKIM key are published.",
            )
        )
    elif spf_ok and dkim_unknown:
        items.append(
            SenderRequirementItem(
                id="bulk_spf_dkim",
                title="Both SPF and DKIM enabled (bulk senders)",
                scope="bulk",
                status="needs_test_email",
                detail=(
                    "SPF is configured, but DKIM could not be confirmed from common selectors."
                ),
                fix="Enter your DKIM selector or send a test email to verify DKIM.",
            )
        )
    else:
        items.append(
            SenderRequirementItem(
                id="bulk_spf_dkim",
                title="Both SPF and DKIM enabled (bulk senders)",
                scope="bulk",
                status="fail",
                detail="Bulk senders must have both SPF and DKIM properly configured.",
                fix="Fix the SPF and/or DKIM issues listed below before sending bulk mail.",
            )
        )

    # 6. Bulk senders: DMARC at least p=none
    if dmarc_ok:
        items.append(
            SenderRequirementItem(
                id="bulk_dmarc",
                title="DMARC record published (bulk senders)",
                scope="bulk",
                status="pass",
                detail=(
                    f"DMARC record is published with policy p={dmarc.effective_policy} "
                    "(minimum required is p=none)."
                ),
            )
        )
    else:
        items.append(
            SenderRequirementItem(
                id="bulk_dmarc",
                title="DMARC record published (bulk senders)",
                scope="bulk",
                status="fail",
                detail="Bulk senders must publish a valid DMARC record (at least p=none).",
                fix=(
                    "Publish a TXT record at _dmarc with at least v=DMARC1; p=none and an "
                    "aggregate report address."
                ),
            )
        )

    # 7. Bulk senders: From-domain alignment (SPF or DKIM aligned)
    items.append(
        SenderRequirementItem(
            id="bulk_alignment",
            title="From-domain alignment with SPF or DKIM (bulk senders)",
            scope="bulk",
            status="needs_test_email",
            detail=(
                "The visible From: domain must align with either the SPF domain or the DKIM "
                "signing domain (d=)."
            ),
            fix="Send a test email to verify live SPF/DKIM alignment against your From: header.",
        )
    )

    # 8. Bulk senders: One-click unsubscribe (RFC 8058, promotional mail only, enforced Jun 1, 2024)
    items.append(
        SenderRequirementItem(
            id="bulk_unsubscribe",
            title="One-click unsubscribe header (bulk promotional mail)",
            scope="bulk",
            status="needs_test_email",
            detail=(
                "Required for promotional and subscribed mail since June 1, 2024 (RFC 8058: "
                "List-Unsubscribe and List-Unsubscribe-Post); transactional mail is exempt."
            ),
            fix="Send a promotional test email to verify one-click unsubscribe headers.",
        )
    )

    return SenderChecklist(
        items=tuple(items),
        timeline_note=(
            "Phased 2024 rollout: Feb 1 (temporary errors), Apr 1 (progressive rejections), "
            "and Jun 1 (one-click unsubscribe for promotional mail)."
        ),
        bulk_threshold_note=(
            "Gmail defines bulk senders as 5,000+ messages/day to personal Gmail accounts; "
            "Yahoo enforces bulk rules for commercial/bulk senders without a published threshold."
        ),
    )
