"""Suggested merged SPF records (within RFC 7208 limits) and DMARC progression records."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from app.checks.dmarc import DMARCCheckResult
from app.checks.spf import (
    SPF_MAX_DNS_LOOKUPS,
    SPFCheckResult,
    SPFIncludeTrace,
    parse_spf_record,
)
from app.dns.providers import MailProvider

# Typical RFC 7208 lookup cost for well-known provider includes (used when not yet in include_tree)
_KNOWN_INCLUDE_COSTS: dict[str, int] = {
    "_spf.google.com": 3,
    "spf.protection.outlook.com": 2,
    "zoho.com": 1,
    "zoho.eu": 1,
    "zoho.in": 1,
    "zoho.com.au": 1,
    "_spf.mail.hostinger.com": 1,
    "sendgrid.net": 1,
    "amazonses.com": 1,
    "servers.mcsv.net": 1,
}


@dataclass(frozen=True)
class SPFSuggestion:
    record: str | None
    record_host: str
    estimated_lookups: int
    within_limit: bool
    note: str


@dataclass(frozen=True)
class DMARCSuggestion:
    record: str | None
    record_host: str
    next_step: str
    progression_note: str


def _lookup_cost_map(traces: Sequence[SPFIncludeTrace]) -> dict[str, int]:
    costs: dict[str, int] = {}
    for node in traces:
        costs[node.domain.lower()] = max(1, node.lookups)
        costs.update(_lookup_cost_map(node.children))
    return costs


def _estimate_term_cost(
    term_raw: str, mechanism: str, arg: str | None, costs: dict[str, int]
) -> int:
    if mechanism in ("ip4", "ip6", "all"):
        return 0
    if mechanism == "include" and arg:
        key = arg.lower().rstrip(".")
        if key in costs:
            return costs[key]
        return _KNOWN_INCLUDE_COSTS.get(key, 1)
    if mechanism in ("a", "mx", "ptr", "exists"):
        return 1
    return 0


def suggest_spf_fix(
    spf: SPFCheckResult,
    detected_providers: Sequence[MailProvider] = (),
) -> SPFSuggestion | None:
    """Generate a merged, RFC-7208-compliant SPF record or explain why a sender must be trimmed."""
    needs_fix = (
        spf.record is None
        or len(spf.all_records) > 1
        or spf.permerror
        or spf.all_qualifier in ("+", "?", None)
        or spf.redirect_ignored
        or bool(spf.dead_terms)
        or bool(spf.missing_provider_includes)
        or spf.has_ptr
    )
    if not needs_fix:
        return None

    observed_costs = _lookup_cost_map(spf.include_tree)

    mechanisms: list[tuple[str, str, str | None]] = []  # (raw_token, mechanism, arg)
    seen_tokens: set[str] = set()
    seen_includes: set[str] = set()
    preferred_all: str = "~all"

    source_records = (
        spf.all_records if spf.all_records else (() if not spf.record else (spf.record,))
    )

    for raw_rec in source_records:
        parsed = parse_spf_record(raw_rec)
        seen_all_in_rec = False
        for term in parsed.terms:
            if seen_all_in_rec:
                # Skip dead terms after 'all'
                continue
            if term.mechanism == "all":
                seen_all_in_rec = True
                if term.qualifier == "-":
                    preferred_all = "-all"
                continue
            if term.mechanism == "ptr":
                # Drop deprecated 'ptr' when building a clean replacement
                continue
            if term.mechanism == "include" and term.argument:
                inc_norm = term.argument.lower().rstrip(".")
                if inc_norm in seen_includes:
                    continue
                seen_includes.add(inc_norm)
                token = f"include:{inc_norm}" if term.qualifier == "+" else term.raw
                mechanisms.append((token, "include", inc_norm))
                seen_tokens.add(token.lower())
                continue
            token_lower = term.raw.lower()
            if token_lower not in seen_tokens:
                seen_tokens.add(token_lower)
                mechanisms.append((term.raw, term.mechanism, term.argument))

    # Add missing required provider includes (never Shopify or Klaviyo)
    for provider in detected_providers:
        if not provider.requires_root_spf_include or not provider.recommended_spf_include:
            continue
        inc_norm = provider.recommended_spf_include.lower()
        already_covered = any(
            inc in seen_includes or any(existing.endswith(f".{inc}") for existing in seen_includes)
            for inc in provider.spf_includes
        )
        if not already_covered:
            seen_includes.add(inc_norm)
            mechanisms.append((f"include:{inc_norm}", "include", inc_norm))

    total_lookups = sum(
        _estimate_term_cost(raw_tok, mech, arg, observed_costs) for raw_tok, mech, arg in mechanisms
    )

    if total_lookups > SPF_MAX_DNS_LOOKUPS:
        heaviest = sorted(
            (
                (raw_tok, _estimate_term_cost(raw_tok, mech, arg, observed_costs))
                for raw_tok, mech, arg in mechanisms
                if _estimate_term_cost(raw_tok, mech, arg, observed_costs) > 0
            ),
            key=lambda pair: pair[1],
            reverse=True,
        )
        top_summary = ", ".join(f"{tok} ({cost})" for tok, cost in heaviest[:4])
        return SPFSuggestion(
            record=None,
            record_host="@",
            estimated_lookups=total_lookups,
            within_limit=False,
            note=(
                f"Merging all current senders would require {total_lookups} DNS lookups "
                f"(limit is {SPF_MAX_DNS_LOOKUPS}). Heaviest terms: {top_summary}. "
                "Remove an unused sender, move bulk/marketing email to a dedicated subdomain, "
                "or flatten static IPs before publishing."
            ),
        )

    parts = ["v=spf1", *(raw_tok for raw_tok, _, _ in mechanisms), preferred_all]
    merged_record = " ".join(parts)

    if len(spf.all_records) > 1:
        note = (
            f"Replace all {len(spf.all_records)} existing SPF TXT records with this single merged "
            f"record ({total_lookups}/{SPF_MAX_DNS_LOOKUPS} DNS lookups)."
        )
    elif spf.record is None:
        note = (
            f"Add this TXT record on your root domain (@) "
            f"({total_lookups}/{SPF_MAX_DNS_LOOKUPS} DNS lookups)."
        )
    else:
        note = (
            f"Update your root TXT record (@) to this cleaned SPF record "
            f"({total_lookups}/{SPF_MAX_DNS_LOOKUPS} DNS lookups)."
        )

    return SPFSuggestion(
        record=merged_record,
        record_host="@",
        estimated_lookups=total_lookups,
        within_limit=True,
        note=note,
    )


def suggest_dmarc_fix(dmarc: DMARCCheckResult) -> DMARCSuggestion | None:
    """Suggest the next DMARC TXT record and explain the none -> quarantine -> reject path."""
    progression = (
        "Recommended rollout path: start with p=none (collect reports) -> move to "
        "p=quarantine (spam-folder failures) -> enforce p=reject (block spoofed mail)."
    )
    host = f"_dmarc.{dmarc.record_domain or dmarc.organizational_domain}"

    if dmarc.record is None:
        starter = (
            f"v=DMARC1; p=none; rua=mailto:dmarc@{dmarc.organizational_domain}; adkim=r; aspf=r"
        )
        return DMARCSuggestion(
            record=starter,
            record_host=host,
            next_step="Publish a starter p=none DMARC record to begin receiving reports safely.",
            progression_note=progression,
        )

    if dmarc.suggested_record is None:
        return None

    if dmarc.effective_policy == "none":
        next_step = (
            "Add a rua= report address first, then move to p=quarantine once reports confirm "
            "every legitimate sender passes."
            if dmarc.parsed and not dmarc.parsed.rua_raw
            else (
                "Once your DMARC reports confirm all legitimate senders pass, "
                "upgrade to p=quarantine."
            )
        )
    elif dmarc.effective_policy == "quarantine":
        next_step = (
            "Once quarantine causes no false positives for legitimate mail, upgrade to p=reject."
        )
    else:
        next_step = "Publish the corrected DMARC record with valid RFC 7489 tag order and syntax."

    return DMARCSuggestion(
        record=dmarc.suggested_record,
        record_host=host,
        next_step=next_step,
        progression_note=progression,
    )
