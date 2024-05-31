"""RFC 7489 DMARC parser, alignment/policy checker, and external report authorization."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from urllib.parse import unquote

from publicsuffixlist import PublicSuffixList

from app.dns.resolver import DNSResolver, DNSStatus, normalize_dns_name

_PSL = PublicSuffixList()

_VALID_POLICIES = frozenset({"none", "quarantine", "reject"})
_VALID_ALIGNMENTS = frozenset({"r", "s"})
_VALID_FO_OPTIONS = frozenset({"0", "1", "d", "s"})
_SIZE_SUFFIX_RE = re.compile(r"^(?P<uri>.+)!(?P<size>\d+[kmgtKMGT]?)$")
_EMAIL_RE = re.compile(r"^[^@\s]+@(?P<domain>[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)$")


@dataclass(frozen=True)
class DMARCIssue:
    severity: str  # "pass", "warn", "fail", "info"
    title: str
    detail: str
    fix: str | None = None
    record_value: str | None = None


@dataclass(frozen=True)
class DMARCReportURI:
    raw: str
    kind: str  # "rua" or "ruf"
    address: str | None = None
    domain: str | None = None
    size_limit: str | None = None
    is_valid: bool = True
    is_external: bool = False
    external_authorized: bool | None = None  # None when same org domain or invalid
    auth_qname: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class ParsedDMARC:
    raw: str
    tags: tuple[tuple[str, str], ...] = ()
    policy: str | None = None
    subdomain_policy: str | None = None
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    ri: int = 86400
    fo: tuple[str, ...] = ("0",)
    rua_raw: tuple[str, ...] = ()
    ruf_raw: tuple[str, ...] = ()
    tag_order_errors: tuple[str, ...] = ()
    syntax_errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class DMARCCheckResult:
    domain: str
    organizational_domain: str
    status: str  # "pass", "warn", "fail", "error"
    record: str | None = None
    all_records: tuple[str, ...] = ()
    record_domain: str | None = None
    inherited_from_org_domain: bool = False
    parsed: ParsedDMARC | None = None
    effective_policy: str | None = None
    report_uris: tuple[DMARCReportURI, ...] = ()
    bimi_eligible: bool = False
    suggested_record: str | None = None
    issues: tuple[DMARCIssue, ...] = ()


def get_organizational_domain(domain: str) -> str:
    """Compute the RFC 7489 Organizational Domain using the offline Public Suffix List."""
    norm = normalize_dns_name(domain)
    if not norm:
        return ""
    priv = _PSL.privatesuffix(norm)
    if priv:
        return str(priv)
    return norm


def is_dmarc_txt_record(txt: str) -> bool:
    """RFC 7489 section 6.3: DMARC TXT records start with case-sensitive 'v=DMARC1'."""
    stripped = txt.strip()
    return (
        stripped == "v=DMARC1"
        or stripped.startswith("v=DMARC1;")
        or stripped.startswith("v=DMARC1 ")
        or stripped.startswith("v=DMARC1\t")
    )


def parse_dmarc_record(raw: str) -> ParsedDMARC:
    """Parse a DMARC TXT record and enforce RFC 7489 section 6.3 tag order and values."""
    tags_list: list[tuple[str, str]] = []
    tag_map: dict[str, str] = {}
    order_errors: list[str] = []
    syntax_errors: list[str] = []

    segments = raw.strip().split(";")
    for segment in segments:
        piece = segment.strip()
        if not piece:
            continue
        if "=" not in piece:
            syntax_errors.append(f"Malformed DMARC tag '{piece}' (missing '=').")
            continue
        name_raw, value_raw = piece.split("=", 1)
        name = name_raw.strip().lower()
        value = value_raw.strip()
        if not name:
            syntax_errors.append(f"Empty DMARC tag name in '{piece}'.")
            continue
        if name in tag_map:
            syntax_errors.append(f"Duplicate DMARC tag '{name}='.")
        tag_map[name] = value
        tags_list.append((name, value))

    # RFC 7489 section 6.3: v=DMARC1 MUST be first and p= MUST be second
    if not tags_list or tags_list[0][0] != "v" or tags_list[0][1] != "DMARC1":
        order_errors.append("Tag 'v=DMARC1' must be the first tag in a DMARC record (RFC 7489).")
    if len(tags_list) < 2 or tags_list[1][0] != "p":
        if "p" in tag_map:
            order_errors.append(
                "Tag 'p=' must immediately follow 'v=DMARC1' as the second tag (RFC 7489)."
            )
        else:
            syntax_errors.append("Missing required 'p=' policy tag.")

    policy: str | None = None
    if "p" in tag_map:
        p_val = tag_map["p"].lower()
        if p_val in _VALID_POLICIES:
            policy = p_val
        else:
            syntax_errors.append(
                f"Invalid DMARC policy 'p={tag_map['p']}' (expected none, quarantine, or reject)."
            )

    subdomain_policy: str | None = None
    if "sp" in tag_map:
        sp_val = tag_map["sp"].lower()
        if sp_val in _VALID_POLICIES:
            subdomain_policy = sp_val
        else:
            syntax_errors.append(
                f"Invalid subdomain policy 'sp={tag_map['sp']}' "
                "(expected none, quarantine, or reject)."
            )

    pct = 100
    if "pct" in tag_map:
        try:
            pct = int(tag_map["pct"])
            if not (0 <= pct <= 100):
                syntax_errors.append(f"DMARC 'pct={pct}' must be between 0 and 100.")
                pct = max(0, min(100, pct))
        except ValueError:
            syntax_errors.append(f"Invalid integer for 'pct={tag_map['pct']}'.")

    adkim = "r"
    if "adkim" in tag_map:
        val = tag_map["adkim"].lower()
        if val in _VALID_ALIGNMENTS:
            adkim = val
        else:
            syntax_errors.append(f"Invalid 'adkim={tag_map['adkim']}' (expected 'r' or 's').")

    aspf = "r"
    if "aspf" in tag_map:
        val = tag_map["aspf"].lower()
        if val in _VALID_ALIGNMENTS:
            aspf = val
        else:
            syntax_errors.append(f"Invalid 'aspf={tag_map['aspf']}' (expected 'r' or 's').")

    ri = 86400
    if "ri" in tag_map:
        try:
            ri = int(tag_map["ri"])
            if ri <= 0:
                syntax_errors.append(f"DMARC 'ri={ri}' must be a positive number of seconds.")
        except ValueError:
            syntax_errors.append(f"Invalid integer for 'ri={tag_map['ri']}'.")

    fo_values: tuple[str, ...] = ("0",)
    if "fo" in tag_map:
        opts = tuple(part.strip().lower() for part in tag_map["fo"].split(":") if part.strip())
        bad_opts = [opt for opt in opts if opt not in _VALID_FO_OPTIONS]
        if bad_opts or not opts:
            syntax_errors.append(
                f"Invalid 'fo={tag_map['fo']}' (valid options are 0, 1, d, s separated by ':')."
            )
        else:
            fo_values = opts

    rua_raw = _split_uri_list(tag_map.get("rua"))
    ruf_raw = _split_uri_list(tag_map.get("ruf"))

    return ParsedDMARC(
        raw=raw,
        tags=tuple(tags_list),
        policy=policy,
        subdomain_policy=subdomain_policy,
        pct=pct,
        adkim=adkim,
        aspf=aspf,
        ri=ri,
        fo=fo_values,
        rua_raw=rua_raw,
        ruf_raw=ruf_raw,
        tag_order_errors=tuple(order_errors),
        syntax_errors=tuple(syntax_errors),
    )


def _split_uri_list(raw_val: str | None) -> tuple[str, ...]:
    if not raw_val:
        return ()
    return tuple(item.strip() for item in raw_val.split(",") if item.strip())


def parse_report_uri(raw_uri: str, kind: str, source_org_domain: str) -> DMARCReportURI:
    """Parse a DMARC rua/ruf URI, stripping !size modifiers before extracting the domain."""
    size_limit: str | None = None
    uri_part = raw_uri.strip()

    size_match = _SIZE_SUFFIX_RE.match(uri_part)
    if size_match:
        uri_part = size_match.group("uri")
        size_limit = size_match.group("size")
    elif "!" in uri_part:
        return DMARCReportURI(
            raw=raw_uri,
            kind=kind,
            is_valid=False,
            error=f"Invalid size modifier in '{raw_uri}' (expected !<number>[k|m|g|t]).",
        )

    if not uri_part.lower().startswith("mailto:"):
        return DMARCReportURI(
            raw=raw_uri,
            kind=kind,
            size_limit=size_limit,
            is_valid=False,
            error=f"Report URI '{raw_uri}' must start with 'mailto:'.",
        )

    address = unquote(uri_part[7:]).strip()
    email_match = _EMAIL_RE.match(address)
    if not email_match:
        return DMARCReportURI(
            raw=raw_uri,
            kind=kind,
            address=address or None,
            size_limit=size_limit,
            is_valid=False,
            error=f"Invalid email address in {kind} URI '{raw_uri}'.",
        )

    dest_domain = normalize_dns_name(email_match.group("domain"))
    dest_org = get_organizational_domain(dest_domain)
    is_external = dest_org != source_org_domain

    return DMARCReportURI(
        raw=raw_uri,
        kind=kind,
        address=address,
        domain=dest_domain,
        size_limit=size_limit,
        is_valid=True,
        is_external=is_external,
    )


async def _verify_external_report_uri(
    uri: DMARCReportURI,
    source_domain: str,
    resolver: DNSResolver,
) -> DMARCReportURI:
    if not uri.is_valid or not uri.is_external or not uri.domain:
        return uri

    auth_qname = f"{source_domain}._report._dmarc.{uri.domain}"
    resp = await resolver.query(auth_qname, "TXT")
    if resp.status == DNSStatus.OK and any(is_dmarc_txt_record(r) for r in resp.records):
        return DMARCReportURI(
            raw=uri.raw,
            kind=uri.kind,
            address=uri.address,
            domain=uri.domain,
            size_limit=uri.size_limit,
            is_valid=True,
            is_external=True,
            external_authorized=True,
            auth_qname=auth_qname,
        )

    error_detail = (
        f"DNS error checking {auth_qname} ({resp.status.value})."
        if resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR)
        else (
            f"External destination {uri.domain} does not publish a v=DMARC1 TXT record at "
            f"{auth_qname}, so receivers will ignore this report address."
        )
    )
    return DMARCReportURI(
        raw=uri.raw,
        kind=uri.kind,
        address=uri.address,
        domain=uri.domain,
        size_limit=uri.size_limit,
        is_valid=True,
        is_external=True,
        external_authorized=False,
        auth_qname=auth_qname,
        error=error_detail,
    )


async def check_dmarc(domain: str, resolver: DNSResolver) -> DMARCCheckResult:
    """Inspect a domain's DMARC record, policy, alignment, and external report authorization."""
    norm_domain = normalize_dns_name(domain)
    org_domain = get_organizational_domain(norm_domain)

    qname = f"_dmarc.{norm_domain}"
    resp = await resolver.query(qname, "TXT")

    if resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
        return DMARCCheckResult(
            domain=norm_domain,
            organizational_domain=org_domain,
            status="error",
            issues=(
                DMARCIssue(
                    severity="fail",
                    title="Could not look up DMARC record",
                    detail=(
                        f"DNS TXT lookup for {qname} failed "
                        f"({resp.error_message or resp.status.value})."
                    ),
                    fix="Check that your domain's nameservers are reachable and try again.",
                ),
            ),
        )

    dmarc_records = tuple(r for r in resp.records if is_dmarc_txt_record(r))
    record_domain = norm_domain
    inherited = False

    # RFC 7489 section 6.6.3: fall back to Organizational Domain when subdomain has no record
    if not dmarc_records and norm_domain != org_domain:
        org_qname = f"_dmarc.{org_domain}"
        org_resp = await resolver.query(org_qname, "TXT")
        if org_resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
            return DMARCCheckResult(
                domain=norm_domain,
                organizational_domain=org_domain,
                status="error",
                issues=(
                    DMARCIssue(
                        severity="fail",
                        title="Could not look up organizational DMARC record",
                        detail=(
                            f"DNS TXT lookup for {org_qname} failed "
                            f"({org_resp.error_message or org_resp.status.value})."
                        ),
                        fix="Check that your domain's nameservers are reachable and try again.",
                    ),
                ),
            )
        org_records = tuple(r for r in org_resp.records if is_dmarc_txt_record(r))
        if org_records:
            dmarc_records = org_records
            record_domain = org_domain
            inherited = True

    if not dmarc_records:
        suggested = f"v=DMARC1; p=none; rua=mailto:dmarc@{org_domain}; adkim=r; aspf=r"
        return DMARCCheckResult(
            domain=norm_domain,
            organizational_domain=org_domain,
            status="fail",
            suggested_record=suggested,
            issues=(
                DMARCIssue(
                    severity="fail",
                    title="No DMARC record found",
                    detail=(
                        f"No DMARC TXT record was found at _dmarc.{norm_domain}, so receiving "
                        "servers have no spoofing policy and bulk senders fail Gmail/Yahoo rules."
                    ),
                    fix=(
                        f"Add a TXT record at _dmarc.{org_domain} starting with p=none to collect "
                        "reports, then progress to p=quarantine and p=reject."
                    ),
                    record_value=suggested,
                ),
            ),
        )

    if len(dmarc_records) > 1:
        return DMARCCheckResult(
            domain=norm_domain,
            organizational_domain=org_domain,
            status="fail",
            all_records=dmarc_records,
            record_domain=record_domain,
            inherited_from_org_domain=inherited,
            issues=(
                DMARCIssue(
                    severity="fail",
                    title=f"Multiple DMARC records found ({len(dmarc_records)})",
                    detail=(
                        f"_dmarc.{record_domain} publishes {len(dmarc_records)} DMARC TXT "
                        "records; RFC 7489 requires receivers to ignore DMARC when more than one "
                        "record exists."
                    ),
                    fix=(
                        f"Delete the duplicate TXT records at _dmarc.{record_domain} so only one "
                        "v=DMARC1 record remains."
                    ),
                ),
            ),
        )

    raw_record = dmarc_records[0]
    parsed = parse_dmarc_record(raw_record)

    effective_policy = (
        parsed.subdomain_policy if (inherited and parsed.subdomain_policy) else parsed.policy
    )

    source_org = get_organizational_domain(record_domain)
    initial_uris = [
        *(parse_report_uri(u, "rua", source_org) for u in parsed.rua_raw),
        *(parse_report_uri(u, "ruf", source_org) for u in parsed.ruf_raw),
    ]
    verified_uris = tuple(
        await asyncio.gather(
            *(_verify_external_report_uri(u, record_domain, resolver) for u in initial_uris)
        )
    )

    issues: list[DMARCIssue] = []
    has_fail = False
    has_warn = False

    for err in parsed.syntax_errors:
        has_fail = True
        issues.append(
            DMARCIssue(
                severity="fail",
                title="DMARC record has syntax errors",
                detail=err,
                fix=f"Correct the invalid tag in your TXT record at _dmarc.{record_domain}.",
            )
        )

    for order_err in parsed.tag_order_errors:
        has_fail = True
        issues.append(
            DMARCIssue(
                severity="fail",
                title="DMARC tags are out of order",
                detail=order_err,
                fix=(
                    "Place 'v=DMARC1;' first and 'p=<policy>;' immediately second in your "
                    f"_dmarc.{record_domain} TXT record."
                ),
            )
        )

    if effective_policy == "none":
        has_warn = True
        issues.append(
            DMARCIssue(
                severity="warn",
                title="DMARC policy is monitoring-only (p=none)",
                detail=(
                    "A policy of 'p=none' satisfies the baseline Gmail/Yahoo requirement but "
                    "does not block or quarantine spoofed emails."
                ),
                fix=(
                    "Review your DMARC reports until all legitimate senders pass SPF/DKIM "
                    "alignment, then move from p=none to p=quarantine and finally p=reject."
                ),
            )
        )
    elif effective_policy in ("quarantine", "reject"):
        if parsed.pct == 0 and effective_policy == "reject":
            has_warn = True
            issues.append(
                DMARCIssue(
                    severity="warn",
                    title="DMARC has p=reject with pct=0",
                    detail=(
                        "Under RFC 7489 section 6.6.4, setting pct=0 with p=reject applies "
                        "quarantine instead of rejecting spoofed messages."
                    ),
                    fix="Increase pct gradually up to pct=100 (or remove pct= to default to 100).",
                )
            )
        elif parsed.pct < 100:
            has_warn = True
            issues.append(
                DMARCIssue(
                    severity="warn",
                    title=(
                        f"DMARC only enforces on {parsed.pct}% of failing mail (pct={parsed.pct})"
                    ),
                    detail=(
                        f"Your policy ({effective_policy}) applies to only {parsed.pct}% of "
                        "failing messages, leaving the rest unenforced and blocking BIMI."
                    ),
                    fix=(
                        "Raise pct to 100 (or remove pct=) once monitoring shows no legitimate "
                        "failures."
                    ),
                )
            )

    if (
        not inherited
        and parsed.policy in ("quarantine", "reject")
        and parsed.subdomain_policy == "none"
    ):
        has_warn = True
        issues.append(
            DMARCIssue(
                severity="warn",
                title="Subdomains are not protected (sp=none)",
                detail=(
                    f"Your root domain enforces p={parsed.policy}, but sp=none leaves subdomains "
                    "without enforcement against spoofing."
                ),
                fix=f"Remove sp=none or change it to sp={parsed.policy}.",
            )
        )

    if not parsed.rua_raw:
        has_warn = True
        issues.append(
            DMARCIssue(
                severity="warn",
                title="No aggregate report address (rua=) configured",
                detail=(
                    "Without a 'rua=' address, receiving mail servers cannot send you daily "
                    "reports showing who is sending email as your domain."
                ),
                fix=(
                    f"Add 'rua=mailto:dmarc@{org_domain}' to your _dmarc.{record_domain} "
                    "TXT record."
                ),
            )
        )

    for uri in verified_uris:
        if not uri.is_valid:
            has_fail = True
            issues.append(
                DMARCIssue(
                    severity="fail",
                    title=f"Invalid DMARC {uri.kind} address",
                    detail=uri.error or f"Could not parse {uri.raw}.",
                    fix=(f"Use a valid mailto URI such as '{uri.kind}=mailto:dmarc@{org_domain}'."),
                )
            )
        elif uri.is_external and uri.external_authorized is False:
            has_warn = True
            issues.append(
                DMARCIssue(
                    severity="warn",
                    title=f"External DMARC report domain '{uri.domain}' is not authorized",
                    detail=uri.error or f"Missing authorization record at {uri.auth_qname}.",
                    fix=(
                        f"Ask the owner of {uri.domain} to publish a TXT record at "
                        f"{uri.auth_qname} with value 'v=DMARC1', or send reports to an address "
                        f"on {org_domain}."
                    ),
                    record_value=f'{uri.auth_qname} TXT "v=DMARC1"',
                )
            )

    bimi_eligible = (
        not has_fail
        and effective_policy in ("quarantine", "reject")
        and parsed.pct == 100
        and (not inherited or effective_policy in ("quarantine", "reject"))
    )

    if inherited:
        issues.append(
            DMARCIssue(
                severity="info",
                title=f"DMARC inherited from organizational domain ({org_domain})",
                detail=(
                    f"No record exists at _dmarc.{norm_domain}, so receivers apply the record "
                    f"from _dmarc.{org_domain} (effective policy: {effective_policy})."
                ),
            )
        )

    if not has_fail and not has_warn:
        issues.insert(
            0,
            DMARCIssue(
                severity="pass",
                title=f"DMARC is enforcing (p={effective_policy})",
                detail=(
                    f"Valid DMARC record at _dmarc.{record_domain} with policy "
                    f"'{effective_policy}' (adkim={parsed.adkim}, aspf={parsed.aspf})."
                ),
            ),
        )

    status = "fail" if has_fail else ("warn" if has_warn else "pass")
    suggested_upgrade = _suggest_dmarc_upgrade(record_domain, org_domain, parsed, effective_policy)

    return DMARCCheckResult(
        domain=norm_domain,
        organizational_domain=org_domain,
        status=status,
        record=raw_record,
        all_records=dmarc_records,
        record_domain=record_domain,
        inherited_from_org_domain=inherited,
        parsed=parsed,
        effective_policy=effective_policy,
        report_uris=verified_uris,
        bimi_eligible=bimi_eligible,
        suggested_record=suggested_upgrade,
        issues=tuple(issues),
    )


def _suggest_dmarc_upgrade(
    record_domain: str,
    org_domain: str,
    parsed: ParsedDMARC,
    effective_policy: str | None,
) -> str | None:
    rua = f"rua={','.join(parsed.rua_raw)}" if parsed.rua_raw else f"rua=mailto:dmarc@{org_domain}"
    if parsed.tag_order_errors or parsed.syntax_errors:
        pol = parsed.policy or "none"
        return f"v=DMARC1; p={pol}; {rua}; adkim={parsed.adkim}; aspf={parsed.aspf}"
    if effective_policy == "none":
        if not parsed.rua_raw:
            return f"v=DMARC1; p=none; {rua}; adkim={parsed.adkim}; aspf={parsed.aspf}"
        return f"v=DMARC1; p=quarantine; {rua}; adkim={parsed.adkim}; aspf={parsed.aspf}"
    if effective_policy == "quarantine":
        return f"v=DMARC1; p=reject; {rua}; adkim={parsed.adkim}; aspf={parsed.aspf}"
    return None
