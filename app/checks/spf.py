"""Hand-written RFC 7208 SPF parser, lookup counter, static auditor, and IP evaluator."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from app.dns.providers import (
    MailProvider,
    detect_providers_from_spf_includes,
)
from app.dns.resolver import DNSResolver, DNSStatus, normalize_dns_name, reverse_ip_for_ptr

SPF_MAX_DNS_LOOKUPS = 10
SPF_MAX_VOID_LOOKUPS = 2
SPF_MAX_PER_MECHANISM_LOOKUPS = 10
SPF_UDP_WARN_BYTES = 450

Qualifier = Literal["+", "-", "~", "?"]
SPFOutcome = Literal["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]

_QUALIFIER_TO_OUTCOME: dict[Qualifier, SPFOutcome] = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
}

_MECHANISM_RE = re.compile(
    r"^(?P<qual>[+\-~?])?(?P<mech>all|include|a|mx|ptr|ip4|ip6|exists)"
    r"(?::(?P<arg>[^/\s]+))?(?P<cidr>(?:/\d+)?(?://\d+)?)?$",
    re.IGNORECASE,
)
_MODIFIER_RE = re.compile(r"^(?P<name>[a-zA-Z][a-zA-Z0-9_.-]*)=(?P<value>\S*)$")
_MACRO_RE = re.compile(r"%\{([slodipvhcrtSLODIPVHCRT])(\d*)([rR]?)([.\-+,/_=]*)\}|%%|%_|%-")
_CIDR_RE = re.compile(r"^(?:/(?P<v4>\d+))?(?://(?P<v6>\d+))?$")
_DOMAIN_SPEC_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")


@dataclass(frozen=True)
class SPFTerm:
    raw: str
    qualifier: Qualifier
    mechanism: str  # "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"
    argument: str | None = None
    cidr4: int | None = None
    cidr6: int | None = None
    has_macro: bool = False


@dataclass(frozen=True)
class SPFModifier:
    raw: str
    name: str  # lowercased, e.g. "redirect", "exp"
    value: str
    has_macro: bool = False


@dataclass(frozen=True)
class ParsedSPF:
    raw: str
    terms: tuple[SPFTerm, ...] = ()
    modifiers: tuple[SPFModifier, ...] = ()
    syntax_errors: tuple[str, ...] = ()

    @property
    def all_term(self) -> SPFTerm | None:
        for term in self.terms:
            if term.mechanism == "all":
                return term
        return None

    @property
    def redirect(self) -> SPFModifier | None:
        for mod in self.modifiers:
            if mod.name == "redirect":
                return mod
        return None


@dataclass(frozen=True)
class SPFIssue:
    severity: str  # "pass", "warn", "fail", "info"
    title: str
    detail: str
    fix: str | None = None
    record_value: str | None = None


@dataclass(frozen=True)
class SPFIncludeTrace:
    domain: str
    lookups: int
    void_lookups: int
    record: str | None = None
    error: str | None = None
    children: tuple[SPFIncludeTrace, ...] = ()


@dataclass(frozen=True)
class SPFCheckResult:
    domain: str
    status: str  # "pass", "warn", "fail", "error"
    record: str | None = None
    all_records: tuple[str, ...] = ()
    parsed: ParsedSPF | None = None
    dns_lookups: int = 0
    void_lookups: int = 0
    all_qualifier: Qualifier | None = None
    has_redirect: bool = False
    redirect_ignored: bool = False
    dead_terms: tuple[str, ...] = ()
    has_ptr: bool = False
    has_macros: bool = False
    loop_detected: bool = False
    loop_chain: tuple[str, ...] = ()
    per_mx_limit_exceeded: bool = False
    permerror: bool = False
    includes: tuple[str, ...] = ()
    include_tree: tuple[SPFIncludeTrace, ...] = ()
    ip4_networks: tuple[str, ...] = ()
    ip6_networks: tuple[str, ...] = ()
    detected_providers: tuple[MailProvider, ...] = ()
    missing_provider_includes: tuple[tuple[MailProvider, str], ...] = ()
    issues: tuple[SPFIssue, ...] = ()


@dataclass(frozen=True)
class SPFEvalResult:
    result: SPFOutcome
    domain: str
    client_ip: str
    dns_lookups: int
    void_lookups: int
    matched_mechanism: str | None = None
    explanation: str | None = None


def _contains_macro(value: str) -> bool:
    return "%" in value


def _validate_macro_syntax(value: str) -> bool:
    """Return True if all '%' escapes in value are valid RFC 7208 macro expressions."""
    idx = 0
    while idx < len(value):
        pos = value.find("%", idx)
        if pos == -1:
            return True
        m = _MACRO_RE.match(value, pos)
        if m is None:
            return False
        idx = m.end()
    return True


def _validate_domain_spec(spec: str) -> bool:
    if not spec:
        return False
    if _contains_macro(spec):
        return _validate_macro_syntax(spec)
    cleaned = spec.rstrip(".")
    if not cleaned or ".." in cleaned:
        return False
    return bool(_DOMAIN_SPEC_RE.match(cleaned))


def is_spf_txt_record(txt: str) -> bool:
    """RFC 7208 section 4.5: record starts with 'v=spf1' followed by end-of-string or space."""
    stripped = txt.strip()
    lower = stripped.lower()
    return lower == "v=spf1" or lower.startswith("v=spf1 ") or lower.startswith("v=spf1\t")


def parse_spf_record(raw: str) -> ParsedSPF:
    """Parse an SPF v1 TXT record according to RFC 7208 grammar."""
    tokens = raw.strip().split()
    if not tokens or tokens[0].lower() != "v=spf1":
        return ParsedSPF(raw=raw, syntax_errors=("Record does not start with 'v=spf1'.",))

    terms: list[SPFTerm] = []
    modifiers: list[SPFModifier] = []
    errors: list[str] = []
    seen_redirect = False
    seen_exp = False

    for token in tokens[1:]:
        # Modifiers contain '=' before any ':' or '/'
        if "=" in token and (":" not in token or token.index("=") < token.index(":")):
            mod_match = _MODIFIER_RE.match(token)
            if not mod_match:
                errors.append(f"Invalid SPF modifier syntax: '{token}'.")
                continue
            name = mod_match.group("name").lower()
            value = mod_match.group("value")
            if name == "redirect":
                if seen_redirect:
                    errors.append("Duplicate 'redirect=' modifier (RFC 7208 allows at most one).")
                    continue
                seen_redirect = True
                if not _validate_domain_spec(value):
                    errors.append(f"Invalid domain in modifier '{token}'.")
                    continue
            elif name == "exp":
                if seen_exp:
                    errors.append("Duplicate 'exp=' modifier (RFC 7208 allows at most one).")
                    continue
                seen_exp = True
                if not _validate_domain_spec(value):
                    errors.append(f"Invalid domain in modifier '{token}'.")
                    continue
            modifiers.append(
                SPFModifier(
                    raw=token,
                    name=name,
                    value=value,
                    has_macro=_contains_macro(value),
                )
            )
            continue

        mech_match = _MECHANISM_RE.match(token)
        if not mech_match:
            errors.append(f"Unknown or malformed SPF mechanism: '{token}'.")
            continue

        qual_raw = mech_match.group("qual") or "+"
        qual: Qualifier = "+"
        if qual_raw in ("+", "-", "~", "?"):
            qual = qual_raw  # type: ignore[assignment]
        mech = mech_match.group("mech").lower()
        arg = mech_match.group("arg")
        cidr_raw = mech_match.group("cidr") or ""

        cidr4: int | None = None
        cidr6: int | None = None

        if mech == "all":
            if arg is not None or cidr_raw:
                errors.append(f"Mechanism 'all' does not accept arguments or CIDR: '{token}'.")
                continue
            terms.append(SPFTerm(raw=token, qualifier=qual, mechanism="all"))
            continue

        if mech in ("include", "exists"):
            if not arg or cidr_raw:
                errors.append(f"Mechanism '{mech}' requires a domain and no CIDR: '{token}'.")
                continue
            if not _validate_domain_spec(arg):
                errors.append(f"Invalid domain in '{token}'.")
                continue
            terms.append(
                SPFTerm(
                    raw=token,
                    qualifier=qual,
                    mechanism=mech,
                    argument=arg,
                    has_macro=_contains_macro(arg),
                )
            )
            continue

        if mech == "ptr":
            if cidr_raw:
                errors.append(f"Mechanism 'ptr' does not accept CIDR lengths: '{token}'.")
                continue
            if arg is not None and not _validate_domain_spec(arg):
                errors.append(f"Invalid domain in '{token}'.")
                continue
            terms.append(
                SPFTerm(
                    raw=token,
                    qualifier=qual,
                    mechanism="ptr",
                    argument=arg,
                    has_macro=_contains_macro(arg) if arg else False,
                )
            )
            continue

        if mech in ("a", "mx"):
            if arg is not None and not _validate_domain_spec(arg):
                errors.append(f"Invalid domain in '{token}'.")
                continue
            if cidr_raw:
                cm = _CIDR_RE.match(cidr_raw)
                if not cm:
                    errors.append(f"Invalid CIDR length in '{token}'.")
                    continue
                if cm.group("v4") is not None:
                    cidr4 = int(cm.group("v4"))
                    if not (0 <= cidr4 <= 32):
                        errors.append(f"IPv4 CIDR out of range (0-32) in '{token}'.")
                        continue
                if cm.group("v6") is not None:
                    cidr6 = int(cm.group("v6"))
                    if not (0 <= cidr6 <= 128):
                        errors.append(f"IPv6 CIDR out of range (0-128) in '{token}'.")
                        continue
            terms.append(
                SPFTerm(
                    raw=token,
                    qualifier=qual,
                    mechanism=mech,
                    argument=arg,
                    cidr4=cidr4,
                    cidr6=cidr6,
                    has_macro=_contains_macro(arg) if arg else False,
                )
            )
            continue

        if mech == "ip4":
            if not arg or "//" in cidr_raw:
                errors.append(f"Invalid ip4 mechanism: '{token}'.")
                continue
            ip_spec = f"{arg}{cidr_raw}"
            try:
                net4 = ipaddress.IPv4Network(ip_spec, strict=False)
            except ValueError:
                errors.append(f"Invalid IPv4 address or CIDR in '{token}'.")
                continue
            terms.append(
                SPFTerm(
                    raw=token,
                    qualifier=qual,
                    mechanism="ip4",
                    argument=str(net4),
                    cidr4=net4.prefixlen,
                )
            )
            continue

        if mech == "ip6":
            if not arg or "//" in cidr_raw:
                errors.append(f"Invalid ip6 mechanism: '{token}'.")
                continue
            ip_spec = f"{arg}{cidr_raw}"
            try:
                net6 = ipaddress.IPv6Network(ip_spec, strict=False)
            except ValueError:
                errors.append(f"Invalid IPv6 address or CIDR in '{token}'.")
                continue
            terms.append(
                SPFTerm(
                    raw=token,
                    qualifier=qual,
                    mechanism="ip6",
                    argument=str(net6),
                    cidr6=net6.prefixlen,
                )
            )
            continue

    return ParsedSPF(
        raw=raw,
        terms=tuple(terms),
        modifiers=tuple(modifiers),
        syntax_errors=tuple(errors),
    )


@dataclass
class _AuditState:
    dns_lookups: int = 0
    void_lookups: int = 0
    has_ptr: bool = False
    has_macros: bool = False
    loop_detected: bool = False
    loop_chain: list[str] = field(default_factory=list)
    per_mx_limit_exceeded: bool = False
    per_mx_offenders: list[str] = field(default_factory=list)
    permerror: bool = False
    permerror_reasons: list[str] = field(default_factory=list)
    temperror_reasons: list[str] = field(default_factory=list)
    all_includes: list[str] = field(default_factory=list)
    ip4_networks: list[str] = field(default_factory=list)
    ip6_networks: list[str] = field(default_factory=list)
    nested_syntax_errors: list[str] = field(default_factory=list)


async def _audit_parsed_spf(
    domain: str,
    parsed: ParsedSPF,
    resolver: DNSResolver,
    state: _AuditState,
    ancestors: tuple[str, ...],
) -> tuple[SPFIncludeTrace, ...]:
    children: list[SPFIncludeTrace] = []
    seen_all = False

    for term in parsed.terms:
        if seen_all:
            # Dead terms after 'all' are never evaluated by receiving servers
            continue

        if term.mechanism == "all":
            seen_all = True
            continue

        if term.mechanism == "ip4":
            if term.argument:
                state.ip4_networks.append(term.argument)
            continue

        if term.mechanism == "ip6":
            if term.argument:
                state.ip6_networks.append(term.argument)
            continue

        if term.has_macro:
            # Count macro-bearing DNS mechanism as 1 lookup without issuing a literal query
            state.has_macros = True
            state.dns_lookups += 1
            if term.mechanism == "ptr":
                state.has_ptr = True
            continue

        if term.mechanism == "ptr":
            state.has_ptr = True
            state.dns_lookups += 1
            continue

        if term.mechanism == "exists":
            state.dns_lookups += 1
            target = normalize_dns_name(term.argument or domain)
            resp = await resolver.query(target, "A")
            if resp.is_void:
                state.void_lookups += 1
            elif resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
                state.temperror_reasons.append(f"Lookup for exists:{target} failed.")
            continue

        if term.mechanism == "a":
            state.dns_lookups += 1
            target = normalize_dns_name(term.argument or domain)
            a_resp = await resolver.query(target, "A")
            aaaa_resp = await resolver.query(target, "AAAA")
            if a_resp.status == DNSStatus.OK:
                for ip in a_resp.records:
                    prefix = term.cidr4 if term.cidr4 is not None else 32
                    state.ip4_networks.append(
                        str(ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False))
                    )
            if aaaa_resp.status == DNSStatus.OK:
                for ip in aaaa_resp.records:
                    prefix = term.cidr6 if term.cidr6 is not None else 128
                    state.ip6_networks.append(
                        str(ipaddress.IPv6Network(f"{ip}/{prefix}", strict=False))
                    )
            if a_resp.is_void and aaaa_resp.is_void:
                state.void_lookups += 1
            elif a_resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR) and aaaa_resp.status in (
                DNSStatus.TIMEOUT,
                DNSStatus.ERROR,
            ):
                state.temperror_reasons.append(f"Lookup for a:{target} failed.")
            continue

        if term.mechanism == "mx":
            state.dns_lookups += 1
            target = normalize_dns_name(term.argument or domain)
            mx_resp = await resolver.query(target, "MX")
            if mx_resp.is_void:
                state.void_lookups += 1
                continue
            if mx_resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
                state.temperror_reasons.append(f"Lookup for mx:{target} failed.")
                continue
            valid_mx = [r for r in mx_resp.mx_records if r.exchange != "."]
            if len(valid_mx) > SPF_MAX_PER_MECHANISM_LOOKUPS:
                state.per_mx_limit_exceeded = True
                state.permerror = True
                state.per_mx_offenders.append(f"mx:{target} ({len(valid_mx)} MX hosts)")
                state.permerror_reasons.append(
                    f"Mechanism 'mx:{target}' returns {len(valid_mx)} hosts, exceeding the "
                    f"RFC 7208 limit of {SPF_MAX_PER_MECHANISM_LOOKUPS} address lookups per mx."
                )
            for mx_rec in valid_mx[:SPF_MAX_PER_MECHANISM_LOOKUPS]:
                a_resp = await resolver.query(mx_rec.exchange, "A")
                aaaa_resp = await resolver.query(mx_rec.exchange, "AAAA")
                if a_resp.status == DNSStatus.OK:
                    for ip in a_resp.records:
                        prefix = term.cidr4 if term.cidr4 is not None else 32
                        state.ip4_networks.append(
                            str(ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False))
                        )
                if aaaa_resp.status == DNSStatus.OK:
                    for ip in aaaa_resp.records:
                        prefix = term.cidr6 if term.cidr6 is not None else 128
                        state.ip6_networks.append(
                            str(ipaddress.IPv6Network(f"{ip}/{prefix}", strict=False))
                        )
            continue

        if term.mechanism == "include":
            target = normalize_dns_name(term.argument or "")
            state.all_includes.append(target)
            child_trace = await _follow_target_spf(
                target=target,
                kind="include",
                resolver=resolver,
                state=state,
                ancestors=ancestors,
            )
            children.append(child_trace)
            continue

    # RFC 7208 section 6.1: redirect= is ignored when an 'all' mechanism is present
    redirect_mod = parsed.redirect
    if redirect_mod is not None and not seen_all:
        if redirect_mod.has_macro:
            state.has_macros = True
            state.dns_lookups += 1
        else:
            target = normalize_dns_name(redirect_mod.value)
            state.all_includes.append(target)
            child_trace = await _follow_target_spf(
                target=target,
                kind="redirect",
                resolver=resolver,
                state=state,
                ancestors=ancestors,
            )
            children.append(child_trace)

    return tuple(children)


async def _follow_target_spf(
    *,
    target: str,
    kind: Literal["include", "redirect"],
    resolver: DNSResolver,
    state: _AuditState,
    ancestors: tuple[str, ...],
) -> SPFIncludeTrace:
    before_lookups = state.dns_lookups
    before_voids = state.void_lookups
    state.dns_lookups += 1

    if target in ancestors:
        state.loop_detected = True
        state.permerror = True
        chain = [*ancestors, target]
        if not state.loop_chain:
            state.loop_chain = chain
        err = f"Loop detected: {' -> '.join(chain)}"
        state.permerror_reasons.append(err)
        return SPFIncludeTrace(
            domain=target,
            lookups=state.dns_lookups - before_lookups,
            void_lookups=state.void_lookups - before_voids,
            error=err,
        )

    # Guard runaway recursion beyond deep broken trees while still surfacing >10 counts
    if len(ancestors) >= 15:
        state.permerror = True
        err = f"Maximum recursion depth reached at {target}."
        state.permerror_reasons.append(err)
        return SPFIncludeTrace(
            domain=target,
            lookups=state.dns_lookups - before_lookups,
            void_lookups=state.void_lookups - before_voids,
            error=err,
        )

    txt_resp = await resolver.query(target, "TXT")
    if txt_resp.is_void:
        state.void_lookups += 1
        state.permerror = True
        err = f"{kind} target '{target}' does not exist or has no TXT records."
        state.permerror_reasons.append(err)
        return SPFIncludeTrace(
            domain=target,
            lookups=state.dns_lookups - before_lookups,
            void_lookups=state.void_lookups - before_voids,
            error=err,
        )

    if txt_resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
        err = f"DNS lookup for {kind} target '{target}' failed ({txt_resp.status.value})."
        state.temperror_reasons.append(err)
        return SPFIncludeTrace(
            domain=target,
            lookups=state.dns_lookups - before_lookups,
            void_lookups=state.void_lookups - before_voids,
            error=err,
        )

    spf_records = [r for r in txt_resp.records if is_spf_txt_record(r)]
    if not spf_records:
        state.permerror = True
        err = f"{kind} target '{target}' has no SPF (v=spf1) record."
        state.permerror_reasons.append(err)
        return SPFIncludeTrace(
            domain=target,
            lookups=state.dns_lookups - before_lookups,
            void_lookups=state.void_lookups - before_voids,
            error=err,
        )

    if len(spf_records) > 1:
        state.permerror = True
        err = f"{kind} target '{target}' publishes multiple SPF records."
        state.permerror_reasons.append(err)
        return SPFIncludeTrace(
            domain=target,
            lookups=state.dns_lookups - before_lookups,
            void_lookups=state.void_lookups - before_voids,
            error=err,
        )

    nested_parsed = parse_spf_record(spf_records[0])
    if nested_parsed.syntax_errors:
        state.permerror = True
        for syntax_err in nested_parsed.syntax_errors:
            state.nested_syntax_errors.append(f"{target}: {syntax_err}")

    sub_children = await _audit_parsed_spf(
        domain=target,
        parsed=nested_parsed,
        resolver=resolver,
        state=state,
        ancestors=(*ancestors, target),
    )
    return SPFIncludeTrace(
        domain=target,
        lookups=state.dns_lookups - before_lookups,
        void_lookups=state.void_lookups - before_voids,
        record=spf_records[0],
        children=sub_children,
    )


def _find_dead_terms(parsed: ParsedSPF) -> tuple[str, ...]:
    dead: list[str] = []
    seen_all = False
    for term in parsed.terms:
        if seen_all:
            dead.append(term.raw)
        elif term.mechanism == "all":
            seen_all = True
    return tuple(dead)


def _resolve_effective_all(
    parsed: ParsedSPF,
    include_tree: tuple[SPFIncludeTrace, ...],
) -> Qualifier | None:
    if parsed.all_term is not None:
        return parsed.all_term.qualifier
    if parsed.redirect is not None and include_tree:
        last = include_tree[-1]
        if last.record:
            sub = parse_spf_record(last.record)
            return _resolve_effective_all(sub, last.children)
    return None


async def check_spf(
    domain: str,
    resolver: DNSResolver,
    *,
    detected_providers: Sequence[MailProvider] = (),
) -> SPFCheckResult:
    """Inspect a domain's SPF record following RFC 7208 lookup and syntax rules."""
    norm_domain = normalize_dns_name(domain)
    txt_resp = await resolver.query(norm_domain, "TXT")

    if txt_resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
        return SPFCheckResult(
            domain=norm_domain,
            status="error",
            issues=(
                SPFIssue(
                    severity="fail",
                    title="Could not look up SPF record",
                    detail=(
                        f"DNS TXT lookup for {norm_domain} failed "
                        f"({txt_resp.error_message or txt_resp.status.value})."
                    ),
                    fix="Check that your domain's nameservers are reachable and try again.",
                ),
            ),
        )

    spf_records = tuple(r for r in txt_resp.records if is_spf_txt_record(r))

    if not spf_records:
        required_includes = _missing_includes_for_providers(detected_providers, ())
        suggested = _build_basic_spf_suggestion([inc for _, inc in required_includes])
        return SPFCheckResult(
            domain=norm_domain,
            status="fail",
            all_records=(),
            missing_provider_includes=required_includes,
            issues=(
                SPFIssue(
                    severity="fail",
                    title="No SPF record found",
                    detail=(
                        f"{norm_domain} does not publish an SPF TXT record, so receiving servers "
                        "cannot verify which mail servers are authorized to send for it."
                    ),
                    fix="Add a TXT record on your root domain (@) authorizing your email senders.",
                    record_value=suggested,
                ),
            ),
        )

    if len(spf_records) > 1:
        return SPFCheckResult(
            domain=norm_domain,
            status="fail",
            all_records=spf_records,
            permerror=True,
            issues=(
                SPFIssue(
                    severity="fail",
                    title=f"Multiple SPF records found ({len(spf_records)})",
                    detail=(
                        "RFC 7208 allows only one v=spf1 TXT record per domain; multiple SPF "
                        "records cause a permanent error (PermError) and fail SPF checks."
                    ),
                    fix=(
                        "Merge all authorized senders into a single v=spf1 TXT record and delete "
                        "the extra SPF TXT records."
                    ),
                ),
            ),
        )

    raw_record = spf_records[0]
    parsed = parse_spf_record(raw_record)
    state = _AuditState()
    if parsed.syntax_errors:
        state.permerror = True

    include_tree = await _audit_parsed_spf(
        domain=norm_domain,
        parsed=parsed,
        resolver=resolver,
        state=state,
        ancestors=(norm_domain,),
    )

    dead_terms = _find_dead_terms(parsed)
    has_redirect = parsed.redirect is not None
    redirect_ignored = has_redirect and parsed.all_term is not None
    effective_all = _resolve_effective_all(parsed, include_tree)

    if state.dns_lookups > SPF_MAX_DNS_LOOKUPS:
        state.permerror = True
    if state.void_lookups > SPF_MAX_VOID_LOOKUPS:
        state.permerror = True

    spf_providers = detect_providers_from_spf_includes(state.all_includes)
    combined_providers: list[MailProvider] = []
    seen_ids: set[str] = set()
    for p in (*detected_providers, *spf_providers):
        if p.id not in seen_ids:
            combined_providers.append(p)
            seen_ids.add(p.id)

    missing_includes = _missing_includes_for_providers(detected_providers, state.all_includes)

    issues: list[SPFIssue] = []
    has_fail = False
    has_warn = False

    if parsed.syntax_errors:
        has_fail = True
        issues.append(
            SPFIssue(
                severity="fail",
                title="SPF record has syntax errors",
                detail=parsed.syntax_errors[0],
                fix="Fix the malformed mechanism or modifier in your SPF TXT record.",
            )
        )

    if state.loop_detected:
        has_fail = True
        issues.append(
            SPFIssue(
                severity="fail",
                title="SPF record contains an include/redirect loop",
                detail=(
                    f"SPF evaluation loops back on itself ({' -> '.join(state.loop_chain)}), "
                    "causing a permanent error (PermError)."
                ),
                fix="Remove the circular include or redirect from your SPF record.",
            )
        )

    if state.dns_lookups > SPF_MAX_DNS_LOOKUPS:
        has_fail = True
        issues.append(
            SPFIssue(
                severity="fail",
                title=(
                    f"SPF exceeds the 10 DNS lookup limit "
                    f"({state.dns_lookups}/{SPF_MAX_DNS_LOOKUPS})"
                ),
                detail=(
                    f"Evaluating this SPF record requires {state.dns_lookups} DNS lookups, "
                    "which exceeds RFC 7208's limit of 10 and causes receiving servers to "
                    "return PermError."
                ),
                fix=(
                    "Remove unused includes, replace 'a' or 'mx' with explicit ip4/ip6 ranges "
                    "where possible, or move high-volume senders to a dedicated subdomain."
                ),
            )
        )
    elif state.dns_lookups >= 9:
        has_warn = True
        issues.append(
            SPFIssue(
                severity="warn",
                title=(
                    f"SPF is close to the 10 DNS lookup limit "
                    f"({state.dns_lookups}/{SPF_MAX_DNS_LOOKUPS})"
                ),
                detail=(
                    f"Your SPF record uses {state.dns_lookups} of the 10 allowed DNS lookups, "
                    "leaving very little room if a provider adds another nested include."
                ),
                fix="Remove any unused sending services from your SPF record to keep headroom.",
            )
        )

    if state.per_mx_limit_exceeded:
        has_fail = True
        issues.append(
            SPFIssue(
                severity="fail",
                title="SPF 'mx' mechanism exceeds the 10-host lookup limit",
                detail=(
                    f"RFC 7208 limits each mx mechanism to 10 MX hostname lookups "
                    f"({', '.join(state.per_mx_offenders)}), causing PermError."
                ),
                fix=(
                    "Replace the mx mechanism with explicit ip4/ip6 mechanisms "
                    "or provider includes."
                ),
            )
        )

    if state.void_lookups > SPF_MAX_VOID_LOOKUPS:
        has_fail = True
        issues.append(
            SPFIssue(
                severity="fail",
                title=(
                    f"SPF exceeds the 2 void lookup limit "
                    f"({state.void_lookups}/{SPF_MAX_VOID_LOOKUPS})"
                ),
                detail=(
                    f"{state.void_lookups} DNS lookups in your SPF record returned NXDOMAIN or "
                    "empty answers, exceeding RFC 7208's limit of 2 and triggering PermError."
                ),
                fix="Remove stale or misspelled include, a, mx, or exists targets from your SPF.",
            )
        )

    for reason in state.permerror_reasons:
        if "Loop detected" in reason or "exceeding the RFC 7208 limit" in reason:
            continue
        has_fail = True
        issues.append(
            SPFIssue(
                severity="fail",
                title="Included SPF target is missing or invalid",
                detail=reason,
                fix="Verify the included domain spelling or remove the broken include/redirect.",
            )
        )

    if state.nested_syntax_errors:
        has_fail = True
        issues.append(
            SPFIssue(
                severity="fail",
                title="Included SPF record has syntax errors",
                detail=state.nested_syntax_errors[0],
                fix="Check or remove the broken included domain from your SPF record.",
            )
        )

    if effective_all == "+":
        has_fail = True
        issues.append(
            SPFIssue(
                severity="fail",
                title="SPF ends with '+all' (allows anyone to send)",
                detail=(
                    "Ending SPF with '+all' authorizes every server on the internet to send email "
                    "as your domain, completely disabling SPF protection."
                ),
                fix="Change '+all' to '~all' (softfail) or '-all' (hardfail).",
            )
        )
    elif effective_all == "?":
        has_warn = True
        issues.append(
            SPFIssue(
                severity="warn",
                title="SPF ends with weak '?all' (neutral)",
                detail=(
                    "Ending SPF with '?all' tells receiving servers to take no position on "
                    "unlisted senders, weakening anti-spoofing protection."
                ),
                fix="Change '?all' to '~all' (or '-all' once all legitimate senders are listed).",
            )
        )
    elif effective_all is None:
        has_warn = True
        issues.append(
            SPFIssue(
                severity="warn",
                title="SPF record has no 'all' ending mechanism",
                detail=(
                    "Without an 'all' mechanism (or a redirect that ends in one), SPF defaults to "
                    "neutral (?all) for unlisted servers."
                ),
                fix="End your SPF record with '~all' or '-all'.",
            )
        )

    if redirect_ignored:
        has_warn = True
        issues.append(
            SPFIssue(
                severity="warn",
                title="SPF 'redirect=' modifier is ignored because 'all' is present",
                detail=(
                    "Per RFC 7208 section 6.1, receiving servers ignore 'redirect=' whenever an "
                    "'all' mechanism appears in the same record."
                ),
                fix=(
                    "Remove the unused 'redirect=' modifier, or remove 'all' if you "
                    "intended to redirect."
                ),
            )
        )

    if dead_terms:
        has_warn = True
        issues.append(
            SPFIssue(
                severity="warn",
                title="SPF has unreachable terms after 'all'",
                detail=(
                    f"Terms after 'all' ({', '.join(dead_terms)}) are never evaluated because "
                    "'all' always matches and ends SPF processing."
                ),
                fix=(
                    "Move those mechanisms before 'all' or delete them if they are "
                    "no longer needed."
                ),
            )
        )

    if state.has_ptr:
        has_warn = True
        issues.append(
            SPFIssue(
                severity="warn",
                title="SPF uses deprecated 'ptr' mechanism",
                detail=(
                    "RFC 7208 section 5.5 deprecates 'ptr' because reverse DNS lookups are slow, "
                    "unreliable, and may be ignored or fail under load."
                ),
                fix=(
                    "Replace 'ptr' with explicit ip4/ip6 addresses, 'a', or provider "
                    "'include:' terms."
                ),
            )
        )

    if len(raw_record.encode("utf-8")) > SPF_UDP_WARN_BYTES:
        has_warn = True
        issues.append(
            SPFIssue(
                severity="warn",
                title="SPF record is very long (risk of DNS UDP truncation)",
                detail=(
                    f"This SPF record is {len(raw_record.encode('utf-8'))} bytes; RFC 7208 "
                    "recommends keeping SPF DNS responses under 512 bytes for UDP reliability."
                ),
                fix="Trim redundant ip4/ip6 entries or unused includes to keep the record compact.",
            )
        )

    for provider, needed_inc in missing_includes:
        has_warn = True
        issues.append(
            SPFIssue(
                severity="warn",
                title=f"SPF is missing include for {provider.name}",
                detail=(
                    f"{provider.name} was detected for this domain, but 'include:{needed_inc}' "
                    "is not present in your SPF record."
                ),
                fix=(
                    f"Add 'include:{needed_inc}' before '~all' or '-all' at the end "
                    "of your SPF record."
                ),
                record_value=f"include:{needed_inc}",
            )
        )

    if any(inc == "shops.shopify.com" for inc in state.all_includes):
        issues.append(
            SPFIssue(
                severity="info",
                title="Legacy Shopify SPF include detected",
                detail=(
                    "Your SPF record contains 'include:shops.shopify.com'. Shopify Email now "
                    "authenticates via CNAME records in Shopify Admin rather than root SPF."
                ),
                fix=(
                    "Once domain authentication is verified in Shopify Admin (Settings -> "
                    "Notifications), you can remove 'include:shops.shopify.com' to save a lookup."
                ),
            )
        )

    if state.has_macros:
        issues.append(
            SPFIssue(
                severity="info",
                title="SPF uses dynamic macros",
                detail=(
                    "One or more SPF mechanisms contain RFC 7208 macros (such as %{i} or %{d}), "
                    "counted as 1 DNS lookup each because they expand per connecting IP."
                ),
            )
        )

    if not has_fail and not has_warn:
        issues.insert(
            0,
            SPFIssue(
                severity="pass",
                title=(
                    f"SPF record is valid ({state.dns_lookups}/{SPF_MAX_DNS_LOOKUPS} DNS lookups)"
                ),
                detail=(
                    f"Single valid v=spf1 record ending with '{effective_all}all' and within "
                    "RFC 7208 lookup limits."
                ),
            ),
        )

    status = "fail" if has_fail else ("warn" if has_warn else "pass")

    return SPFCheckResult(
        domain=norm_domain,
        status=status,
        record=raw_record,
        all_records=spf_records,
        parsed=parsed,
        dns_lookups=state.dns_lookups,
        void_lookups=state.void_lookups,
        all_qualifier=effective_all,
        has_redirect=has_redirect,
        redirect_ignored=redirect_ignored,
        dead_terms=dead_terms,
        has_ptr=state.has_ptr,
        has_macros=state.has_macros,
        loop_detected=state.loop_detected,
        loop_chain=tuple(state.loop_chain),
        per_mx_limit_exceeded=state.per_mx_limit_exceeded,
        permerror=state.permerror,
        includes=tuple(state.all_includes),
        include_tree=include_tree,
        ip4_networks=tuple(state.ip4_networks),
        ip6_networks=tuple(state.ip6_networks),
        detected_providers=tuple(combined_providers),
        missing_provider_includes=missing_includes,
        issues=tuple(issues),
    )


def _missing_includes_for_providers(
    detected_providers: Sequence[MailProvider],
    present_includes: Sequence[str],
) -> tuple[tuple[MailProvider, str], ...]:
    present_lower = {inc.lower().rstrip(".") for inc in present_includes}
    missing: list[tuple[MailProvider, str]] = []
    for provider in detected_providers:
        if not provider.requires_root_spf_include or not provider.recommended_spf_include:
            continue
        if any(
            inc in present_lower or any(p.endswith(f".{inc}") for p in present_lower)
            for inc in provider.spf_includes
        ):
            continue
        missing.append((provider, provider.recommended_spf_include))
    return tuple(missing)


def _build_basic_spf_suggestion(includes: Sequence[str]) -> str:
    parts = ["v=spf1", *(f"include:{inc}" for inc in includes), "~all"]
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Concrete IP SPF evaluation (RFC 7208) for received test-email analysis
# ---------------------------------------------------------------------------


def _expand_spf_macros(
    spec: str,
    *,
    domain: str,
    client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    sender: str,
    helo: str,
) -> str:
    """Expand RFC 7208 section 7 macros in a domain-spec for concrete IP evaluation."""
    if "%" not in spec:
        return spec

    local_part, _, sender_domain = sender.partition("@")
    if not sender_domain:
        local_part = "postmaster"
        sender_domain = domain
    if not local_part:
        local_part = "postmaster"

    if isinstance(client_ip, ipaddress.IPv4Address):
        ip_macro = str(client_ip)
        v_macro = "in-addr"
    else:
        hex_nibbles = client_ip.exploded.replace(":", "")
        ip_macro = ".".join(hex_nibbles)
        v_macro = "ip6"

    values = {
        "s": f"{local_part}@{sender_domain}",
        "l": local_part,
        "o": sender_domain,
        "d": domain,
        "i": ip_macro,
        "v": v_macro,
        "h": helo or domain,
        "p": "unknown",
    }

    def _replace(match: re.Match[str]) -> str:
        token = match.group(0)
        if token == "%%":
            return "%"
        if token == "%_":
            return " "
        if token == "%-":
            return "%20"
        letter = match.group(1).lower()
        digits_str = match.group(2)
        reverse_flag = bool(match.group(3))
        delimiters = match.group(4) or "."
        raw_val = values.get(letter, "")
        split_pattern = f"[{re.escape(delimiters)}]"
        parts = re.split(split_pattern, raw_val)
        if reverse_flag:
            parts.reverse()
        if digits_str:
            count = int(digits_str)
            if count > 0:
                parts = parts[-count:]
        return ".".join(parts)

    return _MACRO_RE.sub(_replace, spec)


@dataclass
class _EvalCounters:
    dns_lookups: int = 0
    void_lookups: int = 0


def _ip_matches_cidr(
    client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    candidate_ip_str: str,
    cidr4: int | None,
    cidr6: int | None,
) -> bool:
    try:
        candidate = ipaddress.ip_address(candidate_ip_str)
    except ValueError:
        return False
    if isinstance(client_ip, ipaddress.IPv4Address) and isinstance(
        candidate, ipaddress.IPv4Address
    ):
        prefix = cidr4 if cidr4 is not None else 32
        return client_ip in ipaddress.IPv4Network(f"{candidate}/{prefix}", strict=False)
    if isinstance(client_ip, ipaddress.IPv6Address) and isinstance(
        candidate, ipaddress.IPv6Address
    ):
        prefix = cidr6 if cidr6 is not None else 128
        return client_ip in ipaddress.IPv6Network(f"{candidate}/{prefix}", strict=False)
    return False


async def evaluate_spf_for_ip(
    domain: str,
    client_ip: str,
    sender: str,
    resolver: DNSResolver,
    *,
    helo: str | None = None,
) -> SPFEvalResult:
    """Evaluate RFC 7208 SPF policy for a concrete connecting IP and sender."""
    norm_domain = normalize_dns_name(domain)
    ip_obj = ipaddress.ip_address(client_ip)
    counters = _EvalCounters()

    outcome, matched, explanation = await _eval_domain_spf(
        domain=norm_domain,
        ip_obj=ip_obj,
        sender=sender,
        helo=helo or norm_domain,
        resolver=resolver,
        counters=counters,
        ancestors=(norm_domain,),
    )
    return SPFEvalResult(
        result=outcome,
        domain=norm_domain,
        client_ip=str(ip_obj),
        dns_lookups=counters.dns_lookups,
        void_lookups=counters.void_lookups,
        matched_mechanism=matched,
        explanation=explanation,
    )


async def _eval_domain_spf(
    *,
    domain: str,
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
    sender: str,
    helo: str,
    resolver: DNSResolver,
    counters: _EvalCounters,
    ancestors: tuple[str, ...],
) -> tuple[SPFOutcome, str | None, str | None]:
    txt_resp = await resolver.query(domain, "TXT")
    if txt_resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
        return "temperror", None, f"DNS error querying SPF for {domain}."
    if txt_resp.is_void:
        return "none", None, f"No SPF record found for {domain}."

    spf_records = [r for r in txt_resp.records if is_spf_txt_record(r)]
    if not spf_records:
        return "none", None, f"No SPF record found for {domain}."
    if len(spf_records) > 1:
        return "permerror", None, f"Multiple SPF records found for {domain}."

    parsed = parse_spf_record(spf_records[0])
    if parsed.syntax_errors:
        return "permerror", None, parsed.syntax_errors[0]

    for term in parsed.terms:
        if term.mechanism == "all":
            return _QUALIFIER_TO_OUTCOME[term.qualifier], term.raw, None

        if term.mechanism == "ip4":
            if (
                isinstance(ip_obj, ipaddress.IPv4Address)
                and term.argument
                and ip_obj in ipaddress.IPv4Network(term.argument, strict=False)
            ):
                return _QUALIFIER_TO_OUTCOME[term.qualifier], term.raw, None
            continue

        if term.mechanism == "ip6":
            if (
                isinstance(ip_obj, ipaddress.IPv6Address)
                and term.argument
                and ip_obj in ipaddress.IPv6Network(term.argument, strict=False)
            ):
                return _QUALIFIER_TO_OUTCOME[term.qualifier], term.raw, None
            continue

        # DNS-querying mechanisms
        counters.dns_lookups += 1
        if counters.dns_lookups > SPF_MAX_DNS_LOOKUPS:
            return "permerror", term.raw, "Exceeded 10 DNS lookups."

        raw_target = term.argument or domain
        expanded = _expand_spf_macros(
            raw_target, domain=domain, client_ip=ip_obj, sender=sender, helo=helo
        )
        target = normalize_dns_name(expanded)

        if term.mechanism == "a":
            rdtype = "A" if isinstance(ip_obj, ipaddress.IPv4Address) else "AAAA"
            resp = await resolver.query(target, rdtype)
            if resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
                return "temperror", term.raw, f"DNS error resolving {target}."
            if resp.is_void:
                counters.void_lookups += 1
                if counters.void_lookups > SPF_MAX_VOID_LOOKUPS:
                    return "permerror", term.raw, "Exceeded 2 void lookups."
                continue
            for addr in resp.records:
                if _ip_matches_cidr(ip_obj, addr, term.cidr4, term.cidr6):
                    return _QUALIFIER_TO_OUTCOME[term.qualifier], term.raw, None
            continue

        if term.mechanism == "mx":
            mx_resp = await resolver.query(target, "MX")
            if mx_resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
                return "temperror", term.raw, f"DNS error resolving MX for {target}."
            if mx_resp.is_void:
                counters.void_lookups += 1
                if counters.void_lookups > SPF_MAX_VOID_LOOKUPS:
                    return "permerror", term.raw, "Exceeded 2 void lookups."
                continue
            valid_mx = [r for r in mx_resp.mx_records if r.exchange != "."]
            if len(valid_mx) > SPF_MAX_PER_MECHANISM_LOOKUPS:
                return "permerror", term.raw, "MX mechanism exceeded 10-host lookup limit."
            rdtype = "A" if isinstance(ip_obj, ipaddress.IPv4Address) else "AAAA"
            for mx_rec in valid_mx:
                addr_resp = await resolver.query(mx_rec.exchange, rdtype)
                if addr_resp.status == DNSStatus.OK:
                    for addr in addr_resp.records:
                        if _ip_matches_cidr(ip_obj, addr, term.cidr4, term.cidr6):
                            return _QUALIFIER_TO_OUTCOME[term.qualifier], term.raw, None
            continue

        if term.mechanism == "ptr":
            ptr_name = reverse_ip_for_ptr(str(ip_obj))
            ptr_resp = await resolver.query(ptr_name, "PTR")
            if ptr_resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
                continue
            if ptr_resp.is_void:
                counters.void_lookups += 1
                if counters.void_lookups > SPF_MAX_VOID_LOOKUPS:
                    return "permerror", term.raw, "Exceeded 2 void lookups."
                continue
            # RFC 7208 section 5.5: validate at most 10 PTR hostnames
            rdtype = "A" if isinstance(ip_obj, ipaddress.IPv4Address) else "AAAA"
            for hostname in ptr_resp.records[:SPF_MAX_PER_MECHANISM_LOOKUPS]:
                norm_host = normalize_dns_name(hostname)
                if norm_host != target and not norm_host.endswith(f".{target}"):
                    continue
                fwd = await resolver.query(norm_host, rdtype)
                if fwd.status == DNSStatus.OK and str(ip_obj) in fwd.records:
                    return _QUALIFIER_TO_OUTCOME[term.qualifier], term.raw, None
            continue

        if term.mechanism == "exists":
            a_resp = await resolver.query(target, "A")
            if a_resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
                return "temperror", term.raw, f"DNS error resolving exists:{target}."
            if a_resp.is_void:
                counters.void_lookups += 1
                if counters.void_lookups > SPF_MAX_VOID_LOOKUPS:
                    return "permerror", term.raw, "Exceeded 2 void lookups."
                continue
            if a_resp.records:
                return _QUALIFIER_TO_OUTCOME[term.qualifier], term.raw, None
            continue

        if term.mechanism == "include":
            if target in ancestors:
                return "permerror", term.raw, f"SPF include loop at {target}."
            sub_outcome, _, sub_expl = await _eval_domain_spf(
                domain=target,
                ip_obj=ip_obj,
                sender=sender,
                helo=helo,
                resolver=resolver,
                counters=counters,
                ancestors=(*ancestors, target),
            )
            if sub_outcome == "pass":
                return _QUALIFIER_TO_OUTCOME[term.qualifier], term.raw, None
            if sub_outcome in ("none", "permerror"):
                return "permerror", term.raw, sub_expl or f"Included domain {target} failed."
            if sub_outcome == "temperror":
                return "temperror", term.raw, sub_expl
            continue

    # RFC 7208 section 6.1: redirect applies only if no 'all' matched
    if parsed.redirect is not None:
        counters.dns_lookups += 1
        if counters.dns_lookups > SPF_MAX_DNS_LOOKUPS:
            return "permerror", parsed.redirect.raw, "Exceeded 10 DNS lookups."
        expanded = _expand_spf_macros(
            parsed.redirect.value, domain=domain, client_ip=ip_obj, sender=sender, helo=helo
        )
        target = normalize_dns_name(expanded)
        if target in ancestors:
            return "permerror", parsed.redirect.raw, f"SPF redirect loop at {target}."
        sub_outcome, matched, sub_expl = await _eval_domain_spf(
            domain=target,
            ip_obj=ip_obj,
            sender=sender,
            helo=helo,
            resolver=resolver,
            counters=counters,
            ancestors=(*ancestors, target),
        )
        if sub_outcome == "none":
            return "permerror", parsed.redirect.raw, f"Redirect target {target} has no SPF record."
        return sub_outcome, matched, sub_expl

    return "neutral", None, None
