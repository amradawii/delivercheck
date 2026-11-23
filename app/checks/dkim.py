"""DKIM selector probing, RFC 6376/8301/8463 record parsing, and key strength checks."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Sequence
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

from app.dns.providers import (
    MailProvider,
    detect_provider_from_dkim_cname,
    selectors_for_providers,
)
from app.dns.resolver import DNSResolver, DNSStatus, normalize_dns_name

RSA_MIN_BITS = 1024
RSA_RECOMMENDED_BITS = 2048
ED25519_PUBLIC_KEY_BYTES = 32


@dataclass(frozen=True)
class DKIMIssue:
    severity: str  # "pass", "warn", "fail", "info"
    title: str
    detail: str
    fix: str | None = None
    record_value: str | None = None


@dataclass(frozen=True)
class ParsedDKIMKey:
    raw: str
    tags: tuple[tuple[str, str], ...] = ()
    version: str | None = None
    key_type: str = "rsa"
    key_bits: int | None = None
    is_revoked: bool = False
    is_testing: bool = False
    is_strict_subdomain: bool = False
    sha1_only: bool = False
    service_disallows_email: bool = False
    parse_errors: tuple[str, ...] = ()

    @property
    def is_valid_active_key(self) -> bool:
        if self.is_revoked or self.parse_errors:
            return False
        if self.key_type == "rsa":
            return self.key_bits is not None and self.key_bits >= RSA_MIN_BITS
        if self.key_type == "ed25519":
            return self.key_bits == 256
        return False


@dataclass(frozen=True)
class DKIMSelectorResult:
    selector: str
    qname: str
    found: bool
    is_custom: bool = False
    cname_target: str | None = None
    detected_provider: MailProvider | None = None
    raw_record: str | None = None
    parsed: ParsedDKIMKey | None = None
    error: str | None = None


@dataclass(frozen=True)
class DKIMCheckResult:
    domain: str
    status: str  # "pass", "warn", "fail", "unknown", "error"
    probed_selectors: tuple[str, ...] = ()
    found_keys: tuple[DKIMSelectorResult, ...] = ()
    custom_selector_result: DKIMSelectorResult | None = None
    detected_providers: tuple[MailProvider, ...] = ()
    unprobeable_providers: tuple[MailProvider, ...] = ()
    issues: tuple[DKIMIssue, ...] = ()

    @property
    def has_active_key(self) -> bool:
        return any(
            k.found and k.parsed is not None and k.parsed.is_valid_active_key
            for k in self.found_keys
        )


def normalize_selector(raw_selector: str | None) -> str | None:
    """Clean a user-supplied DKIM selector (accepting either 'google' or 'google._domainkey...')."""
    if not raw_selector:
        return None
    cleaned = raw_selector.strip().lower().rstrip(".")
    if not cleaned:
        return None
    if "._domainkey" in cleaned:
        cleaned = cleaned.split("._domainkey", 1)[0]
    cleaned = cleaned.strip(".")
    return cleaned or None


def parse_dkim_record(raw: str) -> ParsedDKIMKey:
    """Parse a DKIM public-key TXT record (RFC 6376, RFC 8301, RFC 8463)."""
    errors: list[str] = []
    tags_list: list[tuple[str, str]] = []
    tag_map: dict[str, str] = {}

    segments = raw.strip().split(";")
    for idx, segment in enumerate(segments):
        piece = segment.strip()
        if not piece:
            continue
        if "=" not in piece:
            errors.append(f"Malformed DKIM tag '{piece}' (missing '=').")
            continue
        name_raw, value_raw = piece.split("=", 1)
        name = name_raw.strip().lower()
        value = value_raw.strip()
        if not name:
            errors.append(f"Empty DKIM tag name in '{piece}'.")
            continue
        if name in tag_map:
            errors.append(f"Duplicate DKIM tag '{name}='.")
        tag_map[name] = value
        tags_list.append((name, value))

        # RFC 6376 section 3.6.1: v= is optional, but if present it MUST be first and 'DKIM1'
        if name == "v":
            if idx != 0 or len(tags_list) != 1:
                errors.append("Tag 'v=DKIM1' must appear first when present (RFC 6376).")
            if value != "DKIM1":
                errors.append(f"Unsupported DKIM version 'v={value}' (expected 'DKIM1').")

    version = tag_map.get("v")
    # Read k= first so RSA key-length rules are never applied to Ed25519 keys
    key_type = tag_map.get("k", "rsa").strip().lower() or "rsa"

    flags_raw = tag_map.get("t", "")
    flags = {f.strip().lower() for f in flags_raw.split(":") if f.strip()}
    is_testing = "y" in flags
    is_strict_subdomain = "s" in flags

    sha1_only = False
    if "h" in tag_map and tag_map["h"]:
        hashes = {h.strip().lower() for h in tag_map["h"].split(":") if h.strip()}
        if hashes and "sha256" not in hashes and "sha1" in hashes:
            sha1_only = True

    service_disallows_email = False
    if "s" in tag_map and tag_map["s"]:
        services = {s.strip().lower() for s in tag_map["s"].split(":") if s.strip()}
        if services and "*" not in services and "email" not in services:
            service_disallows_email = True

    if "p" not in tag_map:
        errors.append("Missing required 'p=' public key tag.")
        return ParsedDKIMKey(
            raw=raw,
            tags=tuple(tags_list),
            version=version,
            key_type=key_type,
            is_testing=is_testing,
            is_strict_subdomain=is_strict_subdomain,
            sha1_only=sha1_only,
            service_disallows_email=service_disallows_email,
            parse_errors=tuple(errors),
        )

    p_clean = "".join(tag_map["p"].split())
    if p_clean == "":
        return ParsedDKIMKey(
            raw=raw,
            tags=tuple(tags_list),
            version=version,
            key_type=key_type,
            is_revoked=True,
            is_testing=is_testing,
            is_strict_subdomain=is_strict_subdomain,
            sha1_only=sha1_only,
            service_disallows_email=service_disallows_email,
            parse_errors=tuple(errors),
        )

    try:
        key_bytes = base64.b64decode(p_clean, validate=True)
    except Exception:
        errors.append("Public key 'p=' is not valid base64.")
        return ParsedDKIMKey(
            raw=raw,
            tags=tuple(tags_list),
            version=version,
            key_type=key_type,
            is_testing=is_testing,
            is_strict_subdomain=is_strict_subdomain,
            sha1_only=sha1_only,
            service_disallows_email=service_disallows_email,
            parse_errors=tuple(errors),
        )

    key_bits: int | None = None
    if key_type == "ed25519":
        if len(key_bytes) != ED25519_PUBLIC_KEY_BYTES:
            errors.append(
                f"Invalid Ed25519 public key length ({len(key_bytes)} bytes; expected 32 bytes)."
            )
        else:
            try:
                Ed25519PublicKey.from_public_bytes(key_bytes)
                key_bits = 256
            except Exception:
                errors.append("Could not parse Ed25519 public key bytes.")
    elif key_type == "rsa":
        try:
            pub = load_der_public_key(key_bytes)
            if not isinstance(pub, RSAPublicKey):
                errors.append("Public key in 'p=' is not an RSA public key.")
            else:
                key_bits = pub.key_size
        except Exception:
            errors.append("Could not parse RSA public key from 'p='.")
    else:
        errors.append(f"Unsupported DKIM key type 'k={key_type}'.")

    return ParsedDKIMKey(
        raw=raw,
        tags=tuple(tags_list),
        version=version,
        key_type=key_type,
        key_bits=key_bits,
        is_revoked=False,
        is_testing=is_testing,
        is_strict_subdomain=is_strict_subdomain,
        sha1_only=sha1_only,
        service_disallows_email=service_disallows_email,
        parse_errors=tuple(errors),
    )


def _looks_like_dkim_txt(record: str) -> bool:
    lower = record.lower()
    return "p=" in lower or "v=dkim1" in lower


async def _probe_selector(
    domain: str,
    selector: str,
    resolver: DNSResolver,
    *,
    is_custom: bool = False,
) -> DKIMSelectorResult:
    qname = f"{selector}._domainkey.{domain}"
    resp = await resolver.query(qname, "TXT")

    cname_target = resp.cname_chain[-1] if resp.cname_chain else None
    cname_provider = detect_provider_from_dkim_cname(cname_target) if cname_target else None

    if resp.status in (DNSStatus.TIMEOUT, DNSStatus.ERROR):
        return DKIMSelectorResult(
            selector=selector,
            qname=qname,
            found=False,
            is_custom=is_custom,
            cname_target=cname_target,
            detected_provider=cname_provider,
            error=resp.error_message or resp.status.value,
        )

    if resp.status != DNSStatus.OK or not resp.records:
        return DKIMSelectorResult(
            selector=selector,
            qname=qname,
            found=False,
            is_custom=is_custom,
            cname_target=cname_target,
            detected_provider=cname_provider,
        )

    dkim_candidates = [r for r in resp.records if _looks_like_dkim_txt(r)]
    chosen = dkim_candidates[0] if dkim_candidates else resp.records[0]
    parsed = parse_dkim_record(chosen)

    return DKIMSelectorResult(
        selector=selector,
        qname=qname,
        found=True,
        is_custom=is_custom,
        cname_target=cname_target,
        detected_provider=cname_provider,
        raw_record=chosen,
        parsed=parsed,
    )


async def check_dkim(
    domain: str,
    resolver: DNSResolver,
    *,
    detected_providers: Sequence[MailProvider] = (),
    custom_selector: str | None = None,
) -> DKIMCheckResult:
    """Probe known provider selectors plus an optional user selector and verify key strength."""
    norm_domain = normalize_dns_name(domain)
    clean_custom = normalize_selector(custom_selector)

    candidate_selectors = selectors_for_providers(detected_providers)
    probe_plan: list[tuple[str, bool]] = []
    seen: set[str] = set()
    if clean_custom:
        probe_plan.append((clean_custom, True))
        seen.add(clean_custom)
    for sel in candidate_selectors:
        if sel not in seen:
            probe_plan.append((sel, False))
            seen.add(sel)

    results = await asyncio.gather(
        *(
            _probe_selector(norm_domain, sel, resolver, is_custom=is_custom)
            for sel, is_custom in probe_plan
        )
    )

    custom_result = next((r for r in results if r.is_custom), None)
    found_keys = tuple(r for r in results if r.found)
    probed_selectors = tuple(sel for sel, _ in probe_plan)

    unprobeable = tuple(p for p in detected_providers if p.has_unprobeable_dkim)
    extra_providers: list[MailProvider] = []
    seen_p_ids: set[str] = set()
    for p in detected_providers:
        if p.id not in seen_p_ids:
            extra_providers.append(p)
            seen_p_ids.add(p.id)
    for key in found_keys:
        if key.detected_provider and key.detected_provider.id not in seen_p_ids:
            extra_providers.append(key.detected_provider)
            seen_p_ids.add(key.detected_provider.id)

    issues: list[DKIMIssue] = []
    has_fail = False
    has_warn = False

    if custom_result is not None and not custom_result.found:
        has_fail = True
        if custom_result.error:
            issues.append(
                DKIMIssue(
                    severity="fail",
                    title=f"Could not look up custom DKIM selector '{custom_result.selector}'",
                    detail=(
                        f"DNS lookup for {custom_result.qname} failed ({custom_result.error})."
                    ),
                    fix="Check your DNS server and try the selector again.",
                )
            )
        else:
            issues.append(
                DKIMIssue(
                    severity="fail",
                    title=f"Custom DKIM selector '{custom_result.selector}' was not found",
                    detail=(
                        f"No TXT record exists at {custom_result.qname}, so mail signed with "
                        f"selector '{custom_result.selector}' will fail DKIM verification."
                    ),
                    fix=(
                        "Double-check the selector name in your email provider's DKIM settings "
                        "and make sure the TXT or CNAME record is published."
                    ),
                )
            )

    if not found_keys:
        all_errored = bool(results) and all(r.error is not None for r in results)
        if all_errored:
            return DKIMCheckResult(
                domain=norm_domain,
                status="error",
                probed_selectors=probed_selectors,
                custom_selector_result=custom_result,
                detected_providers=tuple(extra_providers),
                unprobeable_providers=unprobeable,
                issues=(
                    DKIMIssue(
                        severity="fail",
                        title="Could not look up DKIM records",
                        detail=(
                            f"DNS queries for DKIM selectors on {norm_domain} timed out or failed."
                        ),
                        fix="Check that your domain's nameservers are reachable and try again.",
                    ),
                ),
            )

        if custom_result is not None and not custom_result.found:
            return DKIMCheckResult(
                domain=norm_domain,
                status="fail",
                probed_selectors=probed_selectors,
                custom_selector_result=custom_result,
                detected_providers=tuple(extra_providers),
                unprobeable_providers=unprobeable,
                issues=tuple(issues),
            )

        if unprobeable:
            names = ", ".join(p.name for p in unprobeable)
            issues.append(
                DKIMIssue(
                    severity="info",
                    title=f"DKIM selector cannot be guessed automatically for {names}",
                    detail=(
                        f"{names} uses unique or custom DKIM selectors that cannot be discovered "
                        "from DNS without knowing the selector name."
                    ),
                    fix=(
                        "Enter your DKIM selector above or send a test email in the "
                        "'Send a test email' tab to verify DKIM for sure."
                    ),
                )
            )
        else:
            checked_list = ", ".join(probed_selectors)
            issues.append(
                DKIMIssue(
                    severity="info",
                    title="No DKIM key found on common selectors",
                    detail=(
                        f"Checked selectors ({checked_list}) on {norm_domain}, and none returned "
                        "a DKIM record — your domain may use a custom selector or not have DKIM "
                        "enabled yet."
                    ),
                    fix=(
                        "Enter your DKIM selector if you know it, or send a test email to check "
                        "DKIM for sure."
                    ),
                )
            )

        return DKIMCheckResult(
            domain=norm_domain,
            status="unknown",
            probed_selectors=probed_selectors,
            found_keys=(),
            custom_selector_result=custom_result,
            detected_providers=tuple(extra_providers),
            unprobeable_providers=unprobeable,
            issues=tuple(issues),
        )

    valid_active_count = 0

    for item in found_keys:
        parsed = item.parsed
        assert parsed is not None

        if parsed.parse_errors:
            has_fail = True
            issues.append(
                DKIMIssue(
                    severity="fail",
                    title=f"DKIM record for selector '{item.selector}' is invalid",
                    detail=f"{item.qname}: {parsed.parse_errors[0]}",
                    fix=(
                        "Copy the exact DKIM TXT or CNAME value from your email provider and "
                        "republish it without extra characters or line breaks."
                    ),
                )
            )
            continue

        if parsed.is_revoked:
            has_warn = True
            issues.append(
                DKIMIssue(
                    severity="warn",
                    title=f"DKIM key for selector '{item.selector}' is revoked",
                    detail=(
                        f"{item.qname} has an empty 'p=' value, which explicitly revokes this "
                        "signing key."
                    ),
                    fix=(
                        "If this key was rotated out, no action is needed; otherwise generate "
                        "and publish an active DKIM key in your email provider."
                    ),
                )
            )
            continue

        if parsed.key_type == "rsa" and parsed.key_bits is not None:
            if parsed.key_bits < RSA_MIN_BITS:
                has_fail = True
                issues.append(
                    DKIMIssue(
                        severity="fail",
                        title=(
                            f"Weak {parsed.key_bits}-bit RSA DKIM key on selector '{item.selector}'"
                        ),
                        detail=(
                            f"{item.qname} uses a {parsed.key_bits}-bit RSA key, which is below "
                            "the 1024-bit RFC 8301 minimum and is rejected by modern receivers."
                        ),
                        fix=(
                            "Generate a 2048-bit RSA DKIM key (or Ed25519 key) in your email "
                            "provider and replace this DNS record."
                        ),
                    )
                )
                continue

            valid_active_count += 1
            if parsed.key_bits < RSA_RECOMMENDED_BITS:
                has_warn = True
                issues.append(
                    DKIMIssue(
                        severity="warn",
                        title=(
                            f"1024-bit RSA DKIM key on selector '{item.selector}' "
                            "(2048-bit recommended)"
                        ),
                        detail=(
                            f"{item.qname} meets the 1024-bit minimum, but 2048-bit RSA is "
                            "recommended for stronger long-term security."
                        ),
                        fix=(
                            "Rotate this DKIM key to 2048-bit in your email provider when "
                            "convenient."
                        ),
                    )
                )
            else:
                issues.append(
                    DKIMIssue(
                        severity="pass",
                        title=(
                            f"Valid {parsed.key_bits}-bit RSA DKIM key on selector "
                            f"'{item.selector}'"
                        ),
                        detail=(f"{item.qname} publishes an active {parsed.key_bits}-bit RSA key."),
                    )
                )
        elif parsed.key_type == "ed25519":
            valid_active_count += 1
            issues.append(
                DKIMIssue(
                    severity="pass",
                    title=f"Valid Ed25519 DKIM key on selector '{item.selector}'",
                    detail=(f"{item.qname} publishes a strong Ed25519 (RFC 8463) public key."),
                )
            )

        if parsed.is_testing:
            has_warn = True
            issues.append(
                DKIMIssue(
                    severity="warn",
                    title=f"DKIM selector '{item.selector}' is in testing mode (t=y)",
                    detail=(
                        f"{item.qname} includes 't=y', telling receivers to treat DKIM failures "
                        "as unsigned mail instead of real failures."
                    ),
                    fix="Remove 't=y' from the DKIM TXT record once signing is verified.",
                )
            )

        if parsed.sha1_only:
            has_fail = True
            issues.append(
                DKIMIssue(
                    severity="fail",
                    title=f"DKIM selector '{item.selector}' only allows deprecated SHA-1",
                    detail=(
                        f"{item.qname} restricts hashes to 'h=sha1', which is deprecated by "
                        "RFC 8301."
                    ),
                    fix="Remove 'h=sha1' or switch to 'h=sha256' in your DKIM record.",
                )
            )

        if parsed.service_disallows_email:
            has_warn = True
            issues.append(
                DKIMIssue(
                    severity="warn",
                    title=f"DKIM selector '{item.selector}' restricts service type (s=)",
                    detail=(
                        f"{item.qname} sets an 's=' service tag that does not include 'email' "
                        "or '*', so mail servers will not use it for email."
                    ),
                    fix="Remove the 's=' tag or set it to 's=email'.",
                )
            )

    if valid_active_count == 0 or has_fail:
        status = "fail"
    elif has_warn:
        status = "warn"
    else:
        status = "pass"

    return DKIMCheckResult(
        domain=norm_domain,
        status=status,
        probed_selectors=probed_selectors,
        found_keys=found_keys,
        custom_selector_result=custom_result,
        detected_providers=tuple(extra_providers),
        unprobeable_providers=unprobeable,
        issues=tuple(issues),
    )
