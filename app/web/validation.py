"""User input normalization and validation for domains and email addresses."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.dns.resolver import normalize_dns_name

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class DomainValidationResult:
    ok: bool
    domain: str | None = None
    display_domain: str | None = None
    error: str | None = None
    suggested_domain: str | None = None


@dataclass(frozen=True)
class EmailValidationResult:
    ok: bool
    email: str | None = None
    local_part: str | None = None
    domain: str | None = None
    error: str | None = None


_LOCAL_PART_RE = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")


def validate_domain_input(raw: str) -> DomainValidationResult:
    """Validate and normalize a domain name, giving clear messages for URLs and emails."""
    cleaned = raw.strip()
    if not cleaned:
        return DomainValidationResult(
            ok=False,
            error="Enter a domain name such as yourstore.com.",
        )

    # Helpful message if the user pasted an email address
    if "@" in cleaned and "://" not in cleaned:
        parts = cleaned.split("@")
        if len(parts) == 2 and parts[1].strip():
            candidate = parts[1].strip().rstrip(".").lower()
            return DomainValidationResult(
                ok=False,
                error=(
                    f"That looks like an email address. Enter just the domain ({candidate}) "
                    "here, or switch to 'Test a mail server' to test the mailbox."
                ),
                suggested_domain=candidate,
            )
        return DomainValidationResult(
            ok=False,
            error=(
                "That looks like an email address. Enter only the domain name (e.g. yourstore.com)."
            ),
        )

    # Helpful message if the user pasted a full URL
    if "://" in cleaned or "/" in cleaned:
        parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
        host = (parsed.hostname or "").strip().rstrip(".").lower()
        if host.startswith("www.") and host.count(".") >= 2:
            host = host[4:]
        if host:
            return DomainValidationResult(
                ok=False,
                error=(f"Enter just the domain name, not a full URL — try '{host}' instead."),
                suggested_domain=host,
            )
        return DomainValidationResult(
            ok=False,
            error="Enter a domain name like yourstore.com, not a web address.",
        )

    if any(ch.isspace() for ch in cleaned):
        return DomainValidationResult(
            ok=False,
            error="Domain names cannot contain spaces. Example: yourstore.com.",
        )

    display_domain = cleaned.rstrip(".").lower()

    try:
        ipaddress.ip_address(display_domain)
        return DomainValidationResult(
            ok=False,
            error="Enter a domain name (such as yourstore.com), not an IP address.",
        )
    except ValueError:
        pass

    try:
        ascii_domain = normalize_dns_name(display_domain)
    except UnicodeError:
        return DomainValidationResult(
            ok=False,
            error="That domain contains characters that cannot be converted to punycode.",
        )

    if len(ascii_domain) > 253 or "." not in ascii_domain:
        return DomainValidationResult(
            ok=False,
            error="Enter a full domain name including its ending (for example, yourstore.com).",
        )

    labels = ascii_domain.split(".")
    if any(not _LABEL_RE.match(label) for label in labels):
        return DomainValidationResult(
            ok=False,
            error="Invalid domain syntax. Use letters, numbers, hyphens, and dots only.",
        )

    # Top-level label must not be all numeric
    if labels[-1].isdigit() or len(labels[-1]) < 2:
        return DomainValidationResult(
            ok=False,
            error="Enter a valid top-level domain (for example, .com, .co.uk, or .org).",
        )

    return DomainValidationResult(
        ok=True,
        domain=ascii_domain,
        display_domain=display_domain,
    )


def validate_email_input(raw: str) -> EmailValidationResult:
    """Validate an email address such as info@yourstore.com for mail server tests."""
    cleaned = raw.strip()
    if not cleaned:
        return EmailValidationResult(
            ok=False,
            error="Enter an email address such as info@yourstore.com.",
        )
    if any(ch.isspace() for ch in cleaned):
        return EmailValidationResult(
            ok=False,
            error="Email addresses cannot contain spaces.",
        )
    if "@" not in cleaned:
        return EmailValidationResult(
            ok=False,
            error=(
                f"Enter a full email address (for example, info@{cleaned.lower()}), "
                "not just a domain."
            ),
        )
    parts = cleaned.split("@")
    if len(parts) != 2:
        return EmailValidationResult(
            ok=False,
            error="Enter a single valid email address such as info@yourstore.com.",
        )
    local_part, raw_domain = parts[0], parts[1]
    if (
        not _LOCAL_PART_RE.match(local_part)
        or local_part.startswith(".")
        or local_part.endswith(".")
        or ".." in local_part
    ):
        return EmailValidationResult(
            ok=False,
            error="The part before '@' is not a valid email mailbox name.",
        )
    domain_check = validate_domain_input(raw_domain)
    if not domain_check.ok or not domain_check.domain:
        return EmailValidationResult(
            ok=False,
            error=domain_check.error or "The domain part of the email address is invalid.",
        )
    return EmailValidationResult(
        ok=True,
        email=f"{local_part}@{domain_check.domain}",
        local_part=local_part,
        domain=domain_check.domain,
    )
