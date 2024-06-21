"""TLS context builders and X.509 certificate verification/inspection."""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class CertificateInfo:
    verified: bool
    hostname_matches: bool
    is_expired: bool
    is_not_yet_valid: bool
    is_self_signed: bool
    subject_cn: str | None = None
    issuer: str | None = None
    san_dns_names: tuple[str, ...] = ()
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_until_expiry: int | None = None
    tls_version: str | None = None
    cipher: str | None = None
    error: str | None = None


def create_verified_ssl_context(cafile: str | None = None) -> ssl.SSLContext:
    """Create a strict TLS 1.2+ context with hostname and CA verification."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def create_unverified_inspection_ssl_context() -> ssl.SSLContext:
    """Read-only context used ONLY to inspect peer certificate fields after verification fails.

    Never send credentials or mail commands over a connection using this context.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def hostname_matches_pattern(hostname: str, pattern: str) -> bool:
    """RFC 6125 left-most single-label wildcard DNS hostname matching."""
    host = hostname.strip().rstrip(".").lower()
    pat = pattern.strip().rstrip(".").lower()
    if not host or not pat:
        return False
    if pat.startswith("*."):
        suffix = pat[1:]  # ".example.com"
        if not host.endswith(suffix):
            return False
        left = host[: -len(suffix)]
        return bool(left) and "." not in left
    return host == pat


def inspect_der_certificate(
    der_bytes: bytes,
    expected_hostname: str,
    *,
    tls_version: str | None = None,
    cipher: str | None = None,
    verified: bool = True,
    verify_error: str | None = None,
    now: datetime | None = None,
) -> CertificateInfo:
    """Parse a peer DER certificate with cryptography and evaluate expiry and hostname match."""
    cert = x509.load_der_x509_certificate(der_bytes)
    current = now or datetime.now(UTC)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    delta = not_after - current
    days_left = delta.days
    is_expired = current > not_after
    is_not_yet_valid = current < not_before
    is_self_signed = cert.subject == cert.issuer

    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject_cn = str(cn_attrs[0].value) if cn_attrs else None

    issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_parts = [str(attr.value) for attr in (*(issuer_org[:1]), *(issuer_cn[:1])) if attr.value]
    issuer = " / ".join(dict.fromkeys(issuer_parts)) or None

    san_names: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = [str(name) for name in san_ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        san_names = []

    candidates = san_names if san_names else ([subject_cn] if subject_cn else [])
    matches = any(hostname_matches_pattern(expected_hostname, pat) for pat in candidates)

    return CertificateInfo(
        verified=verified,
        hostname_matches=matches,
        is_expired=is_expired,
        is_not_yet_valid=is_not_yet_valid,
        is_self_signed=is_self_signed,
        subject_cn=subject_cn,
        issuer=issuer,
        san_dns_names=tuple(san_names),
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=days_left,
        tls_version=tls_version,
        cipher=cipher,
        error=verify_error,
    )
