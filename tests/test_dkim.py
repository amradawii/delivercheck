"""Tests for DKIM selector probing, RSA/Ed25519 key parsing, revocation, and testing flags."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from app.checks.dkim import check_dkim, normalize_selector, parse_dkim_record
from app.dns.providers import PROVIDERS_BY_ID
from app.dns.resolver import FAKE_TIMEOUT, FakeDNSResolver


def _rsa_pub_b64(bits: int) -> str:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def _ed25519_pub_b64() -> str:
    priv = ed25519.Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def test_normalize_selector() -> None:
    assert normalize_selector("  Google  ") == "google"
    assert normalize_selector("selector1._domainkey.example.com.") == "selector1"
    assert normalize_selector("   ") is None
    assert normalize_selector(None) is None


def test_parse_dkim_v_optional_and_tag_order() -> None:
    key_2048 = _rsa_pub_b64(2048)

    # RFC 6376: v=DKIM1 is optional
    without_v = parse_dkim_record(f"k=rsa; p={key_2048}")
    assert without_v.parse_errors == ()
    assert without_v.version is None
    assert without_v.key_type == "rsa"
    assert without_v.key_bits == 2048
    assert without_v.is_valid_active_key is True

    # v=DKIM1 not first is an RFC 6376 violation
    wrong_order = parse_dkim_record(f"k=rsa; v=DKIM1; p={key_2048}")
    assert any("must appear first" in err for err in wrong_order.parse_errors)


async def test_dkim_found_google_2048_rsa() -> None:
    key_2048 = _rsa_pub_b64(2048)
    resolver = FakeDNSResolver(
        {
            "google._domainkey.yourstore.com": {
                "TXT": [(f"v=DKIM1; k=rsa; p={key_2048[:100]}", key_2048[100:])]
            }
        }
    )
    result = await check_dkim(
        "yourstore.com",
        resolver,
        detected_providers=[PROVIDERS_BY_ID["google_workspace"]],
    )
    assert result.status == "pass"
    assert result.has_active_key is True
    assert len(result.found_keys) == 1
    assert result.found_keys[0].selector == "google"
    assert result.found_keys[0].parsed is not None
    assert result.found_keys[0].parsed.key_bits == 2048


async def test_dkim_ed25519_key_is_strong_not_weak() -> None:
    ed_pub = _ed25519_pub_b64()
    resolver = FakeDNSResolver(
        {
            "ed._domainkey.modern.example": {
                "TXT": [f"v=DKIM1; k=ed25519; p={ed_pub}"],
            }
        }
    )
    result = await check_dkim("modern.example", resolver, custom_selector="ed")
    assert result.status == "pass"
    assert result.has_active_key is True
    parsed = result.found_keys[0].parsed
    assert parsed is not None
    assert parsed.key_type == "ed25519"
    assert parsed.key_bits == 256
    assert any("Ed25519" in issue.title for issue in result.issues)


async def test_dkim_1024_rsa_warns_to_upgrade_and_512_rsa_fails() -> None:
    key_1024 = _rsa_pub_b64(1024)
    # Generate a 512-bit key using cryptography's unsafe/legacy size via pure ASN.1 check:
    # cryptography 42 accepts key_size=512? If not, test with a pre-built 512-bit DER SPKI.
    resolver_1024 = FakeDNSResolver(
        {
            "selector1._domainkey.m365.example": {
                "CNAME": "selector1-m365-example._domainkey.m365.onmicrosoft.com"
            },
            "selector1-m365-example._domainkey.m365.onmicrosoft.com": {
                "TXT": [f"v=DKIM1; k=rsa; p={key_1024}"],
            },
        }
    )
    res_1024 = await check_dkim(
        "m365.example",
        resolver_1024,
        detected_providers=[PROVIDERS_BY_ID["microsoft_365"]],
    )
    assert res_1024.status == "warn"
    assert res_1024.has_active_key is True
    assert res_1024.found_keys[0].detected_provider is not None
    assert res_1024.found_keys[0].detected_provider.id == "microsoft_365"
    assert any("2048-bit recommended" in i.title for i in res_1024.issues)

    # cryptography 50+ refuses generating 512-bit RSA private keys, so construct a
    # 512-bit RSA public key directly via RSAPublicNumbers to test weak-key detection.
    weak_pub = rsa.RSAPublicNumbers(
        e=65537,
        n=(1 << 511) | 0x123456789ABCDEF1,
    ).public_key()
    weak_der = weak_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    weak_512_b64 = base64.b64encode(weak_der).decode("ascii")

    resolver_512 = FakeDNSResolver(
        {"default._domainkey.weak.example": {"TXT": [f"v=DKIM1; k=rsa; p={weak_512_b64}"]}}
    )
    res_512 = await check_dkim("weak.example", resolver_512)
    assert res_512.status == "fail"
    assert res_512.has_active_key is False
    assert any("Weak 512-bit RSA" in i.title for i in res_512.issues)


async def test_dkim_revoked_key_and_testing_flag() -> None:
    key_2048 = _rsa_pub_b64(2048)
    resolver_revoked = FakeDNSResolver(
        {"google._domainkey.revoked.example": {"TXT": ["v=DKIM1; k=rsa; p="]}}
    )
    res_rev = await check_dkim(
        "revoked.example",
        resolver_revoked,
        detected_providers=[PROVIDERS_BY_ID["google_workspace"]],
    )
    assert res_rev.status == "fail"
    assert res_rev.has_active_key is False
    assert res_rev.found_keys[0].parsed is not None
    assert res_rev.found_keys[0].parsed.is_revoked is True
    assert any("revoked" in i.title.lower() for i in res_rev.issues)

    resolver_testing = FakeDNSResolver(
        {"google._domainkey.testing.example": {"TXT": [f"v=DKIM1; k=rsa; t=y; p={key_2048}"]}}
    )
    res_test = await check_dkim(
        "testing.example",
        resolver_testing,
        detected_providers=[PROVIDERS_BY_ID["google_workspace"]],
    )
    assert res_test.status == "warn"
    assert res_test.has_active_key is True
    assert any("testing mode (t=y)" in i.title for i in res_test.issues)


async def test_dkim_not_found_uses_honest_wording_and_handles_unprobeable_providers() -> None:
    resolver = FakeDNSResolver({})

    res_plain = await check_dkim("plain.example", resolver)
    assert res_plain.status == "unknown"
    assert any("test email" in (i.fix or "").lower() for i in res_plain.issues)
    assert not any("missing" in i.title.lower() for i in res_plain.issues)

    res_ses = await check_dkim(
        "ses.example",
        resolver,
        detected_providers=[PROVIDERS_BY_ID["amazon_ses"], PROVIDERS_BY_ID["shopify"]],
    )
    assert res_ses.status == "unknown"
    assert len(res_ses.unprobeable_providers) == 2
    assert any("Amazon SES, Shopify" in i.title for i in res_ses.issues)
    assert not any("missing" in i.title.lower() for i in res_ses.issues)


async def test_dkim_custom_selector_not_found_fails() -> None:
    resolver = FakeDNSResolver({})
    result = await check_dkim("custom.example", resolver, custom_selector="mykey2024")
    assert result.status == "fail"
    assert result.custom_selector_result is not None
    assert result.custom_selector_result.found is False
    assert any("mykey2024" in i.title for i in result.issues)


async def test_dkim_hostinger_and_mailchimp_selectors_probed() -> None:
    key_2048 = _rsa_pub_b64(2048)
    resolver = FakeDNSResolver(
        {
            "hostingermail-a._domainkey.h.example": {
                "CNAME": "hostingermail-a.dkim.mail.hostinger.com"
            },
            "hostingermail-a.dkim.mail.hostinger.com": {"TXT": [f"v=DKIM1; k=rsa; p={key_2048}"]},
            "k2._domainkey.h.example": {"CNAME": "dkim2.mcsv.net"},
            "dkim2.mcsv.net": {"TXT": [f"v=DKIM1; k=rsa; p={key_2048}"]},
        }
    )
    result = await check_dkim(
        "h.example",
        resolver,
        detected_providers=[PROVIDERS_BY_ID["hostinger"], PROVIDERS_BY_ID["mailchimp"]],
    )
    assert result.status == "pass"
    found_sels = {k.selector for k in result.found_keys}
    assert found_sels == {"hostingermail-a", "k2"}


async def test_dkim_dns_timeout_returns_error() -> None:
    resolver = FakeDNSResolver(
        {
            "google._domainkey.slow.example": {"TXT": FAKE_TIMEOUT},
            "default._domainkey.slow.example": {"TXT": FAKE_TIMEOUT},
        }
    )
    result = await check_dkim(
        "slow.example",
        resolver,
        detected_providers=[PROVIDERS_BY_ID["google_workspace"]],
    )
    assert result.status == "error"
