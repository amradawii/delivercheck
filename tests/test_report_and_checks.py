"""Tests for Gmail/Yahoo checklist, SPF/DMARC fixes, blocklists, extras, SSRF, and reports."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.checks.blocklists import check_blocklists
from app.checks.domain import run_domain_check
from app.checks.extras import PolicyFetchResult, check_extras, fetch_mta_sts_policy
from app.checks.fixes import suggest_dmarc_fix, suggest_spf_fix
from app.checks.mx import check_mx
from app.checks.spf import check_spf
from app.dns.providers import PROVIDERS_BY_ID
from app.dns.resolver import DNSResolver, FakeDNSResolver
from app.net_safety import SSRFError, is_public_ip, resolve_public_ips, validate_email_port
from app.report.plain_text import render_domain_report_text


def _rsa_2048_b64() -> str:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def test_net_safety_blocks_private_loopback_reserved_and_non_email_ports() -> None:
    assert is_public_ip("93.184.216.34") is True
    assert is_public_ip("2606:2800:220:1:248:1893:25c8:1946") is True
    for bad_ip in (
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
    ):
        assert is_public_ip(bad_ip) is False, f"Expected {bad_ip} to be rejected"

    assert validate_email_port(25) == 25
    assert validate_email_port(465) == 465
    assert validate_email_port(587) == 587
    for bad_port in (22, 80, 443, 2525, 8080):
        with pytest.raises(SSRFError):
            validate_email_port(bad_port)


async def test_resolve_public_ips_refuses_internal_targets() -> None:
    resolver = FakeDNSResolver(
        {
            "internal.example": {"A": ["10.0.0.5"]},
            "mixed.example": {"A": ["93.184.216.34", "127.0.0.1"]},
            "public.example": {"A": ["93.184.216.34"]},
        }
    )
    assert await resolve_public_ips("public.example", resolver) == ["93.184.216.34"]
    with pytest.raises(SSRFError):
        await resolve_public_ips("internal.example", resolver)
    with pytest.raises(SSRFError):
        await resolve_public_ips("mixed.example", resolver)
    with pytest.raises(SSRFError):
        await resolve_public_ips("127.0.0.1", resolver)


async def test_blocklists_clean_listed_error_codes_and_ipv6_rules() -> None:
    resolver = FakeDNSResolver(
        {
            # Domain lists: Spamhaus DBL error code 127.255.255.254, SURBL 127.0.0.1 refused,
            # URIBL clean (NXDOMAIN)
            "yourstore.com.dbl.spamhaus.org": {"A": ["127.255.255.254"]},
            "yourstore.com.multi.surbl.org": {"A": ["127.0.0.1"]},
            # IPv4 listed on SpamCop, error code 127.255.255.255 on ZEN
            "34.216.184.93.bl.spamcop.net": {"A": ["127.0.0.2"]},
            "34.216.184.93.zen.spamhaus.org": {"A": ["127.255.255.255"]},
        }
    )
    result = await check_blocklists(
        "yourstore.com",
        resolver,
        ips=["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "10.0.0.1"],
    )

    # Private IP skipped
    assert "10.0.0.1" not in result.checked_ips

    # Error codes are NEVER "listed" — always "could_not_check"
    by_name = {(e.list_name, e.target): e for e in result.entries}
    assert by_name[("Spamhaus DBL", "yourstore.com")].status == "could_not_check"
    assert by_name[("SURBL", "yourstore.com")].status == "could_not_check"
    assert by_name[("URIBL", "yourstore.com")].status == "clean"
    assert by_name[("Spamhaus ZEN", "93.184.216.34")].status == "could_not_check"
    assert by_name[("SpamCop", "93.184.216.34")].status == "listed"

    # IPv6 queried on Spamhaus ZEN only (never on IPv4-only SpamCop or Barracuda)
    assert ("Spamhaus ZEN", "2606:2800:220:1:248:1893:25c8:1946") in by_name
    assert ("SpamCop", "2606:2800:220:1:248:1893:25c8:1946") not in by_name
    # Barracuda is opt-in (disabled by default)
    assert all(e.list_name != "Barracuda BRBL" for e in result.entries)
    assert result.status == "fail"


async def test_blocklists_dqs_key_and_barracuda_opt_in_and_dbl_127_0_1_255() -> None:
    resolver = FakeDNSResolver(
        {
            "test.example.mykey.dbl.dq.spamhaus.net": {"A": ["127.0.1.255"]},
            "34.216.184.93.b.barracudacentral.org": {"A": ["127.0.0.2"]},
        }
    )
    result = await check_blocklists(
        "test.example",
        resolver,
        ips=["93.184.216.34"],
        spamhaus_dqs_key="mykey",
        enable_barracuda_brbl=True,
    )
    by_name = {e.list_name: e for e in result.entries}
    assert by_name["Spamhaus DBL"].status == "could_not_check"
    assert by_name["Barracuda BRBL"].status == "listed"
    assert ("test.example.mykey.dbl.dq.spamhaus.net", "A") in resolver.query_log


async def test_suggest_spf_merges_multiple_records_within_limit_and_flags_over_limit() -> None:
    resolver = FakeDNSResolver(
        {
            "merge.example": {
                "TXT": [
                    "v=spf1 include:_spf.google.com ~all",
                    "v=spf1 include:sendgrid.net ~all",
                ]
            },
        }
    )
    spf_multi = await check_spf(
        "merge.example",
        resolver,
        detected_providers=[PROVIDERS_BY_ID["shopify"], PROVIDERS_BY_ID["klaviyo"]],
    )
    suggestion = suggest_spf_fix(
        spf_multi,
        detected_providers=[PROVIDERS_BY_ID["shopify"], PROVIDERS_BY_ID["klaviyo"]],
    )
    assert suggestion is not None
    assert suggestion.within_limit is True
    assert suggestion.record == "v=spf1 include:_spf.google.com include:sendgrid.net ~all"
    # Shopify and Klaviyo are never added to root SPF
    assert "shopify" not in suggestion.record
    assert "klaviyo" not in suggestion.record

    # Over 10 lookups cannot be magically merged — must warn clearly instead of emitting >10 record
    zones: dict[str, dict[str, list[str]]] = {
        "too-many.example": {
            "TXT": ["v=spf1 " + " ".join(f"include:s{i}.example" for i in range(1, 12)) + " ~all"]
        }
    }
    for i in range(1, 12):
        zones[f"s{i}.example"] = {"TXT": [f"v=spf1 ip4:93.184.216.{i} ~all"]}
    spf_over = await check_spf("too-many.example", FakeDNSResolver(zones))
    over_suggestion = suggest_spf_fix(spf_over)
    assert over_suggestion is not None
    assert over_suggestion.within_limit is False
    assert over_suggestion.record is None
    assert "11 DNS lookups" in over_suggestion.note


async def test_extras_mta_sts_mx_matching_and_ssrf_refusal() -> None:
    resolver = FakeDNSResolver(
        {
            "sts.example": {"MX": [(1, "smtp.google.com")]},
            "smtp.google.com": {"A": ["142.250.27.26"]},
            "_mta-sts.sts.example": {"TXT": ["v=STSv1; id=20240601"]},
            "_smtp._tls.sts.example": {"TXT": ["v=TLSRPTv1; rua=mailto:tls@sts.example"]},
            "default._bimi.sts.example": {"TXT": ["v=BIMI1; l=https://sts.example/logo.svg;"]},
            "_dmarc.sts.example": {"TXT": ["v=DMARC1; p=none; rua=mailto:dmarc@sts.example"]},
            "mta-sts.private.example": {"A": ["127.0.0.1"]},
        }
    )

    mx_res = await check_mx("sts.example", resolver)
    from app.checks.dmarc import check_dmarc

    dmarc_res = await check_dmarc("sts.example", resolver)

    async def fake_mismatched_fetcher(domain: str, res: DNSResolver) -> PolicyFetchResult:
        return PolicyFetchResult(
            ok=True,
            status_code=200,
            body=(
                "version: STSv1\nmode: enforce\n"
                "mx: *.mail.protection.outlook.com\nmax_age: 86400\n"
            ),
        )

    extras_bad = await check_extras(
        "sts.example",
        resolver,
        mx_result=mx_res,
        dmarc_result=dmarc_res,
        policy_fetcher=fake_mismatched_fetcher,
    )
    assert extras_bad.mta_sts.unmatched_mx_hosts == ("smtp.google.com",)
    assert any("does not match your MX records" in i.title for i in extras_bad.issues)
    # BIMI present with p=none DMARC should warn
    assert any("BIMI record found" in i.title for i in extras_bad.issues)

    # Real fetch_mta_sts_policy must refuse private IP before making any network call
    ssrf_fetch = await fetch_mta_sts_policy("private.example", resolver)
    assert ssrf_fetch.ok is False
    assert "non-public" in (ssrf_fetch.error or "").lower()


async def test_full_domain_report_and_plain_text_rendering() -> None:
    key_2048 = _rsa_2048_b64()
    resolver = FakeDNSResolver(
        {
            "yourstore.com": {
                "MX": [(1, "smtp.google.com")],
                "NS": ["aria.ns.cloudflare.com", "noah.ns.cloudflare.com"],
                "TXT": [
                    "v=spf1 include:_spf.google.com ~all",
                    "klaviyo-site-verification=xyz",
                ],
            },
            "smtp.google.com": {"A": ["142.250.27.26"]},
            "_spf.google.com": {"TXT": ["v=spf1 ip4:142.250.0.0/15 ~all"]},
            "google._domainkey.yourstore.com": {"TXT": [f"v=DKIM1; k=rsa; p={key_2048}"]},
            "_dmarc.yourstore.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@yourstore.com"]},
        }
    )

    async def no_sts_fetcher(domain: str, res: DNSResolver) -> PolicyFetchResult:
        return PolicyFetchResult(ok=False, error="not called")

    report = await run_domain_check("yourstore.com", resolver, policy_fetcher=no_sts_fetcher)
    assert report.verdict_status == "pass"
    assert report.mailbox_provider is not None
    assert report.mailbox_provider.id == "google_workspace"
    assert [p.id for p in report.sending_providers] == ["klaviyo"]
    assert report.dns_host is not None
    assert report.dns_host.id == "cloudflare"
    assert report.checklist.failed_count == 0
    assert "June 1" in report.checklist.items[-1].detail
    assert "5,000+" in report.checklist.bulk_threshold_note

    dmarc_sug = suggest_dmarc_fix(report.dmarc)
    assert dmarc_sug is None  # already p=reject

    text = render_domain_report_text(report)
    assert "DeliverCheck Domain Report: yourstore.com" in text
    assert "Cloudflare" in text
    assert "Google Workspace" in text
    assert "Klaviyo" in text
    assert "Gmail & Yahoo 2024 Sender Requirements" in text
