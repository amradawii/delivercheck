"""Tests for DNS resolver, caching, normalization, and provider/DNS host detection."""

from __future__ import annotations

import pytest

from app.dns.providers import (
    detect_dns_host,
    detect_dns_host_for_domain,
    detect_mail_provider_from_mx,
    detect_provider_from_dkim_cname,
    detect_providers_from_spf_includes,
    detect_providers_from_txt,
    resolve_smtp_host_for_provider,
    selectors_for_providers,
)
from app.dns.resolver import (
    FAKE_ERROR,
    FAKE_NXDOMAIN,
    FAKE_TIMEOUT,
    CachedDNSResolver,
    DNSStatus,
    FakeDNSResolver,
    normalize_dns_name,
    reverse_ip_for_ptr,
)


def test_normalize_dns_name_handles_punycode_and_underscores() -> None:
    assert normalize_dns_name("  Example.COM. ") == "example.com"
    assert normalize_dns_name("_dmarc.Example.COM") == "_dmarc.example.com"
    assert normalize_dns_name("bücher.example") == "xn--bcher-kva.example"
    assert normalize_dns_name("_dmarc.bücher.example") == "_dmarc.xn--bcher-kva.example"


def test_reverse_ip_for_ptr() -> None:
    assert reverse_ip_for_ptr("192.0.2.10") == "10.2.0.192.in-addr.arpa"
    assert reverse_ip_for_ptr("2001:db8::1").endswith(".ip6.arpa")


async def test_fake_resolver_joins_txt_chunks_and_follows_cnames() -> None:
    resolver = FakeDNSResolver(
        {
            "example.com": {
                "TXT": [("v=spf1 ", "include:_spf.google.com ", "~all")],
                "MX": [(10, "alt1.aspmx.l.google.com."), (1, "aspmx.l.google.com.")],
            },
            "selector1._domainkey.example.com": {
                "CNAME": "selector1-example-com._domainkey.example.onmicrosoft.com",
            },
            "selector1-example-com._domainkey.example.onmicrosoft.com": {
                "TXT": ["v=DKIM1; k=rsa; p=MIIBIjAN"],
            },
            "slow.example": {"TXT": FAKE_TIMEOUT},
            "broken.example": {"TXT": FAKE_ERROR},
            "gone.example": {"TXT": FAKE_NXDOMAIN},
        }
    )

    txt = await resolver.query("example.com", "TXT")
    assert txt.status == DNSStatus.OK
    assert txt.records == ("v=spf1 include:_spf.google.com ~all",)

    mx = await resolver.query("example.com", "MX")
    assert mx.status == DNSStatus.OK
    assert [(r.priority, r.exchange) for r in mx.mx_records] == [
        (1, "aspmx.l.google.com"),
        (10, "alt1.aspmx.l.google.com"),
    ]

    dkim = await resolver.query("selector1._domainkey.example.com", "TXT")
    assert dkim.status == DNSStatus.OK
    assert dkim.cname_chain == ("selector1-example-com._domainkey.example.onmicrosoft.com",)

    assert (await resolver.query("slow.example", "TXT")).status == DNSStatus.TIMEOUT
    assert (await resolver.query("broken.example", "TXT")).status == DNSStatus.ERROR
    assert (await resolver.query("gone.example", "TXT")).status == DNSStatus.NXDOMAIN
    assert (await resolver.query("missing.example", "A")).status == DNSStatus.NXDOMAIN


async def test_cached_resolver_deduplicates_queries() -> None:
    inner = FakeDNSResolver({"example.com": {"A": ["93.184.216.34"]}})
    cached = CachedDNSResolver(inner)

    first = await cached.query("Example.COM.", "a")
    second = await cached.query("example.com", "A")
    assert first == second
    assert len(inner.query_log) == 1


@pytest.mark.parametrize(
    ("mx_hosts", "expected_id", "expected_smtp"),
    [
        (["smtp.google.com"], "google_workspace", "smtp.gmail.com"),
        (["aspmx.l.google.com", "alt1.aspmx.l.google.com"], "google_workspace", "smtp.gmail.com"),
        (["example-com.mail.protection.outlook.com"], "microsoft_365", "smtp.office365.com"),
        (["mx.zoho.com", "mx2.zoho.com"], "zoho", "smtp.zoho.com"),
        (["mx.zoho.eu", "mx2.zoho.eu"], "zoho", "smtp.zoho.eu"),
        (["mx.zoho.in"], "zoho", "smtp.zoho.in"),
        (["mx.zoho.com.au"], "zoho", "smtp.zoho.com.au"),
        (["mx1.hostinger.com", "mx2.hostinger.com"], "hostinger", "smtp.hostinger.com"),
        (
            ["inbound-smtp.us-east-1.amazonaws.com"],
            "amazon_ses",
            "email-smtp.us-east-1.amazonaws.com",
        ),
        (["mail.custom-server.example"], None, None),
    ],
)
def test_detect_mail_provider_and_smtp_host(
    mx_hosts: list[str],
    expected_id: str | None,
    expected_smtp: str | None,
) -> None:
    provider = detect_mail_provider_from_mx(mx_hosts)
    if expected_id is None:
        assert provider is None
        assert resolve_smtp_host_for_provider(provider, mx_hosts) is None
    else:
        assert provider is not None
        assert provider.id == expected_id
        assert resolve_smtp_host_for_provider(provider, mx_hosts) == expected_smtp


def test_detect_senders_from_spf_txt_and_dkim_cnames() -> None:
    spf_providers = detect_providers_from_spf_includes(
        [
            "_spf.google.com",
            "shops.shopify.com",
            "sendgrid.net",
            "servers.mcsv.net",
            "amazonses.com",
        ]
    )
    assert [p.id for p in spf_providers] == [
        "google_workspace",
        "shopify",
        "sendgrid",
        "mailchimp",
        "amazon_ses",
    ]
    # Shopify and Klaviyo never require root SPF includes
    shopify = next(p for p in spf_providers if p.id == "shopify")
    assert shopify.requires_root_spf_include is False
    assert shopify.has_unprobeable_dkim is True

    txt_providers = detect_providers_from_txt(["klaviyo-site-verification=abc123"])
    assert [p.id for p in txt_providers] == ["klaviyo"]
    assert txt_providers[0].requires_root_spf_include is False

    shopify_dkim = detect_provider_from_dkim_cname("dkim1.abc.p1.email.myshopify.com")
    assert shopify_dkim is not None
    assert shopify_dkim.id == "shopify"
    ses_dkim = detect_provider_from_dkim_cname("abc123.dkim.amazonses.com")
    assert ses_dkim is not None
    assert ses_dkim.id == "amazon_ses"
    hostinger_dkim = detect_provider_from_dkim_cname("hostingermail-a.dkim.mail.hostinger.com")
    assert hostinger_dkim is not None
    assert hostinger_dkim.id == "hostinger"

    selectors = selectors_for_providers([txt_providers[0]])
    assert selectors[:4] == ["kl", "kl2", "km1", "km2"]


@pytest.mark.parametrize(
    ("ns_records", "expected_id"),
    [
        (["aria.ns.cloudflare.com", "noah.ns.cloudflare.com"], "cloudflare"),
        (["ns41.domaincontrol.com", "ns42.domaincontrol.com"], "godaddy"),
        (["dns1.registrar-servers.com", "dns2.registrar-servers.com"], "namecheap"),
        (["ns1.dns-parking.com", "ns2.dns-parking.com"], "hostinger"),
        (["ns-123.awsdns-45.org", "ns-456.awsdns-12.co.uk"], "route53"),
        (["ns1.digitalocean.com", "ns2.digitalocean.com"], "digitalocean"),
        (["ns1.custom-dns.example"], None),
    ],
)
def test_detect_dns_host(ns_records: list[str], expected_id: str | None) -> None:
    host = detect_dns_host(ns_records)
    if expected_id is None:
        assert host is None
    else:
        assert host is not None
        assert host.id == expected_id
        assert host.guide_url.startswith("https://")


async def test_detect_dns_host_for_domain_queries_ns() -> None:
    resolver = FakeDNSResolver(
        {"yourstore.com": {"NS": ["aria.ns.cloudflare.com.", "noah.ns.cloudflare.com."]}}
    )
    host = await detect_dns_host_for_domain("yourstore.com", resolver)
    assert host is not None
    assert host.id == "cloudflare"
    assert resolver.query_log == [("yourstore.com", "NS")]
