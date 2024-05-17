"""Comprehensive RFC 7208 SPF parser, lookup counter, auditor, and IP evaluator tests."""

from __future__ import annotations

import pytest

from app.checks.spf import check_spf, evaluate_spf_for_ip, is_spf_txt_record, parse_spf_record
from app.dns.providers import PROVIDERS_BY_ID
from app.dns.resolver import FAKE_TIMEOUT, FakeDNSResolver


def test_is_spf_txt_record_exact_prefix() -> None:
    assert is_spf_txt_record("v=spf1 ~all")
    assert is_spf_txt_record("V=SPF1 -all")
    assert is_spf_txt_record("v=spf1")
    assert not is_spf_txt_record("v=spf10 ~all")
    assert not is_spf_txt_record("google-site-verification=abc")


def test_parse_spf_valid_and_invalid_terms() -> None:
    parsed = parse_spf_record(
        "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a:mail.example.com/24//64 "
        "mx include:_spf.google.com ~all"
    )
    assert parsed.syntax_errors == ()
    assert [t.mechanism for t in parsed.terms] == ["ip4", "ip6", "a", "mx", "include", "all"]
    assert parsed.terms[2].cidr4 == 24
    assert parsed.terms[2].cidr6 == 64

    bad = parse_spf_record("v=spf1 ip4:999.0.0.1 bogus include: ~all")
    assert len(bad.syntax_errors) == 3

    dup_redir = parse_spf_record("v=spf1 redirect=a.example redirect=b.example")
    assert any("Duplicate 'redirect='" in err for err in dup_redir.syntax_errors)


async def test_spf_valid_google_workspace_within_limits() -> None:
    resolver = FakeDNSResolver(
        {
            "yourstore.com": {
                "TXT": [
                    ("v=spf1 ", "include:_spf.google.com ", "ip4:93.184.216.34 ", "~all"),
                ]
            },
            "_spf.google.com": {
                "TXT": ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all"]
            },
            "_netblocks.google.com": {"TXT": ["v=spf1 ip4:142.250.0.0/15 ~all"]},
            "_netblocks2.google.com": {"TXT": ["v=spf1 ip6:2607:f8b0:4000::/36 ~all"]},
        }
    )
    result = await check_spf(
        "yourstore.com",
        resolver,
        detected_providers=[PROVIDERS_BY_ID["google_workspace"]],
    )
    assert result.status == "pass"
    # _spf.google.com (1) + _netblocks (1) + _netblocks2 (1) = 3; ip4/ip6/all do not count
    assert result.dns_lookups == 3
    assert result.void_lookups == 0
    assert result.all_qualifier == "~"
    assert result.missing_provider_includes == ()
    assert [p.id for p in result.detected_providers] == ["google_workspace"]


async def test_spf_multiple_records_is_permerror() -> None:
    resolver = FakeDNSResolver(
        {
            "dup.example": {
                "TXT": [
                    "v=spf1 include:_spf.google.com ~all",
                    "v=spf1 include:sendgrid.net ~all",
                ]
            }
        }
    )
    result = await check_spf("dup.example", resolver)
    assert result.status == "fail"
    assert result.permerror is True
    assert len(result.all_records) == 2
    assert any("Multiple SPF records" in i.title for i in result.issues)


async def test_spf_11_lookups_exceeds_rfc7208_limit() -> None:
    zones: dict[str, dict[str, list[str]]] = {
        "over.example": {
            "TXT": ["v=spf1 " + " ".join(f"include:s{i}.example" for i in range(1, 12)) + " ~all"]
        }
    }
    for i in range(1, 12):
        zones[f"s{i}.example"] = {"TXT": [f"v=spf1 ip4:93.184.216.{i} ~all"]}

    resolver = FakeDNSResolver(zones)
    result = await check_spf("over.example", resolver)
    assert result.status == "fail"
    assert result.dns_lookups == 11
    assert result.permerror is True
    assert any("10 DNS lookup limit" in i.title for i in result.issues)


async def test_spf_10_lookups_exactly_is_within_limit_with_caution() -> None:
    zones: dict[str, dict[str, list[str]]] = {
        "exact10.example": {
            "TXT": ["v=spf1 " + " ".join(f"include:s{i}.example" for i in range(1, 11)) + " -all"]
        }
    }
    for i in range(1, 11):
        zones[f"s{i}.example"] = {"TXT": [f"v=spf1 ip4:93.184.216.{i} ~all"]}

    resolver = FakeDNSResolver(zones)
    result = await check_spf("exact10.example", resolver)
    assert result.dns_lookups == 10
    assert result.permerror is False
    assert result.status == "warn"
    assert any("close to the 10 DNS lookup limit" in i.title for i in result.issues)


async def test_spf_include_loop_detected() -> None:
    resolver = FakeDNSResolver(
        {
            "a.example": {"TXT": ["v=spf1 include:b.example ~all"]},
            "b.example": {"TXT": ["v=spf1 include:a.example ~all"]},
        }
    )
    result = await check_spf("a.example", resolver)
    assert result.status == "fail"
    assert result.loop_detected is True
    assert result.permerror is True
    assert result.loop_chain == ("a.example", "b.example", "a.example")


async def test_spf_void_lookups_over_two_fails() -> None:
    resolver = FakeDNSResolver(
        {
            "voids.example": {
                "TXT": ["v=spf1 a:missing1.example a:missing2.example exists:missing3.example ~all"]
            }
        }
    )
    result = await check_spf("voids.example", resolver)
    assert result.status == "fail"
    assert result.dns_lookups == 3
    assert result.void_lookups == 3
    assert result.permerror is True
    assert any("2 void lookup limit" in i.title for i in result.issues)


async def test_spf_include_without_spf_is_permerror() -> None:
    resolver = FakeDNSResolver(
        {
            "brokeninc.example": {"TXT": ["v=spf1 include:nospf.example ~all"]},
            "nospf.example": {"TXT": ["not-an-spf-record"]},
        }
    )
    result = await check_spf("brokeninc.example", resolver)
    assert result.status == "fail"
    assert result.permerror is True
    assert any("missing or invalid" in i.title.lower() for i in result.issues)


async def test_spf_per_mx_10_host_limit_is_permerror() -> None:
    mx_entries = [(i, f"mx{i}.many.example") for i in range(1, 12)]
    zones: dict[str, dict[str, object]] = {
        "many.example": {
            "TXT": ["v=spf1 mx -all"],
            "MX": mx_entries,
        }
    }
    for i in range(1, 12):
        zones[f"mx{i}.many.example"] = {"A": [f"93.184.216.{i}"]}

    resolver = FakeDNSResolver(zones)  # type: ignore[arg-type]
    result = await check_spf("many.example", resolver)
    assert result.status == "fail"
    assert result.dns_lookups == 1  # mx itself counts as 1 global lookup
    assert result.per_mx_limit_exceeded is True
    assert result.permerror is True


async def test_spf_redirect_ignored_when_all_present_and_dead_terms_flagged() -> None:
    resolver = FakeDNSResolver(
        {
            "dead.example": {
                "TXT": [
                    "v=spf1 ip4:93.184.216.34 ~all include:never-reached.example "
                    "redirect=ignored.example"
                ]
            }
        }
    )
    result = await check_spf("dead.example", resolver)
    assert result.status == "warn"
    assert result.dns_lookups == 0
    assert result.redirect_ignored is True
    assert result.dead_terms == ("include:never-reached.example",)
    # Neither dead term nor ignored redirect should be queried
    assert resolver.query_log == [("dead.example", "TXT")]


async def test_spf_macros_counted_without_literal_dns_query() -> None:
    resolver = FakeDNSResolver(
        {
            "macro.example": {
                "TXT": ["v=spf1 exists:%{i}._spf.macro.example include:%{d}.spf.macro.example -all"]
            }
        }
    )
    result = await check_spf("macro.example", resolver)
    assert result.status == "pass"
    assert result.has_macros is True
    assert result.dns_lookups == 2
    assert result.void_lookups == 0
    # Only the root TXT query was made — never a literal query with '%{...}'
    assert resolver.query_log == [("macro.example", "TXT")]


@pytest.mark.parametrize(
    ("record", "expected_status", "expected_snippet"),
    [
        ("v=spf1 ip4:93.184.216.34 +all", "fail", "+all"),
        ("v=spf1 ip4:93.184.216.34 ?all", "warn", "?all"),
        ("v=spf1 ip4:93.184.216.34", "warn", "no 'all'"),
        ("v=spf1 ptr -all", "warn", "deprecated 'ptr'"),
    ],
)
async def test_spf_endings_and_ptr(
    record: str,
    expected_status: str,
    expected_snippet: str,
) -> None:
    resolver = FakeDNSResolver({"case.example": {"TXT": [record]}})
    result = await check_spf("case.example", resolver)
    assert result.status == expected_status
    assert any(expected_snippet in i.title.lower() for i in result.issues)


async def test_spf_missing_provider_includes_skips_shopify_and_klaviyo() -> None:
    resolver = FakeDNSResolver(
        {
            "store.example": {"TXT": ["v=spf1 ip4:93.184.216.34 ~all"]},
        }
    )
    result = await check_spf(
        "store.example",
        resolver,
        detected_providers=[
            PROVIDERS_BY_ID["google_workspace"],
            PROVIDERS_BY_ID["shopify"],
            PROVIDERS_BY_ID["klaviyo"],
        ],
    )
    assert result.status == "warn"
    # Only Google Workspace should be flagged as missing a root SPF include
    assert [(p.id, inc) for p, inc in result.missing_provider_includes] == [
        ("google_workspace", "_spf.google.com")
    ]


async def test_spf_recognizes_legacy_shopify_include() -> None:
    resolver = FakeDNSResolver(
        {
            "shop.example": {"TXT": ["v=spf1 include:shops.shopify.com ~all"]},
            "shops.shopify.com": {"TXT": ["v=spf1 ip4:23.227.38.65 ~all"]},
        }
    )
    result = await check_spf("shop.example", resolver)
    assert result.status == "pass"
    assert [p.id for p in result.detected_providers] == ["shopify"]
    assert any("Legacy Shopify" in i.title for i in result.issues)


async def test_spf_timeout_returns_error() -> None:
    resolver = FakeDNSResolver({"slow.example": {"TXT": FAKE_TIMEOUT}})
    result = await check_spf("slow.example", resolver)
    assert result.status == "error"


async def test_evaluate_spf_for_ip_pass_softfail_and_macro_exists() -> None:
    resolver = FakeDNSResolver(
        {
            "sender.example": {
                "TXT": ["v=spf1 include:_spf.mail.example exists:%{i}.allow.example ~all"]
            },
            "_spf.mail.example": {"TXT": ["v=spf1 ip4:93.184.216.0/24 ~all"]},
            "198.51.100.7.allow.example": {"A": ["127.0.0.2"]},
        }
    )

    r_pass = await evaluate_spf_for_ip(
        "sender.example", "93.184.216.34", "info@sender.example", resolver
    )
    assert r_pass.result == "pass"
    assert r_pass.dns_lookups == 1

    r_macro = await evaluate_spf_for_ip(
        "sender.example", "198.51.100.7", "info@sender.example", resolver
    )
    assert r_macro.result == "pass"
    assert r_macro.dns_lookups == 2

    r_soft = await evaluate_spf_for_ip(
        "sender.example", "203.0.113.99", "info@sender.example", resolver
    )
    assert r_soft.result == "softfail"
    assert r_soft.void_lookups == 1


async def test_spf_redirect_followed_and_missing_redirect_is_permerror() -> None:
    resolver = FakeDNSResolver(
        {
            "alias.example": {"TXT": ["v=spf1 redirect=main.example"]},
            "main.example": {"TXT": ["v=spf1 ip4:93.184.216.34 -all"]},
            "badredir.example": {"TXT": ["v=spf1 redirect=empty.example"]},
            "empty.example": {"TXT": ["hello=world"]},
        }
    )
    ok = await check_spf("alias.example", resolver)
    assert ok.status == "pass"
    assert ok.dns_lookups == 1
    assert ok.all_qualifier == "-"
    assert ok.redirect_ignored is False

    bad = await check_spf("badredir.example", resolver)
    assert bad.status == "fail"
    assert bad.permerror is True
