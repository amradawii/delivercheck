"""Tests for RFC 7489 DMARC parsing, PSL org domains, tag order, and external rua auth."""

from __future__ import annotations

from app.checks.dmarc import (
    check_dmarc,
    get_organizational_domain,
    parse_dmarc_record,
)
from app.dns.resolver import FAKE_TIMEOUT, FakeDNSResolver


def test_organizational_domain_uses_offline_psl() -> None:
    assert get_organizational_domain("mail.yourstore.com") == "yourstore.com"
    assert get_organizational_domain("shop.yourstore.co.uk") == "yourstore.co.uk"
    assert get_organizational_domain("sub.brand.com.eg") == "brand.com.eg"
    assert get_organizational_domain("yourstore.com") == "yourstore.com"


def test_parse_dmarc_enforces_tag_order_and_values() -> None:
    good = parse_dmarc_record(
        "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=r; pct=100; "
        "rua=mailto:dmarc@example.com!10m; fo=1:d"
    )
    assert good.syntax_errors == ()
    assert good.tag_order_errors == ()
    assert good.policy == "reject"
    assert good.subdomain_policy == "reject"
    assert good.adkim == "s"
    assert good.aspf == "r"
    assert good.pct == 100
    assert good.fo == ("1", "d")

    bad_order = parse_dmarc_record("v=DMARC1; rua=mailto:dmarc@example.com; p=reject")
    assert len(bad_order.tag_order_errors) == 1
    assert "second tag" in bad_order.tag_order_errors[0]

    bad_vals = parse_dmarc_record("v=DMARC1; p=block; pct=150; adkim=x; fo=9")
    assert len(bad_vals.syntax_errors) == 4


async def test_dmarc_missing_suggests_starter_record() -> None:
    resolver = FakeDNSResolver({})
    result = await check_dmarc("yourstore.com", resolver)
    assert result.status == "fail"
    assert result.bimi_eligible is False
    assert result.suggested_record == (
        "v=DMARC1; p=none; rua=mailto:dmarc@yourstore.com; adkim=r; aspf=r"
    )


async def test_dmarc_multiple_records_fail() -> None:
    resolver = FakeDNSResolver(
        {
            "_dmarc.dup.example": {
                "TXT": [
                    "v=DMARC1; p=none; rua=mailto:a@dup.example",
                    "v=DMARC1; p=reject; rua=mailto:b@dup.example",
                ]
            }
        }
    )
    result = await check_dmarc("dup.example", resolver)
    assert result.status == "fail"
    assert len(result.all_records) == 2
    assert any("Multiple DMARC records" in i.title for i in result.issues)


async def test_dmarc_valid_reject_with_size_modifier_and_same_org_co_uk() -> None:
    resolver = FakeDNSResolver(
        {
            "_dmarc.yourstore.co.uk": {
                "TXT": [
                    "v=DMARC1; p=reject; rua=mailto:dmarc@reports.yourstore.co.uk!10m; "
                    "adkim=r; aspf=r"
                ]
            }
        }
    )
    result = await check_dmarc("yourstore.co.uk", resolver)
    assert result.status == "pass"
    assert result.bimi_eligible is True
    assert len(result.report_uris) == 1
    uri = result.report_uris[0]
    assert uri.is_valid is True
    assert uri.domain == "reports.yourstore.co.uk"
    assert uri.size_limit == "10m"
    # Same organizational domain (.co.uk via PSL) — no external _report._dmarc lookup needed
    assert uri.is_external is False
    assert resolver.query_log == [("_dmarc.yourstore.co.uk", "TXT")]


async def test_dmarc_external_rua_authorized_and_unauthorized() -> None:
    resolver_auth = FakeDNSResolver(
        {
            "_dmarc.yourstore.com": {
                "TXT": ["v=DMARC1; p=quarantine; rua=mailto:agg@dmarc-vendor.net!5m"]
            },
            "yourstore.com._report._dmarc.dmarc-vendor.net": {
                "TXT": ["v=DMARC1"],
            },
        }
    )
    res_auth = await check_dmarc("yourstore.com", resolver_auth)
    assert res_auth.status == "pass"
    assert res_auth.bimi_eligible is True
    assert res_auth.report_uris[0].is_external is True
    assert res_auth.report_uris[0].external_authorized is True

    resolver_unauth = FakeDNSResolver(
        {
            "_dmarc.yourstore.com": {
                "TXT": ["v=DMARC1; p=quarantine; rua=mailto:agg@other-vendor.net"]
            },
        }
    )
    res_unauth = await check_dmarc("yourstore.com", resolver_unauth)
    assert res_unauth.status == "warn"
    assert res_unauth.report_uris[0].is_external is True
    assert res_unauth.report_uris[0].external_authorized is False
    assert any("not authorized" in i.title for i in res_unauth.issues)


async def test_dmarc_policy_none_pct_partial_and_sp_none() -> None:
    resolver = FakeDNSResolver(
        {
            "_dmarc.monitor.example": {"TXT": ["v=DMARC1; p=none"]},
            "_dmarc.partial.example": {
                "TXT": ["v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:dmarc@partial.example"]
            },
        }
    )
    res_none = await check_dmarc("monitor.example", resolver)
    assert res_none.status == "warn"
    assert res_none.bimi_eligible is False
    assert any("p=none" in i.title for i in res_none.issues)
    assert any("rua=" in i.title for i in res_none.issues)

    res_partial = await check_dmarc("partial.example", resolver)
    assert res_partial.status == "warn"
    assert res_partial.bimi_eligible is False
    assert any("50%" in i.title for i in res_partial.issues)
    assert any("sp=none" in i.title for i in res_partial.issues)


async def test_dmarc_subdomain_falls_back_to_organizational_domain() -> None:
    resolver = FakeDNSResolver(
        {
            "_dmarc.yourstore.co.uk": {
                "TXT": ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@yourstore.co.uk"]
            }
        }
    )
    result = await check_dmarc("mail.yourstore.co.uk", resolver)
    assert result.status == "pass"
    assert result.inherited_from_org_domain is True
    assert result.record_domain == "yourstore.co.uk"
    assert result.effective_policy == "quarantine"


async def test_dmarc_timeout_returns_error() -> None:
    resolver = FakeDNSResolver({"_dmarc.slow.example": {"TXT": FAKE_TIMEOUT}})
    result = await check_dmarc("slow.example", resolver)
    assert result.status == "error"
