"""Table tests for MX record inspection."""

from __future__ import annotations

from app.checks.mx import check_mx
from app.dns.resolver import FAKE_TIMEOUT, FakeDNSResolver


async def test_mx_valid_google_workspace_modern() -> None:
    resolver = FakeDNSResolver(
        {
            "yourstore.com": {"MX": [(1, "smtp.google.com")]},
            "smtp.google.com": {"A": ["142.250.27.26"], "AAAA": ["2a00:1450:400c:c0b::1a"]},
        }
    )
    result = await check_mx("yourstore.com", resolver)
    assert result.status == "pass"
    assert result.provider is not None
    assert result.provider.id == "google_workspace"
    assert result.suggested_smtp_host == "smtp.gmail.com"
    assert len(result.hosts) == 1
    assert result.hosts[0].resolves is True
    assert not any("legacy" in issue.title.lower() for issue in result.issues)


async def test_mx_legacy_google_workspace_adds_info_tip() -> None:
    resolver = FakeDNSResolver(
        {
            "legacy.example": {
                "MX": [
                    (1, "aspmx.l.google.com"),
                    (5, "alt1.aspmx.l.google.com"),
                ]
            },
            "aspmx.l.google.com": {"A": ["142.250.27.27"]},
            "alt1.aspmx.l.google.com": {"A": ["142.250.153.27"]},
        }
    )
    result = await check_mx("legacy.example", resolver)
    assert result.status == "pass"
    assert result.provider is not None
    assert result.provider.id == "google_workspace"
    assert any(issue.record_value == "1 smtp.google.com" for issue in result.issues)


async def test_mx_null_mx_valid_when_sole_record() -> None:
    resolver = FakeDNSResolver({"parked.example": {"MX": [(0, ".")]}})
    result = await check_mx("parked.example", resolver)
    assert result.status == "pass"
    assert result.is_null_mx is True
    assert any("Null MX" in issue.title for issue in result.issues)


async def test_mx_null_mx_invalid_with_other_records() -> None:
    resolver = FakeDNSResolver(
        {
            "badnull.example": {"MX": [(0, "."), (10, "mail.badnull.example")]},
            "mail.badnull.example": {"A": ["198.51.100.10"]},
        }
    )
    result = await check_mx("badnull.example", resolver)
    assert result.status == "fail"
    assert result.is_null_mx is False
    assert any("Invalid Null MX" in issue.title for issue in result.issues)


async def test_mx_missing_explains_rfc5321_a_fallback() -> None:
    resolver = FakeDNSResolver(
        {
            "webonly.example": {"A": ["198.51.100.55"]},
        }
    )
    result = await check_mx("webonly.example", resolver)
    assert result.status == "fail"
    assert result.implicit_fallback_ips == ("198.51.100.55",)
    assert "RFC 5321" in result.issues[0].detail
    assert "198.51.100.55" in result.issues[0].detail


async def test_mx_missing_with_no_a_or_aaaa() -> None:
    resolver = FakeDNSResolver({})
    result = await check_mx("empty.example", resolver)
    assert result.status == "fail"
    assert result.implicit_fallback_ips == ()
    assert "no A/AAAA" in result.issues[0].detail


async def test_mx_bare_ip_rejected() -> None:
    resolver = FakeDNSResolver({"bareip.example": {"MX": [(10, "198.51.100.25")]}})
    result = await check_mx("bareip.example", resolver)
    assert result.status == "fail"
    assert result.hosts[0].is_bare_ip is True
    assert any("bare IP" in issue.title for issue in result.issues)


async def test_mx_cname_target_rejected() -> None:
    resolver = FakeDNSResolver(
        {
            "cnamemx.example": {"MX": [(10, "mail.cnamemx.example")]},
            "mail.cnamemx.example": {"CNAME": "realmail.cnamemx.example"},
            "realmail.cnamemx.example": {"A": ["198.51.100.40"]},
        }
    )
    result = await check_mx("cnamemx.example", resolver)
    assert result.status == "fail"
    assert result.hosts[0].is_cname is True
    assert result.hosts[0].cname_target == "realmail.cnamemx.example"


async def test_mx_unresolvable_host_and_partial_warning() -> None:
    resolver = FakeDNSResolver(
        {
            "partial.example": {
                "MX": [
                    (10, "mx1.hostinger.com"),
                    (20, "dangling.partial.example"),
                ]
            },
            "mx1.hostinger.com": {"A": ["93.184.216.34"]},
        }
    )
    result = await check_mx("partial.example", resolver)
    assert result.status == "warn"
    assert result.provider is not None
    assert result.provider.id == "hostinger"
    assert any("no A or AAAA" in issue.title for issue in result.issues)


async def test_mx_private_ip_rejected() -> None:
    resolver = FakeDNSResolver(
        {
            "priv.example": {"MX": [(10, "mail.priv.example")]},
            "mail.priv.example": {"A": ["10.0.0.5"]},
        }
    )
    result = await check_mx("priv.example", resolver)
    assert result.status == "fail"
    assert result.hosts[0].has_non_public_ip is True


async def test_mx_timeout_returns_error() -> None:
    resolver = FakeDNSResolver({"slow.example": {"MX": FAKE_TIMEOUT}})
    result = await check_mx("slow.example", resolver)
    assert result.status == "error"
