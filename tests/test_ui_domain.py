"""Tests for the domain check UI routes, streaming sections, validation, and rate limits."""

from __future__ import annotations

import base64
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.checks.extras import PolicyFetchResult
from app.dns.resolver import DNSResolver, FakeDNSResolver
from app.limits import RateLimiter, RateLimitRule
from app.main import create_app


def _rsa_2048_b64() -> str:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def _build_test_app(*, max_domain_requests: int = 30) -> TestClient:
    key_2048 = _rsa_2048_b64()
    resolver = FakeDNSResolver(
        {
            "yourstore.com": {
                "MX": [(1, "smtp.google.com")],
                "NS": ["aria.ns.cloudflare.com", "noah.ns.cloudflare.com"],
                "TXT": [
                    "v=spf1 include:_spf.google.com ~all",
                    "klaviyo-site-verification=abc123",
                ],
            },
            "smtp.google.com": {"A": ["142.250.27.26"]},
            "_spf.google.com": {"TXT": ["v=spf1 ip4:142.250.0.0/15 ~all"]},
            "google._domainkey.yourstore.com": {"TXT": [f"v=DKIM1; k=rsa; p={key_2048}"]},
            "_dmarc.yourstore.com": {"TXT": ["v=DMARC1; p=none"]},
            "xn--bcher-kva.example": {
                "MX": [(1, "smtp.google.com")],
                "TXT": ["v=spf1 include:_spf.google.com ~all"],
            },
        }
    )

    async def fake_fetcher(domain: str, res: DNSResolver) -> PolicyFetchResult:
        return PolicyFetchResult(ok=False, error="not found")

    limiter = RateLimiter(
        {"domain": RateLimitRule(max_requests=max_domain_requests, window_seconds=60.0)}
    )
    app = create_app(resolver=resolver, rate_limiter=limiter, policy_fetcher=fake_fetcher)
    return TestClient(app)


def test_home_page_has_tabs_why_section_and_how_delivery_works() -> None:
    client = _build_test_app()
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text
    assert "Check a domain" in html
    assert "Test a mail server" in html
    assert "Send a test email" in html
    assert "Why DeliverCheck?" in html
    assert "How email delivery works" in html
    # Zero competitor names anywhere in the page
    lower = html.lower()
    for banned in ("mxtoolbox", "mail-tester", "dmarcian", "easydmarc", "mailgenius"):
        assert banned not in lower

    # Other two tabs render cleanly
    assert client.get("/?tab=server").status_code == 200
    assert client.get("/?tab=email").status_code == 200


def test_domain_check_invalid_inputs_return_helpful_400() -> None:
    client = _build_test_app()

    # Empty input
    r_empty = client.post("/domain/check", data={"domain": "   "})
    assert r_empty.status_code == 400
    assert "Enter a domain name" in r_empty.text

    # Full URL pasted
    r_url = client.post("/domain/check", data={"domain": "https://www.yourstore.com/cart"})
    assert r_url.status_code == 400
    assert "yourstore.com" in r_url.text
    assert 'data-fill-domain="yourstore.com"' in r_url.text

    # Email address pasted
    r_email = client.post("/domain/check", data={"domain": "info@yourstore.com"})
    assert r_email.status_code == 400
    assert "email address" in r_email.text
    assert "yourstore.com" in r_email.text

    # Bare IP
    r_ip = client.post("/domain/check", data={"domain": "93.184.216.34"})
    assert r_ip.status_code == 400
    assert "not an IP address" in r_ip.text


def test_domain_check_streams_all_sections_and_plain_text_report() -> None:
    client = _build_test_app()
    start = client.post("/domain/check", data={"domain": "  YourStore.COM  "})
    assert start.status_code == 200
    match = re.search(r'data-domain-report-token="([^"]+)"', start.text)
    assert match is not None
    token = match.group(1)

    for section in ("summary", "mx", "spf", "dkim", "dmarc", "blocklists", "extras"):
        sec_resp = client.get(f"/domain/sections/{token}/{section}")
        assert sec_resp.status_code == 200, f"Section {section} failed"

    summary = client.get(f"/domain/sections/{token}/summary").text
    assert "Google Workspace" in summary
    assert "Klaviyo" in summary
    assert "Cloudflare" in summary
    assert "Copy report" in summary
    assert "Gmail &amp; Yahoo 2024 sender requirements" in summary

    dmarc = client.get(f"/domain/sections/{token}/dmarc").text
    assert "Suggested DMARC record" in dmarc
    assert "data-copy-text=" in dmarc
    assert "Cloudflare DNS guide" in dmarc

    plain = client.get(f"/domain/report/{token}.txt")
    assert plain.status_code == 200
    assert "DeliverCheck Domain Report: yourstore.com" in plain.text


def test_domain_check_accepts_idn_punycode() -> None:
    client = _build_test_app()
    start = client.post("/domain/check", data={"domain": "bücher.example"})
    assert start.status_code == 200
    match = re.search(r'data-domain-report-token="([^"]+)"', start.text)
    assert match is not None
    mx_resp = client.get(f"/domain/sections/{match.group(1)}/mx")
    assert mx_resp.status_code == 200
    assert "smtp.google.com" in mx_resp.text


def test_domain_check_rate_limit_enforced() -> None:
    client = _build_test_app(max_domain_requests=2)
    assert client.post("/domain/check", data={"domain": "yourstore.com"}).status_code == 200
    assert client.post("/domain/check", data={"domain": "yourstore.com"}).status_code == 200
    limited = client.post("/domain/check", data={"domain": "yourstore.com"})
    assert limited.status_code == 429
    assert "Rate limit reached" in limited.text


def test_expired_or_unknown_section_token_returns_404() -> None:
    client = _build_test_app()
    resp = client.get("/domain/sections/nonexistent-token/summary")
    assert resp.status_code == 404
    assert "expired" in resp.text.lower()
