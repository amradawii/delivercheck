"""Tests for the in-memory test inbox receiver, .eml DKIM/SPF/DMARC analysis, and smtplib flow."""

from __future__ import annotations

import base64
import re
import smtplib
import socket
from email.message import EmailMessage

import dkim
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi.testclient import TestClient

from app.config import Settings
from app.dns.resolver import FakeDNSResolver
from app.inbox.analyze import analyze_received_email, render_email_report_text
from app.inbox.server import MAX_INBOX_MESSAGE_BYTES
from app.inbox.store import InboxStore
from app.main import create_app


def _make_rsa_dkim_pair() -> tuple[bytes, str]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    return priv_pem, f"v=DKIM1; k=rsa; p={pub_b64}"


def _make_ed25519_dkim_pair() -> tuple[bytes, str]:
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_b64 = base64.b64encode(priv_raw)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    return priv_b64, f"v=DKIM1; k=ed25519; p={pub_b64}"


def _build_signed_eml(
    *,
    from_addr: str = "info@yourstore.com",
    to_addr: str = "t-abc12345@test.localhost",
    subject: str = "Order confirmation",
    body_text: str | None = "Hello from YourStore.",
    body_html: str | None = "<p>Hello from YourStore.</p>",
    include_unsubscribe: bool = True,
    dkim_domain: bytes = b"yourstore.com",
    dkim_selector: bytes = b"testkey",
    priv_key: bytes | None = None,
    algorithm: bytes = b"rsa-sha256",
    add_attachment: bool = False,
) -> bytes:
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = "Fri, 28 Jun 2024 16:00:00 +0000"
    msg["Message-ID"] = "<test-123@yourstore.com>"
    if include_unsubscribe:
        msg["List-Unsubscribe"] = "<https://yourstore.com/unsubscribe/abc>"
        msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"

    if body_text is not None and body_html is not None:
        msg.set_content(body_text)
        msg.add_alternative(body_html, subtype="html")
    elif body_html is not None:
        msg.set_content(body_html, subtype="html")
    else:
        msg.set_content(body_text or "Plain text")

    if add_attachment:
        msg.add_attachment(
            b"secret-pdf-bytes", maintype="application", subtype="pdf", filename="a.pdf"
        )

    raw = msg.as_bytes()
    if priv_key is not None:
        sig = dkim.sign(
            raw,
            selector=dkim_selector,
            domain=dkim_domain,
            privkey=priv_key,
            include_headers=[b"from", b"to", b"subject", b"date", b"message-id"],
            signature_algorithm=algorithm,
        )
        raw = sig + raw
    return raw


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_inbox_store_expiry_and_recipient_matching() -> None:
    now = [1000.0]
    store = InboxStore(domain="test.delivercheck.example", ttl_seconds=900.0, clock=lambda: now[0])
    slot = store.create_slot()
    assert slot.address.endswith("@test.delivercheck.example")
    assert store.match_recipient(slot.address) is slot
    assert store.match_recipient("someone@other-domain.com") is None
    assert store.match_recipient("t-unknown@test.delivercheck.example") is None

    # Advance past 15-minute expiry
    now[0] += 901.0
    assert store.match_recipient(slot.address) is None
    assert store.get(slot.token) is None


async def test_analyze_eml_passing_rsa_dkim_spf_dmarc_tls_ptr() -> None:
    priv_pem, dkim_txt = _make_rsa_dkim_pair()
    eml = _build_signed_eml(priv_key=priv_pem, add_attachment=True)
    resolver = FakeDNSResolver(
        {
            "yourstore.com": {"TXT": ["v=spf1 ip4:93.184.216.34 -all"]},
            "testkey._domainkey.yourstore.com": {"TXT": [dkim_txt]},
            "_dmarc.yourstore.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@yourstore.com"]},
            "34.216.184.93.in-addr.arpa": {"PTR": ["mail.yourstore.com"]},
            "mail.yourstore.com": {"A": ["93.184.216.34"]},
        }
    )

    report = await analyze_received_email(
        eml,
        peer_ip="93.184.216.34",
        mail_from="info@yourstore.com",
        helo_hostname="mail.yourstore.com",
        tls_used=True,
        tls_version="TLSv1.3",
        tls_cipher="TLS_AES_256_GCM_SHA384",
        resolver=resolver,
    )
    assert report.verdict_status == "pass"
    assert report.spf is not None and report.spf.result == "pass"
    assert report.spf_aligned_relaxed is True
    assert len(report.dkim_signatures) == 1
    assert report.dkim_signatures[0].verified is True
    assert report.dkim_signatures[0].aligned_strict is True
    assert report.dmarc_result == "pass"
    assert report.fcrdns_valid is True
    assert report.one_click_unsubscribe_valid is True
    assert report.attachment_count == 1
    # Ensure attachment payload is never kept on the report object
    assert "secret-pdf-bytes" not in repr(report)

    text = render_email_report_text(report)
    assert "SPF=pass" in text
    assert "DMARC=pass" in text


async def test_analyze_eml_body_modified_after_signing_fails_dkim() -> None:
    priv_pem, dkim_txt = _make_rsa_dkim_pair()
    eml = _build_signed_eml(priv_key=priv_pem)
    tampered = eml.replace(b"Hello from YourStore.", b"Tampered message body!")
    resolver = FakeDNSResolver(
        {
            "yourstore.com": {"TXT": ["v=spf1 ip4:93.184.216.34 -all"]},
            "testkey._domainkey.yourstore.com": {"TXT": [dkim_txt]},
            "_dmarc.yourstore.com": {"TXT": ["v=DMARC1; p=reject"]},
            "34.216.184.93.in-addr.arpa": {"PTR": ["mail.yourstore.com"]},
            "mail.yourstore.com": {"A": ["93.184.216.34"]},
        }
    )

    report = await analyze_received_email(
        tampered,
        peer_ip="93.184.216.34",
        mail_from="info@yourstore.com",
        helo_hostname="mail.yourstore.com",
        tls_used=True,
        tls_version="TLSv1.3",
        tls_cipher=None,
        resolver=resolver,
    )
    assert report.dkim_signatures[0].verified is False
    assert any("DKIM signature failed" in i.title for i in report.issues)


async def test_analyze_eml_misaligned_from_fails_dmarc() -> None:
    priv_pem, dkim_txt = _make_rsa_dkim_pair()
    eml = _build_signed_eml(
        from_addr="info@yourstore.com",
        dkim_domain=b"other-sender.net",
        priv_key=priv_pem,
        include_unsubscribe=False,
        body_text=None,
        body_html="<p>HTML only</p>",
    )
    resolver = FakeDNSResolver(
        {
            "other-sender.net": {"TXT": ["v=spf1 ip4:93.184.216.34 -all"]},
            "testkey._domainkey.other-sender.net": {"TXT": [dkim_txt]},
            "_dmarc.yourstore.com": {"TXT": ["v=DMARC1; p=reject"]},
        }
    )

    report = await analyze_received_email(
        eml,
        peer_ip="93.184.216.34",
        mail_from="bounce@other-sender.net",
        helo_hostname="mail.other-sender.net",
        tls_used=False,
        tls_version=None,
        tls_cipher=None,
        resolver=resolver,
    )
    assert report.spf is not None and report.spf.result == "pass"
    assert report.spf_aligned_relaxed is False
    assert report.dkim_signatures[0].verified is True
    assert report.dkim_signatures[0].aligned_relaxed is False
    assert report.dmarc_result == "fail"
    assert report.one_click_unsubscribe_valid is False
    assert report.has_text_html is True and report.has_text_plain is False
    assert any("DMARC failed" in i.title for i in report.issues)
    assert any("no plain-text part" in i.title.lower() for i in report.issues)


async def test_analyze_eml_ed25519_signature_verifies() -> None:
    priv_b64, dkim_txt = _make_ed25519_dkim_pair()
    eml = _build_signed_eml(
        priv_key=priv_b64,
        dkim_selector=b"ed25519sel",
        algorithm=b"ed25519-sha256",
    )
    resolver = FakeDNSResolver(
        {
            "yourstore.com": {"TXT": ["v=spf1 ip4:93.184.216.34 -all"]},
            "ed25519sel._domainkey.yourstore.com": {"TXT": [dkim_txt]},
            "_dmarc.yourstore.com": {"TXT": ["v=DMARC1; p=reject"]},
            "34.216.184.93.in-addr.arpa": {"PTR": ["mail.yourstore.com"]},
            "mail.yourstore.com": {"A": ["93.184.216.34"]},
        }
    )
    report = await analyze_received_email(
        eml,
        peer_ip="93.184.216.34",
        mail_from="info@yourstore.com",
        helo_hostname="mail.yourstore.com",
        tls_used=True,
        tls_version="TLSv1.3",
        tls_cipher=None,
        resolver=resolver,
    )
    assert report.dkim_signatures[0].verified is True
    assert report.dkim_signatures[0].algorithm == "ed25519-sha256"
    assert report.dmarc_result == "pass"


def test_integration_smtplib_to_local_inbox_and_reject_rules() -> None:
    port = _free_port()
    priv_pem, dkim_txt = _make_rsa_dkim_pair()
    resolver = FakeDNSResolver(
        {
            "yourstore.com": {"TXT": ["v=spf1 ip4:127.0.0.1 ~all"]},
            "testkey._domainkey.yourstore.com": {"TXT": [dkim_txt]},
            "_dmarc.yourstore.com": {"TXT": ["v=DMARC1; p=quarantine"]},
            "1.0.0.127.in-addr.arpa": {"PTR": ["mail.yourstore.com"]},
            "mail.yourstore.com": {"A": ["127.0.0.1"]},
        }
    )
    settings = Settings(
        smtp_inbox_enabled=True,
        smtp_inbox_host="127.0.0.1",
        smtp_inbox_port=port,
        test_inbox_domain="test.localhost",
    )
    app = create_app(settings=settings, resolver=resolver, enable_smtp_inbox=True)

    with TestClient(app) as client:
        # Create unique address via HTTP
        created = client.post("/inbox/new")
        assert created.status_code == 200
        match = re.search(r'data-inbox-token="([^"]+)"', created.text)
        assert match is not None
        token = match.group(1)
        address = f"{token}@test.localhost"

        # Polling before sending shows waiting state
        waiting = client.get(f"/inbox/poll/{token}")
        assert waiting.status_code == 200
        assert "Waiting for your email" in waiting.text

        # 1) Relay to third-party domain must be rejected with 550
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as smtp:
            smtp.ehlo("mail.yourstore.com")
            with pytest.raises(smtplib.SMTPRecipientsRefused):
                smtp.sendmail(
                    "info@yourstore.com", ["victim@example.com"], b"Subject: hi\r\n\r\nno"
                )

        # 2) Unknown test token must be rejected with 550
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as smtp:
            smtp.ehlo("mail.yourstore.com")
            with pytest.raises(smtplib.SMTPRecipientsRefused):
                smtp.sendmail(
                    "info@yourstore.com",
                    ["t-doesnotexist@test.localhost"],
                    b"Subject: hi\r\n\r\nno",
                )

        # 3) Oversized message (> 1 MB) must be rejected with 552
        oversized = b"From: info@yourstore.com\r\nSubject: big\r\n\r\n" + (
            b"A" * (MAX_INBOX_MESSAGE_BYTES + 1024)
        )
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as smtp:
            smtp.ehlo("mail.yourstore.com")
            with pytest.raises((smtplib.SMTPSenderRefused, smtplib.SMTPDataError)) as exc_info:
                smtp.sendmail("info@yourstore.com", [address], oversized)
            assert exc_info.value.smtp_code == 552

        # 4) Valid signed email to the active test address succeeds and appears on poll
        signed_eml = _build_signed_eml(to_addr=address, priv_key=priv_pem)
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as smtp:
            smtp.ehlo("mail.yourstore.com")
            smtp.sendmail("info@yourstore.com", [address], signed_eml)

        received = client.get(f"/inbox/poll/{token}")
        assert received.status_code == 200
        assert "Received test email" in received.text
        assert "DKIM signature passed and aligned" in received.text
        assert "DMARC passed" in received.text
        # Polling stops once received
        assert 'hx-trigger="every 3s"' not in received.text
