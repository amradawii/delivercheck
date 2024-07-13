"""Hardening tests: timeouts, isolated check failures, partial reports, and accessibility."""

from __future__ import annotations

import asyncio
import base64
import datetime
import re
import socket
import ssl
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import dkim
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Envelope, Session
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.checks.domain import run_domain_check
from app.checks.extras import PolicyFetchResult
from app.config import Settings
from app.dns.resolver import DNSResolver, DNSResponse, FakeDNSResolver
from app.inbox.analyze import analyze_received_email
from app.main import create_app
from app.smtp.receive_test import run_receive_test
from app.smtp.send_test import run_send_test


def _make_rsa_dkim_keypair() -> tuple[bytes, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    return priv_pem, f"v=DKIM1; k=rsa; p={pub_b64}"


class _SabotagedResolver:
    """Wraps a FakeDNSResolver to inject hangs or crashes on specific qnames/rtypes."""

    def __init__(
        self,
        base: DNSResolver,
        *,
        hang_match: str | None = None,
        crash_match: str | None = None,
    ) -> None:
        self._base = base
        self._hang_match = hang_match
        self._crash_match = crash_match

    async def query(self, name: str, rdtype: str) -> DNSResponse:
        key = f"{name.lower()}:{rdtype.upper()}"
        if self._hang_match and self._hang_match in key:
            await asyncio.sleep(5.0)
        if self._crash_match and self._crash_match in key:
            raise RuntimeError(f"Simulated DNS crash on {key}")
        return await self._base.query(name, rdtype)


def _healthy_zone(dkim_txt: str) -> FakeDNSResolver:
    return FakeDNSResolver(
        {
            "stablegoods.com": {
                "NS": ["maya.ns.cloudflare.com"],
                "MX": [(1, "smtp.google.com")],
                "TXT": ["v=spf1 include:_spf.google.com ~all"],
            },
            "_spf.google.com": {"TXT": ["v=spf1 ip4:209.85.128.0/17 ~all"]},
            "smtp.google.com": {"A": ["142.250.27.26"]},
            "google._domainkey.stablegoods.com": {"TXT": [dkim_txt]},
            "_dmarc.stablegoods.com": {
                "TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@stablegoods.com"]
            },
        }
    )


async def test_slow_blocklists_check_never_breaks_rest_of_domain_report() -> None:
    _, dkim_txt = _make_rsa_dkim_keypair()
    resolver = _SabotagedResolver(_healthy_zone(dkim_txt), hang_match="spamhaus.org")

    report = await run_domain_check(
        "stablegoods.com",
        resolver,
        check_timeout_seconds=0.15,
    )

    assert report.mx.status == "pass"
    assert report.spf.status == "pass"
    assert report.dkim.status == "pass"
    assert report.dmarc.status == "pass"
    assert report.blocklists.status == "warn"
    assert any("timed out" in i.title.lower() for i in report.blocklists.issues)
    assert any(i.fix for i in report.blocklists.issues)


async def test_crashing_dmarc_and_extras_still_return_partial_domain_report() -> None:
    _, dkim_txt = _make_rsa_dkim_keypair()
    resolver = _SabotagedResolver(_healthy_zone(dkim_txt), crash_match="_dmarc.stablegoods.com")

    async def _crashing_policy(domain: str, res: DNSResolver) -> PolicyFetchResult:
        raise RuntimeError("Simulated HTTPS policy failure")

    report = await run_domain_check(
        "stablegoods.com",
        resolver,
        policy_fetcher=_crashing_policy,
        check_timeout_seconds=1.0,
    )

    assert report.mx.status == "pass"
    assert report.spf.status == "pass"
    assert report.dkim.status == "pass"
    assert report.dmarc.status == "error"
    assert any("could not complete" in i.title.lower() for i in report.dmarc.issues)
    assert all(f.title and f.summary for f in report.findings)


def test_streaming_ui_renders_partial_report_when_one_section_crashes() -> None:
    _, dkim_txt = _make_rsa_dkim_keypair()
    resolver = _SabotagedResolver(_healthy_zone(dkim_txt), crash_match="zen.spamhaus.org")
    app = create_app(
        settings=Settings(check_timeout_seconds=1.0, smtp_inbox_enabled=False),
        resolver=resolver,
        enable_smtp_inbox=False,
    )
    client = TestClient(app)

    start = client.post("/domain/check", data={"domain": "stablegoods.com"})
    assert start.status_code == 200
    m = re.search(r'data-domain-report-token="([^"]+)"', start.text)
    assert m is not None
    token = m.group(1)

    for sec in ("mx", "spf", "dkim", "dmarc", "blocklists", "extras", "summary"):
        resp = client.get(f"/domain/sections/{token}/{sec}")
        assert resp.status_code == 200, f"Section {sec} failed: {resp.status_code}"

    bl_html = client.get(f"/domain/sections/{token}/blocklists").text
    assert "Blocklist check could not complete" in bl_html
    assert "Fix:" in bl_html

    summary_html = client.get(f"/domain/sections/{token}/summary").text
    assert "stablegoods.com" in summary_html
    assert "MX records are valid" in summary_html


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _make_cert(tmp_dir: Path, names: list[str]) -> tuple[Path, Path, Path]:
    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Hardening Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_p = tmp_dir / "ca.pem"
    cert_p = tmp_dir / "srv.pem"
    key_p = tmp_dir / "srv.key"
    ca_p.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_p.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(
        srv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return ca_p, cert_p, key_p


class _GoodMXHandler:
    async def handle_RCPT(
        self, server: SMTP, session: Session, envelope: Envelope, address: str, rcpt_options: Any
    ) -> str:
        if address.lower() == "info@stablegoods.com":
            return "250 2.1.5 OK"
        return "550 5.1.1 Rejected"


@contextmanager
def _running_mx(cert: Path, key: Path) -> Iterator[int]:
    port = _free_port()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    controller = Controller(_GoodMXHandler(), hostname="127.0.0.1", port=port, tls_context=ctx)
    controller.start()
    try:
        yield port
    finally:
        controller.stop()


async def test_receive_test_isolates_slow_or_crashing_mx_host() -> None:
    base_resolver = FakeDNSResolver(
        {
            "stablegoods.com": {
                "MX": [(10, "mx1.stablegoods.com"), (20, "mx2.stablegoods.com")],
            },
            "mx1.stablegoods.com": {"A": ["127.0.0.1"]},
            "mx2.stablegoods.com": {"A": ["127.0.0.1"]},
            "1.0.0.127.in-addr.arpa": {"PTR": ["mx1.stablegoods.com"]},
        }
    )
    # mx2 DNS crashes, while mx1 stays healthy!
    resolver = _SabotagedResolver(base_resolver, crash_match="mx2.stablegoods.com:A")
    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _make_cert(Path(tmp), ["mx1.stablegoods.com"])
        with _running_mx(cert, key) as port:
            report = await run_receive_test(
                "info@stablegoods.com",
                resolver,
                port=port,
                cafile=str(ca),
                host_timeout=5.0,
                allow_private_for_tests=True,
            )

    assert len(report.hosts) == 2
    by_host = {h.mx_host: h for h in report.hosts}
    assert by_host["mx1.stablegoods.com"].reachable is True
    assert by_host["mx2.stablegoods.com"].reachable is False
    assert any(
        "could not complete" in i.title.lower() for i in by_host["mx2.stablegoods.com"].issues
    )


async def test_send_test_outer_timeout_never_leaks_credentials() -> None:
    base_resolver = FakeDNSResolver({"smtp.slowhost.com": {"A": ["127.0.0.1"]}})
    resolver = _SabotagedResolver(base_resolver, hang_match="smtp.slowhost.com:A")
    secret = "TopSecret-Timeout-Pass-42!"

    report = await run_send_test(
        from_email="info@stablegoods.com",
        smtp_host="smtp.slowhost.com",
        port=587,
        security_mode="starttls",
        username="info@stablegoods.com",
        password=secret,
        target_inbox_token="t-timeout1",
        target_inbox_address="t-timeout1@test.localhost",
        resolver=resolver,
        total_timeout=0.1,
        allow_private_for_tests=True,
    )

    assert report.ready_to_send is False
    assert "timed out" in report.verdict_summary.lower()
    assert secret not in repr(report)


async def test_email_analysis_completes_when_ptr_and_dmarc_hang() -> None:
    priv_pem, dkim_txt = _make_rsa_dkim_keypair()
    msg = EmailMessage()
    msg["From"] = "orders@stablegoods.com"
    msg["To"] = "t-abc@test.localhost"
    msg["Subject"] = "Partial resilience check"
    msg["Date"] = "Sat, 13 Jul 2024 12:00:00 +0000"
    msg["Message-ID"] = "<hardening-1@stablegoods.com>"
    msg.set_content("Body text.\n")
    raw = msg.as_bytes()
    sig = dkim.sign(
        raw,
        selector=b"google",
        domain=b"stablegoods.com",
        privkey=priv_pem,
        include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
    )

    resolver = _SabotagedResolver(
        _healthy_zone(dkim_txt),
        hang_match="in-addr.arpa",
        crash_match="_dmarc.stablegoods.com",
    )
    report = await analyze_received_email(
        sig + raw,
        peer_ip="209.85.220.41",
        mail_from="orders@stablegoods.com",
        helo_hostname="mail.google.com",
        tls_used=True,
        tls_version="TLSv1.3",
        tls_cipher=None,
        resolver=resolver,
        check_timeout=0.15,
    )

    # SPF and DKIM still verified even though PTR timed out and DMARC crashed!
    assert report.spf is not None and report.spf.result == "pass"
    assert len(report.dkim_signatures) == 1
    assert report.dkim_signatures[0].verified is True
    assert report.ptr_hostname is None


def test_accessibility_landmarks_labels_and_live_regions_across_tabs() -> None:
    app = create_app(
        settings=Settings(smtp_inbox_enabled=False),
        resolver=FakeDNSResolver({}),
        enable_smtp_inbox=False,
    )
    client = TestClient(app)

    for tab in ("domain", "server", "email"):
        resp = client.get(f"/?tab={tab}")
        assert resp.status_code == 200
        html = resp.text
        assert 'href="#main-content"' in html
        assert 'id="main-content"' in html
        assert 'id="sr-announcer"' in html
        assert 'aria-live="polite"' in html
        assert 'aria-current="page"' in html
        assert 'aria-label="Diagnostic tools"' in html

    # Invalid form input returns role="alert"
    bad = client.post("/domain/check", data={"domain": "not a valid domain!!!"})
    assert bad.status_code == 400
    assert 'role="alert"' in bad.text
