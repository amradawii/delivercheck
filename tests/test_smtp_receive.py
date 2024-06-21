"""Offline fake-SMTP server tests covering every receive-test scenario and SSRF refusal."""

from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Envelope, Session
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.dns.resolver import FakeDNSResolver
from app.limits import RateLimiter, RateLimitRule
from app.main import create_app
from app.smtp.receive_test import render_receive_report_text, run_receive_test


def _generate_ca_and_leaf_certs(
    tmp_dir: Path,
    *,
    dns_names: list[str],
    days_before: int = 1,
    days_after: int = 90,
) -> tuple[Path, Path, Path]:
    """Create a test CA cert and a leaf server cert+key signed by that CA."""
    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DeliverCheck Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=365))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=days_before))
        .not_valid_after(now + datetime.timedelta(days=days_after))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = tmp_dir / "ca.pem"
    cert_path = tmp_dir / "leaf.pem"
    key_path = tmp_dir / "leaf.key"

    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _ConfigurableHandler:
    def __init__(
        self,
        *,
        valid_mailbox: str = "info@yourstore.com",
        open_relay: bool = False,
        catch_all: bool = False,
        greylist: bool = False,
        unknown_user: bool = False,
        refuse_policy: bool = False,
    ) -> None:
        self.valid_mailbox = valid_mailbox.lower()
        self.open_relay = open_relay
        self.catch_all = catch_all
        self.greylist = greylist
        self.unknown_user = unknown_user
        self.refuse_policy = refuse_policy
        self.rcpt_sequence: list[str] = []
        self.data_called = False

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        addr = address.lower()
        self.rcpt_sequence.append(addr)
        if addr.endswith("@example.com"):
            return "250 OK relay accepted" if self.open_relay else "554 5.7.1 Relay access denied"
        if self.refuse_policy:
            return "550 5.7.1 Client host blocked by policy"
        if self.greylist:
            return "451 4.7.1 Greylisted, please try again later"
        if self.unknown_user:
            return "550 5.1.1 User unknown"
        if self.catch_all:
            return "250 OK"
        if addr == self.valid_mailbox:
            return "250 OK"
        return "550 5.1.1 No such user"

    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        self.data_called = True
        return "250 Message accepted"


class _SlowBannerController(Controller):
    def __init__(self, handler: Any, *, delay_seconds: float, **kwargs: Any) -> None:
        super().__init__(handler, **kwargs)
        self._delay_seconds = delay_seconds

    def factory(self) -> SMTP:
        delay = self._delay_seconds

        class _SlowSMTP(SMTP):
            async def _handle_client(self) -> None:
                await asyncio.sleep(delay)
                await super()._handle_client()

        return _SlowSMTP(self.handler, **self.SMTP_kwargs)


@contextmanager
def _fake_smtp_server(
    handler: _ConfigurableHandler,
    *,
    tls_cert: tuple[Path, Path] | None = None,
    banner_delay: float = 0.0,
) -> Iterator[int]:
    port = _free_loopback_port()
    kwargs: dict[str, Any] = {
        "hostname": "127.0.0.1",
        "port": port,
        "ident": "mx.yourstore.com ESMTP TestMTA",
    }
    if tls_cert is not None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(tls_cert[0]), keyfile=str(tls_cert[1]))
        kwargs["tls_context"] = ctx

    controller: Controller
    if banner_delay > 0:
        controller = _SlowBannerController(handler, delay_seconds=banner_delay, **kwargs)
    else:
        controller = Controller(handler, **kwargs)

    controller.start()
    try:
        yield port
    finally:
        controller.stop()


def _loopback_resolver(mx_host: str = "mx.yourstore.com") -> FakeDNSResolver:
    return FakeDNSResolver(
        {
            "yourstore.com": {"MX": [(10, mx_host)]},
            mx_host: {"A": ["127.0.0.1"]},
            "1.0.0.127.in-addr.arpa": {"PTR": [mx_host]},
        }
    )


async def test_receive_healthy_server_with_valid_starttls() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _generate_ca_and_leaf_certs(Path(tmp), dns_names=["mx.yourstore.com"])
        handler = _ConfigurableHandler()
        with _fake_smtp_server(handler, tls_cert=(cert, key)) as port:
            report = await run_receive_test(
                "info@yourstore.com",
                _loopback_resolver(),
                port=port,
                cafile=str(ca),
                allow_private_for_tests=True,
            )

    assert report.verdict == "ready"
    assert report.verdict_label == "Yes"
    assert handler.data_called is False
    host = report.hosts[0]
    assert host.reachable is True
    assert host.supports_starttls is True
    assert host.certificate is not None
    assert host.certificate.verified is True
    assert host.certificate.hostname_matches is True
    assert host.fcrdns_valid is True
    assert host.relay_status == "rejected"
    assert host.mailbox_status == "accepted"
    # Real mailbox probed BEFORE random catch-all probe
    non_relay_rcpts = [r for r in handler.rcpt_sequence if not r.endswith("@example.com")]
    assert non_relay_rcpts[0] == "info@yourstore.com"
    assert len(non_relay_rcpts) == 2

    text = render_receive_report_text(report)
    assert "Ready to receive: Yes" in text


async def test_receive_no_starttls_returns_partly() -> None:
    handler = _ConfigurableHandler()
    with _fake_smtp_server(handler, tls_cert=None) as port:
        report = await run_receive_test(
            "info@yourstore.com",
            _loopback_resolver(),
            port=port,
            allow_private_for_tests=True,
        )
    assert report.verdict == "partly"
    assert report.hosts[0].supports_starttls is False
    assert any("does not support STARTTLS" in i.title for i in report.issues)
    assert handler.data_called is False


async def test_receive_expired_cert_detected_via_readonly_probe() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _generate_ca_and_leaf_certs(
            Path(tmp),
            dns_names=["mx.yourstore.com"],
            days_before=40,
            days_after=-10,
        )
        handler = _ConfigurableHandler()
        with _fake_smtp_server(handler, tls_cert=(cert, key)) as port:
            report = await run_receive_test(
                "info@yourstore.com",
                _loopback_resolver(),
                port=port,
                cafile=str(ca),
                allow_private_for_tests=True,
            )
    assert report.verdict == "partly"
    cert_info = report.hosts[0].certificate
    assert cert_info is not None
    assert cert_info.verified is False
    assert cert_info.is_expired is True
    assert cert_info.days_until_expiry is not None and cert_info.days_until_expiry < 0
    assert any("expired" in i.title.lower() for i in report.issues)


async def test_receive_wrong_hostname_cert_detected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _generate_ca_and_leaf_certs(Path(tmp), dns_names=["wrong.example.net"])
        handler = _ConfigurableHandler()
        with _fake_smtp_server(handler, tls_cert=(cert, key)) as port:
            report = await run_receive_test(
                "info@yourstore.com",
                _loopback_resolver(),
                port=port,
                cafile=str(ca),
                allow_private_for_tests=True,
            )
    assert report.verdict == "partly"
    cert_info = report.hosts[0].certificate
    assert cert_info is not None
    assert cert_info.verified is False
    assert cert_info.hostname_matches is False
    assert any("hostname mismatch" in i.title.lower() for i in report.issues)


async def test_receive_open_relay_is_critical_fail_and_never_sends_data() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _generate_ca_and_leaf_certs(Path(tmp), dns_names=["mx.yourstore.com"])
        handler = _ConfigurableHandler(open_relay=True)
        with _fake_smtp_server(handler, tls_cert=(cert, key)) as port:
            report = await run_receive_test(
                "info@yourstore.com",
                _loopback_resolver(),
                port=port,
                cafile=str(ca),
                allow_private_for_tests=True,
            )
    assert report.verdict == "not_ready"
    assert report.hosts[0].relay_status == "open_relay"
    assert any("open relay" in i.title.lower() for i in report.issues)
    assert handler.data_called is False


@pytest.mark.parametrize(
    ("handler_kwargs", "expected_verdict", "expected_mailbox"),
    [
        ({"unknown_user": True}, "not_ready", "rejected"),
        ({"greylist": True}, "partly", "greylisted"),
        ({"catch_all": True}, "ready", "catch_all"),
        ({"refuse_policy": True}, "ready", "refused"),
    ],
)
async def test_receive_mailbox_behaviors(
    handler_kwargs: dict[str, Any],
    expected_verdict: str,
    expected_mailbox: str,
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _generate_ca_and_leaf_certs(Path(tmp), dns_names=["mx.yourstore.com"])
        handler = _ConfigurableHandler(**handler_kwargs)
        with _fake_smtp_server(handler, tls_cert=(cert, key)) as port:
            report = await run_receive_test(
                "info@yourstore.com",
                _loopback_resolver(),
                port=port,
                cafile=str(ca),
                allow_private_for_tests=True,
            )
    assert report.verdict == expected_verdict
    assert report.hosts[0].mailbox_status == expected_mailbox
    assert handler.data_called is False


async def test_receive_slow_banner_warns_about_tarpitting() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _generate_ca_and_leaf_certs(Path(tmp), dns_names=["mx.yourstore.com"])
        handler = _ConfigurableHandler()
        with _fake_smtp_server(handler, tls_cert=(cert, key), banner_delay=0.25) as port:
            report = await run_receive_test(
                "info@yourstore.com",
                _loopback_resolver(),
                port=port,
                cafile=str(ca),
                slow_banner_ms=150.0,
                allow_private_for_tests=True,
            )
    assert report.verdict == "partly"
    assert report.hosts[0].slow_banner is True
    assert any("Slow SMTP banner" in i.title for i in report.issues)


async def test_receive_connection_refused() -> None:
    closed_port = _free_loopback_port()
    report = await run_receive_test(
        "info@yourstore.com",
        _loopback_resolver(),
        port=closed_port,
        allow_private_for_tests=True,
    )
    assert report.verdict == "not_ready"
    assert report.hosts[0].reachable is False
    assert any("Connection refused" in i.title for i in report.issues)


async def test_receive_ssrf_blocks_private_loopback_ips() -> None:
    # allow_private_for_tests defaults to False -> MUST refuse 127.0.0.1 / 10.0.0.5
    resolver = FakeDNSResolver(
        {
            "internal.example": {"MX": [(10, "mx.internal.example")]},
            "mx.internal.example": {"A": ["10.0.0.5"]},
        }
    )
    report = await run_receive_test("info@internal.example", resolver)
    assert report.verdict == "not_ready"
    assert report.hosts[0].reachable is False
    assert "non-public" in (report.hosts[0].error or "").lower()


def test_server_receive_route_validation_and_rate_limit() -> None:
    resolver = FakeDNSResolver(
        {
            "internal.example": {"MX": [(10, "mx.internal.example")]},
            "mx.internal.example": {"A": ["10.0.0.5"]},
        }
    )
    limiter = RateLimiter({"server": RateLimitRule(max_requests=1, window_seconds=60.0)})
    client = TestClient(create_app(resolver=resolver, rate_limiter=limiter))

    bad = client.post("/server/receive", data={"email": "not-an-email"})
    assert bad.status_code == 400
    assert "full email address" in bad.text

    # Use a fresh app with a 1-request server limit to verify 200 then 429
    limiter2 = RateLimiter({"server": RateLimitRule(max_requests=1, window_seconds=60.0)})
    client2 = TestClient(create_app(resolver=resolver, rate_limiter=limiter2))
    first = client2.post("/server/receive", data={"email": "info@internal.example"})
    assert first.status_code == 200
    assert "Ready to receive: No" in first.text

    second = client2.post("/server/receive", data={"email": "info@internal.example"})
    assert second.status_code == 429
    assert "strictly rate-limited" in second.text
