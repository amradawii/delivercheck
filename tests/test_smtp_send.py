"""Tests for SMTP submission (ready-to-send) login, TLS modes, cert refusal, and masking."""

from __future__ import annotations

import base64
import datetime
import logging
import socket
import ssl
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, AuthResult, Envelope, LoginPassword, Session
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.config import Settings
from app.dns.resolver import FakeDNSResolver
from app.inbox.analyze import analyze_received_email
from app.inbox.store import InboxStore
from app.limits import RateLimiter, RateLimitRule
from app.main import create_app
from app.smtp.send_test import render_send_report_text, run_send_test


def _make_ca_and_cert(
    tmp_dir: Path,
    *,
    dns_names: list[str],
    days_after: int = 90,
) -> tuple[Path, Path, Path]:
    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DeliverCheck Send Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=30))
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
        .not_valid_before(now - datetime.timedelta(days=1))
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


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _SubmissionHandler:
    def __init__(
        self, inbox_store: InboxStore | None = None, resolver: FakeDNSResolver | None = None
    ) -> None:
        self.received_messages: list[bytes] = []
        self._store = inbox_store
        self._resolver = resolver

    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        raw = bytes(envelope.original_content or b"")
        self.received_messages.append(raw)
        if self._store is not None and self._resolver is not None and envelope.rcpt_tos:
            slot = self._store.match_recipient(envelope.rcpt_tos[0])
            if slot is not None:
                analysis = await analyze_received_email(
                    raw,
                    peer_ip="93.184.216.34",
                    mail_from=str(envelope.mail_from or ""),
                    helo_hostname="smtp.yourstore.com",
                    tls_used=True,
                    tls_version="TLSv1.3",
                    tls_cipher=None,
                    resolver=self._resolver,
                )
                self._store.record_analysis(slot.token, analysis)
        return "250 2.0.0 Queued"


class _SubmissionController(Controller):
    def __init__(
        self, handler: Any, *, implicit_ssl_ctx: ssl.SSLContext | None = None, **kwargs: Any
    ) -> None:
        super().__init__(handler, **kwargs)
        self._implicit_ssl_ctx = implicit_ssl_ctx

    def _create_server(self) -> Any:
        return self.loop.create_server(
            self._factory_invoker,
            host=self.hostname,
            port=self.port,
            ssl=self._implicit_ssl_ctx,
        )


@contextmanager
def _fake_submission_server(
    handler: _SubmissionHandler,
    *,
    expected_user: str = "info@yourstore.com",
    expected_pass: str = "SuperSecret-AppPass-999!",
    tls_cert: tuple[Path, Path] | None = None,
    implicit_tls: bool = False,
    custom_fail_message: str | None = None,
) -> Iterator[tuple[int, list[str]]]:
    port = _free_port()
    auth_attempts: list[str] = []

    def _authenticator(
        server: SMTP,
        session: Session,
        envelope: Envelope,
        mechanism: str,
        auth_data: Any,
    ) -> AuthResult:
        auth_attempts.append(mechanism)
        if isinstance(auth_data, LoginPassword):
            u = auth_data.login.decode("utf-8", errors="ignore")
            p = auth_data.password.decode("utf-8", errors="ignore")
            if u == expected_user and p == expected_pass:
                return AuthResult(success=True)
        return AuthResult(
            success=False,
            handled=False,
            message=custom_fail_message or "535 5.7.8 Authentication credentials invalid",
        )

    kwargs: dict[str, Any] = {
        "hostname": "127.0.0.1",
        "port": port,
        "authenticator": _authenticator,
        "auth_required": True,
        "auth_require_tls": not implicit_tls,
    }
    implicit_ctx: ssl.SSLContext | None = None
    if tls_cert is not None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(tls_cert[0]), keyfile=str(tls_cert[1]))
        if implicit_tls:
            implicit_ctx = ctx
        else:
            kwargs["tls_context"] = ctx

    controller = _SubmissionController(handler, implicit_ssl_ctx=implicit_ctx, **kwargs)
    controller.start()
    try:
        yield port, auth_attempts
    finally:
        controller.stop()


async def test_send_starttls_success_masks_credentials_and_delivers_message(
    caplog: Any,
) -> None:
    secret_pw = "SuperSecret-AppPass-999!"
    secret_b64 = base64.b64encode(secret_pw.encode()).decode("ascii")
    resolver = FakeDNSResolver({"smtp.yourstore.com": {"A": ["127.0.0.1"]}})

    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _make_ca_and_cert(Path(tmp), dns_names=["smtp.yourstore.com"])
        handler = _SubmissionHandler()
        with (
            caplog.at_level(logging.DEBUG),
            _fake_submission_server(handler, expected_pass=secret_pw, tls_cert=(cert, key)) as (
                port,
                attempts,
            ),
        ):
            report = await run_send_test(
                from_email="info@yourstore.com",
                smtp_host="smtp.yourstore.com",
                port=port,
                security_mode="starttls",
                username="info@yourstore.com",
                password=secret_pw,
                target_inbox_token="t-abc12345",
                target_inbox_address="t-abc12345@test.localhost",
                resolver=resolver,
                cafile=str(ca),
                allow_private_for_tests=True,
            )

    assert report.ready_to_send is True
    assert report.verdict_label == "Yes"
    assert report.login_succeeded is True
    assert report.message_accepted is True
    assert len(attempts) == 1
    assert len(handler.received_messages) == 1
    assert b"DeliverCheck SMTP sending test" in handler.received_messages[0]

    # Credentials MUST NEVER appear in transcript, plain-text report, repr, or logs
    plain = render_send_report_text(report)
    for blob in (report.transcript, plain, repr(report), caplog.text):
        assert secret_pw not in blob
        assert secret_b64 not in blob
    assert "****" in report.transcript


@pytest.mark.filterwarnings("ignore:Requiring AUTH while not requiring TLS:UserWarning")
async def test_send_implicit_tls_465_success() -> None:
    resolver = FakeDNSResolver({"smtp.yourstore.com": {"A": ["127.0.0.1"]}})
    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _make_ca_and_cert(Path(tmp), dns_names=["smtp.yourstore.com"])
        handler = _SubmissionHandler()
        with _fake_submission_server(handler, tls_cert=(cert, key), implicit_tls=True) as (
            port,
            _,
        ):
            report = await run_send_test(
                from_email="info@yourstore.com",
                smtp_host="smtp.yourstore.com",
                port=port,
                security_mode="implicit_tls",
                username="info@yourstore.com",
                password="SuperSecret-AppPass-999!",
                target_inbox_token="t-465test1",
                target_inbox_address="t-465test1@test.localhost",
                resolver=resolver,
                cafile=str(ca),
                allow_private_for_tests=True,
            )
    assert report.ready_to_send is True
    assert report.message_accepted is True


async def test_send_login_failure_explains_m365_and_gmail_clearly() -> None:
    resolver = FakeDNSResolver(
        {
            "smtp.office365.com": {"A": ["127.0.0.1"]},
            "smtp.gmail.com": {"A": ["127.0.0.1"]},
        }
    )
    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _make_ca_and_cert(
            Path(tmp), dns_names=["smtp.office365.com", "smtp.gmail.com"]
        )
        handler = _SubmissionHandler()
        with _fake_submission_server(
            handler,
            tls_cert=(cert, key),
            custom_fail_message="535 5.7.139 SmtpClientAuthentication is disabled for the Tenant",
        ) as (m365_port, _):
            m365 = await run_send_test(
                from_email="info@yourstore.com",
                smtp_host="smtp.office365.com",
                port=m365_port,
                security_mode="starttls",
                username="info@yourstore.com",
                password="WrongPassword123!",
                target_inbox_token="t-m365fail",
                target_inbox_address="t-m365fail@test.localhost",
                resolver=resolver,
                cafile=str(ca),
                allow_private_for_tests=True,
            )

        with _fake_submission_server(
            handler,
            tls_cert=(cert, key),
            custom_fail_message="535 5.7.8 Username and Password not accepted",
        ) as (gmail_port, _):
            gmail = await run_send_test(
                from_email="info@yourstore.com",
                smtp_host="smtp.gmail.com",
                port=gmail_port,
                security_mode="starttls",
                username="info@yourstore.com",
                password="WrongPassword123!",
                target_inbox_token="t-gmailfail",
                target_inbox_address="t-gmailfail@test.localhost",
                resolver=resolver,
                cafile=str(ca),
                allow_private_for_tests=True,
            )

    assert m365.ready_to_send is False
    assert "Security Defaults" in m365.issues[0].detail
    assert "WrongPassword123!" not in m365.transcript

    assert gmail.ready_to_send is False
    assert "App Password" in (gmail.issues[0].fix or "")
    assert "WrongPassword123!" not in gmail.transcript


async def test_send_wrong_security_mode_and_unverified_cert_refuse_credentials() -> None:
    resolver = FakeDNSResolver({"smtp.yourstore.com": {"A": ["127.0.0.1"]}})
    with tempfile.TemporaryDirectory() as tmp:
        # 1) Wrong security mode: implicit TLS against STARTTLS-only server
        ca, cert, key = _make_ca_and_cert(Path(tmp), dns_names=["smtp.yourstore.com"])
        handler = _SubmissionHandler()
        with _fake_submission_server(handler, tls_cert=(cert, key), implicit_tls=False) as (
            port,
            attempts,
        ):
            wrong_mode = await run_send_test(
                from_email="info@yourstore.com",
                smtp_host="smtp.yourstore.com",
                port=port,
                security_mode="implicit_tls",
                username="info@yourstore.com",
                password="NeverSentPassword!",
                target_inbox_token="t-mode0001",
                target_inbox_address="t-mode0001@test.localhost",
                resolver=resolver,
                cafile=str(ca),
                allow_private_for_tests=True,
            )
        assert wrong_mode.ready_to_send is False
        assert attempts == []
        assert "NeverSentPassword!" not in wrong_mode.transcript

        # 2) Untrusted / wrong-hostname TLS cert MUST abort before sending AUTH
        ca2, bad_cert, bad_key = _make_ca_and_cert(Path(tmp), dns_names=["other.example"])
        with _fake_submission_server(handler, tls_cert=(bad_cert, bad_key)) as (port2, attempts2):
            bad_tls = await run_send_test(
                from_email="info@yourstore.com",
                smtp_host="smtp.yourstore.com",
                port=port2,
                security_mode="starttls",
                username="info@yourstore.com",
                password="NeverSentPassword!",
                target_inbox_token="t-cert0001",
                target_inbox_address="t-cert0001@test.localhost",
                resolver=resolver,
                cafile=str(ca2),
                allow_private_for_tests=True,
            )
        assert bad_tls.ready_to_send is False
        assert attempts2 == []  # Credentials were NEVER sent over unverified TLS!
        assert bad_tls.certificate is not None
        assert bad_tls.certificate.hostname_matches is False
        assert "NeverSentPassword!" not in bad_tls.transcript


async def test_send_ssrf_blocks_private_ip_and_disallowed_port() -> None:
    resolver = FakeDNSResolver({"internal.example": {"A": ["10.0.0.10"]}})

    bad_port = await run_send_test(
        from_email="info@yourstore.com",
        smtp_host="internal.example",
        port=25,
        security_mode="starttls",
        username="u",
        password="p",
        target_inbox_token="t-1",
        target_inbox_address="t-1@test.localhost",
        resolver=resolver,
    )
    assert bad_port.ready_to_send is False
    assert "587" in bad_port.verdict_summary

    priv = await run_send_test(
        from_email="info@yourstore.com",
        smtp_host="internal.example",
        port=587,
        security_mode="starttls",
        username="u",
        password="p",
        target_inbox_token="t-2",
        target_inbox_address="t-2@test.localhost",
        resolver=resolver,
    )
    assert priv.ready_to_send is False
    assert "non-public" in priv.verdict_summary.lower()


def test_server_send_route_renders_received_email_report_and_rate_limits() -> None:
    resolver = FakeDNSResolver(
        {
            "smtp.yourstore.com": {"A": ["127.0.0.1"]},
            "yourstore.com": {"TXT": ["v=spf1 ip4:93.184.216.34 -all"]},
            "_dmarc.yourstore.com": {"TXT": ["v=DMARC1; p=none"]},
            "34.216.184.93.in-addr.arpa": {"PTR": ["smtp.yourstore.com"]},
        }
    )
    inbox_store = InboxStore(domain="test.localhost")
    limiter = RateLimiter({"send": RateLimitRule(max_requests=1, window_seconds=60.0)})
    settings = Settings(smtp_inbox_enabled=False, test_inbox_domain="test.localhost")
    app = create_app(
        settings=settings,
        resolver=resolver,
        rate_limiter=limiter,
        inbox_store=inbox_store,
        enable_smtp_inbox=False,
    )

    with tempfile.TemporaryDirectory() as tmp:
        ca, cert, key = _make_ca_and_cert(Path(tmp), dns_names=["smtp.yourstore.com"])
        handler = _SubmissionHandler(inbox_store=inbox_store, resolver=resolver)
        with _fake_submission_server(handler, tls_cert=(cert, key)) as (port, _):

            async def _local_runner(**kwargs: Any) -> Any:
                kwargs["port"] = port
                kwargs["cafile"] = str(ca)
                kwargs["allow_private_for_tests"] = True
                return await run_send_test(**kwargs)

            app.state.send_test_runner = _local_runner
            client = TestClient(app)

            resp = client.post(
                "/server/send",
                data={
                    "from_email": "info@yourstore.com",
                    "smtp_host": "smtp.yourstore.com",
                    "port": "587",
                    "security_mode": "starttls",
                    "username": "info@yourstore.com",
                    "password": "SuperSecret-AppPass-999!",
                },
            )
            assert resp.status_code == 200
            assert "Ready to send: Yes" in resp.text
            assert "Received test email" in resp.text
            assert "SuperSecret-AppPass-999!" not in resp.text

            limited = client.post(
                "/server/send",
                data={
                    "from_email": "info@yourstore.com",
                    "smtp_host": "smtp.yourstore.com",
                    "port": "587",
                    "security_mode": "starttls",
                    "username": "info@yourstore.com",
                    "password": "SuperSecret-AppPass-999!",
                },
            )
            assert limited.status_code == 429
