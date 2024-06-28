"""In-process aiosmtpd receiver for temporary test addresses (never relays, 1 MB cap)."""

from __future__ import annotations

import ssl
from typing import Any

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Envelope, Session

from app.dns.resolver import DNSResolver
from app.inbox.analyze import analyze_received_email
from app.inbox.store import InboxStore

MAX_INBOX_MESSAGE_BYTES = 1_048_576  # 1 MB


class TestInboxHandler:
    """aiosmtpd handler accepting ONLY active temporary addresses and never relaying."""

    def __init__(self, store: InboxStore, resolver: DNSResolver) -> None:
        self._store = store
        self._resolver = resolver

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        # Never allow multi-recipient abuse
        if envelope.rcpt_tos:
            return "452 4.5.3 Only one test recipient per message is allowed"

        slot = self._store.match_recipient(address)
        if slot is None:
            return "550 5.1.1 Unknown or expired test address; relaying is not permitted"

        envelope.rcpt_tos.append(slot.address)
        return "250 2.1.5 Recipient accepted"

    async def handle_DATA(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
    ) -> str:
        raw_content = envelope.original_content
        if isinstance(raw_content, str):
            raw_bytes = raw_content.encode("utf-8", errors="replace")
        elif isinstance(raw_content, bytes | bytearray):
            raw_bytes = bytes(raw_content)
        else:
            raw_bytes = b""

        if len(raw_bytes) > MAX_INBOX_MESSAGE_BYTES:
            return "552 5.3.4 Message exceeds the 1 MB DeliverCheck test limit"

        if not envelope.rcpt_tos:
            return "550 5.1.1 No valid test recipient"

        slot = self._store.match_recipient(envelope.rcpt_tos[0])
        if slot is None:
            return "550 5.1.1 Test address expired"

        peer = session.peer
        peer_ip = str(peer[0]) if peer and len(peer) >= 1 else "0.0.0.0"
        helo_hostname = str(session.host_name or "")

        tls_used = bool(session.ssl)
        tls_version: str | None = None
        tls_cipher: str | None = None
        if isinstance(session.ssl, dict):
            ver = session.ssl.get("version")
            tls_version = str(ver) if ver else None
            ciph = session.ssl.get("cipher")
            if isinstance(ciph, tuple | list) and ciph:
                tls_cipher = str(ciph[0])
            elif ciph:
                tls_cipher = str(ciph)
        elif session.ssl is not None:
            ver_fn = getattr(session.ssl, "version", None)
            if callable(ver_fn):
                tls_version = str(ver_fn() or "") or None

        analysis = await analyze_received_email(
            raw_bytes,
            peer_ip=peer_ip,
            mail_from=str(envelope.mail_from or ""),
            helo_hostname=helo_hostname,
            tls_used=tls_used,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
            resolver=self._resolver,
        )
        self._store.record_analysis(slot.token, analysis)
        return "250 2.0.0 Test message received and analyzed"


class InboxSMTPServer:
    """Lifecycle wrapper around aiosmtpd.Controller for FastAPI lifespan."""

    def __init__(
        self,
        *,
        store: InboxStore,
        resolver: DNSResolver,
        host: str = "0.0.0.0",
        port: int = 2525,
        tls_cert: str | None = None,
        tls_key: str | None = None,
    ) -> None:
        self.store = store
        self.host = host
        self.port = port
        self._handler = TestInboxHandler(store=store, resolver=resolver)
        self._tls_cert = tls_cert
        self._tls_key = tls_key
        self._controller: Controller | None = None

    def start(self) -> None:
        kwargs: dict[str, Any] = {
            "hostname": self.host,
            "port": self.port,
            "data_size_limit": MAX_INBOX_MESSAGE_BYTES,
            "ident": f"DeliverCheck Test Inbox ({self.store.domain})",
        }
        if self._tls_cert and self._tls_key:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=self._tls_cert, keyfile=self._tls_key)
            kwargs["tls_context"] = ctx

        self._controller = Controller(self._handler, **kwargs)
        self._controller.start()

    def stop(self) -> None:
        if self._controller is not None:
            self._controller.stop()
            self._controller = None
