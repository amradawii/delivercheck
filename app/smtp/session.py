"""Step-by-step asyncio SMTP client with per-step timings and credential-masked transcripts."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from dataclasses import dataclass, field
from typing import Literal

from app.net_safety import validate_email_port
from app.smtp.tls import (
    CertificateInfo,
    create_unverified_inspection_ssl_context,
    inspect_der_certificate,
)

MAX_SMTP_LINE_BYTES = 16 * 1024
MAX_SMTP_RESPONSE_LINES = 64


@dataclass(frozen=True)
class SMTPResponse:
    code: int
    lines: tuple[str, ...]
    duration_ms: float

    @property
    def message(self) -> str:
        return "\n".join(self.lines)

    @property
    def first_line(self) -> str:
        return self.lines[0] if self.lines else ""


@dataclass(frozen=True)
class TranscriptEntry:
    direction: Literal["client", "server", "note"]
    text: str
    elapsed_ms: float


class SMTPProtocolError(RuntimeError):
    """Raised when an SMTP peer returns malformed output or closes unexpectedly."""


@dataclass
class SMTPSession:
    """Asyncio-stream SMTP client pinning a validated IP with SNI and masked logging."""

    ip: str
    port: int
    server_hostname: str
    connect_timeout: float = 8.0
    command_timeout: float = 8.0
    allow_custom_port_for_tests: bool = False
    _reader: asyncio.StreamReader | None = field(default=None, init=False, repr=False)
    _writer: asyncio.StreamWriter | None = field(default=None, init=False, repr=False)
    _started_at: float = field(default=0.0, init=False, repr=False)
    transcript: list[TranscriptEntry] = field(default_factory=list, init=False)
    tls_active: bool = field(default=False, init=False)
    tls_version: str | None = field(default=None, init=False)
    tls_cipher: str | None = field(default=None, init=False)

    def _elapsed_ms(self) -> float:
        if self._started_at <= 0:
            return 0.0
        return round((time.monotonic() - self._started_at) * 1000.0, 1)

    def add_note(self, text: str) -> None:
        self.transcript.append(
            TranscriptEntry(direction="note", text=text, elapsed_ms=self._elapsed_ms())
        )

    async def connect(
        self,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> tuple[float, SMTPResponse]:
        """Connect directly to the pinned IP, optionally with implicit TLS, and read 220 banner."""
        if not self.allow_custom_port_for_tests:
            validate_email_port(self.port)

        self._started_at = time.monotonic()
        t0 = time.monotonic()
        async with asyncio.timeout(self.connect_timeout):
            reader, writer = await asyncio.open_connection(
                host=self.ip,
                port=self.port,
                ssl=ssl_context,
                server_hostname=self.server_hostname if ssl_context is not None else None,
            )
        connect_ms = round((time.monotonic() - t0) * 1000.0, 1)
        self._reader = reader
        self._writer = writer

        if ssl_context is not None:
            self.tls_active = True
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is not None:
                self.tls_version = ssl_obj.version()
                cipher_tuple = ssl_obj.cipher()
                self.tls_cipher = cipher_tuple[0] if cipher_tuple else None
            self.add_note(
                f"Connected to {self.ip}:{self.port} with implicit TLS "
                f"({self.tls_version or 'TLS'}) in {connect_ms:.0f} ms"
            )
        else:
            self.add_note(f"Connected to {self.ip}:{self.port} in {connect_ms:.0f} ms")

        banner = await self.read_response(timeout=self.command_timeout)
        return connect_ms, banner

    def get_peer_der_cert(self) -> bytes | None:
        if self._writer is None:
            return None
        ssl_obj = self._writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return None
        der = ssl_obj.getpeercert(binary_form=True)
        return bytes(der) if der else None

    async def read_response(self, *, timeout: float | None = None) -> SMTPResponse:
        if self._reader is None:
            raise SMTPProtocolError("SMTP connection is not open.")

        wait = timeout if timeout is not None else self.command_timeout
        t0 = time.monotonic()
        lines: list[str] = []
        code: int | None = None

        async with asyncio.timeout(wait):
            for _ in range(MAX_SMTP_RESPONSE_LINES):
                raw = await self._reader.readline()
                if not raw:
                    raise SMTPProtocolError("Server closed the SMTP connection unexpectedly.")
                if len(raw) > MAX_SMTP_LINE_BYTES:
                    raise SMTPProtocolError("SMTP server response line exceeded size limit.")
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                self.transcript.append(
                    TranscriptEntry(direction="server", text=line, elapsed_ms=self._elapsed_ms())
                )
                if len(line) < 3 or not line[:3].isdigit():
                    raise SMTPProtocolError(f"Malformed SMTP response line: '{line}'.")
                line_code = int(line[:3])
                if code is None:
                    code = line_code
                lines.append(line[4:] if len(line) > 4 else "")
                # RFC 5321: hyphen after 3-digit code means more lines follow
                if len(line) == 3 or line[3] == " ":
                    break
            else:
                raise SMTPProtocolError("SMTP multi-line response exceeded maximum line count.")

        duration_ms = round((time.monotonic() - t0) * 1000.0, 1)
        return SMTPResponse(code=code or 0, lines=tuple(lines), duration_ms=duration_ms)

    async def send_command(
        self,
        command: str,
        *,
        mask_in_transcript: str | None = None,
        timeout: float | None = None,
    ) -> SMTPResponse:
        """Send one SMTP command line and return the parsed response.

        If mask_in_transcript is given, that redacted string is recorded in the transcript
        instead of the real command (used for AUTH credentials).
        """
        if self._writer is None:
            raise SMTPProtocolError("SMTP connection is not open.")
        if "\r" in command or "\n" in command:
            raise ValueError("SMTP commands must not contain CR or LF characters.")

        shown = mask_in_transcript if mask_in_transcript is not None else command
        self.transcript.append(
            TranscriptEntry(direction="client", text=shown, elapsed_ms=self._elapsed_ms())
        )
        self._writer.write((command + "\r\n").encode("utf-8"))
        async with asyncio.timeout(timeout if timeout is not None else self.command_timeout):
            await self._writer.drain()
        return await self.read_response(timeout=timeout)

    async def send_data(
        self, message_bytes: bytes, *, timeout: float | None = None
    ) -> SMTPResponse:
        """Send an RFC 5321 dot-stuffed DATA payload after a 354 response."""
        if self._writer is None:
            raise SMTPProtocolError("SMTP connection is not open.")

        normalized = message_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        stuffed_lines = []
        for raw_line in normalized.split(b"\n"):
            if raw_line.startswith(b"."):
                stuffed_lines.append(b"." + raw_line)
            else:
                stuffed_lines.append(raw_line)
        payload = b"\r\n".join(stuffed_lines) + b"\r\n.\r\n"

        self.add_note(f"Sending test message body ({len(message_bytes)} bytes)")
        self._writer.write(payload)
        async with asyncio.timeout(timeout if timeout is not None else self.command_timeout):
            await self._writer.drain()
        return await self.read_response(timeout=timeout)

    async def starttls(self, ssl_context: ssl.SSLContext) -> tuple[SMTPResponse, bytes | None]:
        """Issue STARTTLS and upgrade the asyncio stream in place with SNI."""
        if self._writer is None:
            raise SMTPProtocolError("SMTP connection is not open.")
        resp = await self.send_command("STARTTLS")
        if resp.code != 220:
            return resp, None

        async with asyncio.timeout(self.command_timeout):
            await self._writer.start_tls(ssl_context, server_hostname=self.server_hostname)

        self.tls_active = True
        ssl_obj = self._writer.get_extra_info("ssl_object")
        if ssl_obj is not None:
            self.tls_version = ssl_obj.version()
            cipher_tuple = ssl_obj.cipher()
            self.tls_cipher = cipher_tuple[0] if cipher_tuple else None
        self.add_note(f"TLS established ({self.tls_version or 'TLS'})")
        return resp, self.get_peer_der_cert()

    async def quit_and_close(self) -> None:
        """Send QUIT best-effort and close the underlying transport."""
        if self._writer is not None:
            with contextlib.suppress(Exception):
                await self.send_command("QUIT", timeout=2.0)
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()
        self._writer = None
        self._reader = None

    def format_transcript(self) -> str:
        lines: list[str] = []
        for entry in self.transcript:
            prefix = (
                "C:"
                if entry.direction == "client"
                else ("S:" if entry.direction == "server" else "#")
            )
            lines.append(f"[{entry.elapsed_ms:6.0f} ms] {prefix} {entry.text}")
        return "\n".join(lines)


def parse_ehlo_capabilities(resp: SMTPResponse) -> dict[str, str]:
    """Parse EHLO multi-line response into uppercase capability -> arguments map."""
    caps: dict[str, str] = {}
    for line in resp.lines[1:]:
        parts = line.strip().split(None, 1)
        if not parts:
            continue
        key = parts[0].upper()
        val = parts[1].strip() if len(parts) > 1 else ""
        caps[key] = val
    return caps


async def read_only_cert_probe(
    *,
    ip: str,
    port: int,
    server_hostname: str,
    verify_error: str,
    use_implicit_tls: bool = False,
    ehlo_hostname: str = "delivercheck.local",
    timeout: float = 6.0,
    allow_custom_port_for_tests: bool = False,
) -> CertificateInfo | None:
    """Read-only CERT_NONE probe used ONLY after verification fails to report cert details.

    Never sends AUTH, MAIL, RCPT, or DATA over the unverified TLS session.
    """
    unverified_ctx = create_unverified_inspection_ssl_context()
    probe = SMTPSession(
        ip=ip,
        port=port,
        server_hostname=server_hostname,
        connect_timeout=timeout,
        command_timeout=timeout,
        allow_custom_port_for_tests=allow_custom_port_for_tests,
    )
    try:
        if use_implicit_tls:
            await probe.connect(ssl_context=unverified_ctx)
            der = probe.get_peer_der_cert()
        else:
            await probe.connect()
            await probe.send_command(f"EHLO {ehlo_hostname}")
            _, der = await probe.starttls(unverified_ctx)
        if not der:
            return None
        return inspect_der_certificate(
            der,
            server_hostname,
            tls_version=probe.tls_version,
            cipher=probe.tls_cipher,
            verified=False,
            verify_error=verify_error,
        )
    except Exception:
        return None
    finally:
        await probe.quit_and_close()
