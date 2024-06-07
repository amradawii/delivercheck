"""Optional email security extras (tips only): MTA-STS, TLS-RPT, and BIMI."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from app.checks.dmarc import DMARCCheckResult
from app.checks.mx import MXCheckResult
from app.dns.resolver import DNSResolver, DNSStatus, normalize_dns_name
from app.net_safety import SSRFError, resolve_public_ips

MTA_STS_TIMEOUT_SECONDS = 5.0
MTA_STS_MAX_BYTES = 64 * 1024


@dataclass(frozen=True)
class ExtraIssue:
    severity: str  # "pass", "warn", "info"
    title: str
    detail: str
    fix: str | None = None


@dataclass(frozen=True)
class PolicyFetchResult:
    ok: bool
    status_code: int | None = None
    body: str | None = None
    error: str | None = None
    redirect_blocked: bool = False


PolicyFetcher = Callable[[str, DNSResolver], Awaitable[PolicyFetchResult]]


@dataclass(frozen=True)
class MTASTSResult:
    has_dns_record: bool = False
    dns_record: str | None = None
    policy_fetched: bool = False
    mode: str | None = None
    mx_patterns: tuple[str, ...] = ()
    max_age: int | None = None
    unmatched_mx_hosts: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class ExtrasCheckResult:
    domain: str
    mta_sts: MTASTSResult
    tls_rpt_record: str | None = None
    bimi_record: str | None = None
    issues: tuple[ExtraIssue, ...] = ()


async def fetch_mta_sts_policy(domain: str, resolver: DNSResolver) -> PolicyFetchResult:
    """Fetch https://mta-sts.<domain>/.well-known/mta-sts.txt safely per RFC 8461.

    Security guarantees:
    - Fixed URL only (no redirects allowed per RFC 8461 section 3.3).
    - SSRF-validated IP dialed directly with TLS certificate verification & SNI.
    - 5 second total timeout and 64 KB response cap.
    """
    host = f"mta-sts.{normalize_dns_name(domain)}"
    try:
        public_ips = await resolve_public_ips(host, resolver)
    except SSRFError as exc:
        return PolicyFetchResult(ok=False, error=str(exc))

    target_ip = public_ips[0]
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(MTA_STS_TIMEOUT_SECONDS):
            reader, writer = await asyncio.open_connection(
                host=target_ip,
                port=443,
                ssl=ssl_ctx,
                server_hostname=host,
            )
            request = (
                f"GET /.well-known/mta-sts.txt HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: DeliverCheck/0.1\r\n"
                f"Accept: text/plain\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()

            raw_chunks: list[bytes] = []
            total_read = 0
            limit = MTA_STS_MAX_BYTES + 8192  # headers + up to 64 KB body
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                total_read += len(chunk)
                if total_read > limit:
                    return PolicyFetchResult(
                        ok=False,
                        error="MTA-STS policy response exceeded the 64 KB size limit.",
                    )
                raw_chunks.append(chunk)
    except TimeoutError:
        return PolicyFetchResult(
            ok=False,
            error=f"Timed out fetching https://{host}/.well-known/mta-sts.txt after 5s.",
        )
    except ssl.SSLCertVerificationError as exc:
        return PolicyFetchResult(
            ok=False,
            error=f"TLS certificate verification failed for {host}: {exc.verify_message or exc}.",
        )
    except OSError as exc:
        return PolicyFetchResult(
            ok=False,
            error=f"Could not connect to https://{host}/.well-known/mta-sts.txt: {exc}.",
        )
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    raw_response = b"".join(raw_chunks)
    header_blob, sep, body_bytes = raw_response.partition(b"\r\n\r\n")
    if not sep:
        header_blob, sep, body_bytes = raw_response.partition(b"\n\n")
    if not sep:
        return PolicyFetchResult(ok=False, error="Malformed HTTP response from MTA-STS host.")

    if len(body_bytes) > MTA_STS_MAX_BYTES:
        return PolicyFetchResult(
            ok=False,
            error="MTA-STS policy file exceeded the 64 KB limit.",
        )

    status_line = header_blob.splitlines()[0].decode("latin-1", errors="replace")
    parts = status_line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        return PolicyFetchResult(ok=False, error=f"Invalid HTTP status line: {status_line}.")

    status_code = int(parts[1])
    if 300 <= status_code < 400:
        return PolicyFetchResult(
            ok=False,
            status_code=status_code,
            redirect_blocked=True,
            error=(
                f"MTA-STS policy returned HTTP {status_code} redirect; RFC 8461 forbids "
                "redirects on /.well-known/mta-sts.txt."
            ),
        )
    if status_code != 200:
        return PolicyFetchResult(
            ok=False,
            status_code=status_code,
            error=f"MTA-STS policy returned HTTP {status_code} instead of 200 OK.",
        )

    # Handle Transfer-Encoding: chunked if present
    headers_lower = header_blob.decode("latin-1", errors="replace").lower()
    if "transfer-encoding: chunked" in headers_lower:
        body_bytes = _decode_chunked_body(body_bytes)

    return PolicyFetchResult(
        ok=True,
        status_code=200,
        body=body_bytes.decode("utf-8", errors="replace"),
    )


def _decode_chunked_body(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    length = len(data)
    while pos < length:
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            break
        size_hex = data[pos:line_end].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_hex, 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        start = line_end + 2
        out.extend(data[start : start + chunk_size])
        pos = start + chunk_size + 2
    return bytes(out)


def _mx_matches_sts_pattern(mx_host: str, pattern: str) -> bool:
    """RFC 8461 section 4.1: exact match or single-label left-most wildcard '*.example.com'."""
    host = mx_host.strip().rstrip(".").lower()
    pat = pattern.strip().rstrip(".").lower()
    if not pat:
        return False
    if pat.startswith("*."):
        suffix = pat[1:]  # ".example.com"
        if not host.endswith(suffix):
            return False
        left_part = host[: -len(suffix)]
        return bool(left_part) and "." not in left_part
    return host == pat


def parse_mta_sts_policy(body: str) -> tuple[str | None, tuple[str, ...], int | None, list[str]]:
    """Parse an RFC 8461 MTA-STS policy text file."""
    version: str | None = None
    mode: str | None = None
    mx_patterns: list[str] = []
    max_age: int | None = None
    errors: list[str] = []

    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if ":" not in stripped:
            errors.append(f"Malformed MTA-STS policy line: '{stripped}'.")
            continue
        key_raw, val_raw = stripped.split(":", 1)
        key = key_raw.strip().lower()
        val = val_raw.strip()
        if key == "version":
            version = val
        elif key == "mode":
            mode = val.lower()
        elif key == "mx":
            mx_patterns.append(val.lower().rstrip("."))
        elif key == "max_age":
            try:
                max_age = int(val)
            except ValueError:
                errors.append(f"Invalid max_age value: '{val}'.")

    if version != "STSv1":
        errors.append("Policy file is missing 'version: STSv1'.")
    if mode not in ("enforce", "testing", "none"):
        errors.append(
            f"Invalid or missing MTA-STS mode '{mode}' (expected enforce, testing, or none)."
        )
    if max_age is None or max_age < 0:
        errors.append("Policy file is missing a valid 'max_age' integer.")
    if mode in ("enforce", "testing") and not mx_patterns:
        errors.append(
            "Policy file must list at least one 'mx:' pattern when mode is enforce or testing."
        )

    return mode, tuple(mx_patterns), max_age, errors


async def check_extras(
    domain: str,
    resolver: DNSResolver,
    *,
    mx_result: MXCheckResult,
    dmarc_result: DMARCCheckResult,
    policy_fetcher: PolicyFetcher | None = None,
) -> ExtrasCheckResult:
    """Check MTA-STS, TLS-RPT, and BIMI as optional best-practice tips."""
    norm_domain = normalize_dns_name(domain)
    fetcher = policy_fetcher or fetch_mta_sts_policy

    sts_resp, tlsrpt_resp, bimi_resp = await asyncio.gather(
        resolver.query(f"_mta-sts.{norm_domain}", "TXT"),
        resolver.query(f"_smtp._tls.{norm_domain}", "TXT"),
        resolver.query(f"default._bimi.{norm_domain}", "TXT"),
    )

    issues: list[ExtraIssue] = []

    # --- MTA-STS ---
    sts_records = [
        r
        for r in (sts_resp.records if sts_resp.status == DNSStatus.OK else ())
        if r.strip().startswith("v=STSv1")
    ]
    if not sts_records:
        mta_sts = MTASTSResult(has_dns_record=False)
        issues.append(
            ExtraIssue(
                severity="info",
                title="MTA-STS is not configured (optional tip)",
                detail=(
                    "MTA-STS tells sending servers to require verified TLS when delivering email "
                    "to your domain, preventing downgrade attacks."
                ),
                fix=(
                    f"Optional: publish a TXT record at _mta-sts.{norm_domain} and host a policy "
                    f"at https://mta-sts.{norm_domain}/.well-known/mta-sts.txt."
                ),
            )
        )
    else:
        dns_rec = sts_records[0]
        fetch_res = await fetcher(norm_domain, resolver)
        if not fetch_res.ok or fetch_res.body is None:
            mta_sts = MTASTSResult(
                has_dns_record=True,
                dns_record=dns_rec,
                policy_fetched=False,
                error=fetch_res.error,
            )
            issues.append(
                ExtraIssue(
                    severity="warn",
                    title="MTA-STS DNS record exists, but the policy file could not be loaded",
                    detail=(
                        fetch_res.error
                        or f"Failed to fetch https://mta-sts.{norm_domain}/.well-known/mta-sts.txt."
                    ),
                    fix=(
                        f"Serve a valid HTTPS policy file at "
                        f"https://mta-sts.{norm_domain}/.well-known/mta-sts.txt "
                        "with a valid certificate and no redirects."
                    ),
                )
            )
        else:
            mode, mx_patterns, max_age, parse_errors = parse_mta_sts_policy(fetch_res.body)
            real_mx_hosts: Sequence[str] = [
                h.exchange for h in mx_result.hosts if h.exchange != "." and not h.is_bare_ip
            ]
            unmatched = tuple(
                host
                for host in real_mx_hosts
                if mode in ("enforce", "testing")
                and not any(_mx_matches_sts_pattern(host, pat) for pat in mx_patterns)
            )
            mta_sts = MTASTSResult(
                has_dns_record=True,
                dns_record=dns_rec,
                policy_fetched=True,
                mode=mode,
                mx_patterns=mx_patterns,
                max_age=max_age,
                unmatched_mx_hosts=unmatched,
                error=parse_errors[0] if parse_errors else None,
            )
            if parse_errors:
                issues.append(
                    ExtraIssue(
                        severity="warn",
                        title="MTA-STS policy file has syntax issues",
                        detail=parse_errors[0],
                        fix=(
                            f"Fix https://mta-sts.{norm_domain}/.well-known/mta-sts.txt so it "
                            "includes version: STSv1, mode, mx, and max_age."
                        ),
                    )
                )
            elif unmatched:
                issues.append(
                    ExtraIssue(
                        severity="warn",
                        title="MTA-STS policy does not match your MX records",
                        detail=(
                            f"MX host(s) {', '.join(unmatched)} are not listed in your MTA-STS "
                            f"policy (mode={mode}), which can cause sending servers to reject or "
                            "defer mail under enforce mode."
                        ),
                        fix=(
                            "Add matching 'mx:' lines to "
                            f"https://mta-sts.{norm_domain}/.well-known/mta-sts.txt "
                            "and bump the id= value in _mta-sts."
                        ),
                    )
                )
            else:
                issues.append(
                    ExtraIssue(
                        severity="pass",
                        title=f"MTA-STS is configured (mode={mode})",
                        detail=(
                            f"Valid _mta-sts record and HTTPS policy file matching your MX "
                            f"records (max_age={max_age}s)."
                        ),
                    )
                )

    # --- TLS-RPT ---
    tlsrpt_records = [
        r
        for r in (tlsrpt_resp.records if tlsrpt_resp.status == DNSStatus.OK else ())
        if r.strip().startswith("v=TLSRPTv1")
    ]
    tls_rpt_record = tlsrpt_records[0] if tlsrpt_records else None
    if tls_rpt_record:
        issues.append(
            ExtraIssue(
                severity="pass",
                title="TLS-RPT is configured",
                detail=(
                    f"_smtp._tls.{norm_domain} publishes a TLS reporting record so servers can "
                    "report TLS delivery failures."
                ),
            )
        )
    else:
        issues.append(
            ExtraIssue(
                severity="info",
                title="TLS-RPT is not configured (optional tip)",
                detail=(
                    "TLS-RPT sends you reports when other servers hit TLS or certificate errors "
                    "delivering to your domain."
                ),
                fix=(
                    f"Optional: add a TXT record at _smtp._tls.{norm_domain} with "
                    f"'v=TLSRPTv1; rua=mailto:tls-reports@{dmarc_result.organizational_domain}'."
                ),
            )
        )

    # --- BIMI ---
    bimi_records = [
        r
        for r in (bimi_resp.records if bimi_resp.status == DNSStatus.OK else ())
        if r.strip().startswith("v=BIMI1")
    ]
    bimi_record = bimi_records[0] if bimi_records else None
    if bimi_record:
        if not dmarc_result.bimi_eligible:
            issues.append(
                ExtraIssue(
                    severity="warn",
                    title="BIMI record found, but DMARC does not yet qualify",
                    detail=(
                        "BIMI requires DMARC enforcement at p=quarantine or p=reject with "
                        "pct=100 (and Gmail also requires a Verified Mark Certificate, VMC)."
                    ),
                    fix="Move DMARC to p=quarantine or p=reject with pct=100 to activate BIMI.",
                )
            )
        else:
            issues.append(
                ExtraIssue(
                    severity="pass",
                    title="BIMI record is published",
                    detail=(
                        f"default._bimi.{norm_domain} is published alongside an enforcing DMARC "
                        "policy (Gmail displays logos when backed by a VMC)."
                    ),
                )
            )
    else:
        issues.append(
            ExtraIssue(
                severity="info",
                title="BIMI is not configured (optional tip)",
                detail=(
                    "BIMI lets supported inboxes display your brand logo once DMARC is enforced "
                    "at p=quarantine or p=reject with pct=100 (Gmail requires a VMC)."
                ),
            )
        )

    return ExtrasCheckResult(
        domain=norm_domain,
        mta_sts=mta_sts,
        tls_rpt_record=tls_rpt_record,
        bimi_record=bimi_record,
        issues=tuple(issues),
    )
