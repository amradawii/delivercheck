"""Async DNS resolver with timeouts, retries, caching, and an offline test double."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import dns.reversename


class DNSStatus(StrEnum):
    OK = "ok"
    NXDOMAIN = "nxdomain"
    NO_ANSWER = "no_answer"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True)
class MXRecord:
    priority: int
    exchange: str  # "." for Null MX; otherwise lowercased hostname without trailing dot


@dataclass(frozen=True)
class DNSResponse:
    qname: str
    rdtype: str
    status: DNSStatus
    records: tuple[str, ...] = ()
    mx_records: tuple[MXRecord, ...] = ()
    cname_chain: tuple[str, ...] = ()
    error_message: str | None = None

    @property
    def is_void(self) -> bool:
        """True when a query returned NXDOMAIN or NOERROR with zero answers (RFC 7208)."""
        return self.status in (DNSStatus.NXDOMAIN, DNSStatus.NO_ANSWER)


class DNSResolver(Protocol):
    async def query(self, name: str, rdtype: str) -> DNSResponse: ...


def normalize_dns_name(name: str) -> str:
    """Normalize a DNS hostname: trim, lowercase, strip trailing dot, punycode non-ASCII labels."""
    cleaned = name.strip().rstrip(".")
    if not cleaned:
        return ""
    if cleaned == ".":
        return "."

    labels = cleaned.split(".")
    encoded_labels: list[str] = []
    for label in labels:
        lower_label = label.lower()
        if lower_label.isascii():
            encoded_labels.append(lower_label)
        else:
            encoded_labels.append(lower_label.encode("idna").decode("ascii"))
    return ".".join(encoded_labels)


def reverse_ip_for_ptr(ip_str: str) -> str:
    """Return the in-addr.arpa / ip6.arpa PTR query name for an IP address."""
    ipaddress.ip_address(ip_str)
    return str(dns.reversename.from_address(ip_str)).rstrip(".")


def _resolve_nameserver_ip(nameserver: str) -> str:
    """Resolve a nameserver hostname (e.g. 'unbound') to an IP address for dnspython."""
    try:
        ipaddress.ip_address(nameserver)
        return nameserver
    except ValueError:
        infos = socket.getaddrinfo(nameserver, 53, type=socket.SOCK_DGRAM)
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                return str(sockaddr[0])
        if infos:
            return str(infos[0][4][0])
        raise ValueError(f"Could not resolve DNS nameserver host: {nameserver}") from None


class AsyncDNSResolver:
    """Production async DNS resolver backed by dnspython with timeouts and retries."""

    def __init__(
        self,
        nameserver: str | None = None,
        timeout_seconds: float = 3.0,
        per_try_timeout: float = 1.5,
        retries: int = 1,
    ) -> None:
        self._nameserver = nameserver
        self._timeout_seconds = max(0.5, timeout_seconds)
        self._per_try_timeout = max(0.2, min(per_try_timeout, self._timeout_seconds))
        self._retries = max(0, retries)
        self._resolver: dns.asyncresolver.Resolver | None = None

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        if self._resolver is None:
            res = dns.asyncresolver.Resolver(configure=self._nameserver is None)
            if self._nameserver:
                res.nameservers = [_resolve_nameserver_ip(self._nameserver)]
            res.timeout = self._per_try_timeout
            res.lifetime = self._timeout_seconds
            self._resolver = res
        return self._resolver

    async def query(self, name: str, rdtype: str) -> DNSResponse:
        qname = normalize_dns_name(name)
        rdtype_upper = rdtype.upper()
        if not qname:
            return DNSResponse(
                qname="",
                rdtype=rdtype_upper,
                status=DNSStatus.ERROR,
                error_message="Empty DNS query name",
            )

        try:
            resolver = self._get_resolver()
        except Exception as exc:
            return DNSResponse(
                qname=qname,
                rdtype=rdtype_upper,
                status=DNSStatus.ERROR,
                error_message=str(exc),
            )

        last_exc: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                answer = await resolver.resolve(
                    qname,
                    rdtype_upper,
                    lifetime=self._timeout_seconds,
                    raise_on_no_answer=True,
                )
                return self._parse_answer(qname, rdtype_upper, answer)
            except dns.resolver.NXDOMAIN:
                return DNSResponse(qname=qname, rdtype=rdtype_upper, status=DNSStatus.NXDOMAIN)
            except dns.resolver.NoAnswer:
                return DNSResponse(qname=qname, rdtype=rdtype_upper, status=DNSStatus.NO_ANSWER)
            except (dns.resolver.LifetimeTimeout, dns.exception.Timeout, TimeoutError) as exc:
                last_exc = exc
                if attempt < self._retries:
                    await asyncio.sleep(0.05)
                    continue
                return DNSResponse(
                    qname=qname,
                    rdtype=rdtype_upper,
                    status=DNSStatus.TIMEOUT,
                    error_message=f"DNS query timed out after {self._timeout_seconds:.1f}s",
                )
            except (dns.resolver.NoNameservers, dns.exception.DNSException) as exc:
                last_exc = exc
                if attempt < self._retries:
                    await asyncio.sleep(0.05)
                    continue
                return DNSResponse(
                    qname=qname,
                    rdtype=rdtype_upper,
                    status=DNSStatus.ERROR,
                    error_message=str(exc) or exc.__class__.__name__,
                )

        return DNSResponse(
            qname=qname,
            rdtype=rdtype_upper,
            status=DNSStatus.ERROR,
            error_message=str(last_exc) if last_exc else "DNS query failed",
        )

    @staticmethod
    def _parse_answer(
        qname: str,
        rdtype: str,
        answer: dns.resolver.Answer,
    ) -> DNSResponse:
        cname_chain: list[str] = []
        if answer.response is not None:
            for rrset in answer.response.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    for item in rrset:
                        target = str(item.target).rstrip(".").lower()
                        if target and target not in cname_chain:
                            cname_chain.append(target)

        if rdtype == "MX":
            mx_items: list[MXRecord] = []
            text_items: list[str] = []
            for rdata in answer:
                raw_exchange = str(rdata.exchange)
                exchange = "." if raw_exchange == "." else raw_exchange.rstrip(".").lower()
                mx_items.append(MXRecord(priority=int(rdata.preference), exchange=exchange))
                text_items.append(f"{int(rdata.preference)} {exchange}")
            mx_items.sort(key=lambda r: (r.priority, r.exchange))
            return DNSResponse(
                qname=qname,
                rdtype=rdtype,
                status=DNSStatus.OK,
                records=tuple(text_items),
                mx_records=tuple(mx_items),
                cname_chain=tuple(cname_chain),
            )

        if rdtype == "TXT":
            txt_values: list[str] = []
            for rdata in answer:
                # RFC 7208 section 3.3: join character-strings inside one TXT RR without spaces
                joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
                txt_values.append(joined)
            return DNSResponse(
                qname=qname,
                rdtype=rdtype,
                status=DNSStatus.OK,
                records=tuple(txt_values),
                cname_chain=tuple(cname_chain),
            )

        values: list[str] = []
        for rdata in answer:
            val = str(rdata)
            if rdtype in ("NS", "CNAME", "PTR"):
                val = val.rstrip(".").lower()
            values.append(val)

        return DNSResponse(
            qname=qname,
            rdtype=rdtype,
            status=DNSStatus.OK,
            records=tuple(values),
            cname_chain=tuple(cname_chain),
        )


class CachedDNSResolver:
    """Per-check caching wrapper around any DNSResolver with in-flight deduplication."""

    def __init__(self, inner: DNSResolver) -> None:
        self._inner = inner
        self._cache: dict[tuple[str, str], DNSResponse] = {}
        self._inflight: dict[tuple[str, str], asyncio.Task[DNSResponse]] = {}

    async def query(self, name: str, rdtype: str) -> DNSResponse:
        key = (normalize_dns_name(name), rdtype.upper())
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        task = self._inflight.get(key)
        if task is None:
            task = asyncio.create_task(self._inner.query(key[0], key[1]))
            self._inflight[key] = task

        try:
            response = await task
        finally:
            self._inflight.pop(key, None)

        self._cache[key] = response
        return response


# Sentinel markers for offline FakeDNSResolver fixtures
FAKE_NXDOMAIN = "__NXDOMAIN__"
FAKE_TIMEOUT = "__TIMEOUT__"
FAKE_ERROR = "__ERROR__"

ZoneValue = (
    Sequence[str] | Sequence[tuple[int, str]] | Sequence[tuple[str, ...]] | str | DNSResponse
)


class FakeDNSResolver:
    """Offline DNS resolver driven by in-memory zone fixtures for deterministic tests."""

    def __init__(
        self,
        zones: Mapping[str, Mapping[str, ZoneValue]] | None = None,
        *,
        latency_seconds: float = 0.0,
    ) -> None:
        self._zones: dict[str, dict[str, ZoneValue]] = {}
        for domain, rrsets in (zones or {}).items():
            norm_domain = normalize_dns_name(domain)
            self._zones[norm_domain] = {k.upper(): v for k, v in rrsets.items()}
        self._latency_seconds = latency_seconds
        self.query_log: list[tuple[str, str]] = []

    async def query(self, name: str, rdtype: str) -> DNSResponse:
        qname = normalize_dns_name(name)
        rdtype_upper = rdtype.upper()
        self.query_log.append((qname, rdtype_upper))

        if self._latency_seconds > 0:
            await asyncio.sleep(self._latency_seconds)

        return self._resolve_internal(qname, rdtype_upper, visited=set(), cname_chain=[])

    def _resolve_internal(
        self,
        qname: str,
        rdtype: str,
        visited: set[str],
        cname_chain: list[str],
    ) -> DNSResponse:
        if qname in visited:
            return DNSResponse(
                qname=qname,
                rdtype=rdtype,
                status=DNSStatus.ERROR,
                error_message="CNAME loop detected",
            )
        visited.add(qname)

        domain_records = self._zones.get(qname)
        if domain_records is None:
            return DNSResponse(qname=qname, rdtype=rdtype, status=DNSStatus.NXDOMAIN)

        # Follow CNAME transparently for non-CNAME record queries, recording the chain
        if rdtype != "CNAME" and "CNAME" in domain_records and rdtype not in domain_records:
            cname_val = domain_records["CNAME"]
            if isinstance(cname_val, str) and cname_val not in (
                FAKE_NXDOMAIN,
                FAKE_TIMEOUT,
                FAKE_ERROR,
            ):
                target = normalize_dns_name(cname_val)
                return self._resolve_internal(target, rdtype, visited, [*cname_chain, target])
            if isinstance(cname_val, Sequence) and cname_val and isinstance(cname_val[0], str):
                target = normalize_dns_name(cname_val[0])
                return self._resolve_internal(target, rdtype, visited, [*cname_chain, target])

        if rdtype not in domain_records:
            return DNSResponse(
                qname=qname,
                rdtype=rdtype,
                status=DNSStatus.NO_ANSWER,
                cname_chain=tuple(cname_chain),
            )

        raw = domain_records[rdtype]
        if isinstance(raw, DNSResponse):
            return raw
        if raw == FAKE_NXDOMAIN:
            return DNSResponse(qname=qname, rdtype=rdtype, status=DNSStatus.NXDOMAIN)
        if raw == FAKE_TIMEOUT:
            return DNSResponse(
                qname=qname,
                rdtype=rdtype,
                status=DNSStatus.TIMEOUT,
                error_message="Simulated DNS timeout",
            )
        if raw == FAKE_ERROR:
            return DNSResponse(
                qname=qname,
                rdtype=rdtype,
                status=DNSStatus.ERROR,
                error_message="Simulated DNS error",
            )

        if isinstance(raw, str):
            val = raw.rstrip(".").lower() if rdtype in ("NS", "CNAME", "PTR") else raw
            return DNSResponse(
                qname=qname,
                rdtype=rdtype,
                status=DNSStatus.OK,
                records=(val,),
                cname_chain=tuple(cname_chain),
            )

        if rdtype == "MX":
            mx_list: list[MXRecord] = []
            str_list: list[str] = []
            for item in raw:
                if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], int):
                    pref, exch_raw = item
                    exch = "." if exch_raw == "." else normalize_dns_name(str(exch_raw))
                    mx_list.append(MXRecord(priority=pref, exchange=exch))
                    str_list.append(f"{pref} {exch}")
                elif isinstance(item, str):
                    parts = item.strip().split(None, 1)
                    pref = int(parts[0])
                    exch = "." if parts[1] == "." else normalize_dns_name(parts[1])
                    mx_list.append(MXRecord(priority=pref, exchange=exch))
                    str_list.append(f"{pref} {exch}")
            mx_list.sort(key=lambda r: (r.priority, r.exchange))
            return DNSResponse(
                qname=qname,
                rdtype=rdtype,
                status=DNSStatus.OK,
                records=tuple(str_list),
                mx_records=tuple(mx_list),
                cname_chain=tuple(cname_chain),
            )

        if rdtype == "TXT":
            txt_list: list[str] = []
            for item in raw:
                if isinstance(item, tuple):
                    txt_list.append("".join(str(chunk) for chunk in item))
                else:
                    txt_list.append(str(item))
            return DNSResponse(
                qname=qname,
                rdtype=rdtype,
                status=DNSStatus.OK,
                records=tuple(txt_list),
                cname_chain=tuple(cname_chain),
            )

        records_out: list[str] = []
        for item in raw:
            val = str(item)
            if rdtype in ("NS", "CNAME", "PTR"):
                val = normalize_dns_name(val)
            records_out.append(val)

        return DNSResponse(
            qname=qname,
            rdtype=rdtype,
            status=DNSStatus.OK,
            records=tuple(records_out),
            cname_chain=tuple(cname_chain),
        )
