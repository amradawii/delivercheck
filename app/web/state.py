"""Short-lived in-memory session store for streaming domain check sections via htmx."""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field

from app.checks.blocklists import BlocklistCheckResult
from app.checks.dkim import DKIMCheckResult
from app.checks.dmarc import DMARCCheckResult
from app.checks.domain import (
    _extract_single_spf_ips,
    assemble_domain_report,
    safe_check_blocklists,
    safe_check_dkim,
    safe_check_dmarc,
    safe_check_extras,
    safe_check_mx,
    safe_check_spf,
    safe_detect_dns_host,
    safe_query_root_txt,
)
from app.checks.extras import ExtrasCheckResult, PolicyFetcher
from app.checks.mx import MXCheckResult
from app.checks.spf import SPFCheckResult
from app.config import Settings
from app.dns.providers import DNSHost, MailProvider, detect_providers_from_txt
from app.dns.resolver import CachedDNSResolver, DNSResolver, DNSStatus, normalize_dns_name
from app.report.models import DomainReport

SESSION_TTL_SECONDS = 180.0
MAX_SESSIONS = 400


@dataclass
class DomainCheckSession:
    token: str
    domain: str
    display_domain: str
    custom_selector: str | None
    created_at: float
    _resolver: DNSResolver
    _settings: Settings
    _policy_fetcher: PolicyFetcher | None
    _loop: asyncio.AbstractEventLoop | None = field(default=None, init=False, repr=False)
    _mx_task: asyncio.Task[MXCheckResult] | None = field(default=None, init=False, repr=False)
    _dns_host_task: asyncio.Task[DNSHost | None] | None = field(
        default=None, init=False, repr=False
    )
    _spf_task: asyncio.Task[SPFCheckResult] | None = field(default=None, init=False, repr=False)
    _dmarc_task: asyncio.Task[DMARCCheckResult] | None = field(default=None, init=False, repr=False)
    _dkim_task: asyncio.Task[DKIMCheckResult] | None = field(default=None, init=False, repr=False)
    _blocklists_task: asyncio.Task[BlocklistCheckResult] | None = field(
        default=None, init=False, repr=False
    )
    _extras_task: asyncio.Task[ExtrasCheckResult] | None = field(
        default=None, init=False, repr=False
    )
    _report_task: asyncio.Task[DomainReport] | None = field(default=None, init=False, repr=False)

    def _ensure_tasks(self) -> None:
        current_loop = asyncio.get_running_loop()
        if (
            self._loop is current_loop
            and self._mx_task is not None
            and not self._mx_task.cancelled()
        ):
            return

        self._loop = current_loop
        norm_domain = normalize_dns_name(self.domain)
        scoped = CachedDNSResolver(self._resolver)
        settings = self._settings
        timeout = settings.check_timeout_seconds
        policy_fetcher = self._policy_fetcher
        custom_selector = self.custom_selector

        mx_task = asyncio.create_task(safe_check_mx(norm_domain, scoped, timeout_seconds=timeout))
        dns_host_task = asyncio.create_task(
            safe_detect_dns_host(norm_domain, scoped, timeout_seconds=timeout)
        )
        root_txt_task = asyncio.create_task(
            safe_query_root_txt(norm_domain, scoped, timeout_seconds=timeout)
        )
        dmarc_task = asyncio.create_task(
            safe_check_dmarc(norm_domain, scoped, timeout_seconds=timeout)
        )

        async def _initial_providers() -> list[MailProvider]:
            mx_res, root_txt = await asyncio.gather(mx_task, root_txt_task)
            found: list[MailProvider] = []
            if mx_res.provider is not None:
                found.append(mx_res.provider)
            if root_txt.status == DNSStatus.OK:
                for p in detect_providers_from_txt(root_txt.records):
                    if all(existing.id != p.id for existing in found):
                        found.append(p)
            return found

        initial_providers_task = asyncio.create_task(_initial_providers())

        async def _run_spf() -> SPFCheckResult:
            providers = await initial_providers_task
            return await safe_check_spf(
                norm_domain,
                scoped,
                detected_providers=providers,
                timeout_seconds=timeout,
            )

        spf_task = asyncio.create_task(_run_spf())

        async def _all_providers() -> list[MailProvider]:
            initial, spf_res = await asyncio.gather(initial_providers_task, spf_task)
            merged = list(initial)
            for p in spf_res.detected_providers:
                if all(existing.id != p.id for existing in merged):
                    merged.append(p)
            return merged

        all_providers_task = asyncio.create_task(_all_providers())

        async def _run_dkim() -> DKIMCheckResult:
            providers = await all_providers_task
            return await safe_check_dkim(
                norm_domain,
                scoped,
                detected_providers=providers,
                custom_selector=custom_selector,
                timeout_seconds=timeout,
            )

        async def _run_blocklists() -> BlocklistCheckResult:
            mx_res, spf_res = await asyncio.gather(mx_task, spf_task)
            ips: list[str] = []
            for host in mx_res.hosts:
                ips.extend(host.all_ips)
            ips.extend(_extract_single_spf_ips(spf_res.ip4_networks, spf_res.ip6_networks))
            return await safe_check_blocklists(
                norm_domain,
                scoped,
                ips=ips,
                spamhaus_dqs_key=settings.spamhaus_dqs_key,
                enable_barracuda_brbl=settings.enable_barracuda_brbl,
                timeout_seconds=timeout,
            )

        async def _run_extras() -> ExtrasCheckResult:
            mx_res, dmarc_res = await asyncio.gather(mx_task, dmarc_task)
            return await safe_check_extras(
                norm_domain,
                scoped,
                mx_result=mx_res,
                dmarc_result=dmarc_res,
                policy_fetcher=policy_fetcher,
                timeout_seconds=timeout,
            )

        dkim_task = asyncio.create_task(_run_dkim())
        blocklists_task = asyncio.create_task(_run_blocklists())
        extras_task = asyncio.create_task(_run_extras())

        async def _assemble_report() -> DomainReport:
            mx_res = await mx_task
            dns_host = await dns_host_task
            spf_res = await spf_task
            dmarc_res = await dmarc_task
            dkim_res = await dkim_task
            bl_res = await blocklists_task
            ex_res = await extras_task
            providers = await all_providers_task
            return assemble_domain_report(
                domain=norm_domain,
                mx_result=mx_res,
                dns_host=dns_host,
                spf_result=spf_res,
                dkim_result=dkim_res,
                dmarc_result=dmarc_res,
                blocklist_result=bl_res,
                extras_result=ex_res,
                detected_providers=providers,
            )

        self._mx_task = mx_task
        self._dns_host_task = dns_host_task
        self._spf_task = spf_task
        self._dmarc_task = dmarc_task
        self._dkim_task = dkim_task
        self._blocklists_task = blocklists_task
        self._extras_task = extras_task
        self._report_task = asyncio.create_task(_assemble_report())

    @property
    def mx_task(self) -> asyncio.Task[MXCheckResult]:
        self._ensure_tasks()
        assert self._mx_task is not None
        return self._mx_task

    @property
    def dns_host_task(self) -> asyncio.Task[DNSHost | None]:
        self._ensure_tasks()
        assert self._dns_host_task is not None
        return self._dns_host_task

    @property
    def spf_task(self) -> asyncio.Task[SPFCheckResult]:
        self._ensure_tasks()
        assert self._spf_task is not None
        return self._spf_task

    @property
    def dmarc_task(self) -> asyncio.Task[DMARCCheckResult]:
        self._ensure_tasks()
        assert self._dmarc_task is not None
        return self._dmarc_task

    @property
    def dkim_task(self) -> asyncio.Task[DKIMCheckResult]:
        self._ensure_tasks()
        assert self._dkim_task is not None
        return self._dkim_task

    @property
    def blocklists_task(self) -> asyncio.Task[BlocklistCheckResult]:
        self._ensure_tasks()
        assert self._blocklists_task is not None
        return self._blocklists_task

    @property
    def extras_task(self) -> asyncio.Task[ExtrasCheckResult]:
        self._ensure_tasks()
        assert self._extras_task is not None
        return self._extras_task

    @property
    def report_task(self) -> asyncio.Task[DomainReport]:
        self._ensure_tasks()
        assert self._report_task is not None
        return self._report_task


class DomainSessionStore:
    """In-memory short-lived store holding parallel domain check tasks per request."""

    def __init__(self, ttl_seconds: float = SESSION_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._sessions: dict[str, DomainCheckSession] = {}

    def _prune(self, now: float) -> None:
        expired = [k for k, sess in self._sessions.items() if now - sess.created_at > self._ttl]
        for k in expired:
            self._sessions.pop(k, None)
        while len(self._sessions) >= MAX_SESSIONS:
            oldest = next(iter(self._sessions))
            self._sessions.pop(oldest, None)

    def start_session(
        self,
        *,
        domain: str,
        display_domain: str,
        custom_selector: str | None,
        resolver: DNSResolver,
        settings: Settings,
        policy_fetcher: PolicyFetcher | None = None,
    ) -> DomainCheckSession:
        now = time.monotonic()
        self._prune(now)

        token = secrets.token_urlsafe(12)
        session = DomainCheckSession(
            token=token,
            domain=domain,
            display_domain=display_domain,
            custom_selector=custom_selector,
            created_at=now,
            _resolver=resolver,
            _settings=settings,
            _policy_fetcher=policy_fetcher,
        )
        session._ensure_tasks()
        self._sessions[token] = session
        return session

    def get(self, token: str) -> DomainCheckSession | None:
        now = time.monotonic()
        sess = self._sessions.get(token)
        if sess is None:
            return None
        if now - sess.created_at > self._ttl:
            self._sessions.pop(token, None)
            return None
        return sess
