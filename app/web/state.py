"""Short-lived in-memory session store for streaming domain check sections via htmx."""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field

from app.checks.blocklists import BlocklistCheckResult, check_blocklists
from app.checks.dkim import DKIMCheckResult, check_dkim
from app.checks.dmarc import DMARCCheckResult, check_dmarc
from app.checks.domain import _as_severity, _extract_single_spf_ips
from app.checks.extras import ExtrasCheckResult, PolicyFetcher, check_extras
from app.checks.fixes import suggest_dmarc_fix, suggest_spf_fix
from app.checks.mx import MXCheckResult, check_mx
from app.checks.requirements import evaluate_sender_requirements
from app.checks.spf import SPFCheckResult, check_spf
from app.config import Settings
from app.dns.providers import (
    DNSHost,
    MailProvider,
    detect_dns_host_for_domain,
    detect_providers_from_txt,
)
from app.dns.resolver import CachedDNSResolver, DNSResolver, DNSStatus, normalize_dns_name
from app.report.models import DomainReport, Finding, build_verdict, sort_findings

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
        policy_fetcher = self._policy_fetcher
        custom_selector = self.custom_selector

        mx_task = asyncio.create_task(check_mx(norm_domain, scoped))
        dns_host_task = asyncio.create_task(detect_dns_host_for_domain(norm_domain, scoped))
        root_txt_task = asyncio.create_task(scoped.query(norm_domain, "TXT"))
        dmarc_task = asyncio.create_task(check_dmarc(norm_domain, scoped))

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
            return await check_spf(norm_domain, scoped, detected_providers=providers)

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
            return await check_dkim(
                norm_domain,
                scoped,
                detected_providers=providers,
                custom_selector=custom_selector,
            )

        async def _run_blocklists() -> BlocklistCheckResult:
            mx_res, spf_res = await asyncio.gather(mx_task, spf_task)
            ips: list[str] = []
            for host in mx_res.hosts:
                ips.extend(host.all_ips)
            ips.extend(_extract_single_spf_ips(spf_res.ip4_networks, spf_res.ip6_networks))
            return await check_blocklists(
                norm_domain,
                scoped,
                ips=ips,
                spamhaus_dqs_key=settings.spamhaus_dqs_key,
                enable_barracuda_brbl=settings.enable_barracuda_brbl,
            )

        async def _run_extras() -> ExtrasCheckResult:
            mx_res, dmarc_res = await asyncio.gather(mx_task, dmarc_task)
            return await check_extras(
                norm_domain,
                scoped,
                mx_result=mx_res,
                dmarc_result=dmarc_res,
                policy_fetcher=policy_fetcher,
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
            full_providers = list(providers)
            for p in dkim_res.detected_providers:
                if all(existing.id != p.id for existing in full_providers):
                    full_providers.append(p)

            mailbox_provider = mx_res.provider
            sending_providers = tuple(
                p for p in full_providers if mailbox_provider is None or p.id != mailbox_provider.id
            )
            checklist = evaluate_sender_requirements(spf_res, dkim_res, dmarc_res)
            spf_sug = suggest_spf_fix(spf_res, full_providers)
            dmarc_sug = suggest_dmarc_fix(dmarc_res)

            findings: list[Finding] = []
            for mx_i in mx_res.issues:
                findings.append(
                    Finding(
                        section="MX",
                        severity=_as_severity(mx_i.severity),
                        title=mx_i.title,
                        summary=mx_i.detail,
                        fix=mx_i.fix,
                        record_value=mx_i.record_value,
                        record_host="@",
                    )
                )
            for spf_i in spf_res.issues:
                rec_val = spf_i.record_value
                if rec_val is None and spf_sug and spf_sug.record and spf_i.severity == "fail":
                    rec_val = spf_sug.record
                findings.append(
                    Finding(
                        section="SPF",
                        severity=_as_severity(spf_i.severity),
                        title=spf_i.title,
                        summary=spf_i.detail,
                        fix=spf_i.fix,
                        record_value=rec_val,
                        record_host="@",
                    )
                )
            for dkim_i in dkim_res.issues:
                findings.append(
                    Finding(
                        section="DKIM",
                        severity=_as_severity(dkim_i.severity),
                        title=dkim_i.title,
                        summary=dkim_i.detail,
                        fix=dkim_i.fix,
                        record_value=dkim_i.record_value,
                    )
                )
            dmarc_host = f"_dmarc.{dmarc_res.record_domain or dmarc_res.organizational_domain}"
            for dmarc_i in dmarc_res.issues:
                findings.append(
                    Finding(
                        section="DMARC",
                        severity=_as_severity(dmarc_i.severity),
                        title=dmarc_i.title,
                        summary=dmarc_i.detail,
                        fix=dmarc_i.fix,
                        record_value=dmarc_i.record_value,
                        record_host=dmarc_host if dmarc_i.record_value else None,
                    )
                )
            for bl_i in bl_res.issues:
                findings.append(
                    Finding(
                        section="Blocklists",
                        severity=_as_severity(bl_i.severity),
                        title=bl_i.title,
                        summary=bl_i.detail,
                        fix=bl_i.fix,
                    )
                )
            for ex_i in ex_res.issues:
                findings.append(
                    Finding(
                        section="Extras",
                        severity=_as_severity(ex_i.severity),
                        title=ex_i.title,
                        summary=ex_i.detail,
                        fix=ex_i.fix,
                    )
                )

            sorted_findings = sort_findings(findings)
            verdict_status, verdict_line = build_verdict(
                sorted_findings,
                checklist,
                is_null_mx=mx_res.is_null_mx,
            )
            return DomainReport(
                domain=norm_domain,
                verdict_status=verdict_status,
                verdict_line=verdict_line,
                mailbox_provider=mailbox_provider,
                sending_providers=sending_providers,
                dns_host=dns_host,
                checklist=checklist,
                mx=mx_res,
                spf=spf_res,
                dkim=dkim_res,
                dmarc=dmarc_res,
                blocklists=bl_res,
                extras=ex_res,
                spf_suggestion=spf_sug,
                dmarc_suggestion=dmarc_sug,
                findings=sorted_findings,
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
    """In-memory store holding active streaming domain checks so sections share DNS results."""

    def __init__(self, ttl_seconds: float = SESSION_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._sessions: dict[str, DomainCheckSession] = {}

    def _prune(self) -> None:
        now = time.monotonic()
        expired = [
            tok for tok, sess in self._sessions.items() if now - sess.created_at > self._ttl_seconds
        ]
        for tok in expired:
            self._sessions.pop(tok, None)
        while len(self._sessions) >= MAX_SESSIONS:
            oldest_key = next(iter(self._sessions))
            self._sessions.pop(oldest_key, None)

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
        self._prune()
        token = secrets.token_urlsafe(12)
        session = DomainCheckSession(
            token=token,
            domain=normalize_dns_name(domain),
            display_domain=display_domain,
            custom_selector=custom_selector,
            created_at=time.monotonic(),
            _resolver=resolver,
            _settings=settings,
            _policy_fetcher=policy_fetcher,
        )
        session._ensure_tasks()
        self._sessions[token] = session
        return session

    def get(self, token: str) -> DomainCheckSession | None:
        self._prune()
        return self._sessions.get(token)
