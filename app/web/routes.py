"""HTML and htmx partial routes for DeliverCheck."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from app.checks.dkim import normalize_selector
from app.checks.fixes import suggest_dmarc_fix, suggest_spf_fix
from app.inbox.analyze import render_email_report_text
from app.report.plain_text import render_domain_report_text
from app.smtp.receive_test import render_receive_report_text, run_receive_test
from app.web.validation import validate_domain_input, validate_email_input

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()

VALID_TABS = frozenset({"domain", "server", "email"})


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


@router.get("/", response_class=HTMLResponse)
async def home(
    request: Request,
    tab: str = Query(default="domain"),
    domain: str = Query(default=""),
) -> HTMLResponse:
    active_tab = tab if tab in VALID_TABS else "domain"
    settings = request.app.state.settings
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "page_title": "DeliverCheck — Check if your email is ready to send and receive",
            "active_tab": active_tab,
            "prefill_domain": domain.strip(),
            "is_local_inbox": settings.is_local_inbox_domain,
            "inbox_port": settings.smtp_inbox_port,
        },
    )


@router.post("/domain/check", response_class=HTMLResponse)
async def start_domain_check(
    request: Request,
    domain: str = Form(default=""),
    selector: str = Form(default=""),
) -> HTMLResponse:
    decision = request.app.state.rate_limiter.check("domain", _client_ip(request))
    if not decision.allowed:
        return templates.TemplateResponse(
            request=request,
            name="partials/domain_error.html",
            status_code=429,
            context={
                "error_title": "Too many checks from this address",
                "error_message": (
                    f"Rate limit reached. Please wait {decision.retry_after_seconds} seconds "
                    "before running another domain check."
                ),
                "suggested_domain": None,
            },
        )

    validation = validate_domain_input(domain)
    if not validation.ok or not validation.domain:
        return templates.TemplateResponse(
            request=request,
            name="partials/domain_error.html",
            status_code=400,
            context={
                "error_title": "Check your domain name",
                "error_message": validation.error or "Please enter a valid domain name.",
                "suggested_domain": validation.suggested_domain,
            },
        )

    clean_selector = normalize_selector(selector)
    session = request.app.state.domain_sessions.start_session(
        domain=validation.domain,
        display_domain=validation.display_domain or validation.domain,
        custom_selector=clean_selector,
        resolver=request.app.state.resolver,
        settings=request.app.state.settings,
        policy_fetcher=request.app.state.policy_fetcher,
    )

    return templates.TemplateResponse(
        request=request,
        name="partials/domain_shell.html",
        context={
            "session": session,
        },
    )


@router.get("/domain/sections/{token}/{section}", response_class=HTMLResponse)
async def domain_section(request: Request, token: str, section: str) -> HTMLResponse:
    session = request.app.state.domain_sessions.get(token)
    if session is None:
        return templates.TemplateResponse(
            request=request,
            name="partials/domain_error.html",
            status_code=404,
            context={
                "error_title": "Report session expired",
                "error_message": (
                    "This check session expired. Enter the domain again to run a fresh check."
                ),
                "suggested_domain": None,
            },
        )

    if section == "summary":
        report = await session.report_task
        plain_text = render_domain_report_text(report)
        return templates.TemplateResponse(
            request=request,
            name="partials/domain_summary.html",
            context={
                "token": token,
                "report": report,
                "plain_text_report": plain_text,
            },
        )

    if section == "mx":
        mx_result = await session.mx_task
        return templates.TemplateResponse(
            request=request,
            name="partials/section_mx.html",
            context={"mx": mx_result},
        )

    if section == "spf":
        mx_result = await session.mx_task
        spf_result = await session.spf_task
        providers = list(spf_result.detected_providers)
        if mx_result.provider and all(p.id != mx_result.provider.id for p in providers):
            providers.insert(0, mx_result.provider)
        spf_suggestion = suggest_spf_fix(spf_result, providers)
        dns_host = await session.dns_host_task
        return templates.TemplateResponse(
            request=request,
            name="partials/section_spf.html",
            context={
                "spf": spf_result,
                "spf_suggestion": spf_suggestion,
                "dns_host": dns_host,
            },
        )

    if section == "dkim":
        dkim_result = await session.dkim_task
        return templates.TemplateResponse(
            request=request,
            name="partials/section_dkim.html",
            context={"dkim": dkim_result},
        )

    if section == "dmarc":
        dmarc_result = await session.dmarc_task
        dmarc_suggestion = suggest_dmarc_fix(dmarc_result)
        dns_host = await session.dns_host_task
        return templates.TemplateResponse(
            request=request,
            name="partials/section_dmarc.html",
            context={
                "dmarc": dmarc_result,
                "dmarc_suggestion": dmarc_suggestion,
                "dns_host": dns_host,
            },
        )

    if section == "blocklists":
        blocklists_result = await session.blocklists_task
        return templates.TemplateResponse(
            request=request,
            name="partials/section_blocklists.html",
            context={"blocklists": blocklists_result},
        )

    if section == "extras":
        extras_result = await session.extras_task
        return templates.TemplateResponse(
            request=request,
            name="partials/section_extras.html",
            context={"extras": extras_result},
        )

    return templates.TemplateResponse(
        request=request,
        name="partials/domain_error.html",
        status_code=404,
        context={
            "error_title": "Unknown report section",
            "error_message": f"Section '{section}' does not exist.",
            "suggested_domain": None,
        },
    )


@router.get("/domain/report/{token}.txt", response_class=PlainTextResponse)
async def domain_report_plain_text(request: Request, token: str) -> PlainTextResponse:
    session = request.app.state.domain_sessions.get(token)
    if session is None:
        return PlainTextResponse("Report session expired.", status_code=404)
    report = await session.report_task
    return PlainTextResponse(render_domain_report_text(report))


@router.post("/server/receive", response_class=HTMLResponse)
async def test_mail_server_receive(
    request: Request,
    email: str = Form(default=""),
) -> HTMLResponse:
    decision = request.app.state.rate_limiter.check("server", _client_ip(request))
    if not decision.allowed:
        return templates.TemplateResponse(
            request=request,
            name="partials/domain_error.html",
            status_code=429,
            context={
                "error_title": "Too many server tests from this address",
                "error_message": (
                    f"Server tests open live connections and are strictly rate-limited. "
                    f"Please wait {decision.retry_after_seconds} seconds and try again."
                ),
                "suggested_domain": None,
            },
        )

    validation = validate_email_input(email)
    if not validation.ok or not validation.email:
        return templates.TemplateResponse(
            request=request,
            name="partials/domain_error.html",
            status_code=400,
            context={
                "error_title": "Check your email address",
                "error_message": validation.error or "Please enter a valid email address.",
                "suggested_domain": None,
            },
        )

    receive_runner = getattr(request.app.state, "receive_test_runner", None) or run_receive_test
    report = await receive_runner(validation.email, request.app.state.resolver)
    plain_text = render_receive_report_text(report)

    return templates.TemplateResponse(
        request=request,
        name="partials/server_receive_report.html",
        context={
            "report": report,
            "plain_text_report": plain_text,
        },
    )


@router.post("/inbox/new", response_class=HTMLResponse)
async def create_test_inbox_address(request: Request) -> HTMLResponse:
    decision = request.app.state.rate_limiter.check("inbox", _client_ip(request))
    if not decision.allowed:
        return templates.TemplateResponse(
            request=request,
            name="partials/domain_error.html",
            status_code=429,
            context={
                "error_title": "Too many test addresses created",
                "error_message": (
                    f"Please wait {decision.retry_after_seconds} seconds before creating "
                    "another temporary test address."
                ),
                "suggested_domain": None,
            },
        )

    store = request.app.state.inbox_store
    slot = store.create_slot()
    settings = request.app.state.settings
    mins = max(1, (slot.seconds_remaining(store.now()) + 59) // 60)

    return templates.TemplateResponse(
        request=request,
        name="partials/inbox_waiting.html",
        context={
            "slot": slot,
            "minutes_remaining": mins,
            "is_local_inbox": settings.is_local_inbox_domain,
            "inbox_port": settings.smtp_inbox_port,
        },
    )


@router.get("/inbox/poll/{token}", response_class=HTMLResponse)
async def poll_test_inbox(request: Request, token: str) -> HTMLResponse:
    store = request.app.state.inbox_store
    slot = store.get(token)
    if slot is None:
        return templates.TemplateResponse(
            request=request,
            name="partials/domain_error.html",
            status_code=404,
            context={
                "error_title": "Test address expired",
                "error_message": (
                    "Temporary test addresses expire automatically after 15 minutes. "
                    "Create a new test address to send another message."
                ),
                "suggested_domain": None,
            },
        )

    if slot.analysis is not None:
        return templates.TemplateResponse(
            request=request,
            name="partials/email_report.html",
            context={
                "token": slot.token,
                "address": slot.address,
                "report": slot.analysis,
                "plain_text_report": render_email_report_text(slot.analysis),
            },
        )

    settings = request.app.state.settings
    mins = max(1, (slot.seconds_remaining(store.now()) + 59) // 60)
    return templates.TemplateResponse(
        request=request,
        name="partials/inbox_waiting.html",
        context={
            "slot": slot,
            "minutes_remaining": mins,
            "is_local_inbox": settings.is_local_inbox_domain,
            "inbox_port": settings.smtp_inbox_port,
        },
    )
