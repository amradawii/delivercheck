"""Mail provider, sending service, and DNS host fingerprints (mid-2024)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from fnmatch import fnmatch

from app.dns.resolver import DNSResolver, DNSStatus, normalize_dns_name


@dataclass(frozen=True)
class MailProvider:
    id: str
    name: str
    role: str  # "mailbox" or "sender"
    mx_patterns: tuple[str, ...] = ()
    spf_includes: tuple[str, ...] = ()
    # True when this provider requires a root SPF include when detected
    requires_root_spf_include: bool = True
    # Recommended canonical SPF include (used when suggesting fixes)
    recommended_spf_include: str | None = None
    dkim_selectors: tuple[str, ...] = ()
    dkim_cname_patterns: tuple[str, ...] = ()
    # True when the provider generates random/custom selectors that cannot be reliably guessed
    has_unprobeable_dkim: bool = False
    txt_verification_prefixes: tuple[str, ...] = ()
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_auth_hint: str | None = None
    recommended_mx: str | None = None


@dataclass(frozen=True)
class DNSHost:
    id: str
    name: str
    ns_patterns: tuple[str, ...]
    guide_url: str


MAIL_PROVIDERS: tuple[MailProvider, ...] = (
    MailProvider(
        id="google_workspace",
        name="Google Workspace",
        role="mailbox",
        mx_patterns=(
            "smtp.google.com",
            "aspmx.l.google.com",
            "*.aspmx.l.google.com",
            "aspmx*.googlemail.com",
            "*.aspmx.l.googlemail.com",
        ),
        spf_includes=("_spf.google.com",),
        requires_root_spf_include=True,
        recommended_spf_include="_spf.google.com",
        dkim_selectors=("google",),
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_auth_hint=(
            "Google accounts with 2-Step Verification require an App Password for SMTP login."
        ),
        recommended_mx="1 smtp.google.com",
    ),
    MailProvider(
        id="microsoft_365",
        name="Microsoft 365",
        role="mailbox",
        mx_patterns=("*.mail.protection.outlook.com",),
        spf_includes=("spf.protection.outlook.com",),
        requires_root_spf_include=True,
        recommended_spf_include="spf.protection.outlook.com",
        dkim_selectors=("selector1", "selector2"),
        dkim_cname_patterns=("*.onmicrosoft.com", "*.dkim.mail.microsoft"),
        smtp_host="smtp.office365.com",
        smtp_port=587,
        smtp_auth_hint=(
            "Microsoft 365 disables SMTP AUTH by default under Security Defaults. "
            "App passwords will not work unless SMTP AUTH is enabled for the mailbox."
        ),
    ),
    MailProvider(
        id="zoho",
        name="Zoho Mail",
        role="mailbox",
        mx_patterns=(
            "mx*.zoho.com",
            "mx*.zoho.eu",
            "mx*.zoho.in",
            "mx*.zoho.com.au",
            "mx*.zoho.jp",
            "mx*.zohomail.com",
            "mx*.zohomail.eu",
            "mx*.zohomail.in",
            "mx*.zohomail.com.au",
        ),
        spf_includes=(
            "zoho.com",
            "zoho.eu",
            "zoho.in",
            "zoho.com.au",
            "zohomail.com",
            "zohomail.eu",
            "zohomail.in",
        ),
        requires_root_spf_include=True,
        recommended_spf_include="zoho.com",
        dkim_selectors=("zmail", "zoho"),
        has_unprobeable_dkim=True,
        smtp_host="smtp.zoho.com",
        smtp_port=587,
        smtp_auth_hint=(
            "Use your Zoho App Password if two-factor authentication is enabled "
            "(and match your regional host such as smtp.zoho.eu or smtp.zoho.in)."
        ),
    ),
    MailProvider(
        id="hostinger",
        name="Hostinger",
        role="mailbox",
        mx_patterns=("mx1.hostinger.com", "mx2.hostinger.com", "*.hostinger.com"),
        spf_includes=("_spf.mail.hostinger.com",),
        requires_root_spf_include=True,
        recommended_spf_include="_spf.mail.hostinger.com",
        dkim_selectors=("hostingermail-a", "hostingermail-b", "hostingermail-c"),
        dkim_cname_patterns=("*.dkim.mail.hostinger.com",),
        smtp_host="smtp.hostinger.com",
        smtp_port=465,
        smtp_auth_hint="Use your full Hostinger mailbox address and mailbox password.",
    ),
    MailProvider(
        id="cpanel",
        name="cPanel",
        role="mailbox",
        mx_patterns=(),
        spf_includes=(),
        requires_root_spf_include=False,
        dkim_selectors=("default",),
        smtp_host=None,
        smtp_port=465,
        smtp_auth_hint=(
            "Use mail.<your-domain> or your hosting server hostname with your mailbox password."
        ),
    ),
    MailProvider(
        id="shopify",
        name="Shopify",
        role="sender",
        mx_patterns=(),
        # Legacy include recognized for detection only; modern Shopify Email uses CNAMEs.
        spf_includes=("shops.shopify.com",),
        requires_root_spf_include=False,
        recommended_spf_include=None,
        dkim_selectors=(),
        dkim_cname_patterns=("*.email.myshopify.com",),
        has_unprobeable_dkim=True,
        smtp_host=None,
    ),
    MailProvider(
        id="klaviyo",
        name="Klaviyo",
        role="sender",
        mx_patterns=(),
        spf_includes=(),
        requires_root_spf_include=False,
        recommended_spf_include=None,
        dkim_selectors=("kl", "kl2", "km1", "km2"),
        dkim_cname_patterns=("*.klaviyodns.com", "*.klaviyo.com"),
        txt_verification_prefixes=("klaviyo-site-verification=",),
        smtp_host=None,
    ),
    MailProvider(
        id="mailchimp",
        name="Mailchimp",
        role="sender",
        mx_patterns=(),
        spf_includes=("servers.mcsv.net",),
        requires_root_spf_include=False,
        recommended_spf_include=None,
        dkim_selectors=("k2", "k3", "k1"),
        dkim_cname_patterns=("*.mcsv.net", "*.mailchimp.com"),
        smtp_host=None,
        smtp_auth_hint=(
            "Mailchimp marketing does not offer direct SMTP submission "
            "(only Mailchimp Transactional / Mandrill uses smtp.mandrillapp.com)."
        ),
    ),
    MailProvider(
        id="sendgrid",
        name="SendGrid",
        role="sender",
        mx_patterns=(),
        spf_includes=("sendgrid.net",),
        requires_root_spf_include=True,
        recommended_spf_include="sendgrid.net",
        dkim_selectors=("s1", "s2"),
        dkim_cname_patterns=("*.sendgrid.net",),
        smtp_host="smtp.sendgrid.net",
        smtp_port=587,
        smtp_auth_hint="Use 'apikey' as the username and a SendGrid API key as the password.",
    ),
    MailProvider(
        id="amazon_ses",
        name="Amazon SES",
        role="sender",
        mx_patterns=("inbound-smtp.*.amazonaws.com",),
        spf_includes=("amazonses.com",),
        requires_root_spf_include=True,
        recommended_spf_include="amazonses.com",
        dkim_selectors=(),
        dkim_cname_patterns=("*.dkim.amazonses.com",),
        has_unprobeable_dkim=True,
        smtp_host="email-smtp.us-east-1.amazonaws.com",
        smtp_port=587,
        smtp_auth_hint=(
            "Use your Amazon SES SMTP credentials (not IAM console password) "
            "and match your AWS region host."
        ),
    ),
)

PROVIDERS_BY_ID: dict[str, MailProvider] = {p.id: p for p in MAIL_PROVIDERS}

# Default fallback selectors probed when no provider-specific selector matches
COMMON_DKIM_SELECTORS: tuple[str, ...] = (
    "google",
    "selector1",
    "selector2",
    "default",
    "k2",
    "k3",
    "k1",
    "s1",
    "s2",
    "mail",
    "dkim",
)

DNS_HOSTS: tuple[DNSHost, ...] = (
    DNSHost(
        id="cloudflare",
        name="Cloudflare",
        ns_patterns=("*.ns.cloudflare.com",),
        guide_url="https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/",
    ),
    DNSHost(
        id="godaddy",
        name="GoDaddy",
        ns_patterns=("*.domaincontrol.com",),
        guide_url="https://www.godaddy.com/help/manage-dns-records-680",
    ),
    DNSHost(
        id="namecheap",
        name="Namecheap",
        ns_patterns=("*.registrar-servers.com", "*.namecheaphosting.com"),
        guide_url=(
            "https://www.namecheap.com/support/knowledgebase/article.aspx/317/2237/"
            "how-do-i-add-txtspfdkimdmarc-records-for-my-domain/"
        ),
    ),
    DNSHost(
        id="hostinger",
        name="Hostinger",
        ns_patterns=("*.dns-parking.com", "*.hostinger.com"),
        guide_url="https://www.hostinger.com/tutorials/how-to-manage-dns-records",
    ),
    DNSHost(
        id="route53",
        name="Amazon Route 53",
        ns_patterns=(
            "*.awsdns-*.com",
            "*.awsdns-*.net",
            "*.awsdns-*.org",
            "*.awsdns-*.co.uk",
        ),
        guide_url="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/rrsets-working-with.html",
    ),
    DNSHost(
        id="google_cloud_dns",
        name="Google Cloud DNS",
        ns_patterns=("*.googledomains.com",),
        guide_url="https://cloud.google.com/dns/docs/records",
    ),
    DNSHost(
        id="squarespace",
        name="Squarespace Domains",
        ns_patterns=("*.squarespacedns.com",),
        guide_url="https://support.squarespace.com/hc/en-us/articles/360002101888-Adding-custom-DNS-records-to-your-Squarespace-managed-domain",
    ),
    DNSHost(
        id="digitalocean",
        name="DigitalOcean",
        ns_patterns=("*.digitalocean.com",),
        guide_url="https://docs.digitalocean.com/products/networking/dns/how-to/manage-records/",
    ),
    DNSHost(
        id="porkbun",
        name="Porkbun",
        ns_patterns=("*.porkbun.com",),
        guide_url="https://kb.porkbun.com/article/68-how-to-edit-dns-records",
    ),
    DNSHost(
        id="azure_dns",
        name="Microsoft Azure DNS",
        ns_patterns=(
            "*.azure-dns.com",
            "*.azure-dns.net",
            "*.azure-dns.org",
            "*.azure-dns.info",
        ),
        guide_url="https://learn.microsoft.com/en-us/azure/dns/dns-getstarted-portal",
    ),
    DNSHost(
        id="hetzner",
        name="Hetzner",
        ns_patterns=("*.hetzner.com", "*.hetzner.de", "*.ns.hetzner.de"),
        guide_url="https://docs.hetzner.com/dns-console/dns/manage-dns-records/",
    ),
    DNSHost(
        id="ovh",
        name="OVHcloud",
        ns_patterns=("*.ovh.net", "*.anycast.me"),
        guide_url="https://help.ovhcloud.com/csm/en-dns-edit-dns-zone",
    ),
    DNSHost(
        id="wix",
        name="Wix",
        ns_patterns=("*.wixdns.net",),
        guide_url="https://support.wix.com/en/article/adding-or-updating-txt-records-in-your-wix-account",
    ),
)


def _matches_any(value: str, patterns: Sequence[str]) -> bool:
    lower = value.strip().rstrip(".").lower()
    return any(fnmatch(lower, pattern) for pattern in patterns)


def detect_mail_provider_from_mx(mx_hosts: Sequence[str]) -> MailProvider | None:
    """Detect the primary mailbox provider from MX hostnames."""
    for host in mx_hosts:
        cleaned = host.strip().rstrip(".").lower()
        if not cleaned or cleaned == ".":
            continue
        for provider in MAIL_PROVIDERS:
            if provider.mx_patterns and _matches_any(cleaned, provider.mx_patterns):
                return provider
    return None


def resolve_smtp_host_for_provider(
    provider: MailProvider | None,
    mx_hosts: Sequence[str] = (),
) -> str | None:
    """Return the pre-filled SMTP submission host, respecting regional Zoho hosts."""
    if provider is None:
        return None
    if provider.id == "zoho":
        for host in mx_hosts:
            lower = host.lower()
            if lower.endswith(".zoho.eu") or lower.endswith(".zohomail.eu"):
                return "smtp.zoho.eu"
            if lower.endswith(".zoho.in") or lower.endswith(".zohomail.in"):
                return "smtp.zoho.in"
            if lower.endswith(".zoho.com.au") or lower.endswith(".zohomail.com.au"):
                return "smtp.zoho.com.au"
            if lower.endswith(".zoho.jp"):
                return "smtp.zoho.jp"
        return "smtp.zoho.com"
    return provider.smtp_host


def detect_providers_from_spf_includes(includes: Sequence[str]) -> list[MailProvider]:
    """Detect mailbox/sending providers referenced via SPF include targets."""
    found: list[MailProvider] = []
    seen_ids: set[str] = set()
    for target in includes:
        lower = target.strip().rstrip(".").lower()
        for provider in MAIL_PROVIDERS:
            if provider.id in seen_ids:
                continue
            if any(lower == inc or lower.endswith(f".{inc}") for inc in provider.spf_includes):
                found.append(provider)
                seen_ids.add(provider.id)
    return found


def detect_providers_from_txt(txt_records: Sequence[str]) -> list[MailProvider]:
    """Detect sending services from root TXT verification records (e.g. Klaviyo)."""
    found: list[MailProvider] = []
    seen_ids: set[str] = set()
    for record in txt_records:
        lower = record.strip().lower()
        for provider in MAIL_PROVIDERS:
            if provider.id in seen_ids or not provider.txt_verification_prefixes:
                continue
            if any(lower.startswith(prefix) for prefix in provider.txt_verification_prefixes):
                found.append(provider)
                seen_ids.add(provider.id)
    return found


def detect_provider_from_dkim_cname(cname_target: str) -> MailProvider | None:
    """Detect a provider from a DKIM record's CNAME target."""
    cleaned = cname_target.strip().rstrip(".").lower()
    if not cleaned:
        return None
    for provider in MAIL_PROVIDERS:
        if provider.dkim_cname_patterns and _matches_any(cleaned, provider.dkim_cname_patterns):
            return provider
    return None


def detect_dns_host(ns_records: Sequence[str]) -> DNSHost | None:
    """Detect the domain's DNS host from NS hostnames."""
    for ns in ns_records:
        cleaned = ns.strip().rstrip(".").lower()
        if not cleaned:
            continue
        for host in DNS_HOSTS:
            if _matches_any(cleaned, host.ns_patterns):
                return host
    return None


async def detect_dns_host_for_domain(domain: str, resolver: DNSResolver) -> DNSHost | None:
    """Query NS records for a domain and detect its DNS host."""
    norm = normalize_dns_name(domain)
    ns_resp = await resolver.query(norm, "NS")
    if ns_resp.status != DNSStatus.OK or not ns_resp.records:
        return None
    return detect_dns_host(ns_resp.records)


def selectors_for_providers(providers: Sequence[MailProvider]) -> list[str]:
    """Build an ordered, deduplicated list of DKIM selectors to probe for detected providers."""
    ordered: list[str] = []
    seen: set[str] = set()
    for provider in providers:
        for selector in provider.dkim_selectors:
            if selector not in seen:
                ordered.append(selector)
                seen.add(selector)
    if not ordered:
        return list(COMMON_DKIM_SELECTORS)
    # Always include cPanel 'default' as a low-cost fallback if not already present
    if "default" not in seen:
        ordered.append("default")
    return ordered
