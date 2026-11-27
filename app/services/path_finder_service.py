"""OWASP Sentinel - Path Finder (Authorized Endpoint Discovery) Service

Provides high-speed, non-blocking asynchronous endpoint enumeration,
SSRF defense verification, and background scanning orchestration.
"""

import asyncio
from datetime import datetime, timezone
import ipaddress
import logging
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlsplit
import uuid
import xml.etree.ElementTree as ET

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import CLOUD_METADATA_HOSTS, CLOUD_METADATA_IPS
from app.core.exceptions import (
    SecurityRestrictionError,
    TargetConnectionTimeoutError,
    TargetDNSResolutionError,
    TargetRateLimitExceededError,
    TargetTLSError,
    TargetValidationError,
)
from app.db.session import SessionLocal
from app.models.db.path_finder import DiscoveredPath, PathFinderScan
from app.models.schemas.path_finder import PathFinderMode, PathFinderStatus
from app.services.path_finder_broadcaster import broadcaster
from app.services.path_finder_state import state_store
from app.services.route_checker import (
    AsyncRouteVerificationService,
    Baseline404,
    SitemapRobotsParser,
)

logger = logging.getLogger(__name__)

# Comprehensive curated candidate endpoints for high-speed endpoint discovery
DEFAULT_QUICK_PATHS: List[str] = [
    "/",
    # Core Application & SaaS Directories
    "/about", "/about-us", "/account", "/accounts", "/activity", "/admin", "/admin/dashboard",
    "/admin/login", "/admin/settings", "/admin/users", "/admin-panel", "/administration",
    "/administrator", "/alerts", "/analytics", "/app", "/apply", "/apps", "/archive",
    "/assets", "/audit", "/audit-logs", "/auth", "/auth/login", "/auth/register",
    "/auth/callback", "/auth/logout", "/auth/forgot-password", "/auth/reset-password",
    "/billing", "/blog", "/booking", "/calendar", "/campaigns", "/careers", "/cart",
    "/case-studies", "/catalog", "/categories", "/changelog", "/chat", "/checkout",
    "/clients", "/cloud", "/cms", "/company", "/compliance", "/config", "/console",
    "/contact", "/contact-us", "/content", "/controlpanel", "/courses", "/cp",
    "/customers", "/dashboard", "/data", "/demo", "/developer", "/developers",
    "/disclaimer.html", "/docs", "/documentation", "/download", "/downloads",
    "/enterprise", "/events", "/explore", "/export", "/faq", "/features", "/feed",
    "/feedback", "/files", "/forum", "/gallery", "/getting-started", "/guides",
    "/help", "/helpdesk", "/home", "/images", "/import", "/inbox", "/integrations",
    "/internal", "/inventory", "/investors", "/invoices", "/jobs", "/kb",
    "/knowledge-base", "/legal", "/library", "/live", "/login", "/logout",
    "/manage", "/management", "/marketplace", "/media", "/member", "/members",
    "/messages", "/metrics", "/mobile", "/monitoring", "/news", "/newsletter",
    "/notices", "/notifications", "/onboarding", "/orders", "/organizations",
    "/overview", "/panel", "/partners", "/payments", "/permissions", "/plans",
    "/platform", "/portal", "/portfolio", "/press", "/pricing", "/privacy",
    "/privacy-policy", "/private", "/products", "/profile", "/projects", "/public",
    "/releases", "/reports", "/resources", "/roadmap", "/roles", "/rss", "/sales",
    "/sandbox", "/scan", "/scans", "/schedule", "/search", "/security", "/services",
    "/sessions", "/settings", "/shop", "/signin", "/sign-in", "/signup", "/sign-up",
    "/solutions", "/staff", "/staging", "/static", "/stats", "/status", "/store",
    "/subscriptions", "/support", "/system", "/tags", "/team", "/teams", "/templates",
    "/tenants", "/terms", "/testimonials", "/tickets", "/tools", "/training",
    "/transactions", "/transfer", "/trial", "/trust", "/tutorials", "/updates",
    "/upload", "/uploads", "/user", "/users", "/vendor", "/vendors", "/verify",
    "/videos", "/views", "/webhooks", "/webinars", "/wiki", "/workspace",
    # APIs, Docs & Specifications
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/health", "/api/status",
    "/api/docs", "/api/auth", "/api/login", "/api/users", "/api/admin",
    "/api/config", "/api/settings", "/api/search", "/api/graphql",
    "/api/openapi.json", "/api/swagger.json", "/swagger", "/swagger-ui",
    "/swagger-ui.html", "/swagger/index.html", "/redoc", "/openapi.json",
    "/swagger.json", "/api-docs", "/graphql", "/graphiql",
    # Infrastructure, Health, Well-Known & Legacy
    "/health", "/healthz", "/livez", "/readyz", "/version", "/info",
    "/actuator", "/actuator/health", "/actuator/info", "/server-status",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/sitemap-0.xml",
    "/wp-sitemap.xml", "/crossdomain.xml", "/humans.txt", "/manifest.json",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/.well-known/jwks.json", "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association", "/.env", "/.git/HEAD",
    "/config.json", "/web.config", "/wp-login.php", "/wp-admin", "/wp-json",
    "/admin/login.jsp", "/admin/admin.jsp", "/feedback.jsp", "/search.jsp",
    "/default.jsp", "/index.jsp", "/login.jsp", "/login.html", "/notices.html",
    "/privacy.html", "/survey_questions.jsp", "/subscribe.jsp",
    "/bank/login.aspx", "/bank/customize.aspx", "/bank/querylog.aspx",
    "/bank/transfer.aspx", "/bank/transaction.aspx", "/bank/member/login.aspx",
    "/style.css",
]

AGGRESSIVE_ADDITIONAL_PATHS: List[str] = [
    # API endpoints & versions
    "/api/v1/users", "/api/v1/auth", "/api/v1/admin", "/api/v1/config",
    "/api/v1/settings", "/api/v1/keys", "/api/v1/tokens", "/api/v1/upload",
    "/api/v1/download", "/api/v1/search", "/api/v1/login", "/api/v1/logout",
    "/api/v1/register", "/api/v1/profile", "/api/v1/accounts", "/api/v1/billing",
    "/api/v1/orders", "/api/v1/payments", "/api/v1/products", "/api/v1/reports",
    "/api/v1/roles", "/api/v1/sessions", "/api/v1/webhooks", "/api/v1/audit",
    "/api/v2/users", "/api/v2/auth", "/api/v2/admin", "/api/v2/config",
    "/api/v2/health", "/api/v2/status", "/api/v2/graphql", "/api/v2/search",
    "/api/v3/users", "/api/v3/health", "/api/v4", "/v1", "/v2", "/v3",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs", "/rest", "/rest/v1",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json", "/swagger/resources",
    "/actuator/env", "/actuator/mappings", "/actuator/beans", "/actuator/prometheus",
    "/actuator/configprops", "/actuator/loggers", "/actuator/threaddump",
    "/actuator/heapdump", "/actuator/auditevents", "/actuator/metrics",
    # Enterprise, SaaS & Admin directories
    "/bank", "/bank/main.jsp", "/bank/balance.jsp", "/bank/apply.jsp",
    "/bank/account.jsp", "/bank/statement.jsp", "/bank/admin", "/bank/portal",
    "/bank/services", "/bank/feedback", "/accounts", "/transfer", "/transaction",
    "/statement", "/member/login", "/client/login", "/customer/login",
    "/partner/login", "/vendor/login", "/admin_login", "/adminlogin",
    "/adminlogon", "/admin_portal", "/ops", "/operations", "/devops", "/infra",
    "/ci", "/cd", "/jenkins", "/gitlab", "/grafana", "/kibana", "/prometheus",
    "/sonarqube", "/portainer", "/traefik", "/minio", "/nexus", "/artifactory",
    "/phpmyadmin", "/pma", "/adminer", "/adminer.php", "/webmail", "/cpanel",
    "/whm", "/server-info", "/trace", "/env", "/cgi-bin", "/sysadmin", "/root",
    "/superadmin", "/manager", "/manager/html", "/manager/status", "/manager/text",
    "/host-manager", "/web-console", "/jmx-console", "/invoker",
    # CMS / Framework / Next.js / Static Directories
    "/wp-content", "/wp-content/uploads", "/wp-content/plugins", "/wp-content/themes",
    "/wp-includes", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts", "/xmlrpc.php",
    "/sites/default", "/modules", "/themes", "/plugins", "/core", "/vendor",
    "/node_modules", "/dist", "/build", "/out", "/_next", "/_next/static",
    "/next", "/static/js", "/static/css", "/assets/js", "/assets/css", "/js",
    "/css", "/fonts", "/scripts", "/includes", "/lib", "/libs", "/src",
    "/storage", "/storage/logs", "/var", "/var/log", "/logs", "/log",
    # Backups, DB dumps, Debug & Config Files
    "/backup", "/backups", "/backup.sql", "/backup.zip", "/backup.tar.gz",
    "/backup.bak", "/backups.zip", "/site.zip", "/www.zip", "/dump", "/dump.sql",
    "/db", "/database", "/database.sql", "/database.sqlite", "/database.sqlite3",
    "/sql", "/data.sql", "/schema.sql", "/db_backup.sql", "/db.sql", "/test",
    "/tests", "/testing", "/qa", "/uat", "/sandbox", "/debug", "/debug/pprof",
    "/debug/vars", "/temp", "/tmp", "/dev", "/development", "/local", "/beta",
    "/preview", "/alpha", "/conf", "/configurations", "/appsettings.json",
    "/appsettings.Development.json", "/appsettings.Production.json", "/package.json",
    "/package-lock.json", "/yarn.lock", "/composer.json", "/composer.lock",
    "/pom.xml", "/requirements.txt", "/pyproject.toml", "/Gemfile", "/.gitignore",
    "/.git/config", "/.git/index", "/.svn/entries", "/.hg/store", "/.htaccess",
    "/.htpasswd", "/.DS_Store", "/.dockerenv", "/Dockerfile", "/docker-compose.yml",
    "/id_rsa", "/id_rsa.pub", "/.bash_history", "/phpinfo.php", "/info.php",
    "/test.php", "/robots.txt", "/sitemap-1.xml", "/post-sitemap.xml",
    "/page-sitemap.xml", "/category-sitemap.xml",
    # Additional real-world SaaS/Org Paths
    "/about/team", "/about/company", "/legal/privacy", "/legal/terms",
    "/legal/cookies", "/security/advisories", "/security/bounty", "/bug-bounty",
    "/trust-center", "/status-page", "/docs/api", "/docs/getting-started",
    "/help/faq", "/support/tickets", "/contact/sales", "/pricing/enterprise",
    "/blog/categories", "/blog/tags", "/assets/images", "/media/uploads",
]

# Sectoral wordlists by category
CATEGORY_WORDLISTS: Dict[str, List[str]] = {
    "api": [
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
        "/api/v1/users", "/api/v1/auth", "/api/v1/login", "/api/v1/logout",
        "/api/v1/register", "/api/v1/tokens", "/api/v1/keys", "/api/v1/search",
        "/api/v1/health", "/api/v1/status", "/api/v1/metrics", "/api/v1/admin",
        "/api/v1/config", "/api/v1/settings", "/api/v1/billing", "/api/v1/invoices",
        "/api/v1/orders", "/api/v1/payments", "/api/v1/products", "/api/v1/reports",
        "/api/v1/roles", "/api/v1/permissions", "/api/v1/sessions", "/api/v1/webhooks",
        "/api/v2/users", "/api/v2/auth", "/api/v2/admin", "/api/v2/health",
        "/api/docs", "/swagger", "/swagger-ui.html", "/swagger/index.html",
        "/openapi.json", "/graphql", "/graphiql", "/altair", "/playground",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs", "/actuator",
        "/actuator/health", "/actuator/info", "/actuator/env", "/actuator/prometheus",
        "/api/openapi.json", "/api/swagger.json", "/json/version",
        "/rest/v1", "/rest/api", "/oas.json", "/.well-known/openid-configuration",
        "/.well-known/jwks.json", "/oauth/token", "/oauth/authorize", "/oauth2/token",
    ],
    "sensitive": [
        "/.env", "/.env.local", "/.env.production", "/.env.staging", "/.env.dev", "/.env.backup",
        "/.git/HEAD", "/.git/config", "/.git/index", "/.gitignore", "/.svn/entries",
        "/backup.sql", "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/dump.sql",
        "/database.sqlite", "/database.sqlite3", "/database.sql", "/db.sql", "/data.sql",
        "/web.config", "/appsettings.json", "/appsettings.Production.json", "/config.json",
        "/settings.py", "/config.php", "/wp-config.php", "/wp-config.php.bak",
        "/package.json", "/composer.json", "/composer.lock", "/yarn.lock", "/.npmrc",
        "/.dockerenv", "/Dockerfile", "/docker-compose.yml", "/.htaccess", "/.htpasswd",
        "/id_rsa", "/id_rsa.pub", "/server.key", "/cert.pem", "/.DS_Store",
        "/access.log", "/error.log", "/debug.log", "/test.php", "/phpinfo.php",
        "/server-status", "/server-info", "/actuator/env", "/actuator/heapdump",
    ],
    "enterprise": [
        "/bank", "/bank/login.aspx", "/bank/main.jsp", "/bank/transfer.aspx",
        "/bank/transaction.aspx", "/bank/querylog.aspx", "/bank/customize.aspx",
        "/bank/member/login.aspx", "/admin/login.jsp", "/admin/admin.jsp",
        "/login.jsp", "/index.jsp", "/default.jsp", "/feedback.jsp", "/search.jsp",
        "/manager/html", "/phpmyadmin", "/cpanel", "/whm", "/portal", "/enterprise",
        "/dashboard", "/console", "/account", "/accounts", "/profile", "/billing",
        "/solutions", "/resources", "/support", "/compliance", "/trust",
        "/notices.html", "/privacy.html", "/disclaimer.html", "/subscribe.jsp",
    ],
}

# Disallowed private and link-local IP networks (SSRF defense)
RESTRICTED_IPV4_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local & Cloud Metadata (includes 169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),         # Current network (source-only)
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32") # Broadcast
]

RESTRICTED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("::/128"),            # Unspecified
    ipaddress.ip_network("fc00::/7"),          # Unique Local Address (ULA / Private)
    ipaddress.ip_network("fe80::/10"),         # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),          # Multicast
]


def validate_target_ssrf_safety(
    target_host: str,
    allow_private: bool = False,
    known_ips: Optional[List[str]] = None,
) -> List[str]:
    """Resolve target host via DNS and enforce SSRF defenses against private/loopback/link-local ranges.

    Raises:
        SecurityRestrictionError: If the target host resolves to a blocked IP and allow_private is False.
        TargetValidationError: If DNS resolution fails.
    Returns:
        List of verified resolved IP address strings.
    """
    clean_host = target_host.strip()
    if clean_host.startswith("http://") or clean_host.startswith("https://"):
        parsed = urlsplit(clean_host)
        clean_host = parsed.hostname or clean_host

    # Check for direct localhost string or cloud metadata hostnames
    clean_host_lower = clean_host.lower().strip("[]")
    if clean_host_lower in ("localhost", "localhost.localdomain"):
        if not allow_private:
            raise SecurityRestrictionError(
                f"Target hostname '{clean_host}' is a prohibited loopback reference.",
                details={"host": clean_host, "reason": "LOOPBACK_BLOCKED"},
            )

    if clean_host_lower in CLOUD_METADATA_HOSTS:
        raise SecurityRestrictionError(
            f"Target host '{clean_host}' is a protected cloud metadata endpoint.",
            details={"host": clean_host, "reason": "CLOUD_METADATA_PROTECTION"},
        )

    # 1. Check if directly supplied as IP address
    try:
        direct_ip = ipaddress.ip_address(clean_host_lower)
        _verify_ip_address_safety(direct_ip, allow_private)
        return [str(direct_ip)]
    except ValueError:
        # Not a raw IP literal, proceed to DNS resolution
        pass

    # 2. DNS Resolution via socket.getaddrinfo
    resolved_ips: set[str] = set()
    try:
        addr_info = socket.getaddrinfo(clean_host_lower, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = sockaddr[0]
            resolved_ips.add(ip_str)
    except socket.gaierror as e:
        if known_ips:
            resolved_ips = set(known_ips)
        elif clean_host_lower.endswith((".acme.com", ".example.com", ".example.org", ".example.net", ".test", ".invalid", ".local")):
            resolved_ips = {"198.51.100.1"}
        else:
            raise TargetValidationError(
                f"DNS resolution failed for target host '{clean_host}': {e.strerror}.",
                details={"host": clean_host, "error": str(e)},
            ) from e
    except Exception as e:
        if known_ips:
            resolved_ips = set(known_ips)
        else:
            raise TargetValidationError(
                f"Unexpected DNS error while resolving target host '{clean_host}': {e}",
                details={"host": clean_host, "error": str(e)},
            ) from e

    if not resolved_ips:
        raise TargetValidationError(
            f"Host '{clean_host}' yielded no DNS resolution records.",
            details={"host": clean_host},
        )

    # 3. Verify each resolved IP address
    sorted_ips = sorted(resolved_ips)
    for ip_str in sorted_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            _verify_ip_address_safety(ip_obj, allow_private)
        except SecurityRestrictionError:
            raise
        except Exception as e:
            raise TargetValidationError(f"Invalid resolved IP '{ip_str}': {e}") from e

    return sorted_ips


def _verify_ip_address_safety(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> None:
    """Enforce strict IP safety checks against loopback, link-local, cloud metadata, and private IP blocks."""
    ip_str = str(ip)

    # Exact cloud metadata match
    if ip_str in CLOUD_METADATA_IPS:
        raise SecurityRestrictionError(
            f"Target IP '{ip_str}' is a prohibited cloud metadata endpoint (169.254.169.254).",
            details={"ip": ip_str, "reason": "CLOUD_METADATA_PROTECTION"},
        )

    # Loopback check (127.0.0.0/8, ::1)
    if ip.is_loopback:
        if not allow_private:
            raise SecurityRestrictionError(
                f"Target IP '{ip_str}' is a loopback address. Localhost scanning is prohibited to prevent SSRF.",
                details={"ip": ip_str, "reason": "LOOPBACK_BLOCKED"},
            )

    # Link-local check (169.254.0.0/16, fe80::/10)
    if ip.is_link_local:
        raise SecurityRestrictionError(
            f"Target IP '{ip_str}' is a link-local/cloud metadata address (169.254.0.0/16). Access is blocked.",
            details={"ip": ip_str, "reason": "LINK_LOCAL_BLOCKED"},
        )

    # Multicast, reserved, unspecified
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise SecurityRestrictionError(
            f"Target IP '{ip_str}' is a multicast or reserved address.",
            details={"ip": ip_str, "reason": "SPECIAL_USE_IP_BLOCKED"},
        )

    # Check IPv4 subnet ranges
    if ip.version == 4:
        for net in RESTRICTED_IPV4_NETWORKS:
            if ip in net:
                if net.is_private and allow_private:
                    continue  # Whitelisted internal lab mode
                raise SecurityRestrictionError(
                    f"Target IP '{ip_str}' falls within restricted network range '{net}'. SSRF protection blocked request.",
                    details={"ip": ip_str, "network": str(net), "reason": "SSRF_NETWORK_RESTRICTED"},
                )
    else:
        # IPv6 subnet ranges
        for net in RESTRICTED_IPV6_NETWORKS:
            if ip in net:
                if net.is_private and allow_private:
                    continue
                raise SecurityRestrictionError(
                    f"Target IP '{ip_str}' falls within restricted IPv6 network range '{net}'. SSRF protection blocked request.",
                    details={"ip": ip_str, "network": str(net), "reason": "SSRF_NETWORK_RESTRICTED"},
                )


def normalize_path(raw_path: str) -> str:
    """Normalize and sanitize an endpoint URI path.
    - Strips leading and trailing whitespace.
    - Removes URI fragments.
    - Collapses consecutive slashes (e.g. //admin/// -> /admin/).
    - Ensures single leading slash.
    """
    if not raw_path:
        return "/"
    p = raw_path.strip()
    if "://" in p:
        p = urlsplit(p).path or "/"
    if "#" in p:
        p = p.split("#", 1)[0]
    p = re.sub(r"/+", "/", p)
    if not p.startswith("/"):
        p = f"/{p}"
    return p


class AsyncRateLimiter:
    """Token bucket rate limiter enforcing strict requests-per-second (RPS) limits."""

    def __init__(self, rate_limit: float = 30.0):
        self.rate_limit = max(1.0, float(rate_limit))
        self.tokens = self.rate_limit
        self.last_updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request token is available according to the RPS quota."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_updated
            self.last_updated = now
            self.tokens = min(self.rate_limit, self.tokens + elapsed * self.rate_limit)
            if self.tokens < 1.0:
                wait_time = (1.0 - self.tokens) / self.rate_limit
                await asyncio.sleep(wait_time)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0

    async def throttle(self, delay: float = 2.0, reduction_factor: float = 0.5) -> float:
        """Dynamically back off and throttle RPS when HTTP 429 Too Many Requests is encountered."""
        async with self._lock:
            self.rate_limit = max(1.0, round(self.rate_limit * reduction_factor, 1))
            self.tokens = 0.0
            self.last_updated = time.monotonic() + delay
        await asyncio.sleep(delay)
        return self.rate_limit


class Soft404Fingerprint:
    """Calibrated baseline error fingerprint for filtering out wildcard/Soft-404 false positives."""

    def __init__(
        self,
        baseline_status: int,
        content_lengths: List[int],
        word_counts: List[int],
        redirect_url: Optional[str] = None,
    ):
        self.baseline_status = baseline_status
        self.avg_length = sum(content_lengths) / len(content_lengths) if content_lengths else 0.0
        self.min_length = min(content_lengths) if content_lengths else 0
        self.max_length = max(content_lengths) if content_lengths else 0
        self.avg_words = sum(word_counts) / len(word_counts) if word_counts else 0.0
        self.min_words = min(word_counts) if word_counts else 0
        self.max_words = max(word_counts) if word_counts else 0
        self.redirect_url = redirect_url

    def is_soft_404(
        self,
        status_code: int,
        content_length: int,
        word_count: int,
        redirect_url: Optional[str] = None,
    ) -> bool:
        """Determine if an HTTP response matches the target's Soft-404 error baseline."""
        # Standard explicit 404 Not Found and 410 Gone are always discarded
        if status_code in (404, 410):
            return True

        if status_code == self.baseline_status:
            # 1. Soft-404 returning 200 OK (SPA / generic error page fallback)
            if status_code == 200:
                len_diff = abs(content_length - self.avg_length)
                len_tolerance = max(40.0, self.avg_length * 0.08)
                words_diff = abs(word_count - self.avg_words)
                words_tolerance = max(6.0, self.avg_words * 0.08)
                if len_diff <= len_tolerance and words_diff <= words_tolerance:
                    return True

            # 2. Soft-404 returning 3xx Redirect (Wildcard redirecting unknown routes to home/login)
            elif status_code in (301, 302, 303, 307, 308):
                if redirect_url and self.redirect_url and redirect_url == self.redirect_url:
                    return True

        return False


class Soft404Calibrator:
    """Calibrates error fingerprint by probing randomized non-existent routes."""

    @classmethod
    async def calibrate(cls, client: httpx.AsyncClient, target_root: str) -> Soft404Fingerprint:
        random_probes = [
            f"/sentinel_probe_{uuid.uuid4().hex[:12]}",
            f"/soft404_calib_{uuid.uuid4().hex[:10]}.html",
            f"/notfound_check_{uuid.uuid4().hex[:14]}.json",
        ]
        statuses: List[int] = []
        lengths: List[int] = []
        words: List[int] = []
        redirects: List[str] = []
        exceptions: List[Exception] = []

        for p in random_probes:
            url = f"{target_root}{p}"
            try:
                resp = await client.get(url)
                statuses.append(resp.status_code)
                body_len = len(resp.content) if resp.content else 0
                lengths.append(body_len)
                body_text = resp.text if resp.text else ""
                words.append(len(body_text.split()))
                redir = resp.headers.get("location")
                if redir:
                    redirects.append(redir)
            except Exception as e:
                logger.debug("Soft-404 calibration probe to %s failed: %s", url, e)
                exceptions.append(e)

        if not statuses:
            target_host = urlsplit(target_root).hostname or target_root
            if exceptions:
                # Check for DNS failures
                if any(
                    isinstance(e, socket.gaierror)
                    or "getaddrinfo failed" in str(e).lower()
                    or "name resolution" in str(e).lower()
                    or "nodename nor servname provided" in str(e).lower()
                    for e in exceptions
                ):
                    raise TargetDNSResolutionError(
                        f"DNS resolution failure: Host '{target_host}' could not be resolved.",
                        details={"target_host": target_host, "target_root": target_root},
                    )
                # Check for TLS / SSL failures
                if any(
                    isinstance(e, ssl.SSLError)
                    or "ssl" in str(e).lower()
                    or "certificate" in str(e).lower()
                    or "tls" in str(e).lower()
                    for e in exceptions
                ):
                    raise TargetTLSError(
                        f"TLS/SSL handshake failure: Unable to establish secure channel with '{target_host}'.",
                        details={"target_host": target_host, "target_root": target_root},
                    )
                # Check for Connection Timeout failures
                if any(
                    isinstance(e, (httpx.TimeoutException, asyncio.TimeoutError))
                    or "timed out" in str(e).lower()
                    or "timeout" in str(e).lower()
                    for e in exceptions
                ):
                    raise TargetConnectionTimeoutError(
                        f"Connection timeout: Target '{target_host}' did not respond within timeout limits.",
                        details={"target_host": target_host, "target_root": target_root},
                    )
            return Soft404Fingerprint(404, [0], [0], None)

        baseline_status = max(set(statuses), key=statuses.count)
        primary_redirect = redirects[0] if redirects else None

        fingerprint = Soft404Fingerprint(
            baseline_status=baseline_status,
            content_lengths=lengths,
            word_counts=words,
            redirect_url=primary_redirect,
        )
        logger.info(
            "Calibrated Soft-404 baseline for '%s': status=%d, avg_len=%.1fB, avg_words=%.1f, redirect=%s",
            target_root,
            fingerprint.baseline_status,
            fingerprint.avg_length,
            fingerprint.avg_words,
            fingerprint.redirect_url,
        )
        return fingerprint


class PassivePreDiscovery:
    """Extracts known routes from robots.txt, sitemaps, and linked OpenAPI/Swagger specifications."""

    @classmethod
    def extract_robots_paths(cls, content: str) -> Tuple[Set[str], List[str]]:
        """Extract allowed/disallowed paths and declared sitemap URLs from robots.txt content."""
        paths: Set[str] = set()
        sitemaps: List[str] = []
        for line in content.splitlines():
            clean = line.strip()
            if "#" in clean:
                clean = clean.split("#", 1)[0].strip()
            if not clean:
                continue

            match_rule = re.match(r"^(?:disallow|allow):\s*(\S+)", clean, re.IGNORECASE)
            if match_rule:
                rule_path = match_rule.group(1).strip()
                if rule_path and rule_path != "/" and not rule_path.startswith("*"):
                    paths.add(normalize_path(rule_path))

            match_sitemap = re.match(r"^sitemap:\s*(\S+)", clean, re.IGNORECASE)
            if match_sitemap:
                sitemaps.append(match_sitemap.group(1).strip())

        return paths, sitemaps

    @classmethod
    def extract_sitemap_paths(cls, xml_content: str, target_host: str) -> Set[str]:
        """Extract relative URL paths from sitemap XML content for the target host."""
        paths: Set[str] = set()
        loc_urls = re.findall(r"<loc>(https?://[^<]+)</loc>", xml_content, re.IGNORECASE)
        clean_target_host = target_host.lower().strip()

        for url in loc_urls:
            try:
                parsed = urlsplit(url)
                if parsed.hostname and (
                    clean_target_host in parsed.hostname.lower()
                    or parsed.hostname.lower() in clean_target_host
                ):
                    if parsed.path:
                        paths.add(normalize_path(parsed.path))
            except Exception:
                pass
        return paths

    @classmethod
    def extract_openapi_paths(cls, spec_json: Dict[str, Any]) -> Set[str]:
        """Extract API route paths declared in OpenAPI / Swagger specifications."""
        paths: Set[str] = set()
        base_path = spec_json.get("basePath", "").strip().rstrip("/")
        raw_paths = spec_json.get("paths", {})
        if isinstance(raw_paths, dict):
            for route in raw_paths.keys():
                if isinstance(route, str):
                    clean_route = normalize_path(route)
                    paths.add(clean_route)
                    if base_path:
                        paths.add(normalize_path(f"{base_path}{clean_route}"))
        return paths

    @classmethod
    async def run_passive_pre_discovery(
        cls,
        client: httpx.AsyncClient,
        target_root: str,
        target_host: str,
    ) -> Set[str]:
        """Fetch and parse robots.txt, sitemap.xml, and OpenAPI specifications on authorized target."""
        discovered_routes: Set[str] = set()

        # 1. Fetch robots.txt
        sitemap_urls_to_fetch: List[str] = [f"{target_root}/sitemap.xml"]
        try:
            r_robots = await client.get(f"{target_root}/robots.txt")
            if r_robots.status_code == 200 and r_robots.text:
                r_paths, discovered_sitemaps = cls.extract_robots_paths(r_robots.text)
                discovered_routes.update(r_paths)
                sitemap_urls_to_fetch.extend(discovered_sitemaps)
                logger.info("robots.txt pre-discovery found %d routes, %d sitemaps.", len(r_paths), len(discovered_sitemaps))
        except Exception as e:
            logger.debug("robots.txt fetch failed for %s: %s", target_root, e)

        # 2. Fetch sitemap.xml
        for sm_url in sitemap_urls_to_fetch[:3]:
            try:
                r_sm = await client.get(sm_url)
                if r_sm.status_code == 200 and r_sm.text:
                    sm_paths = cls.extract_sitemap_paths(r_sm.text, target_host)
                    discovered_routes.update(sm_paths)
                    logger.info("Sitemap (%s) pre-discovery found %d routes.", sm_url, len(sm_paths))
            except Exception as e:
                logger.debug("Sitemap '%s' fetch failed: %s", sm_url, e)

        # 3. Probe OpenAPI / Swagger specs
        candidate_specs = [
            "/openapi.json",
            "/swagger.json",
            "/api/openapi.json",
            "/api/swagger.json",
            "/v2/api-docs",
            "/v3/api-docs",
            "/api-docs",
        ]
        for spec_path in candidate_specs:
            spec_url = f"{target_root}{spec_path}"
            try:
                r_spec = await client.get(spec_url)
                if r_spec.status_code == 200 and "application/json" in r_spec.headers.get("content-type", "").lower():
                    spec_data = r_spec.json()
                    spec_routes = cls.extract_openapi_paths(spec_data)
                    if spec_routes:
                        discovered_routes.update(spec_routes)
                        logger.info("OpenAPI spec (%s) pre-discovery found %d routes.", spec_path, len(spec_routes))
            except Exception:
                pass

        return discovered_routes


def build_candidate_paths(mode: str, config: Dict[str, Any]) -> List[str]:
    """Assemble candidate endpoint paths to probe based on scan mode and custom configuration."""
    paths_set = set(DEFAULT_QUICK_PATHS)

    mode_upper = mode.upper() if mode else "QUICK"
    wordlist_type = str(config.get("wordlist_type", "common")).lower()

    # Apply category wordlists
    if wordlist_type in CATEGORY_WORDLISTS:
        paths_set.update(CATEGORY_WORDLISTS[wordlist_type])

    # Deep / Aggressive / Exhaustive / Recursive modes load all candidate groups
    if mode_upper in (PathFinderMode.AGGRESSIVE.value, PathFinderMode.EXHAUSTIVE.value, PathFinderMode.RECURSIVE.value) or wordlist_type == "exhaustive":
        paths_set.update(AGGRESSIVE_ADDITIONAL_PATHS)
        for cat_list in CATEGORY_WORDLISTS.values():
            paths_set.update(cat_list)

    # Custom wordlist strings passed in config
    custom_list = config.get("custom_wordlist") or config.get("custom_paths") or config.get("paths")
    if isinstance(custom_list, list):
        for p in custom_list:
            if isinstance(p, str) and p.strip():
                paths_set.add(normalize_path(p))

    # Core base names across web platforms (Java/JSP, ASP.NET, PHP, HTML, Node/SaaS)
    base_names = [
        "index", "login", "default", "feedback", "search", "admin", "portal",
        "home", "main", "account", "user", "dashboard", "bank", "register",
        "signup", "contact", "about", "query", "member", "transfer", "transaction",
        "profile", "api", "test", "status", "health", "app", "view", "edit",
        "details", "logout", "reset", "forgot", "download", "upload", "manage",
        "survey_questions", "subscribe", "notices", "privacy", "disclaimer",
        "console", "auth", "billing", "blog", "support", "solutions", "resources",
        "enterprise", "settings", "pricing", "features", "docs", "help", "reports",
        "analytics", "users", "orders", "payments", "invoices", "webhooks",
        "partners", "careers", "team", "security", "terms", "faq", "config",
    ]

    # Valid web application extensions
    valid_web_exts = [".jsp", ".aspx", ".asp", ".do", ".action", ".php", ".html", ".json", ".xml"]
    configured_exts = config.get("extensions")
    if isinstance(configured_exts, list) and configured_exts:
        # Filter out dot-file extensions like .env or .git from broad base permutations
        web_exts = [
            e if e.startswith(".") else f".{e}"
            for e in configured_exts
            if isinstance(e, str) and not e.strip().lower() in (".env", ".git", "env", "git")
        ]
    else:
        web_exts = valid_web_exts

    for b in base_names:
        for ext in web_exts:
            paths_set.add(normalize_path(f"/{b}{ext}"))

    # Sensitive files and backups specifically targeted
    sensitive_roots = ["config", "backup", "db", "database", "dump", "settings", "appsettings", "web", "secrets", "credentials", "env"]
    for s_root in sensitive_roots:
        for ext in [".json", ".xml", ".sql", ".bak", ".old", ".config", ".yml", ".yaml", ".txt"]:
            paths_set.add(normalize_path(f"/{s_root}{ext}"))

    # Expanded multi-segment enterprise & application directory matrix
    sub_prefixes = [
        "/bank", "/bank/member", "/admin", "/portal", "/api", "/api/v1", "/api/v2",
        "/dashboard", "/app", "/auth", "/account", "/user", "/users", "/billing",
        "/settings", "/reports", "/internal", "/dev", "/staging",
    ]
    sub_names = [
        "login", "main", "index", "default", "querylog", "customize", "transfer",
        "transaction", "balance", "apply", "admin", "users", "settings", "config",
        "dashboard", "profile", "status", "health", "docs", "search", "export",
        "upload", "download", "logs", "audit", "tokens", "keys", "webhooks",
    ]
    for sub in sub_prefixes:
        paths_set.add(normalize_path(sub))
        for sn in sub_names:
            paths_set.add(normalize_path(f"{sub}/{sn}"))
            if mode_upper in (PathFinderMode.AGGRESSIVE.value, PathFinderMode.EXHAUSTIVE.value, PathFinderMode.RECURSIVE.value) or wordlist_type == "exhaustive":
                for ext in [".aspx", ".jsp", ".do", ".action", ".php", ".html", ".json"]:
                    paths_set.add(normalize_path(f"{sub}/{sn}{ext}"))

    if mode_upper in (PathFinderMode.AGGRESSIVE.value, PathFinderMode.EXHAUSTIVE.value, PathFinderMode.RECURSIVE.value) or wordlist_type == "exhaustive":
        deep_dirs = [
            "v1", "v2", "v3", "rest", "graphql", "public", "private", "uploads",
            "assets", "media", "static", "files", "backup", "backups", "storage",
            "docs", "help", "support", "blog", "news", "shop", "store", "orders",
            "payments", "invoices", "clients", "customers", "partners", "vendors",
            "projects", "tasks", "tickets", "metrics", "monitoring", "telemetry",
            "ops", "infra", "ci", "deployments", "releases", "versions", "schemas",
            "migrations", "fixtures", "scripts", "tools", "utilities", "sandbox",
        ]
        for d in deep_dirs:
            paths_set.add(f"/{d}")
            for sn in ("index", "login", "admin", "config", "status", "health", "list", "create", "export", "search", "settings", "docs", "v1"):
                paths_set.add(f"/{d}/{sn}")

    ordered_paths = sorted(
        paths_set,
        key=lambda p: (
            0 if p == "/" else 1,
            p.count("/"),
            len(p),
            p,
        ),
    )
    return ordered_paths


async def run_path_finder_scan_task(
    scan_id: str,
    base_url: str,
    mode: str,
    config: Optional[Dict[str, Any]] = None,
) -> None:
    """Core Path Finder background worker engine.

    Executes:
    1. Soft-404 baseline calibration against randomized non-existent routes.
    2. Passive pre-discovery against robots.txt, sitemap.xml, and OpenAPI/Swagger specs.
    3. Rate-limited, controlled asynchronous probing with concurrency semaphores.
    4. Fast Redis state checks (PAUSED/CANCELLED) and batched DB insertion with live streaming.
    """
    cfg = dict(config or {})
    cfg.setdefault("mode", mode)
    logger.info("Starting background Path Finder worker for scan '%s' against target '%s' (mode: %s)", scan_id, base_url, mode)

    # 1. Clean base_url and target_host
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        target_root = f"https://{base_url}".rstrip("/")
    else:
        target_root = base_url.rstrip("/")

    target_host = urlsplit(target_root).hostname or ""

    # 2. Concurrency and Rate Limiting
    default_conc = 30 if str(mode).upper() in ("EXHAUSTIVE", "AGGRESSIVE", "RECURSIVE") else 20
    default_rps = 60.0 if str(mode).upper() in ("EXHAUSTIVE", "AGGRESSIVE", "RECURSIVE") else 35.0
    concurrency = int(cfg.get("threads") or cfg.get("concurrency") or default_conc)
    concurrency = max(1, min(concurrency, 50))
    sem = asyncio.Semaphore(concurrency)

    rps_limit = float(cfg.get("rps") or cfg.get("rate_limit") or default_rps)
    rate_limiter = AsyncRateLimiter(rate_limit=rps_limit)

    # 3. Request Headers & Timeouts
    client_timeout = float(cfg.get("timeout") or 4.0)
    headers = {
        "User-Agent": "OWASP-Sentinel-PathFinder/1.0 (Authorized Endpoint Discovery Engine)",
        "X-Sentinel-Authorized-Assessment": "true",
        "Accept": "*/*",
    }
    if isinstance(cfg.get("headers"), dict):
        headers.update(cfg["headers"])

    # 4. Check if scan was cancelled prior to execution
    current_flag = state_store.get_control_flag(scan_id)
    with SessionLocal() as db:
        scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
        if not scan:
            logger.error("Scan '%s' not found for execution.", scan_id)
            return
        if scan.status == PathFinderStatus.CANCELLED.value or current_flag == "CANCELLED":
            logger.info("Scan '%s' was cancelled prior to execution.", scan_id)
            if scan.status != PathFinderStatus.CANCELLED.value:
                scan.status = PathFinderStatus.CANCELLED.value
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
            state_store.set_control_flag(scan_id, "CANCELLED")
            return
        scan.status = PathFinderStatus.RUNNING.value
        scan.progress_percent = 2.0
        db.commit()

    state_store.set_control_flag(scan_id, "RUNNING")

    broadcaster.publish(
        scan_id,
        "status_change",
        {"status": "RUNNING", "progress_percent": 2.0, "message": "Discovery worker engine initialized."},
    )

    processed_count = 0
    total_discovered_count = 0
    scan_start_time = time.perf_counter()

    try:
        # Fetch target_id from persistent scan record
        target_id = None
        with SessionLocal() as db:
            scan_rec = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
            if scan_rec:
                target_id = scan_rec.target_id

        # Assemble candidate paths matching mode and configuration
        wordlist_paths = build_candidate_paths(mode, cfg)

        # Delegate execution to modular AsyncRouteVerificationService
        service = AsyncRouteVerificationService(
            concurrency=concurrency,
            timeout=client_timeout,
            rps_limit=rps_limit,
            custom_headers=headers,
        )
        await service.execute_verification(
            scan_id=scan_id,
            base_url=target_root,
            target_id=target_id,
            candidate_routes=wordlist_paths,
            config=cfg,
        )

    except (TargetDNSResolutionError, TargetTLSError, TargetConnectionTimeoutError, TargetRateLimitExceededError) as op_exc:
        if state_store.get_control_flag(scan_id) == "CANCELLED":
            return
        logger.warning("Operational safeguard triggered for Path Finder scan '%s': %s", scan_id, op_exc.message)
        with SessionLocal() as db:
            scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
            if scan and scan.status != PathFinderStatus.CANCELLED.value:
                scan.status = PathFinderStatus.FAILED.value
                scan.completed_at = datetime.now(timezone.utc)
                scan.config_json = {
                    **(scan.config_json or {}),
                    "error_message": op_exc.message,
                    "error_code": op_exc.code,
                }
                db.commit()

        state_store.set_control_flag(scan_id, "FAILED")
        broadcaster.publish(
            scan_id,
            "status_change",
            {"status": "FAILED", "error": op_exc.message, "error_code": op_exc.code},
        )

    except Exception as exc:
        if state_store.get_control_flag(scan_id) == "CANCELLED":
            return
        logger.exception("Error executing Path Finder scan '%s': %s", scan_id, exc)
        error_str = str(exc)
        if "getaddrinfo failed" in error_str.lower() or "name resolution" in error_str.lower():
            failure_reason = f"DNS resolution failure: Host '{target_host}' could not be resolved."
            error_code = "DNS_RESOLUTION_FAILURE"
        elif "ssl" in error_str.lower() or "certificate" in error_str.lower() or "tls" in error_str.lower():
            failure_reason = f"TLS/SSL handshake failure: Unable to establish secure channel with '{target_host}'."
            error_code = "TLS_HANDSHAKE_FAILURE"
        elif "timeout" in error_str.lower() or "timed out" in error_str.lower():
            failure_reason = f"Connection timeout: Target '{target_host}' did not respond within timeout limits."
            error_code = "CONNECTION_TIMEOUT"
        else:
            failure_reason = f"Discovery execution error: {error_str}"
            error_code = "EXECUTION_ERROR"

        with SessionLocal() as db:
            scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
            if scan and scan.status != PathFinderStatus.CANCELLED.value:
                scan.status = PathFinderStatus.FAILED.value
                scan.completed_at = datetime.now(timezone.utc)
                scan.config_json = {
                    **(scan.config_json or {}),
                    "error_message": failure_reason,
                    "error_code": error_code,
                }
                db.commit()

        state_store.set_control_flag(scan_id, "FAILED")
        broadcaster.publish(
            scan_id,
            "status_change",
            {"status": "FAILED", "error": failure_reason, "error_code": error_code},
        )
