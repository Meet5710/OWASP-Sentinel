"""OWASP Sentinel - Async Route Verification Service (Route Checker)

Modular service executed by the Path Finder background worker providing:
1. Sitemap & Robots Parser: Extracts routes and endpoints from robots.txt and sitemap.xml
   using verified database target assets.
2. Default 404 Baseline Calibration: Dispatches 2 non-existent requests
   (/health-check-nonexistent-<uuid>) to record status code and content length baselines.
3. Rate-Limited Async HTTP Client: Powered by httpx with configurable concurrency (e.g., 10),
   timeout (e.g., 5.0s), and custom HTTP assessment headers.
4. Live Updates & State Checks: Batched processing (chunks of 20 URLs) with Redis/DB
   state polling (PAUSED/CANCELLED), baseline filtering, SSE/WebSocket broadcasting,
   and batch database persistence into discovered_paths.
"""

import asyncio
from datetime import datetime, timezone
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

from app.core.exceptions import (
    SecurityRestrictionError,
    TargetConnectionTimeoutError,
    TargetDNSResolutionError,
    TargetRateLimitExceededError,
    TargetTLSError,
    TargetValidationError,
)
from app.db.session import SessionLocal
from app.models.db.asset import AuthorizedAsset
from app.models.db.path_finder import DiscoveredPath, PathFinderScan
from app.models.schemas.path_finder import PathFinderStatus
from app.services.path_finder_broadcaster import broadcaster
from app.services.path_finder_state import state_store

logger = logging.getLogger(__name__)


def normalize_route_path(path: str) -> str:
    """Normalizes candidate route into clean, slash-prefixed URI path."""
    if not path:
        return "/"
    p = path.strip()
    # Strip URL schemes if present
    if "://" in p:
        p = urlsplit(p).path
    # Strip query parameters and fragments
    p = p.split("?")[0].split("#")[0]
    # Collapse multiple slashes
    p = re.sub(r"/+", "/", p)
    if not p.startswith("/"):
        p = f"/{p}"
    return p


class Baseline404:
    """Encapsulates response fingerprint for non-existent routes (404 baseline & Soft-404)."""

    def __init__(
        self,
        status_codes: List[int],
        content_lengths: List[int],
        tolerance_ratio: float = 0.08,
        redirect_url: Optional[str] = None,
        soft_404_lengths: Optional[List[int]] = None,
    ):
        self.status_codes: Set[int] = set(status_codes) if status_codes else {404}
        self.content_lengths: List[int] = content_lengths or [0]
        self.soft_404_lengths: List[int] = soft_404_lengths or [
            l for s, l in zip(status_codes, content_lengths) if s == 200 and l > 0
        ]
        self.avg_length: float = sum(self.content_lengths) / max(len(self.content_lengths), 1)
        self.avg_200_length: float = (
            sum(self.soft_404_lengths) / len(self.soft_404_lengths)
            if self.soft_404_lengths
            else 0.0
        )
        self.tolerance_ratio: float = tolerance_ratio
        self.redirect_url: Optional[str] = redirect_url

    def is_match(
        self,
        status_code: int,
        content_length: int,
        redirect_url: Optional[str] = None,
        body_text: Optional[str] = None,
    ) -> bool:
        """Determines whether a probed route matches the target's default 404 / wildcard baseline."""
        # 1. Standard explicit 404 Not Found and 410 Gone are always discarded
        if status_code in (404, 410):
            return True

        # 2. Wildcard redirect matching (e.g. wildcard redirecting non-existent paths to / or /login)
        if self.redirect_url and redirect_url and self.redirect_url == redirect_url:
            return True

        # 3. Soft-404 returning 200 OK matching calibrated 200 baseline length
        if status_code == 200 and self.avg_200_length > 0:
            diff = abs(content_length - self.avg_200_length)
            allowed_variance = max(60.0, self.avg_200_length * self.tolerance_ratio)
            if diff <= allowed_variance:
                return True

        # 4. Check if status code matches baseline (e.g. 404, or SPA wildcard 200 OK)
        if status_code in self.status_codes:
            if self.avg_length > 0:
                length_diff = abs(content_length - self.avg_length)
                max_allowed_diff = max(40.0, self.avg_length * self.tolerance_ratio)
                if length_diff <= max_allowed_diff:
                    return True
            elif content_length == 0:
                return True

        # 5. Check body content for blatant not-found titles when returning 200 OK
        if status_code == 200 and body_text:
            lower = body_text.lower()
            if "<title>" in lower:
                title_search = re.search(r"<title>(.*?)</title>", lower, re.DOTALL)
                if title_search:
                    t = title_search.group(1).strip()
                    if any(term in t for term in ("404 not found", "page not found", "not found", "nothing found", "error 404", "doesn't exist", "page can't be found")):
                        return True

        return False


class SitemapRobotsParser:
    """Fetches and parses robots.txt and sitemap.xml to seed verified routes."""

    @classmethod
    async def fetch_robots_paths(
        cls,
        client: httpx.AsyncClient,
        base_url: str,
    ) -> Tuple[Set[str], List[str]]:
        """Parses robots.txt for disallowed/allowed routes and linked sitemaps."""
        discovered_paths: Set[str] = set()
        sitemap_urls: List[str] = []
        robots_url = urljoin(f"{base_url.rstrip('/')}/", "robots.txt")

        try:
            resp = await client.get(robots_url)
            if resp.status_code == 200 and resp.text:
                for line in resp.text.splitlines():
                    clean_line = line.strip()
                    if not clean_line or clean_line.startswith("#"):
                        continue
                    if ":" in clean_line:
                        directive, _, value = clean_line.partition(":")
                        directive = directive.strip().lower()
                        value = value.strip()
                        if directive in ("disallow", "allow") and value:
                            parsed_path = normalize_route_path(value)
                            if parsed_path not in ("/", "/*"):
                                discovered_paths.add(parsed_path)
                        elif directive == "sitemap" and value:
                            sitemap_urls.append(value)
        except Exception as exc:
            logger.debug("Failed fetching robots.txt from '%s': %s", robots_url, exc)

        return discovered_paths, sitemap_urls

    @classmethod
    async def fetch_sitemap_paths(
        cls,
        client: httpx.AsyncClient,
        sitemap_url: str,
        target_host: str,
        max_depth: int = 2,
    ) -> Set[str]:
        """Recursively parses XML sitemaps and sitemap indexes."""
        discovered: Set[str] = set()
        if max_depth <= 0:
            return discovered

        try:
            resp = await client.get(sitemap_url)
            if resp.status_code == 200 and resp.content:
                # Strip XML namespaces for standard parsing
                xml_text = re.sub(r'\sxmlns(:\w+)?="[^"]+"', "", resp.text, count=1)
                root = ET.fromstring(xml_text)

                # 1. Sitemap Index (nested sitemaps)
                for sitemap_elem in root.findall(".//sitemap/loc"):
                    child_url = (sitemap_elem.text or "").strip()
                    if child_url and urlsplit(child_url).hostname == target_host:
                        sub_paths = await cls.fetch_sitemap_paths(
                            client, child_url, target_host, max_depth=max_depth - 1
                        )
                        discovered.update(sub_paths)

                # 2. URL Entries
                for url_elem in root.findall(".//url/loc"):
                    loc_url = (url_elem.text or "").strip()
                    if loc_url:
                        parts = urlsplit(loc_url)
                        if not parts.hostname or parts.hostname == target_host:
                            if parts.path:
                                discovered.add(normalize_route_path(parts.path))
        except Exception as exc:
            logger.debug("Failed parsing sitemap at '%s': %s", sitemap_url, exc)

        return discovered

    @classmethod
    async def fetch_html_links(
        cls,
        client: httpx.AsyncClient,
        base_url: str,
        target_host: str,
    ) -> Set[str]:
        """Parses target root HTML to discover embedded relative and intra-host links, excluding static media assets."""
        discovered: Set[str] = set()
        clean_target_host = target_host.lower().strip()
        MEDIA_EXTS = {
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp",
            ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
            ".avi", ".mov", ".map", ".js"
        }
        try:
            resp = await client.get(base_url)
            if resp.status_code == 200 and resp.text:
                for match in re.finditer(r'(?:href|action)=["\']([^"\']+)["\']', resp.text, re.IGNORECASE):
                    raw_val = match.group(1).strip()
                    if not raw_val or raw_val.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                        continue
                    if "://" in raw_val:
                        parts = urlsplit(raw_val)
                        if parts.hostname and (clean_target_host in parts.hostname.lower() or parts.hostname.lower() in clean_target_host):
                            if parts.path:
                                norm = normalize_route_path(parts.path)
                                ext = norm.split(".")[-1].lower() if "." in norm else ""
                                if f".{ext}" not in MEDIA_EXTS and not any(ign in norm for ign in ("/wp-content/themes/", "/wp-content/uploads/")):
                                    discovered.add(norm)
                    else:
                        norm = normalize_route_path(raw_val)
                        if norm != "/":
                            ext = norm.split(".")[-1].lower() if "." in norm else ""
                            if f".{ext}" not in MEDIA_EXTS and not any(ign in norm for ign in ("/wp-content/themes/", "/wp-content/uploads/")):
                                discovered.add(norm)
        except Exception as exc:
            logger.debug("Failed fetching HTML links from '%s': %s", base_url, exc)
        return discovered

    @classmethod
    async def discover_known_routes(
        cls,
        client: httpx.AsyncClient,
        base_url: str,
        target_host: str,
    ) -> Set[str]:
        """Executes full passive route collection across robots.txt, sitemaps, and root HTML links."""
        routes: Set[str] = set()

        # 1. robots.txt
        robots_routes, sitemap_urls = await cls.fetch_robots_paths(client, base_url)
        routes.update(robots_routes)

        # 2. Default sitemap + sitemaps discovered in robots.txt
        sitemaps_to_probe = [urljoin(f"{base_url.rstrip('/')}/", "sitemap.xml")]
        for sm in sitemap_urls:
            if sm not in sitemaps_to_probe:
                sitemaps_to_probe.append(sm)

        for sm_url in sitemaps_to_probe[:3]:
            sm_routes = await cls.fetch_sitemap_paths(client, sm_url, target_host)
            routes.update(sm_routes)

        # 3. Root HTML relative links (filtering static theme media assets)
        html_routes = await cls.fetch_html_links(client, base_url, target_host)
        routes.update(html_routes)

        return routes


class AsyncRouteVerificationService:
    """Core Async Route Verification Service called by background workers."""

    def __init__(
        self,
        concurrency: int = 10,
        timeout: float = 5.0,
        rps_limit: float = 30.0,
        custom_headers: Optional[Dict[str, str]] = None,
    ):
        self.concurrency: int = max(1, min(concurrency, 30))
        self.timeout: float = max(1.0, float(timeout))
        self.rps_limit: float = max(1.0, float(rps_limit))
        self.semaphore = asyncio.Semaphore(self.concurrency)
        self.rate_limiter_tokens = self.rps_limit
        self.rate_limiter_last = time.monotonic()
        self.rate_limiter_lock = asyncio.Lock()

        # Build headers
        self.headers: Dict[str, str] = {
            "User-Agent": "OWASP-Sentinel-PathFinder/1.0 (Route Verification Service)",
            "X-Sentinel-Authorized-Assessment": "true",
            "Accept": "*/*",
        }
        if custom_headers:
            self.headers.update(custom_headers)

        # Dynamic Wildcard Redirect & False-Positive Elimination State
        self.wildcard_redirects: Set[Tuple[str, str]] = set()  # (prefix, normalized_redirect_url)
        self.tested_redirect_prefixes: Set[str] = set()
        self.destination_status_cache: Dict[str, bool] = {}  # destination_path -> is_valid
        self.redirect_counts: Dict[str, int] = {}
        self._wildcard_lock = asyncio.Lock()

    async def _is_wildcard_or_dead_redirect(
        self,
        client: httpx.AsyncClient,
        target_root: str,
        target_host: str,
        route_path: str,
        status_code: int,
        redirect_header: str,
        baseline: Baseline404,
    ) -> bool:
        """Determines whether a 3xx redirect is a catch-all/wildcard rule or points to a dead 404 target."""
        if not redirect_header:
            return False

        redir_clean = redirect_header.strip()
        parsed_redir = urlsplit(redir_clean)

        # Check if internal redirect on the same host or relative
        if parsed_redir.netloc and parsed_redir.netloc.lower() != target_host.lower():
            norm_redir = redir_clean
            is_internal = False
        else:
            norm_redir = normalize_route_path(parsed_redir.path)
            is_internal = True

        # 1. Circular redirect loop (redirects to itself)
        if norm_redir == route_path:
            return True

        # 2. Check root baseline redirect
        if baseline.redirect_url and (baseline.redirect_url == redir_clean or baseline.redirect_url == norm_redir):
            return True

        # 3. Candidate prefixes (root, directory, and stem)
        segments = [s for s in route_path.strip("/").split("/") if s]
        first_seg = segments[0] if segments else ""
        candidate_prefixes: List[str] = ["/"]
        if first_seg:
            candidate_prefixes.extend([f"/{first_seg}/", f"/{first_seg}"])

        # Quick check in cached wildcard rules
        for pfx in candidate_prefixes:
            if (pfx, norm_redir) in self.wildcard_redirects:
                return True

        # Quick check in cached dead destinations
        if is_internal and self.destination_status_cache.get(norm_redir) is False:
            return True

        # 4. Synchronized Wildcard Probe & Destination Verification
        async with self._wildcard_lock:
            # Re-check inside lock
            for pfx in candidate_prefixes:
                if (pfx, norm_redir) in self.wildcard_redirects:
                    return True
            if is_internal and self.destination_status_cache.get(norm_redir) is False:
                return True

            # Track frequency of this redirect target
            self.redirect_counts[norm_redir] = self.redirect_counts.get(norm_redir, 0) + 1

            # Determine untested prefixes to calibrate
            prefixes_to_probe: List[str] = []
            for pfx in candidate_prefixes:
                if pfx not in self.tested_redirect_prefixes:
                    prefixes_to_probe.append(pfx)
                    self.tested_redirect_prefixes.add(pfx)

            # If this redirect target has appeared 3+ times across different routes, also probe root
            if self.redirect_counts[norm_redir] >= 3 and "/" not in self.tested_redirect_prefixes:
                prefixes_to_probe.append("/")
                self.tested_redirect_prefixes.add("/")

            for pfx in prefixes_to_probe:
                probe_token = f"sentinel-wc-{uuid.uuid4().hex[:8]}"
                if pfx == "/":
                    probe_path = f"/{probe_token}"
                elif pfx.endswith("/"):
                    probe_path = f"{pfx}{probe_token}"
                else:
                    probe_path = f"{pfx}-{probe_token}"

                try:
                    probe_url = f"{target_root}{probe_path}"
                    r = await client.get(probe_url)
                    if r.status_code in (301, 302, 303, 307, 308):
                        p_loc = r.headers.get("location", "").strip()
                        p_parsed = urlsplit(p_loc)
                        p_norm = (
                            normalize_route_path(p_parsed.path)
                            if not p_parsed.netloc or p_parsed.netloc.lower() == target_host.lower()
                            else p_loc
                        )
                        if p_norm == norm_redir:
                            logger.info(
                                "Identified wildcard redirect signature: prefix '%s' wildcard-redirects to '%s' (probed '%s', status %d)",
                                pfx,
                                norm_redir,
                                probe_path,
                                r.status_code,
                            )
                            self.wildcard_redirects.add((pfx, norm_redir))
                            return True
                except Exception as exc:
                    logger.debug("Wildcard redirect probe error for '%s': %s", probe_path, exc)

            # 5. Destination Validation: If redirect points to dead 404 or baseline error page
            if is_internal and norm_redir not in self.destination_status_cache:
                try:
                    dest_url = f"{target_root}{norm_redir}"
                    d_resp = await client.get(dest_url)
                    d_len = len(d_resp.content) if d_resp.content else 0
                    d_redir = d_resp.headers.get("location")
                    d_snippet = d_resp.text[:1200] if d_resp.text else ""

                    if d_resp.status_code in (404, 410) or baseline.is_match(d_resp.status_code, d_len, d_redir, d_snippet):
                        logger.info(
                            "Redirect target '%s' is dead (status %d, len %d) - discarding route '%s'",
                            norm_redir,
                            d_resp.status_code,
                            d_len,
                            route_path,
                        )
                        self.destination_status_cache[norm_redir] = False
                        return True
                    else:
                        self.destination_status_cache[norm_redir] = True
                except Exception as exc:
                    logger.debug("Destination check error for '%s': %s", norm_redir, exc)
                    self.destination_status_cache[norm_redir] = False
                    return True

            if is_internal and self.destination_status_cache.get(norm_redir) is False:
                return True

        return False

    async def _acquire_rate_token(self) -> None:
        """Enforces RPS quota using token bucket."""
        async with self.rate_limiter_lock:
            now = time.monotonic()
            elapsed = now - self.rate_limiter_last
            self.rate_limiter_last = now
            self.rate_limiter_tokens = min(self.rps_limit, self.rate_limiter_tokens + elapsed * self.rps_limit)
            if self.rate_limiter_tokens < 1.0:
                wait_time = (1.0 - self.rate_limiter_tokens) / self.rps_limit
                await asyncio.sleep(wait_time)
                self.rate_limiter_tokens = 0.0
            else:
                self.rate_limiter_tokens -= 1.0

    async def establish_404_baseline(
        self,
        client: httpx.AsyncClient,
        target_root: str,
    ) -> Baseline404:
        """Requirement 2: Dispatches randomized probes across extensions to record 404 & Soft-404 baseline."""
        nonexistent_paths = [
            f"/health-check-nonexistent-{uuid.uuid4().hex[:12]}",
            f"/health-check-nonexistent-{uuid.uuid4().hex[:12]}",
        ]
        statuses: List[int] = []
        lengths: List[int] = []
        soft_404_lens: List[int] = []
        redirects: List[str] = []
        exceptions: List[Exception] = []

        for rel_path in nonexistent_paths:
            probe_url = f"{target_root}{rel_path}"
            try:
                resp = await client.get(probe_url)
                statuses.append(resp.status_code)
                clen = len(resp.content) if resp.content else 0
                lengths.append(clen)
                if resp.status_code == 200 and clen > 0:
                    soft_404_lens.append(clen)
                redir = resp.headers.get("location")
                if redir:
                    redirects.append(redir)
            except Exception as exc:
                logger.debug("Baseline check to '%s' failed: %s", probe_url, exc)
                exceptions.append(exc)

        # Operational failure detection if all probes fail
        if not statuses and exceptions:
            target_host = urlsplit(target_root).hostname or target_root
            if any(isinstance(e, socket.gaierror) or "getaddrinfo failed" in str(e).lower() for e in exceptions):
                raise TargetDNSResolutionError(f"DNS resolution failure: Host '{target_host}' could not be resolved.")
            if any(isinstance(e, ssl.SSLError) or "ssl" in str(e).lower() for e in exceptions):
                raise TargetTLSError(f"TLS/SSL handshake failure: Unable to establish secure channel with '{target_host}'.")
            if any(isinstance(e, httpx.TimeoutException) or "timed out" in str(e).lower() for e in exceptions):
                raise TargetConnectionTimeoutError(f"Connection timeout: Target '{target_host}' did not respond.")

        baseline = Baseline404(
            status_codes=statuses or [404],
            content_lengths=lengths or [0],
            redirect_url=redirects[0] if redirects else None,
            soft_404_lengths=soft_404_lens if soft_404_lens else None,
        )
        if redirects:
            norm_r = normalize_route_path(redirects[0])
            self.wildcard_redirects.add(("/", norm_r))
            self.wildcard_redirects.add(("/", redirects[0].strip()))
        logger.info(
            "Established 404 baseline for '%s': statuses=%s, soft_404_avg_len=%.1fB, redirect=%s",
            target_root,
            baseline.status_codes,
            baseline.avg_200_length,
            baseline.redirect_url,
        )
        return baseline

    async def execute_verification(
        self,
        scan_id: str,
        base_url: str,
        target_id: Optional[str] = None,
        candidate_routes: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        """Requirement 1-4: Executes full route verification pipeline."""
        cfg = config or {}

        # 1. Clean and verify target root
        target_root = base_url.rstrip("/")
        if not target_root.startswith("http://") and not target_root.startswith("https://"):
            target_root = f"https://{target_root}"
        target_host = urlsplit(target_root).hostname or ""

        # Verify target in authorized inventory if target_id provided
        if target_id:
            with SessionLocal() as db:
                asset = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.id == target_id))
                if asset and asset.canonical_url:
                    target_root = asset.canonical_url.rstrip("/")
                    target_host = asset.host or urlsplit(target_root).hostname or ""

        # Update initial progress
        broadcaster.publish(
            scan_id,
            "status_change",
            {"status": "RUNNING", "progress_percent": 5.0, "message": "Calibrating baseline signatures..."},
        )

        total_discovered = 0
        processed_count = 0
        scan_start_time = time.perf_counter()

        client_cm = None
        if client is None:
            client_cm = httpx.AsyncClient(
                verify=False,
                follow_redirects=False,
                timeout=self.timeout,
                headers=self.headers,
            )
            active_client = await client_cm.__aenter__()
        else:
            active_client = client

        try:
            # -----------------------------------------------------------------
            # Step 1: Default 404 Baseline Check (diverse non-existent probes)
            # -----------------------------------------------------------------
            baseline = await self.establish_404_baseline(active_client, target_root)

            # -----------------------------------------------------------------
            # Step 2: Sitemap & Robots Parser (extract known paths)
            # -----------------------------------------------------------------
            passive_paths = await SitemapRobotsParser.discover_known_routes(active_client, target_root, target_host)

            # Assemble complete candidate routes list
            paths_to_verify: List[str] = ["/"]
            for p in sorted(passive_paths):
                if p not in paths_to_verify:
                    paths_to_verify.append(p)

            if candidate_routes:
                for c in candidate_routes:
                    norm = normalize_route_path(c)
                    if norm not in paths_to_verify:
                        paths_to_verify.append(norm)

            total_routes = max(len(paths_to_verify), 1)

            # Broadcast start of active probing
            broadcaster.publish(
                scan_id,
                "progress",
                {
                    "progress_percent": 10.0,
                    "requests_per_second": 0.0,
                    "total_discovered": 0,
                    "processed_paths": 0,
                    "total_paths": total_routes,
                    "status": "RUNNING",
                },
            )

            # -----------------------------------------------------------------
            # Step 3: Batch Verification in chunks of 20 URLs
            # -----------------------------------------------------------------
            batch_size = 20
            pending_db_records: List[DiscoveredPath] = []
            consecutive_net_failures = 0

            for batch_start in range(0, len(paths_to_verify), batch_size):
                # Live State Check: Redis / DB control flag polling
                control_flag = state_store.get_control_flag(scan_id)

                # Exit cleanly if CANCELLED
                if control_flag == "CANCELLED":
                    logger.info("Scan '%s' received CANCELLED flag during route verification.", scan_id)
                    with SessionLocal() as db:
                        if pending_db_records:
                            db.add_all(pending_db_records)
                        s = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
                        if s:
                            s.status = PathFinderStatus.CANCELLED.value
                            s.completed_at = datetime.now(timezone.utc)
                            db.commit()
                    broadcaster.publish(scan_id, "status_change", {"status": "CANCELLED"})
                    return {"scan_id": scan_id, "status": "CANCELLED", "total_discovered": total_discovered}

                # Sleep in loop if PAUSED until resumed
                if control_flag == "PAUSED":
                    with SessionLocal() as db:
                        if pending_db_records:
                            db.add_all(pending_db_records)
                            pending_db_records.clear()
                        s = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
                        if s and s.status != PathFinderStatus.PAUSED.value:
                            s.status = PathFinderStatus.PAUSED.value
                            db.commit()
                    broadcaster.publish(scan_id, "status_change", {"status": "PAUSED"})

                    while state_store.get_control_flag(scan_id) == "PAUSED":
                        await asyncio.sleep(0.5)

                    if state_store.get_control_flag(scan_id) == "CANCELLED":
                        with SessionLocal() as db:
                            s = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
                            if s:
                                s.status = PathFinderStatus.CANCELLED.value
                                s.completed_at = datetime.now(timezone.utc)
                                db.commit()
                        broadcaster.publish(scan_id, "status_change", {"status": "CANCELLED"})
                        return {"scan_id": scan_id, "status": "CANCELLED", "total_discovered": total_discovered}

                    with SessionLocal() as db:
                        s = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
                        if s and s.status != PathFinderStatus.RUNNING.value:
                            s.status = PathFinderStatus.RUNNING.value
                            db.commit()
                    broadcaster.publish(scan_id, "status_change", {"status": "RUNNING"})

                batch_chunk = paths_to_verify[batch_start : batch_start + batch_size]

                async def _verify_single_route(route_path: str) -> Tuple[bool, Optional[Tuple[str, str, int, int, Optional[str], Optional[str], float]]]:
                    full_url = f"{target_root}{route_path}"
                    start_t = time.perf_counter()

                    await self._acquire_rate_token()

                    async with self.semaphore:
                        try:
                            resp = await active_client.get(full_url)
                            latency = round((time.perf_counter() - start_t) * 1000.0, 2)
                            content_len = len(resp.content) if resp.content else 0
                            ctype = resp.headers.get("content-type")
                            redir = resp.headers.get("location")
                            body_snippet = resp.text[:1200] if resp.text else ""

                            # Filter out responses that match the 404 / Soft-404 baseline
                            if baseline.is_match(resp.status_code, content_len, redir, body_snippet):
                                return (True, None)

                            # Filter out standard 404 / 410 codes
                            if resp.status_code in (404, 410):
                                return (True, None)

                            # If target returns 503 / 504 / 429 server throttling
                            if resp.status_code in (503, 504, 429):
                                return (False, None)

                            # Check and filter out catch-all / wildcard redirects and dead 404 redirect targets
                            if resp.status_code in (301, 302, 303, 307, 308) and redir:
                                if await self._is_wildcard_or_dead_redirect(
                                    client=active_client,
                                    target_root=target_root,
                                    target_host=target_host,
                                    route_path=route_path,
                                    status_code=resp.status_code,
                                    redirect_header=redir,
                                    baseline=baseline,
                                ):
                                    return (True, None)

                            return (True, (route_path, full_url, resp.status_code, content_len, ctype, redir, latency))
                        except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError, ssl.SSLError):
                            return (False, None)
                        except Exception as e:
                            logger.debug("Verification request to '%s' failed: %s", full_url, e)
                            return (False, None)

                results = await asyncio.gather(*[_verify_single_route(r) for r in batch_chunk], return_exceptions=True)

                # Circuit breaker: track consecutive target connection failures
                net_errors = 0
                for item in results:
                    if isinstance(item, tuple):
                        success, route_data = item
                        if not success:
                            net_errors += 1
                        elif route_data is not None:
                            route_path, full_url, status_code, content_len, ctype, redir, latency = route_data
                            record_uuid = str(uuid.uuid4())
                            discovered_record = DiscoveredPath(
                                id=record_uuid,
                                scan_id=scan_id,
                                path=route_path,
                                full_url=full_url,
                                status_code=status_code,
                                content_length=content_len,
                                content_type=ctype,
                                redirect_url=redir,
                                response_time_ms=latency,
                                discovered_at=datetime.now(timezone.utc),
                            )
                            pending_db_records.append(discovered_record)
                            total_discovered += 1

                            # Publish to live SSE/WebSocket channel immediately
                            broadcaster.publish(
                                scan_id,
                                "path_discovered",
                                {
                                    "path": {
                                        "id": record_uuid,
                                        "scan_id": discovered_record.scan_id,
                                        "path": discovered_record.path,
                                        "full_url": discovered_record.full_url,
                                        "status_code": discovered_record.status_code,
                                        "content_length": discovered_record.content_length,
                                        "content_type": discovered_record.content_type,
                                        "redirect_url": discovered_record.redirect_url,
                                        "response_time_ms": discovered_record.response_time_ms,
                                        "discovered_at": discovered_record.discovered_at.isoformat() if discovered_record.discovered_at else "",
                                    }
                                },
                            )
                    else:
                        net_errors += 1

                processed_count += len(batch_chunk)
                current_pct = min(99.0, round(5.0 + (processed_count / total_routes) * 94.0, 1))
                elapsed = max(0.05, time.perf_counter() - scan_start_time)
                req_per_sec = round(processed_count / elapsed, 1)

                # Always commit progress and pending discovered records to database on every batch
                with SessionLocal() as db:
                    if pending_db_records:
                        db.add_all(pending_db_records)
                        pending_db_records.clear()
                    s = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
                    if s and s.status == PathFinderStatus.RUNNING.value:
                        s.progress_percent = current_pct
                    db.commit()

                # Stream progress telemetry
                metrics_data = {
                    "progress_percent": current_pct,
                    "requests_per_second": req_per_sec,
                    "total_discovered": total_discovered,
                    "processed_paths": processed_count,
                    "total_paths": total_routes,
                    "status": "RUNNING",
                }
                state_store.set_metrics(scan_id, metrics_data)
                broadcaster.publish(scan_id, "progress", metrics_data)

                # Check circuit breaker: if target server is completely unresponsive for 30 consecutive requests
                if net_errors == len(batch_chunk):
                    consecutive_net_failures += len(batch_chunk)
                    if consecutive_net_failures >= 30 and processed_count >= 40:
                        logger.warning(
                            "Target server '%s' is dropping connections (%d consecutive network failures). Concluding scan safely.",
                            target_host,
                            consecutive_net_failures,
                        )
                        break
                else:
                    consecutive_net_failures = 0

            # -----------------------------------------------------------------
            # Step 4: Final Flush & Completion
            # -----------------------------------------------------------------
            with SessionLocal() as db:
                if pending_db_records:
                    db.add_all(pending_db_records)
                    pending_db_records.clear()
                s = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
                if s and s.status != PathFinderStatus.CANCELLED.value:
                    s.status = PathFinderStatus.COMPLETED.value
                    s.progress_percent = 100.0
                    s.completed_at = datetime.now(timezone.utc)
                    db.commit()

            final_metrics = {
                "progress_percent": 100.0,
                "requests_per_second": round(processed_count / max(0.1, time.perf_counter() - scan_start_time), 1),
                "total_discovered": total_discovered,
                "processed_paths": processed_count,
                "total_paths": total_routes,
                "status": "COMPLETED",
            }
            state_store.set_control_flag(scan_id, "COMPLETED")
            state_store.set_metrics(scan_id, final_metrics)
            broadcaster.publish(scan_id, "progress", final_metrics)
            broadcaster.publish(scan_id, "status_change", {"status": "COMPLETED", "progress_percent": 100.0})

            return {"scan_id": scan_id, "status": "COMPLETED", "total_discovered": total_discovered}
        finally:
            if client_cm is not None:
                await client_cm.__aexit__(None, None, None)

