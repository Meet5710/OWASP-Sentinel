"""OWASP Sentinel - Subdomain Discovery & Reconnaissance Engine Tests

Verifies expanded dictionary scale (>800 prefixes), normalization logic,
DNS packet generation, wildcard DNS suppression, and API endpoints.
"""

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from app.models.schemas.target import SubdomainDiscoveryRequest
from app.services.subdomain_service import (
    EXPANDED_SUBDOMAIN_PREFIXES,
    SubdomainDiscoveryService,
    _build_dns_query,
    _parse_dns_response,
)


class TestSubdomainReconScaleAndLogic:
    """Tests for SubdomainDiscoveryService dictionary scale, DNS wire protocol, and normalization."""

    def test_expanded_wordlist_scale(self) -> None:
        """Ensure wordlist contains 10,000+ comprehensive enterprise-grade prefixes."""
        assert len(EXPANDED_SUBDOMAIN_PREFIXES) >= 10000
        # Ensure crucial enterprise prefixes exist
        essential_prefixes = [
            "www", "api", "admin", "dev", "staging", "uat", "qa", "portal", "sso", "auth",
            "vpn", "mail", "cdn", "k8s", "grafana", "git", "ci", "db", "ems", "swm",
            "netmon", "sensor", "iot", "pay", "billing", "shop", "status", "docs"
        ]
        for p in essential_prefixes:
            assert p in EXPANDED_SUBDOMAIN_PREFIXES, f"Missing essential prefix: {p}"

    def test_normalize_apex_domain(self) -> None:
        """Test domain sanitization across raw URLs, ports, paths, and www prefixes."""
        assert SubdomainDiscoveryService.normalize_apex_domain("https://www.smarttrichy.in/app") == "smarttrichy.in"
        assert SubdomainDiscoveryService.normalize_apex_domain("http://example.com:8080/path") == "example.com"
        assert SubdomainDiscoveryService.normalize_apex_domain("WWW.ACME.COM") == "acme.com"
        assert SubdomainDiscoveryService.normalize_apex_domain("sub.portal.company.org") == "sub.portal.company.org"

    def test_dns_wire_query_builder_and_parser(self) -> None:
        """Test RFC 1035 wire format DNS packet serialization and deserialization."""
        qid = 4321
        pkt = _build_dns_query("test.example.com", qid)
        assert len(pkt) > 12  # Header is 12 bytes + qname + tail
        assert pkt[:2] == (4321).to_bytes(2, byteorder="big")

        # Empty data returns 0, []
        resp_qid, ips = _parse_dns_response(b"")
        assert resp_qid == 0
        assert ips == []

    @pytest.mark.anyio
    async def test_detect_wildcard_dns_no_wildcard(self, monkeypatch) -> None:
        """Verify wildcard detector returns empty set when canaries fail to resolve."""
        async def mock_resolve_hosts(hosts, timeout=1.8):
            return {h: [] for h in hosts}

        monkeypatch.setattr(SubdomainDiscoveryService, "_resolve_hosts", mock_resolve_hosts)
        wildcards = await SubdomainDiscoveryService._detect_wildcard_dns("safe-domain.org")
        assert wildcards == set()

    @pytest.mark.anyio
    async def test_detect_wildcard_dns_active(self, monkeypatch) -> None:
        """Verify wildcard detector catches active wildcard records."""
        async def mock_resolve_hosts(hosts, timeout=1.8):
            return {h: ["192.0.2.1"] for h in hosts}

        monkeypatch.setattr(SubdomainDiscoveryService, "_resolve_hosts", mock_resolve_hosts)
        wildcards = await SubdomainDiscoveryService._detect_wildcard_dns("wildcard-domain.org")
        assert "192.0.2.1" in wildcards

    @pytest.mark.anyio
    async def test_query_subdomain_center_parsing(self, monkeypatch) -> None:
        """Verify _query_subdomain_center parses and sanitizes json list response."""
        import httpx

        class MockResponse:
            status_code = 200
            def json(self):
                return ["app.target.com", "api.target.com", "invalid.other.com", "target.com"]

        class MockAsyncClient:
            def __init__(self, *args, **kwargs):
                pass
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def get(self, *args, **kwargs):
                return MockResponse()

        monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)
        results = await SubdomainDiscoveryService._query_subdomain_center("target.com")
        assert "app.target.com" in results
        assert "api.target.com" in results
        assert "invalid.other.com" not in results
        assert "target.com" not in results


class TestSubdomainDiscoveryAPI:
    """Tests for /targets/find-subdomains endpoint."""

    def test_find_subdomains_endpoint_mocked(self, client: TestClient, monkeypatch) -> None:
        """Test API endpoint returns structured SubdomainDiscoveryResponse."""
        async def mock_query_crt(apex):
            return {"app." + apex, "ems." + apex}

        async def mock_query_cs(apex):
            return {"swm." + apex}

        async def mock_query_sc(apex):
            return set()

        async def mock_query_ht(apex):
            return set(), {}

        async def mock_query_empty(apex):
            return set()

        async def mock_resolve_hosts(hosts, timeout=2.0, *args, **kwargs):
            res = {}
            for h in hosts:
                if any(x in h for x in ["app", "ems", "swm", "www"]):
                    res[h] = ["1.2.3.4"]
                else:
                    res[h] = []
            return res

        async def mock_verify_live(sub):
            return True, "https", 443, 200, 45.0

        monkeypatch.setattr(SubdomainDiscoveryService, "_query_crt_sh", mock_query_crt)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_urlscan", mock_query_empty)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_certspotter", mock_query_cs)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_subdomain_center", mock_query_sc)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_hackertarget", mock_query_ht)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_alienvault", mock_query_empty)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_anubis", mock_query_empty)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_wayback_cdx", mock_query_empty)
        monkeypatch.setattr(SubdomainDiscoveryService, "_resolve_hosts", mock_resolve_hosts)
        monkeypatch.setattr(SubdomainDiscoveryService, "_verify_live_service", mock_verify_live)

        payload = {
            "domain": "testcity.gov",
            "include_dns_probe": True,
            "include_cert_transparency": True,
            "verify_live": True,
        }
        resp = client.post("/api/v1/targets/find-subdomains", json=payload)
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()

        assert data["target_domain"] == "testcity.gov"
        assert data["total_discovered"] >= 3
        sub_names = [s["subdomain"] for s in data["subdomains"]]
        assert "app.testcity.gov" in sub_names
        assert "ems.testcity.gov" in sub_names
        assert "swm.testcity.gov" in sub_names
        assert data["live_count"] >= 3

    def test_find_subdomains_stream_endpoint(self, client: TestClient, monkeypatch) -> None:
        """Test continuous live streaming endpoint /targets/find-subdomains/stream."""
        import json

        async def mock_query_crt(apex):
            return {"app." + apex, "ems." + apex}

        async def mock_query_cs(apex):
            return {"swm." + apex}

        async def mock_query_sc(apex):
            return set()

        async def mock_query_ht(apex):
            return set(), {}

        async def mock_query_empty(apex):
            return set()

        async def mock_resolve_hosts(hosts, timeout=2.0, *args, **kwargs):
            res = {}
            for h in hosts:
                if any(x in h for x in ["app", "ems", "swm", "www"]):
                    res[h] = ["1.2.3.4"]
                else:
                    res[h] = []
            return res

        async def mock_verify_live(sub):
            return True, "https", 443, 200, 45.0, "nginx/1.24"

        monkeypatch.setattr(SubdomainDiscoveryService, "_query_crt_sh", mock_query_crt)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_urlscan", mock_query_empty)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_certspotter", mock_query_cs)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_subdomain_center", mock_query_sc)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_hackertarget", mock_query_ht)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_alienvault", mock_query_empty)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_anubis", mock_query_empty)
        monkeypatch.setattr(SubdomainDiscoveryService, "_query_wayback_cdx", mock_query_empty)
        monkeypatch.setattr(SubdomainDiscoveryService, "_resolve_hosts", mock_resolve_hosts)
        monkeypatch.setattr(SubdomainDiscoveryService, "_verify_live_service", mock_verify_live)

        payload = {
            "domain": "testcity.gov",
            "include_dns_probe": True,
            "include_cert_transparency": True,
            "verify_live": True,
            "continuous_scan": True,
        }
        resp = client.post("/api/v1/targets/find-subdomains/stream", json=payload)
        assert resp.status_code == status.HTTP_200_OK

        lines = [line.strip() for line in resp.text.split("\n") if line.strip()]
        assert len(lines) >= 3  # Contains phases and batches
        events = [json.loads(line) for line in lines]
        types = [e.get("type") for e in events]
        assert "phase" in types
        assert "complete" in types
        complete_event = next(e for e in events if e.get("type") == "complete")
        assert complete_event["total_discovered"] >= 3
        assert complete_event["live_count"] >= 3

    def test_unbounded_dynamic_vocabulary_and_permutations(self) -> None:
        """Verify dynamic target vocabulary mining and unbounded candidate generation break static wordlist limits."""
        apex = "targetcorp.io"
        sample_discovered = [
            "delhi.targetcorp.io",
            "transport.delhi.targetcorp.io",
            "vahan.targetcorp.io",
            "payments-gateway.targetcorp.io",
            "cluster01.targetcorp.io",
        ]

        # 1. Test vocabulary extraction
        tokens = SubdomainDiscoveryService._mine_target_vocabulary(sample_discovered, apex)
        assert "delhi" in tokens
        assert "transport" in tokens
        assert "vahan" in tokens
        assert "payments" in tokens
        assert "gateway" in tokens
        assert "cluster" in tokens

        # 2. Test unbounded candidate generation
        candidates = SubdomainDiscoveryService._generate_unbounded_candidates(apex, sample_discovered)
        assert len(candidates) > len(EXPANDED_SUBDOMAIN_PREFIXES)

        # Ensure dynamic mutations based on mined tokens exist
        assert f"api-delhi.{apex}" in candidates
        assert f"dev-vahan.{apex}" in candidates
        assert f"portal-payments.{apex}" in candidates
        assert f"api.delhi.{apex}" in candidates
        assert f"web01.{apex}" in candidates
        assert f"api1.{apex}" in candidates

    @pytest.mark.anyio
    async def test_query_wayback_cdx_mocked(self, monkeypatch) -> None:
        """Verify Wayback CDX API parsing of archive snapshots."""
        import httpx

        mock_cdx_data = [
            ["original"],
            ["https://portal.targetcorp.io/app/login"],
            ["http://api.dev.targetcorp.io:8080/v1"],
            ["https://targetcorp.io/"],
            ["https://static.cdn.targetcorp.io/bundle.js"],
        ]

        class MockResponse:
            status_code = 200
            def json(self):
                return mock_cdx_data

        class MockAsyncClient:
            def __init__(self, *args, **kwargs):
                pass
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def get(self, url, *args, **kwargs):
                return MockResponse()

        monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)
        results = await SubdomainDiscoveryService._query_wayback_cdx("targetcorp.io")
        assert "portal.targetcorp.io" in results
        assert "api.dev.targetcorp.io" in results
        assert "static.cdn.targetcorp.io" in results
        assert "targetcorp.io" not in results  # Apex itself excluded

    @pytest.mark.anyio
    async def test_live_scrape_target_network_mocked(self, monkeypatch) -> None:
        """Verify live scraper harvests subdomains from HTML, JS bundles, and CSP headers."""
        apex = "myacme.com"

        async def mock_resolve_hosts(hosts, timeout=1.5):
            return {h: ["10.0.0.1"] for h in hosts}

        async def mock_verify_live(sub):
            return True, "https", 443, 200, 32.0, "nginx/1.22", "Acme Portal Title"

        monkeypatch.setattr(SubdomainDiscoveryService, "_resolve_hosts", mock_resolve_hosts)
        monkeypatch.setattr(SubdomainDiscoveryService, "_verify_live_service", mock_verify_live)

        html_body = r"""
        <html>
            <head>
                <title>Acme Main Portal</title>
                <link rel="modulepreload" href="/static/module.js">
            </head>
            <body>
                <script src="/static/js/app.bundle.js"></script>
                <a href="https://auth.myacme.com/login">Login</a>
                <p>Contact dev-team at api.dev.myacme.com</p>
                <script>
                    window.ENV = {"gateway": "https:\/\/json-gw.myacme.com\/api"};
                </script>
            </body>
        </html>
        """
        js_body = """
        const API_BASE = "https://internal-api.myacme.com/v2";
        const WS_URL = "wss://realtime.myacme.com/stream";
        """

        import httpx

        class MockResponse:
            def __init__(self, url):
                self.url = str(url)
                self.status_code = 200
                self.headers = {
                    "content-security-policy": "default-src 'self' cdn.myacme.com *.myacme.com",
                    "server": "cloudflare",
                }
                if ".js" in self.url:
                    self.text = js_body
                elif "robots.txt" in self.url:
                    self.text = "Sitemap: https://sitemap.myacme.com/sitemap.xml\nDisallow: /admin"
                elif "sitemap.xml" in self.url:
                    self.text = "<urlset><loc>https://docs.myacme.com/guide</loc></urlset>"
                else:
                    self.text = html_body

        class MockAsyncClient:
            def __init__(self, *args, **kwargs):
                pass
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def get(self, url, *args, **kwargs):
                return MockResponse(url)

        monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)

        scraped = await SubdomainDiscoveryService._live_scrape_target_network(
            apex=apex,
            seed_hosts=[apex],
            max_hosts=2,
            max_depth=1,
        )

        assert len(scraped) > 0
        assert "auth.myacme.com" in scraped
        assert "internal-api.myacme.com" in scraped
        assert "realtime.myacme.com" in scraped
        assert "cdn.myacme.com" in scraped
        assert "json-gw.myacme.com" in scraped
        assert scraped["auth.myacme.com"]["is_live"] is True
        assert scraped["auth.myacme.com"]["live_scraped"] is True
        assert scraped["auth.myacme.com"]["page_title"] == "Acme Portal Title"

    @pytest.mark.anyio
    async def test_verify_live_service_extracts_title(self, monkeypatch) -> None:
        """Verify _verify_live_service extracts HTML <title> tag properly."""
        import httpx

        class MockResponse:
            status_code = 200
            headers = {"server": "nginx"}
            text = "<html><head><title>  Acme Secure Auth Gateway  </title></head><body><h1>Welcome</h1></body></html>"

        class MockAsyncClient:
            def __init__(self, *args, **kwargs):
                pass
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def get(self, *args, **kwargs):
                return MockResponse()

        monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)
        res = await SubdomainDiscoveryService._verify_live_service("auth.acme.com")
        is_live, scheme, port, status_code, latency, server, title = res
        assert is_live is True
        assert status_code == 200
        assert title == "Acme Secure Auth Gateway"




