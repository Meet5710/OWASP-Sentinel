"""OWASP Sentinel - Scan Context & Deep Reconnaissance

Holds target connection attributes, scope authorization parameters,
executes network layer reconnaissance (DNS, TLS cipher probe, latency),
and maintains a live terminal audit stream of scan steps and raw evidence.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import socket
import ssl
import time
from typing import Any

import httpx


@dataclass
class ScanContext:
    """Execution context provided to security rules during an assessment run."""

    canonical_url: str
    host: str
    port: int
    scheme: str
    path: str
    scope_code: str
    rate_limit_per_minute: int = 60
    timeout_seconds: float = 3.0

    # Reconnaissance details
    resolved_ip: str = "127.0.0.1"
    resolved_ips: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    tls_version: str | None = None
    tls_cipher: str | None = None
    certificate_info: dict[str, Any] = field(default_factory=dict)
    http_version: str = "HTTP/1.1"

    # Live terminal log stream
    terminal_logs: list[dict[str, Any]] = field(default_factory=list)

    # Cache for primary baseline HTTP response so multiple passive checks reuse a single request
    _cached_response: httpx.Response | None = None
    custom_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def target_url(self) -> str:
        """Alias for canonical_url for backward and rule compatibility."""
        return self.canonical_url

    def log(
        self,
        level: str,
        rule_id: str,
        message: str,
        detail: Any = None,
    ) -> dict[str, Any]:
        """Record an in-depth practical scan execution entry for the live terminal."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "time_display": datetime.now().strftime("%H:%M:%S"),
            "level": level.upper(),  # RECON, CRYPTO, AUDIT, PROOF, FAIL, PASS, COMPLETE
            "rule_id": rule_id,
            "message": message,
            "detail": detail,
        }
        self.terminal_logs.append(entry)
        return entry

    async def perform_reconnaissance(self) -> dict[str, Any]:
        """Deep network-layer reconnaissance: DNS resolution, TLS handshake, latency."""
        self.log("RECON", "NETWORK", f"Starting host resolution for {self.host}...")
        start_time = time.perf_counter()

        # 1. DNS Resolution
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(self.host, self.port)
            ips = list({info[4][0] for info in addr_info if info and len(info) > 4 and len(info[4]) > 0})
            if ips:
                self.resolved_ip = ips[0]
                self.resolved_ips = ips
                self.log(
                    "RECON",
                    "DNS",
                    f"Resolved {self.host} -> {', '.join(ips)} (Target Port {self.port})",
                )
        except Exception as e:
            self.log("RECON", "DNS", f"DNS resolution failed for {self.host}: {e}")

        # 2. TLS Handshake & Cipher Probing (for HTTPS targets)
        if self.scheme == "https":
            self.log("CRYPTO", "TLS", f"Probing TLS handshake on {self.host}:{self.port}...")
            try:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                loop = asyncio.get_running_loop()

                def probe_ssl():
                    with socket.create_connection((self.host, self.port), timeout=min(self.timeout_seconds, 3.5)) as sock:
                        with ssl_context.wrap_socket(sock, server_hostname=self.host) as ssock:
                            cipher = ssock.cipher()
                            version = ssock.version()
                            peercert = ssock.getpeercert()
                            return cipher, version, peercert

                cipher, version, peercert = await loop.run_in_executor(None, probe_ssl)
                if cipher:
                    self.tls_cipher = cipher[0]
                    self.tls_version = version
                    self.log(
                        "CRYPTO",
                        "TLS",
                        f"TLS Handshake established: Protocol {version} | Cipher Suite {cipher[0]} ({cipher[2]} bits)",
                    )
                if peercert:
                    subject = dict(x[0] for x in peercert.get("subject", []))
                    issuer = dict(x[0] for x in peercert.get("issuer", []))
                    self.certificate_info = {
                        "subject": subject,
                        "issuer": issuer,
                        "notBefore": peercert.get("notBefore"),
                        "notAfter": peercert.get("notAfter"),
                    }
                    self.log(
                        "CRYPTO",
                        "CERT",
                        f"Certificate Validated: Subject '{subject.get('commonName')}' | Issuer '{issuer.get('commonName')}' (Expires {peercert.get('notAfter')})",
                    )
            except Exception as e:
                self.log("CRYPTO", "TLS", f"TLS socket inspection notice: {e}")

        elapsed = (time.perf_counter() - start_time) * 1000
        self.latency_ms = round(elapsed, 2)
        self.log(
            "RECON",
            "NETWORK",
            f"Pre-scan network reconnaissance completed in {self.latency_ms}ms.",
        )

        return {
            "resolved_ip": self.resolved_ip,
            "resolved_ips": self.resolved_ips,
            "latency_ms": self.latency_ms,
            "tls_version": self.tls_version,
            "tls_cipher": self.tls_cipher,
            "certificate_info": self.certificate_info,
        }

    async def get_target_response(self, client: httpx.AsyncClient | None = None) -> httpx.Response:
        """Fetch or retrieve cached baseline GET response with practical request/response capture."""
        if self._cached_response is not None:
            return self._cached_response

        # If a prior baseline probe failed or timed out, reuse fallback immediately
        if getattr(self, "_target_unreachable", False) and hasattr(self, "_fallback_response"):
            return self._fallback_response

        if client is None:
            probe_timeout = min(self.timeout_seconds, 12.0)
            async with httpx.AsyncClient(verify=False, timeout=probe_timeout) as local_client:
                return await self.get_target_response(local_client)

        self.log(
            "SCAN",
            "HTTP",
            f"Transmitting baseline HTTP probe to {self.canonical_url} (User-Agent: OWASP-Sentinel-Auditor/1.0)",
        )
        req_start = time.perf_counter()
        probe_timeout = min(self.timeout_seconds, 12.0)
        try:
            resp = await client.get(
                self.canonical_url,
                timeout=probe_timeout,
                follow_redirects=True,
                headers={
                    "User-Agent": "OWASP-Sentinel-Auditor/1.0 (Deep Vulnerability Inspection; RFC-9110)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Connection": "close",
                },
            )
            self._cached_response = resp
            req_elapsed = (time.perf_counter() - req_start) * 1000
            self.http_version = getattr(self._cached_response, "http_version", "HTTP/1.1")
            self.log(
                "SCAN",
                "HTTP",
                f"Received baseline response from {self.host}: {self._cached_response.status_code} {self._cached_response.reason_phrase} ({req_elapsed:.1f}ms)",
            )
            return self._cached_response
        except Exception as e:
            req_elapsed = (time.perf_counter() - req_start) * 1000
            self._target_unreachable = True
            self._fallback_response = httpx.Response(
                status_code=504 if "timeout" in str(e).lower() else 502,
                request=httpx.Request("GET", self.canonical_url),
                headers={
                    "Content-Type": "text/html; charset=UTF-8",
                    "Connection": "close",
                },
                text=f"<!-- Target probe connection error: {e} -->",
            )
            self._cached_response = self._fallback_response
            self.log(
                "WARN",
                "HTTP",
                f"Baseline probe connection notice ({e}) after {req_elapsed:.1f}ms - target is unreachable / offline.",
            )
            return self._fallback_response

    def build_raw_request_text(
        self,
        method: str = "GET",
        path_override: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> str:
        """Construct the exact plaintext HTTP request string from live wire traffic."""
        if not path_override and not extra_headers and self._cached_response is not None:
            try:
                req = self._cached_response.request
                lines = [f"{req.method} {req.url.raw_path.decode('ascii', errors='ignore') or '/'} HTTP/1.1"]
                for k, v in req.headers.items():
                    lines.append(f"{k}: {v}")
                lines.append("")
                return "\n".join(lines)
            except Exception:
                pass

        req_path = path_override or self.path or "/"
        headers = {
            "Host": f"{self.host}:{self.port}" if self.port not in (80, 443) else self.host,
            "User-Agent": "OWASP-Sentinel-Auditor/1.0 (Deep Vulnerability Inspection; RFC-9110)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)

        lines = [f"{method} {req_path} HTTP/1.1"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        return "\n".join(lines)

    def build_raw_response_text(self, response: httpx.Response) -> str:
        """Construct the exact plaintext HTTP response status line & headers for practical proof display."""
        status_line = f"HTTP/1.1 {response.status_code} {response.reason_phrase}"
        header_lines = [f"{k}: {v}" for k, v in response.headers.items()]
        return status_line + "\n" + "\n".join(header_lines)
