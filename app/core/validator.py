"""OWASP Sentinel - Target Input Validator

Implements strict validation, canonical normalization, DNS resolution,
and SSRF protection rules for security assessment targets.
"""

import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit

from app.core.config import settings
from app.core.constants import (
    ALLOWED_SCHEMES,
    CLOUD_METADATA_HOSTS,
    CLOUD_METADATA_IPS,
    DEFAULT_HTTP_PORT,
    DEFAULT_HTTPS_PORT,
    MAX_TCP_PORT,
    MIN_TCP_PORT,
)
from app.core.exceptions import (
    SecurityRestrictionError,
    TargetValidationError,
    UnauthorizedTargetError,
)
from app.models.schemas.target import (
    TargetValidationRequest,
    TargetValidationResponse,
)

# Regex for standard RFC 1123 domain names
DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


class TargetValidator:
    """Validates and normalizes security assessment targets with built-in SSRF safeguards."""

    @classmethod
    def validate(cls, request: TargetValidationRequest) -> TargetValidationResponse:
        """Validate, normalize, and enforce security policies on target request."""
        raw_target = request.target.strip()
        warnings: list[str] = []

        # 1. Enforce Explicit Authorization
        if not request.is_authorized:
            raise UnauthorizedTargetError(
                message="Target assessment rejected: Explicit authorization is required to assess any target.",
                details={"target": raw_target, "scope_grant_id": request.scope_grant_id},
            )

        # 2. Basic sanitization & bounds checks
        cls._validate_input_string(raw_target)

        # 3. Protocol and URL Scheme extraction
        scheme, url_without_scheme = cls._extract_scheme(raw_target)

        # 4. Parse host, port, path
        parsed = urlsplit(f"{scheme}://{url_without_scheme}")
        hostname = parsed.hostname
        if not hostname:
            raise TargetValidationError("Unable to extract valid hostname or IP from target input.")

        # Normalize hostname (lowercase)
        hostname = hostname.lower()

        # Check for disallowed cloud metadata hostnames
        if hostname in CLOUD_METADATA_HOSTS:
            raise SecurityRestrictionError(
                f"Target hostname '{hostname}' is a restricted cloud metadata service.",
                details={"hostname": hostname},
            )

        # 5. Port extraction and validation
        try:
            raw_port = parsed.port
        except ValueError as exc:
            raise TargetValidationError(
                f"Port is outside valid TCP port range ({MIN_TCP_PORT}-{MAX_TCP_PORT}).",
                details={"error": str(exc)},
            ) from exc

        port = cls._resolve_port(raw_port, scheme)

        # 6. Host classification (IP vs Domain) and SSRF verification
        is_ip, ip_obj = cls._parse_ip(hostname)
        resolved_ips: list[str] = []
        is_private = False

        if is_ip and ip_obj is not None:
            # Direct IP target
            is_private = ip_obj.is_private
            cls._check_ip_security(ip_obj, request.allow_private_ips)
            resolved_ips = [str(ip_obj)]
            if is_private:
                warnings.append(
                    f"Target IP {ip_obj} is in a private network space (RFC 1918 / RFC 4193). Authorized lab mode enabled."
                )
        else:
            # FQDN / Domain target
            cls._validate_domain_name(hostname)

            if request.skip_dns_resolution:
                warnings.append("DNS resolution check was skipped per request parameter.")
            else:
                resolved_ips, is_private = cls._resolve_and_verify_dns(
                    hostname=hostname,
                    port=port,
                    allow_private_ips=request.allow_private_ips,
                )
                if is_private:
                    warnings.append(
                        f"Domain {hostname} resolves to private IP address ({', '.join(resolved_ips)}). Authorized lab mode enabled."
                    )

        # 7. Path normalization
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # 8. Canonical URL assembly
        canonical_url = cls._build_canonical_url(
            scheme=scheme,
            host=hostname,
            port=port,
            path=path,
            is_ipv6=is_ip and ip_obj is not None and ip_obj.version == 6,
        )

        return TargetValidationResponse(
            is_valid=True,
            original_input=raw_target,
            canonical_url=canonical_url,
            scheme=scheme,
            host=hostname,
            port=port,
            path=path,
            is_ip_address=is_ip,
            resolved_ips=resolved_ips,
            is_private_ip=is_private,
            authorization_confirmed=True,
            scope_grant_id=request.scope_grant_id,
            security_warnings=warnings,
        )

    @classmethod
    def _validate_input_string(cls, raw: str) -> None:
        """Sanitize raw string against control characters, null bytes, and length limits."""
        if len(raw) > settings.MAX_TARGET_URL_LENGTH:
            raise TargetValidationError(
                f"Target length ({len(raw)}) exceeds maximum allowed limit ({settings.MAX_TARGET_URL_LENGTH})."
            )

        # Reject null bytes and CRLF to prevent HTTP response splitting / header injection
        if any(char in raw for char in ("\x00", "\r", "\n")):
            raise TargetValidationError("Target contains illegal control or null characters.")

    @classmethod
    def _extract_scheme(cls, raw: str) -> tuple[str, str]:
        """Detect and validate scheme or apply default scheme safely."""
        # Detect if a scheme is specified
        if "://" in raw:
            scheme_part, rest = raw.split("://", 1)
            scheme = scheme_part.lower()

            if scheme not in ALLOWED_SCHEMES:
                raise TargetValidationError(
                    f"Unsupported protocol scheme '{scheme}'. Only {', '.join(ALLOWED_SCHEMES)} are supported for web assessments.",
                    details={"provided_scheme": scheme, "allowed_schemes": list(ALLOWED_SCHEMES)},
                )
            return scheme, rest

        # Check for disallowed schemes with colon prefix (e.g. javascript:alert(1), file:/etc/passwd)
        colon_idx = raw.find(":")
        if colon_idx != -1:
            potential_scheme = raw[:colon_idx].lower()
            # If the portion before the colon looks like an alphanumeric protocol name (not IPv6 or host:port)
            if potential_scheme.isalpha() and potential_scheme not in ALLOWED_SCHEMES:
                raise TargetValidationError(
                    f"Unsupported protocol scheme '{potential_scheme}'. Only {', '.join(ALLOWED_SCHEMES)} are supported.",
                    details={"provided_scheme": potential_scheme},
                )

        # No explicit scheme provided, default to configured default scheme (https)
        return settings.DEFAULT_SCHEME, raw

    @classmethod
    def _resolve_port(cls, parsed_port: int | None, scheme: str) -> int:
        """Determine effective TCP port and validate range 1-65535."""
        if parsed_port is not None:
            if not (MIN_TCP_PORT <= parsed_port <= MAX_TCP_PORT):
                raise TargetValidationError(
                    f"Port {parsed_port} is outside valid TCP port range ({MIN_TCP_PORT}-{MAX_TCP_PORT})."
                )
            return parsed_port

        return DEFAULT_HTTPS_PORT if scheme == "https" else DEFAULT_HTTP_PORT

    @classmethod
    def _parse_ip(cls, host: str) -> tuple[bool, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
        """Check if host string is a valid IPv4 or IPv6 address."""
        # Strip square brackets if IPv6
        clean_host = host.strip("[]")
        try:
            ip = ipaddress.ip_address(clean_host)
            return True, ip
        except ValueError:
            return False, None

    @classmethod
    def _check_ip_security(
        cls,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        allow_private_ips: bool,
    ) -> None:
        """Enforce SSRF defenses: block cloud metadata, loopback, multicast, and unauthorized private IPs."""
        ip_str = str(ip)

        # Block cloud metadata IPs
        if ip_str in CLOUD_METADATA_IPS:
            raise SecurityRestrictionError(
                f"Target IP '{ip_str}' is a protected cloud metadata address.",
                details={"ip": ip_str, "reason": "CLOUD_METADATA_PROTECTION"},
            )

        # Block loopback (127.0.0.0/8, ::1)
        if ip.is_loopback:
            raise SecurityRestrictionError(
                f"Target IP '{ip_str}' is a loopback address. Localhost scanning is prohibited to prevent SSRF.",
                details={"ip": ip_str, "reason": "LOOPBACK_BLOCKED"},
            )

        # Block link-local addresses (169.254.0.0/16, fe80::/10)
        if ip.is_link_local:
            raise SecurityRestrictionError(
                f"Target IP '{ip_str}' is a link-local address.",
                details={"ip": ip_str, "reason": "LINK_LOCAL_BLOCKED"},
            )

        # Block multicast / reserved / unspecified (0.0.0.0)
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise SecurityRestrictionError(
                f"Target IP '{ip_str}' is a multicast, reserved, or unspecified address.",
                details={"ip": ip_str, "reason": "SPECIAL_USE_IP_BLOCKED"},
            )

        # Check private RFC 1918 / RFC 4193 addresses
        if ip.is_private and not allow_private_ips:
            raise SecurityRestrictionError(
                f"Target IP '{ip_str}' is an internal/private network address. To scan authorized internal targets, set allow_private_ips=True.",
                details={"ip": ip_str, "reason": "PRIVATE_IP_RESTRICTED"},
            )

    @classmethod
    def _validate_domain_name(cls, hostname: str) -> None:
        """Validate FQDN syntax according to RFC 1123 / RFC 952."""
        if hostname == "localhost":
            raise SecurityRestrictionError(
                "Hostname 'localhost' is restricted to prevent SSRF vulnerabilities.",
                details={"hostname": hostname, "reason": "LOCALHOST_BLOCKED"},
            )

        if len(hostname) > 253:
            raise TargetValidationError(f"Hostname length exceeds 253 characters ({len(hostname)}).")

        labels = hostname.rstrip(".").split(".")
        if not labels or any(not label for label in labels):
            raise TargetValidationError(f"Invalid domain format: '{hostname}'.")

        for label in labels:
            if len(label) > 63:
                raise TargetValidationError(f"Domain label '{label}' exceeds 63 characters.")
            if not DOMAIN_LABEL_REGEX.match(label):
                raise TargetValidationError(f"Invalid characters in domain label '{label}'.")

    @classmethod
    def _resolve_and_verify_dns(
        cls,
        hostname: str,
        port: int,
        allow_private_ips: bool,
    ) -> tuple[list[str], bool]:
        """Perform DNS resolution and verify resolved IPs against SSRF rules."""
        resolved_ips: list[str] = []
        has_private = False

        try:
            addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            unique_ips = {str(item[4][0]) for item in addr_info}
            resolved_ips = sorted(unique_ips)
        except socket.gaierror as e:
            # DNS resolution failure
            raise TargetValidationError(
                f"DNS resolution failed for hostname '{hostname}': {e.strerror}.",
                details={"hostname": hostname, "dns_error": str(e)},
            ) from e

        # Inspect every resolved IP address
        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                cls._check_ip_security(ip_obj, allow_private_ips)
                if ip_obj.is_private:
                    has_private = True
            except SecurityRestrictionError:
                raise
            except Exception as e:
                raise TargetValidationError(f"Error validating resolved IP '{ip_str}': {e}") from e

        return resolved_ips, has_private

    @classmethod
    def _build_canonical_url(
        cls,
        scheme: str,
        host: str,
        port: int,
        path: str,
        is_ipv6: bool = False,
    ) -> str:
        """Construct canonical URL omitting standard default ports."""
        host_repr = f"[{host}]" if is_ipv6 and not host.startswith("[") else host

        # Only append port if non-standard
        include_port = not (
            (scheme == "https" and port == DEFAULT_HTTPS_PORT) or (scheme == "http" and port == DEFAULT_HTTP_PORT)
        )

        netloc = f"{host_repr}:{port}" if include_port else host_repr
        # Ensure path begins with /
        clean_path = path if path.startswith("/") else f"/{path}"
        return urlunsplit((scheme, netloc, clean_path, "", ""))
