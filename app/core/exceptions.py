"""OWASP Sentinel - Domain Exceptions and Error Definitions

Provides structured exceptions for input validation, security violations,
and authorization failures.
"""

from typing import Any


class SentinelException(Exception):
    """Base exception for all OWASP Sentinel errors."""

    def __init__(self, message: str, code: str = "INTERNAL_ERROR", details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class TargetValidationError(SentinelException):
    """Raised when target URL, domain, or IP fails syntactic or semantic validation."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, code="TARGET_VALIDATION_ERROR", details=details)


class UnauthorizedTargetError(SentinelException):
    """Raised when an assessment is requested without explicit legal authorization."""

    def __init__(
        self,
        message: str = "Assessment rejected: Explicit authorization is required.",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message=message, code="UNAUTHORIZED_TARGET", details=details)


class SecurityRestrictionError(SentinelException):
    """Raised when a target violates SSRF safeguards, cloud metadata blocks, or loopback rules."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, code="SECURITY_RESTRICTION_VIOLATION", details=details)


class TargetDNSResolutionError(SentinelException):
    """Raised when target domain or hostname cannot be resolved via DNS."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, code="DNS_RESOLUTION_FAILURE", details=details)


class TargetConnectionTimeoutError(SentinelException):
    """Raised when connections to the target exceed allowed timeout limits."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, code="CONNECTION_TIMEOUT", details=details)


class TargetTLSError(SentinelException):
    """Raised when a TLS/SSL handshake or protocol failure occurs with the target."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, code="TLS_HANDSHAKE_FAILURE", details=details)


class TargetRateLimitExceededError(SentinelException):
    """Raised when the target returns persistent HTTP 429 Too Many Requests responses."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, code="RATE_LIMIT_EXCEEDED", details=details)

