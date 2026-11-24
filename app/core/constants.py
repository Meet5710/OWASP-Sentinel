"""OWASP Sentinel - Global Constants

Defines standard security constants, official OWASP editions, and network
boundary safeguards such as cloud metadata addresses for SSRF prevention.
"""

from typing import Final

# Standard HTTP & HTTPS Schemes
ALLOWED_SCHEMES: Final[tuple[str, ...]] = ("http", "https")
DEFAULT_SCHEME: Final[str] = "https"

# Common Web Ports permitted for security testing
DEFAULT_HTTP_PORT: Final[int] = 80
DEFAULT_HTTPS_PORT: Final[int] = 443

# Common Web Assessment Ports (can be configured or extended per scope grant)
STANDARD_WEB_PORTS: Final[tuple[int, ...]] = (
    80,
    443,
    8000,
    8008,
    8080,
    8443,
    8888,
    9000,
    9443,
)

# Minimum and Maximum Valid TCP Port Numbers
MIN_TCP_PORT: Final[int] = 1
MAX_TCP_PORT: Final[int] = 65535

# Maximum permitted URL input length to prevent DOS / buffer exhaustion
MAX_URL_LENGTH: Final[int] = 2048

# Cloud Metadata IP addresses and hostnames that MUST NEVER be scanned (SSRF guard)
CLOUD_METADATA_IPS: Final[frozenset[str]] = frozenset(
    [
        "169.254.169.254",  # AWS, Azure, GCP, OpenStack
        "169.254.169.253",  # Azure wire server DNS
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud IMDS
    ]
)

CLOUD_METADATA_HOSTS: Final[frozenset[str]] = frozenset(
    [
        "metadata.google.internal",
        "metadata.azure.internal",
        "instance-data",
    ]
)

# Supported Historical OWASP Top 10 Editions (Official years published)
OFFICIAL_OWASP_EDITIONS: Final[tuple[str, ...]] = (
    "2003",
    "2004",
    "2007",
    "2010",
    "2013",
    "2017",
    "2021",
)

# Current default OWASP Top 10 edition
LATEST_OWASP_EDITION: Final[str] = "2021"
