"""OWASP Sentinel Detection Rules Package.

Exposes comprehensive automated detection checks spanning all 19 OWASP historical timeline themes
and all OWASP Top 10 editions.
"""

from app.scanner.rules.auth_failures import AuthenticationHardeningCheck
from app.scanner.rules.buffer_overflow import BufferOverflowResilienceCheck
from app.scanner.rules.cookies import CookieSecurityCheck
from app.scanner.rules.cors import CorsConfigurationCheck
from app.scanner.rules.csrf import CsrfDefenseCheck
from app.scanner.rules.data_integrity import SubresourceDataIntegrityCheck
from app.scanner.rules.dos_resilience import DosResilienceCheck
from app.scanner.rules.headers import HttpSecurityHeadersCheck
from app.scanner.rules.http_methods import HttpMethodSecurityCheck
from app.scanner.rules.info_leak import ServerInformationLeakCheck
from app.scanner.rules.injection import InjectionDefenseCheck
from app.scanner.rules.insecure_design import InsecureDesignCheck
from app.scanner.rules.logging_monitoring import SecurityLoggingMonitoringCheck
from app.scanner.rules.redirects import UnvalidatedRedirectsCheck
from app.scanner.rules.sensitive_files import SensitiveEndpointExposureCheck
from app.scanner.rules.ssrf import SsrfProtectionCheck
from app.scanner.rules.tls import TlsConfigurationCheck
from app.scanner.rules.vulnerable_components import VulnerableComponentsCheck
from app.scanner.rules.xxe import XxeInjectionCheck

ALL_RULES = [
    HttpSecurityHeadersCheck(),          # RULE-SEC-001 (A02:2025 Security Misconfiguration)
    TlsConfigurationCheck(),             # RULE-SEC-002 (A04:2025 Cryptographic Failures)
    CookieSecurityCheck(),               # RULE-SEC-003 (A07:2025 Authentication Failures)
    ServerInformationLeakCheck(),        # RULE-SEC-004 (A10:2025 Exceptional Conditions)
    CorsConfigurationCheck(),            # RULE-SEC-005 (A01:2025 Broken Access Control)
    SensitiveEndpointExposureCheck(),   # RULE-SEC-006 (A01:2025 Broken Access Control)
    HttpMethodSecurityCheck(),           # RULE-SEC-007 (A01:2025 Broken Access Control)
    InjectionDefenseCheck(),             # RULE-SEC-008 (A05:2025 Injection)
    InsecureDesignCheck(),               # RULE-SEC-009 (A06:2025 Insecure Design)
    VulnerableComponentsCheck(),         # RULE-SEC-010 (A03:2025 Software Supply Chain)
    AuthenticationHardeningCheck(),      # RULE-SEC-011 (A07:2025 Authentication Failures)
    SubresourceDataIntegrityCheck(),     # RULE-SEC-012 (A08:2025 Software/Data Integrity)
    SecurityLoggingMonitoringCheck(),    # RULE-SEC-013 (A09:2025 Security Logging & Alerting)
    SsrfProtectionCheck(),               # RULE-SEC-014 (A01:2025 Broken Access Control / SSRF)
    CsrfDefenseCheck(),                  # RULE-SEC-015 (A01:2025 Broken Access Control / CSRF)
    BufferOverflowResilienceCheck(),     # RULE-SEC-016 (A02:2025 Security Misconfiguration / Buffer Overflow)
    DosResilienceCheck(),                # RULE-SEC-017 (A10:2025 Exceptional Conditions / Denial of Service)
    UnvalidatedRedirectsCheck(),         # RULE-SEC-018 (A01:2025 Broken Access Control / Redirects)
    XxeInjectionCheck(),                 # RULE-SEC-019 (A02:2025 Security Misconfiguration / XXE)
]
