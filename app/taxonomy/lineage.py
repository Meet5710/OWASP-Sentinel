"""OWASP Sentinel - Merged OWASP Top 10 Timeline (2003-2025) & Lineage Analysis Engine

Authoritative lineage data model tracking the 22-year evolution of web security risks
across all 8 official OWASP Top 10 publications (2003, 2004, 2007, 2010, 2013, 2017, 2021, 2025).
Provides the core analysis algorithm that evaluates every scanned input and technical observation
against multi-edition historical taxonomy.
"""

from typing import Any

# Official 2025 OWASP Top 10 Categories
OWASP_2025_CATEGORIES: dict[str, str] = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

# Merged OWASP Top 10 Timeline (2003–2025) Risk Theme Lineages
# As specified by the official OWASP Top 10 comparative historical publications
MERGED_OWASP_TIMELINE: list[dict[str, Any]] = [
    {
        "id": "broken-access-control",
        "theme": "Broken Access Control",
        "current_status": "ACTIVE_PRIMARY",
        "current_2025_category": "A01:2025 Broken Access Control",
        "description": "Access control enforces policy such that users cannot act outside of their intended permissions. In 2025, SSRF is absorbed directly into Broken Access Control, alongside IDOR and functional authorization failures.",
        "years_present_summary": "2003: A2 Broken Access Control; 2004: A2 Broken Access Control; 2007: split into A4 Insecure Direct Object Reference & A10 Failure to Restrict URL Access; 2010: A4 Insecure Direct Object References & A8 Failure to Restrict URL Access; 2013: A4 Insecure Direct Object References & A7 Missing Function Level Access Control; 2017: A5 Broken Access Control; 2021: A01 Broken Access Control; 2025: A01 Broken Access Control (SSRF absorbed here)",
        "timeline": {
            "2003": "A2:2003 Broken Access Control",
            "2004": "A2:2004 Broken Access Control",
            "2007": "A4:2007 Insecure Direct Object Reference & A10:2007 Failure to Restrict URL Access",
            "2010": "A4:2010 Insecure Direct Object References & A8:2010 Failure to Restrict URL Access",
            "2013": "A4:2013 Insecure Direct Object References & A7:2013 Missing Function Level Access Control",
            "2017": "A5:2017 Broken Access Control",
            "2021": "A01:2021 Broken Access Control",
            "2025": "A01:2025 Broken Access Control (SSRF absorbed here)",
        },
        "notable_changes": "SSRF absorbed into Broken Access Control in 2025. Previously unified IDOR and URL Access checks into A5 in 2017.",
    },
    {
        "id": "injection",
        "theme": "Injection (incl. XSS)",
        "current_status": "ACTIVE",
        "current_2025_category": "A05:2025 Injection",
        "description": "Occurs when untrusted input is interpreted as commands or queries (SQL, OS, LDAP, XSS). XSS was merged into Injection in 2021 and remains classified under A05 in 2025.",
        "years_present_summary": "2003: A1 Unvalidated Parameters, A4 Cross Site Scripting, A6 Injection Flaws; 2004: A1 Unvalidated Input, A4 XSS, A6 Injection Flaws; 2007: A1 XSS, A2 Injection Flaws; 2010: A1 Injection, A2 XSS; 2013: A1 Injection, A3 XSS; 2017: A1 Injection, A7 XSS; 2021: A03 Injection (XSS merged in); 2025: A05 Injection",
        "timeline": {
            "2003": "A1:2003 Unvalidated Parameters, A4:2003 Cross Site Scripting, A6:2003 Injection Flaws",
            "2004": "A1:2004 Unvalidated Input, A4:2004 XSS, A6:2004 Injection Flaws",
            "2007": "A1:2007 XSS, A2:2007 Injection Flaws",
            "2010": "A1:2010 Injection, A2:2010 XSS",
            "2013": "A1:2013 Injection, A3:2013 XSS",
            "2017": "A1:2017 Injection, A7:2017 XSS",
            "2021": "A03:2021 Injection (XSS merged in)",
            "2025": "A05:2025 Injection",
        },
        "notable_changes": "XSS was standalone from 2003 to 2017; merged into Injection in 2021. Positioned at A05 in 2025.",
    },
    {
        "id": "crypto-data-exposure",
        "theme": "Cryptographic / Data Exposure",
        "current_status": "ACTIVE",
        "current_2025_category": "A04:2025 Cryptographic Failures",
        "description": "Failures related to data protection in transit (TLS/SSL) and at rest (weak storage, weak ciphers). Formerly Sensitive Data Exposure.",
        "years_present_summary": "2003: A8 Insecure Storage; 2004: A8 Insecure Storage; 2007: A8 Insecure Cryptographic Storage, A9 Insecure Communications; 2010: A7 Insecure Cryptographic Storage, A9 Insufficient Transport Layer Protection; 2013: A6 Sensitive Data Exposure (merger of 2010 A7 + A9); 2017: A3 Sensitive Data Exposure; 2021: A02 Cryptographic Failures; 2025: A04 Cryptographic Failures",
        "timeline": {
            "2003": "A8:2003 Insecure Storage",
            "2004": "A8:2004 Insecure Storage",
            "2007": "A8:2007 Insecure Cryptographic Storage, A9:2007 Insecure Communications",
            "2010": "A7:2010 Insecure Cryptographic Storage, A9:2010 Insufficient Transport Layer Protection",
            "2013": "A6:2013 Sensitive Data Exposure (merger of 2010 A7 + A9)",
            "2017": "A3:2017 Sensitive Data Exposure",
            "2021": "A02:2021 Cryptographic Failures",
            "2025": "A04:2025 Cryptographic Failures",
        },
        "notable_changes": "Merged storage and transport into Sensitive Data Exposure in 2013; renamed to Cryptographic Failures in 2021; positioned at A04 in 2025.",
    },
    {
        "id": "security-misconfiguration",
        "theme": "Security Misconfiguration",
        "current_status": "ACTIVE_HIGH_PRIORITY",
        "current_2025_category": "A02:2025 Security Misconfiguration",
        "description": "Insecure defaults, missing defensive HTTP headers, open cloud storage, verbose debugging, and unhardened server configurations. Promoted to #2 in 2025.",
        "years_present_summary": "2003: A10 Insecure Configuration Management; 2004: A10 Insecure Configuration Management; 2007: dropped (not in Top 10); 2010: A6 Security Misconfiguration; 2013: A5 Security Misconfiguration; 2017: A6 Security Misconfiguration; 2021: A05 Security Misconfiguration; 2025: A02 Security Misconfiguration",
        "timeline": {
            "2003": "A10:2003 Insecure Configuration Management",
            "2004": "A10:2004 Insecure Configuration Management",
            "2007": "Dropped (not in Top 10)",
            "2010": "A6:2010 Security Misconfiguration",
            "2013": "A5:2013 Security Misconfiguration",
            "2017": "A6:2017 Security Misconfiguration",
            "2021": "A05:2021 Security Misconfiguration",
            "2025": "A02:2025 Security Misconfiguration",
        },
        "notable_changes": "Omitted in 2007; returned in 2010 as A6; risen steadily to #2 (A02:2025) reflecting widespread cloud misconfiguration risks.",
    },
    {
        "id": "authentication-session",
        "theme": "Authentication & Session",
        "current_status": "ACTIVE",
        "current_2025_category": "A07:2025 Authentication Failures",
        "description": "Confirmation of user identity, session management tokens, credential stuffing resilience, and multi-factor authentication controls.",
        "years_present_summary": "2003: A3 Broken Account and Session Management; 2004: A3 Broken Authentication and Session Management; 2007: A7 Broken Authentication and Session Management; 2010: A3 Broken Authentication and Session Management; 2013: A2 Broken Authentication and Session Management; 2017: A2 Broken Authentication; 2021: A07 Identification and Authentication Failures; 2025: A07 Authentication Failures",
        "timeline": {
            "2003": "A3:2003 Broken Account and Session Management",
            "2004": "A3:2004 Broken Authentication and Session Management",
            "2007": "A7:2007 Broken Authentication and Session Management",
            "2010": "A3:2010 Broken Authentication and Session Management",
            "2013": "A2:2013 Broken Authentication and Session Management",
            "2017": "A2:2017 Broken Authentication",
            "2021": "A07:2021 Identification and Authentication Failures",
            "2025": "A07:2025 Authentication Failures",
        },
        "notable_changes": "Consistent Top 10 presence across all 8 editions. Named Authentication Failures in 2025.",
    },
    {
        "id": "vulnerable-components",
        "theme": "Vulnerable / Outdated Components",
        "current_status": "ACTIVE_EXPANDED",
        "current_2025_category": "A03:2025 Software Supply Chain Failures",
        "description": "Dependencies, open-source libraries, package feeds, and software build pipelines. Scope expanded in 2025 to Software Supply Chain Failures.",
        "years_present_summary": "2013: A9 Using Known Vulnerable Components (new); 2017: A9 Using Components with Known Vulnerabilities; 2021: A06 Vulnerable and Outdated Components; 2025: A03 Software Supply Chain Failures (expanded scope)",
        "timeline": {
            "2003": "Not Present",
            "2004": "Not Present",
            "2007": "Not Present",
            "2010": "Not Present",
            "2013": "A9:2013 Using Known Vulnerable Components (new)",
            "2017": "A9:2017 Using Components with Known Vulnerabilities",
            "2021": "A06:2021 Vulnerable and Outdated Components",
            "2025": "A03:2025 Software Supply Chain Failures (expanded scope)",
        },
        "notable_changes": "Introduced in 2013 as A9; expanded to entire software supply chain in 2025 as A03.",
    },
    {
        "id": "integrity-failures",
        "theme": "Integrity Failures / Deserialization",
        "current_status": "ACTIVE",
        "current_2025_category": "A08:2025 Software or Data Integrity Failures",
        "description": "Untrusted object deserialization, unverified script/subresource inclusion (SRI), and CI/CD artifact tampering.",
        "years_present_summary": "2017: A8 Insecure Deserialization (new); 2021: A08 Software and Data Integrity Failures; 2025: A08 Software or Data Integrity Failures",
        "timeline": {
            "2003": "Not Present",
            "2004": "Not Present",
            "2007": "Not Present",
            "2010": "Not Present",
            "2013": "Not Present",
            "2017": "A8:2017 Insecure Deserialization (new)",
            "2021": "A08:2021 Software and Data Integrity Failures",
            "2025": "A08:2025 Software or Data Integrity Failures",
        },
        "notable_changes": "Started as Insecure Deserialization in 2017; expanded to broader Software & Data Integrity Failures in 2021 and 2025.",
    },
    {
        "id": "logging-monitoring",
        "theme": "Logging & Monitoring / Alerting",
        "current_status": "ACTIVE",
        "current_2025_category": "A09:2025 Security Logging and Alerting Failures",
        "description": "Lack of security telemetry, missing audit trails, and failure to alert on suspicious activity, enabling extended attacker dwell time.",
        "years_present_summary": "2017: A10 Insufficient Logging & Monitoring (new); 2021: A09 Security Logging and Monitoring Failures; 2025: A09 Security Logging and Alerting Failures",
        "timeline": {
            "2003": "Not Present",
            "2004": "Not Present",
            "2007": "Not Present",
            "2010": "Not Present",
            "2013": "Not Present",
            "2017": "A10:2017 Insufficient Logging & Monitoring (new)",
            "2021": "A09:2021 Security Logging and Monitoring Failures",
            "2025": "A09:2025 Security Logging and Alerting Failures",
        },
        "notable_changes": "Introduced in 2017 as A10; evolved to include active Alerting in 2025 (A09).",
    },
    {
        "id": "ssrf",
        "theme": "SSRF",
        "current_status": "ABSORBED",
        "current_2025_category": "A01:2025 Broken Access Control",
        "description": "Server-Side Request Forgery flaws allow attackers to coerce backend applications into issuing arbitrary outbound HTTP/TCP requests.",
        "years_present_summary": "2021: A10 Server-Side Request Forgery (new); 2025: merged into A01 Broken Access Control",
        "timeline": {
            "2003": "Not Present",
            "2004": "Not Present",
            "2007": "Not Present",
            "2010": "Not Present",
            "2013": "Not Present",
            "2017": "Not Present",
            "2021": "A10:2021 Server-Side Request Forgery (new)",
            "2025": "Merged into A01:2025 Broken Access Control",
        },
        "notable_changes": "Introduced as standalone A10 in 2021; absorbed into Broken Access Control (A01) in 2025.",
    },
    {
        "id": "insecure-design",
        "theme": "Insecure Design",
        "current_status": "ACTIVE",
        "current_2025_category": "A06:2025 Insecure Design",
        "description": "Design and architectural flaws that cannot be fixed by implementation controls alone; emphasizes threat modeling and secure design patterns.",
        "years_present_summary": "2021: A04 Insecure Design (new); 2025: A06 Insecure Design",
        "timeline": {
            "2003": "Not Present",
            "2004": "Not Present",
            "2007": "Not Present",
            "2010": "Not Present",
            "2013": "Not Present",
            "2017": "Not Present",
            "2021": "A04:2021 Insecure Design (new)",
            "2025": "A06:2025 Insecure Design",
        },
        "notable_changes": "Introduced in 2021 as A04; moved to A06 in 2025.",
    },
    {
        "id": "exception-error-handling",
        "theme": "Exception / Error Handling",
        "current_status": "RETURNED_ACTIVE",
        "current_2025_category": "A10:2025 Mishandling of Exceptional Conditions",
        "description": "Improper handling of errors, unhandled exceptions leading to denial of service, and leaking diagnostic system architecture details in stack traces.",
        "years_present_summary": "2003: A7 Improper Error Handling; 2004: A7 Improper Error Handling; 2007: A6 Information Leakage and Improper Error Handling; 2010–2021: dropped as standalone; 2025: A10 Mishandling of Exceptional Conditions (new/returned)",
        "timeline": {
            "2003": "A7:2003 Improper Error Handling",
            "2004": "A7:2004 Improper Error Handling",
            "2007": "A6:2007 Information Leakage and Improper Error Handling",
            "2010": "Dropped as standalone",
            "2013": "Dropped as standalone",
            "2017": "Dropped as standalone",
            "2021": "Dropped as standalone (subsumed under A05)",
            "2025": "A10:2025 Mishandling of Exceptional Conditions (returned)",
        },
        "notable_changes": "Top 10 in 2003-2007; dropped as standalone from 2010 to 2021; reintroduced in 2025 as A10 Mishandling of Exceptional Conditions.",
    },
    {
        "id": "csrf",
        "theme": "CSRF",
        "current_status": "DROPPED",
        "current_2025_category": "Subsumed / Defended by Framework Defaults",
        "description": "Cross-Site Request Forgery forces an authenticated end user to execute unintended actions.",
        "years_present_summary": "2007: A5 Cross Site Request Forgery (new); 2010: A5 CSRF; 2013: A8 CSRF; 2017 onward: dropped (not Top 10)",
        "timeline": {
            "2003": "Not Present",
            "2004": "Not Present",
            "2007": "A5:2007 Cross Site Request Forgery (new)",
            "2010": "A5:2010 CSRF",
            "2013": "A8:2013 CSRF",
            "2017": "Dropped (not in Top 10)",
            "2021": "Dropped (not in Top 10)",
            "2025": "Dropped (not in Top 10)",
        },
        "notable_changes": "Peak concern 2007-2013; dropped in 2017 due to automatic CSRF tokens and SameSite cookie standards in modern frameworks.",
    },
    {
        "id": "buffer-overflow",
        "theme": "Buffer Overflow",
        "current_status": "DROPPED",
        "current_2025_category": "Memory Safety / Systems Level Concern",
        "description": "Buffer overrun vulnerabilities in C/C++ backend daemons or web server extensions.",
        "years_present_summary": "2003: A5 Buffer Overflow; 2004: A5 Buffer Overflow; 2007 onward: dropped",
        "timeline": {
            "2003": "A5:2003 Buffer Overflow",
            "2004": "A5:2004 Buffer Overflow",
            "2007": "Dropped",
            "2010": "Dropped",
            "2013": "Dropped",
            "2017": "Dropped",
            "2021": "Dropped",
            "2025": "Dropped",
        },
        "notable_changes": "Dropped after 2004 as memory-safe managed runtimes (Java, .NET, Python, Node.js) became dominant for web layers.",
    },
    {
        "id": "denial-of-service",
        "theme": "Denial of Service",
        "current_status": "DROPPED",
        "current_2025_category": "Infrastructure / Availability Concern",
        "description": "Attacks designed to exhaust computing resources and crash application services.",
        "years_present_summary": "2003: A9 Remote Administration Flaws (related); 2004: A9 Application Denial of Service; 2007 onward: dropped",
        "timeline": {
            "2003": "A9:2003 Remote Administration Flaws (related)",
            "2004": "A9:2004 Application Denial of Service",
            "2007": "Dropped",
            "2010": "Dropped",
            "2013": "Dropped",
            "2017": "Dropped",
            "2021": "Dropped",
            "2025": "Dropped",
        },
        "notable_changes": "Classified primarily as network/infrastructure layer rather than core application security flaw.",
    },
    {
        "id": "unvalidated-redirects",
        "theme": "Unvalidated Redirects / Forwards",
        "current_status": "DROPPED",
        "current_2025_category": "Subsumed under Broken Access Control",
        "description": "Web applications redirecting or forwarding users to external arbitrary URLs without verification.",
        "years_present_summary": "2010: A10 Unvalidated Redirects and Forwards (new); 2013: A10 Unvalidated Redirects and Forwards; 2017 onward: dropped",
        "timeline": {
            "2003": "Not Present",
            "2004": "Not Present",
            "2007": "Not Present",
            "2010": "A10:2010 Unvalidated Redirects and Forwards (new)",
            "2013": "A10:2013 Unvalidated Redirects and Forwards",
            "2017": "Dropped (not in Top 10)",
            "2021": "Dropped (not in Top 10)",
            "2025": "Dropped (not in Top 10)",
        },
        "notable_changes": "Recognized in 2010/2013; dropped in 2017 as low standalone exploitability; handled under access control policies.",
    },
    {
        "id": "idor",
        "theme": "Insecure Direct Object Reference (standalone)",
        "current_status": "ABSORBED",
        "current_2025_category": "A01:2025 Broken Access Control",
        "description": "Direct reference to internal objects (database IDs, filenames) without authorization checks.",
        "years_present_summary": "2007: A4; 2010: A4; 2013: A4; 2017 onward: absorbed into Broken Access Control",
        "timeline": {
            "2003": "Under A2 Broken Access Control",
            "2004": "Under A2 Broken Access Control",
            "2007": "A4:2007 Insecure Direct Object Reference",
            "2010": "A4:2010 Insecure Direct Object References",
            "2013": "A4:2013 Insecure Direct Object References",
            "2017": "Absorbed into A5:2017 Broken Access Control",
            "2021": "Absorbed into A01:2021 Broken Access Control",
            "2025": "Absorbed into A01:2025 Broken Access Control",
        },
        "notable_changes": "Standalone category 2007-2013; consolidated back into Broken Access Control in 2017 onward.",
    },
    {
        "id": "function-level-access",
        "theme": "Missing Function Level Access Control",
        "current_status": "ABSORBED",
        "current_2025_category": "A01:2025 Broken Access Control",
        "description": "Failure to restrict administrative or elevated URL paths and API endpoints.",
        "years_present_summary": "2013: A7 (renamed from 2010 A8); 2017 onward: absorbed into Broken Access Control",
        "timeline": {
            "2003": "Under A2 Broken Access Control",
            "2004": "Under A2 Broken Access Control",
            "2007": "A10:2007 Failure to Restrict URL Access",
            "2010": "A8:2010 Failure to Restrict URL Access",
            "2013": "A7:2013 Missing Function Level Access Control",
            "2017": "Absorbed into A5:2017 Broken Access Control",
            "2021": "Absorbed into A01:2021 Broken Access Control",
            "2025": "Absorbed into A01:2025 Broken Access Control",
        },
        "notable_changes": "Renamed in 2013 from 2010 A8; consolidated into Broken Access Control in 2017 onward.",
    },
    {
        "id": "remote-file-include",
        "theme": "Malicious File Execution / Remote File Include",
        "current_status": "DROPPED",
        "current_2025_category": "Subsumed under Injection / File Exposure",
        "description": "Direct execution of remote unverified scripts or user-supplied file includes (PHP RFI).",
        "years_present_summary": "2007: A3 Insecure Remote File Include (new); 2010 onward: dropped",
        "timeline": {
            "2003": "Not Present",
            "2004": "Not Present",
            "2007": "A3:2007 Insecure Remote File Include (new)",
            "2010": "Dropped",
            "2013": "Dropped",
            "2017": "Dropped",
            "2021": "Dropped",
            "2025": "Dropped",
        },
        "notable_changes": "Standalone only in 2007; subsequent editions folded file inclusions into Injection or Access Control.",
    },
    {
        "id": "xxe",
        "theme": "XXE (XML External Entities)",
        "current_status": "DROPPED",
        "current_2025_category": "Subsumed under Security Misconfiguration",
        "description": "Flaws in XML processors that evaluate external entity references within weakly configured XML documents.",
        "years_present_summary": "2017: A4 XML External Entities (new); 2021 onward: dropped (not Top 10)",
        "timeline": {
            "2003": "Not Present",
            "2004": "Not Present",
            "2007": "Not Present",
            "2010": "Not Present",
            "2013": "Not Present",
            "2017": "A4:2017 XML External Entities (new)",
            "2021": "Dropped (not in Top 10)",
            "2025": "Dropped (not in Top 10)",
        },
        "notable_changes": "New in 2017 as A4; dropped in 2021 due to shift from XML to JSON and default parser entity disabling.",
    },
]

# Lookup map by ID
TIMELINE_BY_ID: dict[str, dict[str, Any]] = {item["id"]: item for item in MERGED_OWASP_TIMELINE}


class LineageScannerAlgorithm:
    """Core evaluation engine that passes every scanned target observation through
    the multi-edition 2003-2025 lineage taxonomy.
    """

    @classmethod
    def resolve_lineage(
        cls,
        rule_id: str,
        technical_issue_type: str,
        base_mappings: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Deep analysis of an observed issue against the 2003-2025 merged timeline.
        Returns:
            - primary_2025_code: e.g. 'A01:2025'
            - primary_2025_title: e.g. 'Broken Access Control'
            - theme_id: identifier in MERGED_OWASP_TIMELINE
            - theme_name: human-readable theme
            - multi_edition_mappings: dictionary mapping edition strings to category strings
            - historical_evolution: list of transitions across years
            - lineage_rationale: detailed context explaining historical progression
        """
        issue = technical_issue_type.upper()
        rule = rule_id.upper()

        # 1. Determine Primary Theme & 2025 Mapping
        if "SSRF" in issue or rule == "RULE-SEC-014":
            theme_id = "ssrf"
            primary_2025 = "A01:2025-Broken Access Control"
            rationale = (
                "Under OWASP Top 10: 2025, Server-Side Request Forgery (SSRF) has been absorbed into "
                "A01:2025 Broken Access Control. SSRF was previously introduced as a standalone category (A10:2021) "
                "and is now unified under access perimeter controls."
            )
        elif any(k in issue for k in ["INJECTION", "XSS", "SQLI", "COMMAND"]) or rule == "RULE-SEC-008":
            theme_id = "injection"
            primary_2025 = "A05:2025-Injection"
            rationale = (
                "Mapped to A05:2025 Injection. Across the 2003-2025 timeline, XSS and injection flaws have evolved "
                "from separate categories (2003-2017) to unified Injection (2021 A03, 2025 A05)."
            )
        elif any(k in issue for k in ["TLS", "SSL", "CIPHER", "CRYPTO", "CERT"]) or rule == "RULE-SEC-002":
            theme_id = "crypto-data-exposure"
            primary_2025 = "A04:2025-Cryptographic Failures"
            rationale = (
                "Evaluated under A04:2025 Cryptographic Failures. Previously classified as Cryptographic Failures "
                "(A02:2021), Sensitive Data Exposure (2013-2017), and Insecure Communications/Storage (2003-2010)."
            )
        elif any(k in issue for k in ["STACK_TRACE", "ERROR_LEAK", "EXCEPTION", "DEBUG_LEAK"]) or (
            rule == "RULE-SEC-004" and "ERROR" in issue
        ):
            theme_id = "exception-error-handling"
            primary_2025 = "A10:2025-Mishandling of Exceptional Conditions"
            rationale = (
                "Evaluated under A10:2025 Mishandling of Exceptional Conditions. Improper Error Handling was a standalone "
                "category in 2003/2004 (A7) and 2007 (A6), dropped from 2010-2021, and has returned in 2025 as A10."
            )
        elif any(k in issue for k in ["COOKIE", "AUTH", "CREDENTIAL", "SESSION"]) or rule == "RULE-SEC-011":
            theme_id = "authentication-session"
            primary_2025 = "A07:2025-Authentication Failures"
            rationale = (
                "Evaluated under A07:2025 Authentication Failures. Authentication & Session flaws have been consistently "
                "tracked across all 8 OWASP editions (2003-2025)."
            )
        elif any(k in issue for k in ["DEPENDENCY", "OUTDATED", "SUPPLY_CHAIN"]) or rule == "RULE-SEC-010":
            theme_id = "vulnerable-components"
            primary_2025 = "A03:2025-Software Supply Chain Failures"
            rationale = (
                "Evaluated under A03:2025 Software Supply Chain Failures. Originally introduced in 2013 as A9 Using Known "
                "Vulnerable Components, this category has been significantly expanded in 2025 to cover complete supply chain risks."
            )
        elif any(k in issue for k in ["SRI", "INTEGRITY", "DESERIALIZATION"]) or rule == "RULE-SEC-012":
            theme_id = "integrity-failures"
            primary_2025 = "A08:2025-Software or Data Integrity Failures"
            rationale = (
                "Evaluated under A08:2025 Software or Data Integrity Failures. Originated as Insecure Deserialization (A8:2017) "
                "and expanded to subresource and data integrity in 2021 and 2025."
            )
        elif any(k in issue for k in ["LOGGING", "ALERTING", "AUDIT"]) or rule == "RULE-SEC-013":
            theme_id = "logging-monitoring"
            primary_2025 = "A09:2025-Security Logging and Alerting Failures"
            rationale = (
                "Evaluated under A09:2025 Security Logging and Alerting Failures. Introduced in 2017 as A10, expanded "
                "in 2025 to emphasize active alerting capabilities."
            )
        elif any(k in issue for k in ["DESIGN", "ARCHITECTURE"]) or rule == "RULE-SEC-009":
            theme_id = "insecure-design"
            primary_2025 = "A06:2025-Insecure Design"
            rationale = (
                "Evaluated under A06:2025 Insecure Design. Introduced in 2021 as A04 to distinguish architectural flaws "
                "from implementation bugs."
            )
        elif any(k in issue for k in ["CSRF", "XSRF"]) or rule == "RULE-SEC-015":
            theme_id = "csrf"
            primary_2025 = "A01:2025-Broken Access Control"
            rationale = (
                "Evaluated under Cross-Site Request Forgery (CSRF) theme and mapped to A01:2025 Broken Access Control. "
                "CSRF was tracked as a standalone Top 10 category (2007-2013) before being subsumed under access control and SameSite standards."
            )
        elif any(k in issue for k in ["REDIRECT", "FORWARD"]) or rule == "RULE-SEC-018":
            theme_id = "unvalidated-redirects"
            primary_2025 = "A01:2025-Broken Access Control"
            rationale = (
                "Evaluated under Unvalidated Redirects / Forwards theme and mapped to A01:2025 Broken Access Control. "
                "Unvalidated Redirects were tracked in 2010/2013 (A10) and are now classified under access control policies."
            )
        elif any(k in issue for k in ["DOS", "RATE_LIMIT", "THROTTLING"]) or rule == "RULE-SEC-017":
            theme_id = "denial-of-service"
            primary_2025 = "A10:2025-Mishandling of Exceptional Conditions"
            rationale = (
                "Evaluated under Denial of Service theme and mapped to A10:2025 Mishandling of Exceptional Conditions. "
                "Application DoS was featured in 2004 (A9) and returns in 2025 under exceptional conditions and rate limiting."
            )
        elif any(k in issue for k in ["BUFFER", "OVERFLOW"]) or rule == "RULE-SEC-016":
            theme_id = "buffer-overflow"
            primary_2025 = "A02:2025-Security Misconfiguration"
            rationale = (
                "Evaluated under Buffer Overflow theme and mapped to A02:2025 Security Misconfiguration. Buffer overflows "
                "featured in 2003/2004 (A5) and in modern web architectures are addressed through request line limits and proxy configurations."
            )
        elif any(k in issue for k in ["XXE", "XML"]) or rule == "RULE-SEC-019":
            theme_id = "xxe"
            primary_2025 = "A02:2025-Security Misconfiguration"
            rationale = (
                "Evaluated under XML External Entities (XXE) theme and mapped to A02:2025 Security Misconfiguration. "
                "XXE was a standalone category in 2017 (A4) and is now governed under XML parser security configurations."
            )
        elif any(k in issue for k in ["CORS", "SENSITIVE_FILE", "DIRECTORY", "IDOR", "ACCESS_CONTROL"]) or rule in [
            "RULE-SEC-005",
            "RULE-SEC-006",
            "RULE-SEC-007",
        ]:
            theme_id = "broken-access-control"
            primary_2025 = "A01:2025-Broken Access Control"
            rationale = (
                "Evaluated under A01:2025 Broken Access Control. Ranks as the #1 critical risk in both 2021 and 2025, "
                "encompassing CORS bypasses, sensitive exposure endpoints, and authorization flaws."
            )
        else:
            # Default to Security Misconfiguration
            theme_id = "security-misconfiguration"
            primary_2025 = "A02:2025-Security Misconfiguration"
            rationale = (
                "Evaluated under A02:2025 Security Misconfiguration. Ranks #2 in OWASP 2025 due to pervasive missing defensive "
                "HTTP headers, unnecessary HTTP verbs, and unhardened default server configurations."
            )

        theme_data = TIMELINE_BY_ID.get(theme_id, MERGED_OWASP_TIMELINE[0])

        # 2. Build multi-edition mappings across 2003-2025
        multi_mappings: dict[str, str] = {}

        # Always start from rule's base_mappings if supplied
        if base_mappings:
            multi_mappings.update(base_mappings)

        # Ensure 2025 is always set correctly
        multi_mappings["2025"] = primary_2025

        # Backfill or synchronize historical editions based on theme timeline if missing
        theme_timeline = theme_data.get("timeline", {})
        for year, entry in theme_timeline.items():
            if "Not Present" in entry or "Dropped" in entry:
                continue
            if year not in multi_mappings:
                multi_mappings[year] = entry

        # Construct historical evolution list
        evolution: list[dict[str, str]] = []
        for year in ["2003", "2004", "2007", "2010", "2013", "2017", "2021", "2025"]:
            mapping_for_year = multi_mappings.get(year, theme_timeline.get(year, "Not In Top 10"))
            evolution.append({"year": year, "designation": mapping_for_year})

        return {
            "theme_id": theme_id,
            "theme_name": theme_data["theme"],
            "current_status": theme_data.get("current_status", "ACTIVE"),
            "primary_2025_code": primary_2025.split("-")[0].strip(),
            "primary_2025_title": primary_2025.split("-", 1)[1].strip() if "-" in primary_2025 else primary_2025,
            "primary_2025_mapping": primary_2025,
            "multi_edition_mappings": multi_mappings,
            "evolution": evolution,
            "lineage_rationale": rationale,
            "theme_summary": theme_data.get("years_present_summary", ""),
        }

