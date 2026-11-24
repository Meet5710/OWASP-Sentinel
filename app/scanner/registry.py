"""OWASP Sentinel - Detection Rule Registry & Coverage Matrix

Maintains modular security rules and computes the OWASP Top 10 coverage matrix.
"""

import re
from typing import Any

from app.scanner.base_rule import BaseDetectionRule
from app.scanner.rules import ALL_RULES
from app.taxonomy.lineage import OWASP_2025_CATEGORIES

# Official OWASP Top 10: 2021 Reference Categories
OWASP_2021_CATEGORIES: dict[str, str] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}

# Official OWASP Top 10: 2017 Reference Categories
OWASP_2017_CATEGORIES: dict[str, str] = {
    "A1:2017": "Injection",
    "A2:2017": "Broken Authentication",
    "A3:2017": "Sensitive Data Exposure",
    "A4:2017": "XML External Entities (XXE)",
    "A5:2017": "Broken Access Control",
    "A6:2017": "Security Misconfiguration",
    "A7:2017": "Cross-Site Scripting (XSS)",
    "A8:2017": "Insecure Deserialization",
    "A9:2017": "Using Components with Known Vulnerabilities",
    "A10:2017": "Insufficient Logging & Monitoring",
}

# Official OWASP Top 10: 2013 Reference Categories
OWASP_2013_CATEGORIES: dict[str, str] = {
    "A1:2013": "Injection",
    "A2:2013": "Broken Authentication and Session Management",
    "A3:2013": "Cross-Site Scripting (XSS)",
    "A4:2013": "Insecure Direct Object References",
    "A5:2013": "Security Misconfiguration",
    "A6:2013": "Sensitive Data Exposure",
    "A7:2013": "Missing Function Level Access Control",
    "A8:2013": "Cross-Site Request Forgery (CSRF)",
    "A9:2013": "Using Components with Known Vulnerabilities",
    "A10:2013": "Unvalidated Redirects and Forwards",
}


def _matches_category(target_code: str, rule_mapping: str) -> bool:
    """Match category code against rule mapping string with tolerance for zero-padding (e.g. A1:2017 <-> A01:2017)."""
    if not rule_mapping:
        return False
    if target_code in rule_mapping:
        return True
    m = re.match(r"^A(\d+):(\d{4})$", target_code.strip())
    if m:
        num = int(m.group(1))
        year = m.group(2)
        p1 = f"A{num}:{year}"
        p2 = f"A{num:02d}:{year}"
        if p1 in rule_mapping or p2 in rule_mapping:
            return True
    return False


class RuleRegistry:
    """Registry maintaining available detection checks and coverage mapping."""

    def __init__(self) -> None:
        self._rules: dict[str, BaseDetectionRule] = {}
        for rule in ALL_RULES:
            self.register(rule)

    def register(self, rule: BaseDetectionRule) -> None:
        """Register a detection rule instance."""
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> BaseDetectionRule | None:
        """Lookup a registered rule by its rule_id."""
        return self._rules.get(rule_id)

    def list_rules(self) -> list[BaseDetectionRule]:
        """Return all registered rules."""
        return list(self._rules.values())

    def get_coverage_matrix(self, edition: str = "2025") -> dict[str, Any]:
        """Generate accurate OWASP Top 10 coverage matrix distinguishing automated rules,
        partial checks, manual reviews, and unimplemented categories."""
        if str(edition) == "2025":
            categories_dict = OWASP_2025_CATEGORIES
        elif str(edition) == "2021":
            categories_dict = OWASP_2021_CATEGORIES
        elif str(edition) == "2017":
            categories_dict = OWASP_2017_CATEGORIES
        elif str(edition) == "2013":
            categories_dict = OWASP_2013_CATEGORIES
        else:
            # Fallback to looking up from official editions dataset
            from app.taxonomy.official_editions import OFFICIAL_EDITIONS_DATA

            ed = next((e for e in OFFICIAL_EDITIONS_DATA if str(e["edition_identifier"]) == str(edition)), None)
            if ed:
                categories_dict = {c["category_code"]: c["category_title"] for c in ed["categories"]}
            else:
                categories_dict = OWASP_2025_CATEGORIES

        matrix: list[dict[str, Any]] = []

        for code, title in categories_dict.items():
            matching_rules = [
                r
                for r in self._rules.values()
                if edition in r.owasp_category_mappings
                and _matches_category(code, r.owasp_category_mappings[edition])
            ]

            if matching_rules:
                status = "AUTOMATED_CHECKS"
                rule_ids = [r.rule_id for r in matching_rules]
                rule_names = [r.name for r in matching_rules]
            else:
                status = "NO_IMPLEMENTED_DETECTION"
                rule_ids = []
                rule_names = []

            all_limitations: list[str] = []
            for r in matching_rules:
                if isinstance(r.known_limitations, list):
                    all_limitations.extend(r.known_limitations)
                elif r.known_limitations:
                    all_limitations.append(str(r.known_limitations))

            matrix.append(
                {
                    "category_code": code,
                    "category_title": title,
                    "edition": edition,
                    "coverage_status": status,
                    "automated_rule_count": len(matching_rules),
                    "rule_ids": rule_ids,
                    "rule_names": rule_names,
                    "capabilities": [f"{r.rule_id} ({r.name}): {r.description}" for r in matching_rules],
                    "limitations": list(dict.fromkeys(all_limitations)),
                }
            )

        return {
            "edition": edition,
            "total_categories": len(categories_dict),
            "categories_with_automated_rules": sum(1 for m in matrix if m["coverage_status"] == "AUTOMATED_CHECKS"),
            "categories_requiring_manual_review": sum(
                1 for m in matrix if m["coverage_status"] == "MANUAL_REVIEW_REQUIRED"
            ),
            "uncovered_categories": sum(1 for m in matrix if m["coverage_status"] == "NO_IMPLEMENTED_DETECTION"),
            "coverage_matrix": matrix,
        }


rule_registry = RuleRegistry()
