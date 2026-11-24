"""OWASP Sentinel - Base Detection Rule Interface

Defines the contract for all modular security assessment checks with complete
documentation, evidence collection, and OWASP category mappings.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.scanner.context import ScanContext


@dataclass
class CheckFinding:
    """Represents a discrete technical issue or weakness identified by a rule."""

    rule_id: str
    title: str
    technical_issue_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str  # CERTAIN, FIRM, TENTATIVE
    evidence: dict[str, Any]
    remediation: str
    references: list[str] = field(default_factory=list)


class BaseDetectionRule(ABC):
    """Abstract base class for all OWASP Sentinel detection rules.

    Each rule must thoroughly document what it tests, why it matters,
    evidence collected, known limitations, and remediation guidance.
    """

    rule_id: str
    name: str
    description: str
    why_it_matters: str
    evidence_description: str
    owasp_category_mappings: dict[str, str]  # e.g. {"2021": "A05:2021", "2017": "A06:2017"}
    required_permissions: str
    known_limitations: str
    potential_false_positives: str
    remediation_guidance: str
    references: list[str]

    @abstractmethod
    async def check(self, context: ScanContext) -> list[CheckFinding]:
        """Execute the security check against the authorized target context."""
        pass

    def to_metadata_dict(self) -> dict[str, Any]:
        """Export comprehensive rule metadata and documentation."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "why_it_matters": self.why_it_matters,
            "evidence_description": self.evidence_description,
            "owasp_category_mappings": self.owasp_category_mappings,
            "required_permissions": self.required_permissions,
            "known_limitations": self.known_limitations,
            "potential_false_positives": self.potential_false_positives,
            "remediation_guidance": self.remediation_guidance,
            "references": self.references,
            "severity": getattr(self, "severity", "MEDIUM"),
            "confidence": getattr(self, "confidence", "HIGH"),
        }
