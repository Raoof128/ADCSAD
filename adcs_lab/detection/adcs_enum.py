"""ADCS enumeration utilities for modelling ESC1-ESC8 misconfigurations.

This module uses mock data structures to mirror common fields returned by
PowerShell/Certipy/Certify and can be reused by CLI or notebooks.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

LOGGER = logging.getLogger(__name__)


@dataclass
class CertificateTemplate:
    """Represents a certificate template in Active Directory."""

    name: str
    enrollment_permissions: list[str]
    enhanced_key_usages: list[str]
    publish_to_ad: bool
    requires_manager_approval: bool
    allow_subordinate_ca: bool
    minimum_rsa_key_size: int
    authorized_signatures: int = 0
    raw_acl: dict[str, list[str]] | None = None

    def __post_init__(self) -> None:
        if self.minimum_rsa_key_size <= 0:
            raise ValueError("minimum_rsa_key_size must be greater than zero")

    def is_esc1(self) -> bool:
        """Return True if any authenticated user can enroll (ESC1)."""
        return "Authenticated Users" in self.enrollment_permissions

    def is_esc2(self) -> bool:
        """Return True if the template allows ENROLLEE_SUPPLIES_SUBJECT (ESC2)."""
        return "ENROLLEE_SUPPLIES_SUBJECT" in self.enrollment_permissions

    def is_esc3(self) -> bool:
        """Return True when dangerous EKUs enable agent-style usage (ESC3)."""
        dangerous = {"CertificateRequestAgent", "EnrollOnBehalf"}
        return bool(dangerous.intersection(self.enhanced_key_usages))

    def is_esc4(self) -> bool:
        """Return True for AnyPurpose or NoEKU templates (ESC4)."""
        return "AnyPurpose" in self.enhanced_key_usages or "NoEKU" in self.enhanced_key_usages

    def is_esc6(self) -> bool:
        """Return True if the template allows subordinate CA issuance (ESC6)."""
        return self.allow_subordinate_ca

    def is_esc7(self) -> bool:
        """Return True if RSA key size is below recommended threshold (ESC7)."""
        return self.minimum_rsa_key_size < 2048

    def is_esc8(self) -> bool:
        """Return True if the template is not published to AD (enabling ESC8 abuse)."""
        return not self.publish_to_ad


@dataclass
class CertificateAuthority:
    """Represents a certificate authority and its relevant metadata."""

    name: str
    http_enrollment_url: str
    has_relay_protection: bool
    ace_permissions: dict[str, list[str]] = field(default_factory=dict)
    templates: list[CertificateTemplate] = field(default_factory=list)

    def is_esc5(self) -> bool:
        """Return True if CA ACLs allow low-privilege users to manage CA (ESC5)."""
        manage_rights = {"ManageCA", "ManageCertificates"}
        for principal, rights in self.ace_permissions.items():
            if principal in {"Authenticated Users", "Domain Users"} and manage_rights.intersection(rights):
                LOGGER.debug("CA %s flagged for ESC5 via %s", self.name, principal)
                return True
        return False


@dataclass
class ScanResult:
    """Aggregated template and CA inventory used by the scanner."""

    templates: list[CertificateTemplate]
    authorities: list[CertificateAuthority]

    def to_json(self) -> str:
        """Serialise the scan results with ESC summary information."""
        return json.dumps(
            {
                "templates": [template.__dict__ for template in self.templates],
                "authorities": [
                    {
                        **{k: v for k, v in ca.__dict__.items() if k != "templates"},
                        "templates": [t.name for t in ca.templates],
                    }
                    for ca in self.authorities
                ],
                "findings": self.findings_summary(),
            },
            indent=2,
        )

    def findings_summary(self) -> dict[str, list[str]]:
        """Summarise templates and authorities by ESC category."""
        summary: dict[str, list[str]] = {f"ESC{i}": [] for i in range(1, 9)}
        for template in self.templates:
            _apply_predicates(summary, template)
        for ca in self.authorities:
            if ca.is_esc5():
                summary["ESC5"].append(ca.name)
        return summary


def load_mock_environment() -> ScanResult:
    """Load a high-fidelity mock environment that mirrors common PKI issues."""
    user_template = CertificateTemplate(
        name="User",
        enrollment_permissions=["Authenticated Users"],
        enhanced_key_usages=["ClientAuth"],
        publish_to_ad=True,
        requires_manager_approval=False,
        allow_subordinate_ca=False,
        minimum_rsa_key_size=1024,
    )
    enrollment_agent_template = CertificateTemplate(
        name="EnrollmentAgent",
        enrollment_permissions=["ENROLLEE_SUPPLIES_SUBJECT", "Domain Users"],
        enhanced_key_usages=["CertificateRequestAgent", "ClientAuth"],
        publish_to_ad=True,
        requires_manager_approval=False,
        allow_subordinate_ca=False,
        minimum_rsa_key_size=2048,
    )
    any_purpose_template = CertificateTemplate(
        name="AnyPurpose",
        enrollment_permissions=["Domain Users"],
        enhanced_key_usages=["AnyPurpose"],
        publish_to_ad=False,
        requires_manager_approval=False,
        allow_subordinate_ca=False,
        minimum_rsa_key_size=4096,
    )
    subca_template = CertificateTemplate(
        name="SubCA",
        enrollment_permissions=["CA Operators"],
        enhanced_key_usages=["CertificateRequestAgent"],
        publish_to_ad=True,
        requires_manager_approval=True,
        allow_subordinate_ca=True,
        minimum_rsa_key_size=3072,
        authorized_signatures=2,
    )
    ca = CertificateAuthority(
        name="corp-CA01",
        http_enrollment_url="http://pki.corp.local/certsrv/",
        has_relay_protection=False,
        ace_permissions={"Authenticated Users": ["ManageCA"]},
        templates=[user_template, enrollment_agent_template, any_purpose_template, subca_template],
    )
    result = ScanResult(
        templates=[user_template, enrollment_agent_template, any_purpose_template, subca_template],
        authorities=[ca],
    )
    LOGGER.info(
        "Loaded mock environment with %d templates and %d authorities",
        len(result.templates),
        len(result.authorities),
    )
    return result


def render_markdown(result: ScanResult) -> str:
    """Render a Markdown summary of ESC findings and CA metadata."""
    lines = ["# ADCS Enumeration Report", "", "## Findings by ESC", ""]
    findings = result.findings_summary()
    for esc, items in findings.items():
        lines.append(f"### {esc}")
        if items:
            for item in items:
                lines.append(f"- {item}")
        else:
            lines.append("- None detected")
        lines.append("")
    lines.append("## Authority Overview")
    for ca in result.authorities:
        lines.extend(
            [
                f"- **CA**: {ca.name}",
                f"  - HTTP Enrollment: {ca.http_enrollment_url}",
                f"  - Relay Protection: {'Enabled' if ca.has_relay_protection else 'Disabled'}",
                f"  - ESC5 Risk: {'Yes' if ca.is_esc5() else 'No'}",
            ]
        )
    return "\n".join(lines)


__all__ = [
    "CertificateTemplate",
    "CertificateAuthority",
    "ScanResult",
    "load_mock_environment",
    "render_markdown",
]


def _apply_predicates(summary: dict[str, list[str]], template: CertificateTemplate) -> None:
    """Apply ESC predicates for a template and mutate the summary in place."""
    mapping: dict[str, Callable[[], bool]] = {
        "ESC1": template.is_esc1,
        "ESC2": template.is_esc2,
        "ESC3": template.is_esc3,
        "ESC4": template.is_esc4,
        "ESC6": template.is_esc6,
        "ESC7": template.is_esc7,
        "ESC8": template.is_esc8,
    }
    for esc, predicate in mapping.items():
        if predicate():
            summary[esc].append(template.name)
