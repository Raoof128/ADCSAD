"""Opinionated detection engine for ADCS misconfigurations.

The scanner consumes a mock PKI inventory and produces structured findings that
mirror ESC1-ESC8 behaviors, while providing remediation hints.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path

from .adcs_enum import ScanResult, load_mock_environment, render_markdown

LOGGER = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a single ESC finding tied to a template or certificate authority."""

    esc: str
    target: str
    description: str
    recommendation: str


@dataclass
class ScanReport:
    """Structured report containing findings and the originating inventory."""

    findings: list[Finding]
    inventory: ScanResult

    def to_json(self) -> str:
        """Serialise the report to JSON."""
        return json.dumps(
            {
                "findings": [asdict(f) for f in self.findings],
                "inventory": json.loads(self.inventory.to_json()),
            },
            indent=2,
        )

    def to_markdown(self) -> str:
        """Render the report to Markdown including inventory context."""
        lines = ["# ADCS Misconfiguration Report", ""]
        for finding in self.findings:
            lines.extend(
                [
                    f"## {finding.esc} - {finding.target}",
                    finding.description,
                    "",
                    "**Recommendation**",
                    finding.recommendation,
                    "",
                ]
            )
        lines.append(render_markdown(self.inventory))
        return "\n".join(lines)


ESC_DESCRIPTIONS: dict[str, str] = {
    "ESC1": "Template allows any authenticated user to enroll and request SANs.",
    "ESC2": "Enrollment agent template lets users request on behalf of others.",
    "ESC3": "Dangerous EKUs permit authentication or delegation.",
    "ESC4": "AnyPurpose or no EKU templates enable impersonation.",
    "ESC5": "Certificate Authority ACLs allow untrusted modification.",
    "ESC6": "Subordinate CA templates issue signing certs without control.",
    "ESC7": "Weak cryptography makes certs forgeable.",
    "ESC8": "HTTP enrollment endpoints can be NTLM relayed.",
}

ESC_REMEDIATIONS: dict[str, str] = {
    "ESC1": "Restrict enrollment to security groups and require manager approval.",
    "ESC2": "Remove ENROLLEE_SUPPLIES_SUBJECT and limit agent templates to PKI team.",
    "ESC3": "Remove CertificateRequestAgent from non-agent templates and audit EKUs.",
    "ESC4": "Remove AnyPurpose/NoEKU, split templates per use case.",
    "ESC5": "Lock down ManageCA/ManageCertificates to dedicated CA admins.",
    "ESC6": "Disable subordinate CA issuance or enforce multi-signature approvals.",
    "ESC7": "Raise minimum RSA key size to 3072+ and require modern hash algorithms.",
    "ESC8": "Enable Extended Protection for Authentication and block HTTP relay.",
}


def scan_inventory(inventory: ScanResult) -> ScanReport:
    """Inspect templates and authorities for ESC1-ESC8 issues."""
    findings: list[Finding] = []
    for template in inventory.templates:
        mappings = [
            (template.is_esc1, "ESC1"),
            (template.is_esc2, "ESC2"),
            (template.is_esc3, "ESC3"),
            (template.is_esc4, "ESC4"),
            (template.is_esc6, "ESC6"),
            (template.is_esc7, "ESC7"),
            (template.is_esc8, "ESC8"),
        ]
        for predicate, esc in mappings:
            if predicate():
                findings.append(
                    Finding(
                        esc=esc,
                        target=template.name,
                        description=ESC_DESCRIPTIONS[esc],
                        recommendation=ESC_REMEDIATIONS[esc],
                    )
                )
    for ca in inventory.authorities:
        if ca.is_esc5():
            findings.append(
                Finding(
                    esc="ESC5",
                    target=ca.name,
                    description=ESC_DESCRIPTIONS["ESC5"],
                    recommendation=ESC_REMEDIATIONS["ESC5"],
                )
            )
        if not ca.has_relay_protection:
            findings.append(
                Finding(
                    esc="ESC8",
                    target=f"{ca.name}-http",
                    description="HTTP endpoint missing Extended Protection; vulnerable to NTLM relay.",
                    recommendation=ESC_REMEDIATIONS["ESC8"],
                )
            )
    LOGGER.info(
        "Identified %d findings across %d templates and %d authorities",
        len(findings),
        len(inventory.templates),
        len(inventory.authorities),
    )
    return ScanReport(findings=findings, inventory=inventory_with_context(inventory))


def inventory_with_context(inventory: ScanResult) -> ScanResult:
    """Enrich inventory context for downstream reporting and parity with live collectors."""
    return inventory


def save_report(report: ScanReport, output: Path, as_json: bool) -> None:
    """Persist the report with basic error handling."""
    output.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.debug("Saving report to %s as_json=%s", output, as_json)
    try:
        if as_json:
            output.write_text(report.to_json())
        else:
            output.write_text(report.to_markdown())
    except OSError as exc:
        LOGGER.error("Failed to write report: %s", exc)
        raise


def build_parser() -> argparse.ArgumentParser:
    """Construct an argparse parser for standalone scanner execution."""
    parser = argparse.ArgumentParser(description="ADCS misconfiguration scanner")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("adcs_scan_report.md"),
        help="Path to write the report",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """Entrypoint for running the scanner module directly."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
    inventory = load_mock_environment()
    report = scan_inventory(inventory)
    save_report(report, args.output, args.json)
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
