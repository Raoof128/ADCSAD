"""Simulate ESC3 by abusing templates with dangerous EKUs."""

from __future__ import annotations

import logging

from adcs_lab.detection.adcs_enum import CertificateTemplate

LOGGER = logging.getLogger(__name__)


def build_authentication_certificate(template: CertificateTemplate, service_principal: str) -> dict[str, str]:
    """Return a mock certificate payload that can be used for authentication abuse."""
    if not template.is_esc3():
        raise ValueError("Template is not vulnerable to ESC3")
    LOGGER.info("Building ESC3 certificate for %s via %s", service_principal, template.name)
    return {
        "template": template.name,
        "eku": template.enhanced_key_usages,
        "subject": f"CN={service_principal}",
        "notes": "Authenticate to services using the agent EKU certificate.",
    }
