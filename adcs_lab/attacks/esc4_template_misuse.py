"""Simulate ESC4 by exploiting AnyPurpose/NoEKU templates."""

from __future__ import annotations

import logging

from adcs_lab.detection.adcs_enum import CertificateTemplate

LOGGER = logging.getLogger(__name__)


def request_anypurpose_cert(template: CertificateTemplate, identity: str) -> dict[str, str]:
    """Return a mock certificate that can impersonate services due to broad EKUs."""
    if not template.is_esc4():
        raise ValueError("Template is not vulnerable to ESC4")
    LOGGER.info("Requesting AnyPurpose certificate for %s via %s", identity, template.name)
    return {
        "template": template.name,
        "eku": template.enhanced_key_usages or ["AnyPurpose"],
        "subject": f"CN={identity}",
        "notes": "Use forged certificate with PKINIT/SChannel depending on EKU.",
    }
