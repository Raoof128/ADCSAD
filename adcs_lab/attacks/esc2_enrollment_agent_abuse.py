"""Simulate ESC2 by abusing an enrollment agent template."""

from __future__ import annotations

import logging

from adcs_lab.detection.adcs_enum import CertificateTemplate

LOGGER = logging.getLogger(__name__)


def forge_agent_request(template: CertificateTemplate, target_user: str) -> dict[str, str]:
    """Return a mock enrollment request where an agent impersonates another user."""
    if not template.is_esc2():
        raise ValueError("Template is not vulnerable to ESC2")
    LOGGER.info("Simulating enrollment agent misuse for %s via %s", target_user, template.name)
    csr = {
        "on_behalf_of": target_user,
        "eku": template.enhanced_key_usages,
        "subject": f"CN={target_user}, OU=Operations",
    }
    return {
        "template": template.name,
        "csr": csr,
        "issued_certificate": f"delegated-{target_user}.pem",
        "notes": "Use the delegated certificate for S4U2Self/S4U2Proxy impersonation.",
    }
