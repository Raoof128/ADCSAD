"""Simulate ESC8 by modelling NTLM relay to ADCS HTTP enrollment endpoints."""

from __future__ import annotations

import logging

from adcs_lab.detection.adcs_enum import CertificateAuthority

LOGGER = logging.getLogger(__name__)


def simulate_ntlm_relay(ca: CertificateAuthority, relay_host: str) -> dict[str, str]:
    """Return a mock NTLM relay flow for the CA HTTP endpoint."""
    LOGGER.info("Simulating NTLM relay from %s to %s", relay_host, ca.http_enrollment_url)
    if ca.has_relay_protection:
        raise ValueError("CA has relay protections enabled; cannot abuse ESC8")
    return {
        "target": ca.http_enrollment_url,
        "relay_host": relay_host,
        "attack_steps": [
            "Listen for inbound NTLM auth",
            "Relay to certsrv/",
            "Request enrollment agent cert",
            "Export PFX",
        ],
        "mitigation": "Enable Extended Protection for Authentication and require HTTPS",
    }
