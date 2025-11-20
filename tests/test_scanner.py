"""Unit tests for the ADCS mock scanner and helper utilities."""

from __future__ import annotations

import json
from pathlib import Path

from adcs_lab.detection.adcs_enum import CertificateTemplate, load_mock_environment
from adcs_lab.detection.pki_misconfig_scanner import ScanReport, save_report, scan_inventory


def test_load_mock_environment_has_expected_templates():
    env = load_mock_environment()
    template_names = {template.name for template in env.templates}
    assert {"User", "EnrollmentAgent", "AnyPurpose", "SubCA"}.issubset(template_names)


def test_scan_inventory_flags_all_esc_categories():
    env = load_mock_environment()
    report = scan_inventory(env)
    esc_keys = {finding.esc for finding in report.findings}
    # ESC1-ESC8 except ESC5 may be absent if CA not flagged; ensure coverage of major templates
    for esc in ("ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7", "ESC8"):
        assert esc in esc_keys


def test_save_report_writes_json(tmp_path: Path):
    env = load_mock_environment()
    report: ScanReport = scan_inventory(env)
    output = tmp_path / "report.json"
    save_report(report, output, as_json=True)
    content = json.loads(output.read_text())
    assert "findings" in content and content["findings"], "findings should be serialised"


def test_certificate_template_predicates():
    template = CertificateTemplate(
        name="Test",
        enrollment_permissions=["Authenticated Users", "ENROLLEE_SUPPLIES_SUBJECT"],
        enhanced_key_usages=["CertificateRequestAgent", "AnyPurpose"],
        publish_to_ad=False,
        requires_manager_approval=False,
        allow_subordinate_ca=True,
        minimum_rsa_key_size=1024,
    )
    assert template.is_esc1()
    assert template.is_esc2()
    assert template.is_esc3()
    assert template.is_esc4()
    assert template.is_esc6()
    assert template.is_esc7()
    assert template.is_esc8()
