"""CLI entrypoint for ADCS Attack & Defence Lab."""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from adcs_lab.attacks.esc1_exploit import ESC1Exploit
from adcs_lab.attacks.esc2_enrollment_agent_abuse import forge_agent_request
from adcs_lab.attacks.esc3_dangerous_eku_demo import build_authentication_certificate
from adcs_lab.attacks.esc4_template_misuse import request_anypurpose_cert
from adcs_lab.attacks.esc8_ntlm_relay_simulation import simulate_ntlm_relay
from adcs_lab.detection.adcs_enum import CertificateTemplate, load_mock_environment
from adcs_lab.detection.pki_misconfig_scanner import save_report, scan_inventory

LOGGER = logging.getLogger(__name__)


def configure_logging(verbosity: int) -> None:
    """Configure a console logger honoring verbosity flags."""
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=level)
    LOGGER.debug("Logging configured for verbosity=%s", verbosity)


def handle_detect(args: argparse.Namespace) -> None:
    """Run the misconfiguration scan and write output to disk."""
    inventory = load_mock_environment()
    report = scan_inventory(inventory)
    output_path = Path(args.output).expanduser().resolve()
    LOGGER.info("Writing detection output to %s", output_path)
    save_report(report, output_path, as_json=args.json)
    print(f"[+] Detection report written to {output_path}")


def handle_exploit(args: argparse.Namespace) -> None:
    """Simulate the requested exploitation technique against the mock inventory."""
    env = load_mock_environment()
    template: CertificateTemplate
    if args.technique == "esc1":
        template = env.templates[0]
        result: Any = ESC1Exploit(template).execute(args.user)
    elif args.technique == "esc2":
        template = _find_template(env.templates, name="EnrollmentAgent")
        result = forge_agent_request(template, args.user)
    elif args.technique == "esc3":
        template = _find_template(env.templates, predicate=lambda t: t.is_esc3())
        result = build_authentication_certificate(template, args.user)
    elif args.technique == "esc4":
        template = _find_template(env.templates, predicate=lambda t: t.is_esc4())
        result = request_anypurpose_cert(template, args.user)
    elif args.technique == "esc8":
        result = simulate_ntlm_relay(env.authorities[0], args.host)
    else:
        raise ValueError(f"Unsupported technique {args.technique}")

    print(json.dumps(result, indent=2))


def handle_defend(_: argparse.Namespace) -> None:
    """Display defensive assets and guidance for hardening."""
    LOGGER.info("Showing hardening pointers")
    print("[+] Defence mode provides guidance; apply PowerShell hardening scripts on a Windows host.")
    print("    - defence/hardening/remove_dangerous_ekus.ps1")
    print("    - defence/hardening/restrict_enrollment.ps1")
    print("    - defence/hardening/audit_ca_permissions.ps1")


def _find_template(
    templates: list[CertificateTemplate],
    name: str | None = None,
    predicate: Callable[[CertificateTemplate], bool] | None = None,
) -> CertificateTemplate:
    """Locate a template by name or predicate with helpful errors."""
    if name:
        for template in templates:
            if template.name == name:
                return template
        raise ValueError(f"Template named '{name}' not found in inventory")
    if predicate:
        for template in templates:
            if predicate(template):
                return template
    raise ValueError("No template matching predicate found in inventory")


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(description="ADCS attack & defence lab CLI")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase log verbosity (repeatable)")
    sub = parser.add_subparsers(dest="command", required=True)

    detect = sub.add_parser("detect", help="Run detection against mock inventory")
    detect.add_argument("--json", action="store_true", help="Emit JSON output")
    detect.add_argument("--output", default="adcs_report.md", help="Path to write report")
    detect.set_defaults(func=handle_detect)

    exploit = sub.add_parser("exploit", help="Simulate an ESC technique")
    exploit.add_argument("--technique", choices=["esc1", "esc2", "esc3", "esc4", "esc8"], required=True)
    exploit.add_argument("--user", default="attacker", help="User or SPN to impersonate")
    exploit.add_argument("--host", default="relay-host", help="Host for ESC8 relay simulation")
    exploit.set_defaults(func=handle_exploit)

    defend = sub.add_parser("defend", help="Show hardening guidance")
    defend.set_defaults(func=handle_defend)

    return parser


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint for module execution."""
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    args.func(args)


if __name__ == "__main__":
    main()
