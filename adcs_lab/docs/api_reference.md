# API Reference

## Modules

### `adcs_lab.detection.adcs_enum`
- `load_mock_environment() -> ScanResult`: load mock PKI templates and authorities.
- `CertificateTemplate`: dataclass with ESC predicate helpers (`is_esc1` ... `is_esc8`).
- `CertificateAuthority`: dataclass with `is_esc5` ACL evaluation.
- `render_markdown(result: ScanResult) -> str`: render findings summary.

### `adcs_lab.detection.pki_misconfig_scanner`
- `scan_inventory(inventory: ScanResult) -> ScanReport`: evaluate ESC1–ESC8.
- `save_report(report: ScanReport, output: Path, as_json: bool) -> None`: persist results.
- `ScanReport.to_json()/to_markdown()`: serialise findings with context.

### `adcs_lab.attacks`
- `ESC1Exploit.execute(username: str) -> dict`: simulate open enrollment.
- `forge_agent_request(template, target_user) -> dict`: enrollment-agent abuse (ESC2).
- `build_authentication_certificate(template, service_principal) -> dict`: dangerous EKU issuance (ESC3).
- `request_anypurpose_cert(template, identity) -> dict`: AnyPurpose/NoEKU misuse (ESC4).
- `simulate_ntlm_relay(ca, relay_host) -> dict`: NTLM relay modelling (ESC8).

## CLI

```
usage: adcs-scan [-v] {detect,exploit,defend} ...

options:
  -v, --verbose           Increase log verbosity (repeatable)

detect:
  --json                  Emit JSON output
  --output OUTPUT         Path to write report

exploit:
  --technique {esc1,esc2,esc3,esc4,esc8}
  --user USER             User or SPN to impersonate
  --host HOST             Host for ESC8 relay simulation

defend:
  Show hardening guidance
```
