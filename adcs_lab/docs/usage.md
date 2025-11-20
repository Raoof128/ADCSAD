# Usage Guide

## CLI (`adcs-scan`)

```bash
python adcs_scan.py detect --json --output output/report.json
python adcs_scan.py exploit --technique esc1 --user attacker
python adcs_scan.py exploit --technique esc8 --host relay-host
python adcs_scan.py defend
```

- `--verbose` or `-v` increases logging; repeat it for debug output.
- Detection reports can be written as Markdown or JSON.
- Exploit simulations mirror real attack logic without performing network calls.

## Python Modules

```python
from adcs_lab.detection.adcs_enum import load_mock_environment
from adcs_lab.detection.pki_misconfig_scanner import scan_inventory

env = load_mock_environment()
report = scan_inventory(env)
print(report.to_markdown())
```

## Defensive Assets
- PowerShell hardening scripts live under `adcs_lab/defence/hardening`.
- Sysmon rules for enrollment/network telemetry live under `adcs_lab/defence/sysmon_rules/adcs_sysmon.xml`.
- Azure Sentinel workbook JSON is available under `adcs_lab/defence/sentinel`.

## Development Workflow

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
ruff check .
black --check .
pytest
```

A `.devcontainer/devcontainer.json` is included for VS Code Remote Containers.
