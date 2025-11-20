"""Integration-style tests for the adcs-scan CLI."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Execute the CLI entrypoint with the provided arguments and return the process result."""

    cmd = ["python", "adcs_scan.py", *args]
    return subprocess.run(cmd, cwd=PROJECT_ROOT, text=True, capture_output=True, check=True)


def test_detect_outputs_json(tmp_path: Path) -> None:
    output_path = tmp_path / "report.json"
    result = run_cli(["detect", "--json", "--output", str(output_path)])
    assert output_path.exists(), result.stdout
    content = json.loads(output_path.read_text())
    assert "findings" in content and content["findings"], "Findings should be present"


def test_exploit_esc1_returns_payload(tmp_path: Path) -> None:
    result = run_cli(["exploit", "--technique", "esc1", "--user", "attacker"])
    payload = json.loads(result.stdout)
    assert payload["template"] == "User"
    assert payload["csr"]["subject"].startswith("CN=attacker")


def test_defend_command_runs(tmp_path: Path) -> None:
    result = run_cli(["defend"])
    assert "Defence mode" in result.stdout
