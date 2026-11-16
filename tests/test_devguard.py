"""Tests for DevGuard secret scanning, Python AST checks, config/deps, plugins, and reports."""

import json
from pathlib import Path

from devguard.cli import main as cli_main
from devguard.engine import scan_repository
from devguard.models import Finding, GuardConfig
from devguard.reporters import render_html, render_json


def test_devguard_detects_secrets_ast_configs_deps_and_plugins(tmp_path: Path) -> None:
    repo = tmp_path / "sample_repo"
    repo.mkdir()

    # 1. Secret + Python AST issues + ignore comment
    (repo / "app.py").write_text(
        "\n".join(
            [
                "import os, subprocess, yaml",
                'AWS_KEY = "' + "AKIA" + '1234567890ABCDEF"',
                'IGNORED = "' + "AKIA" + '0000000000IGNORE"  # devguard:ignore',
                'eval("1+1")',
                'subprocess.run("ls", shell=True)',
                'yaml.load("a: 1")',
                "DEBUG = True",
            ]
        ),
        encoding="utf-8",
    )

    # 2. Committed .env and risky Dockerfile
    (repo / ".env").write_text("DB_PASS=supersecret\n", encoding="utf-8")
    (repo / "Dockerfile").write_text("FROM python:latest\nCMD ['python']\n", encoding="utf-8")

    # 3. Unpinned dependencies
    (repo / "requirements.txt").write_text("requests\nfastapi>=0.115.0\n", encoding="utf-8")

    # 4. Custom plugin
    plugin_file = tmp_path / "custom_plugin.py"
    plugin_file.write_text(
        "from pathlib import Path\n"
        "from devguard.models import Finding, GuardConfig\n"
        "def run_plugin(root: Path, cfg: GuardConfig) -> list[Finding]:\n"
        "    return [Finding('PLG-001', 'plugin', 'LOW', 'Custom Check', 'README.md', 1, 'Missing README')]\n",
        encoding="utf-8",
    )

    result = scan_repository(repo, plugin_paths=[plugin_file])
    rule_ids = {f.rule_id for f in result.findings}

    assert "SEC-001" in rule_ids
    assert "PY-001" in rule_ids
    assert "PY-003" in rule_ids
    assert "PY-005" in rule_ids
    assert "CFG-001" in rule_ids
    assert "CFG-002" in rule_ids
    assert "CFG-003" in rule_ids
    assert "CFG-004" in rule_ids
    assert "DEP-001" in rule_ids
    assert "PLG-001" in rule_ids

    # Ensure devguard:ignore suppressed the ignored key
    sec001 = [f for f in result.findings if f.rule_id == "SEC-001"]
    assert len(sec001) == 1

    # Verify JSON and HTML reports
    parsed_json = json.loads(render_json(result))
    assert parsed_json["summary"]["CRITICAL"] == 1
    assert "DevGuard Security Report" in render_html(result)

    # Verify CLI exit code 1 when --fail-on high
    out_json = tmp_path / "out.json"
    exit_code = cli_main(["scan", str(repo), "--format", "json", "--output", str(out_json), "--fail-on", "high"])
    assert exit_code == 1
    assert out_json.is_file()


def test_devguard_config_disables_rules(tmp_path: Path) -> None:
    repo = tmp_path / "clean_repo"
    repo.mkdir()
    (repo / ".devguard.toml").write_text('disabled_rules = ["DEP-001"]\n', encoding="utf-8")
    (repo / "requirements.txt").write_text("pytest\n", encoding="utf-8")
    cfg = GuardConfig.load(repo)
    res = scan_repository(repo, cfg=cfg)
    assert len(res.findings) == 0
    assert isinstance(Finding("a", "b", "LOW", "c", "d", 1, "e").to_dict(), dict)
