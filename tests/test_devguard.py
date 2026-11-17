"""Tests for DevGuard secret scanning, Python AST checks, config/deps, plugins, and reports."""

import json
from pathlib import Path

from devguard.cli import main as cli_main
from devguard.engine import scan_repository
from devguard.models import Finding, GuardConfig
from devguard.reporters import render_html, render_json, render_sarif


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


def test_pyproject_and_gomod_dependency_checks(tmp_path: Path) -> None:
    repo = tmp_path / "polyglot_repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["httpx", "fastapi>=0.115.0"]\n',
        encoding="utf-8",
    )
    (repo / "go.mod").write_text(
        "module example.com/app\ngo 1.24\nreplace example.com/lib => ../local-lib\n",
        encoding="utf-8",
    )
    res = scan_repository(repo)
    rules = {f.rule_id for f in res.findings}
    assert "DEP-001" in rules
    assert "DEP-004" in rules


def test_sarif_workflows_baseline_and_inline_suppression(tmp_path: Path) -> None:
    repo = tmp_path / "ci_repo"
    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)

    (wf_dir / "deploy.yml").write_text(
        "\n".join(
            [
                "on: pull_request_target",
                "permissions: write-all",
                "jobs:",
                "  build:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - uses: actions/checkout@v4",
                "        with:",
                "          ref: ${{ github.event.pull_request.head.sha }}",
                "      - uses: thirdparty/some-action@main",
                "      - run: echo ${{ github.event.issue.title }}",
                "      - uses: thirdparty/ignored-action@v1  # devguard: ignore CI-002",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "script.py").write_text('eval("2+2")\n', encoding="utf-8")

    res = scan_repository(repo)
    rules = {f.rule_id for f in res.findings}
    assert "CI-001" in rules
    assert "CI-003" in rules
    assert "CI-004" in rules
    assert "CI-005" in rules
    assert "CI-002" not in rules  # suppressed inline by '# devguard: ignore CI-002'
    assert "PY-001" in rules
    assert res.suppressed_count >= 1

    # Verify SARIF v2.1.0 output structure
    sarif = json.loads(render_sarif(res))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "DevGuard"
    assert len(sarif["runs"][0]["results"]) == len(res.findings)

    # Generate baseline via CLI and confirm subsequent scan suppresses all recorded findings
    baseline_file = repo / ".devguard-baseline.json"
    assert cli_main(["baseline", str(repo), "--output", str(baseline_file)]) == 0
    assert baseline_file.is_file()

    sarif_out = tmp_path / "report.sarif"
    rc = cli_main(
        [
            "scan",
            str(repo),
            "--baseline",
            str(baseline_file),
            "--format",
            "sarif",
            "--output",
            str(sarif_out),
            "--fail-on",
            "low",
        ]
    )
    assert rc == 0
    filtered = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert filtered["runs"][0]["results"] == []
