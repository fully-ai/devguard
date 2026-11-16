"""Dependency manifest hygiene analyzer (requirements.txt, pyproject.toml, package.json, go.mod)."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from devguard.models import Finding, GuardConfig

_REQ_PIN_RE = re.compile(r"^[a-zA-Z0-9_.-]+(?:\[[^\]]+\])?(==|>=|<=|~=|!=|<|>)")


def scan_dependencies(path: Path, rel_path: str, text: str, cfg: GuardConfig) -> list[Finding]:
    findings: list[Finding] = []
    name = path.name

    if name == "requirements.txt" and "DEP-001" not in cfg.disabled_rules:
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith(("#", "-r", "--")):
                continue
            if line.startswith("http://"):
                findings.append(
                    Finding(
                        rule_id="DEP-002",
                        category="dependencies",
                        severity="HIGH",
                        title="Insecure HTTP Dependency URL",
                        file_path=rel_path,
                        line=lineno,
                        message="Use HTTPS instead of plain HTTP for package sources.",
                    )
                )
            elif not _REQ_PIN_RE.match(line):
                findings.append(
                    Finding(
                        rule_id="DEP-001",
                        category="dependencies",
                        severity="LOW",
                        title="Unpinned Python Dependency",
                        file_path=rel_path,
                        line=lineno,
                        message=f"Dependency '{line}' has no version constraint.",
                    )
                )

    elif name == "pyproject.toml" and "DEP-001" not in cfg.disabled_rules:
        try:
            data = tomllib.loads(text)
        except Exception:
            return findings
        deps = data.get("project", {}).get("dependencies", [])
        if isinstance(deps, list):
            for dep in deps:
                spec = str(dep).strip()
                if spec and not _REQ_PIN_RE.match(spec):
                    findings.append(
                        Finding(
                            rule_id="DEP-001",
                            category="dependencies",
                            severity="LOW",
                            title="Unpinned Python Dependency",
                            file_path=rel_path,
                            line=1,
                            message=f"pyproject.toml dependency '{spec}' has no version constraint.",
                        )
                    )

    elif name == "package.json" and "DEP-003" not in cfg.disabled_rules:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return findings
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if isinstance(deps, dict):
                for pkg, ver in deps.items():
                    if str(ver).strip() in {"*", "latest", ""}:
                        findings.append(
                            Finding(
                                rule_id="DEP-003",
                                category="dependencies",
                                severity="MEDIUM",
                                title="Unpinned NPM Dependency",
                                file_path=rel_path,
                                line=1,
                                message=f"Package '{pkg}' uses wildcard/latest version '{ver}'.",
                            )
                        )

    elif name == "go.mod" and "DEP-004" not in cfg.disabled_rules:
        for lineno, raw in enumerate(text.splitlines(), start=1):
            stripped = raw.strip()
            if stripped.startswith("replace ") and "=>" in stripped:
                target = stripped.split("=>", 1)[1].strip()
                if target.startswith(("./", "../", "/")):
                    findings.append(
                        Finding(
                            rule_id="DEP-004",
                            category="dependencies",
                            severity="MEDIUM",
                            title="Local Path Replace Directive in go.mod",
                            file_path=rel_path,
                            line=lineno,
                            message=f"Local filesystem replace directive '{stripped}' breaks reproducible builds.",
                        )
                    )

    return findings
