"""Configuration, environment file, and container security checks."""

from __future__ import annotations

import re
from pathlib import Path

from devguard.models import Finding, GuardConfig

_CORS_WILD_RE = re.compile(r"""allow_origins\s*=\s*\[\s*["']\*["']\s*\]""")
_DEBUG_TRUE_RE = re.compile(r"""^\s*DEBUG\s*=\s*True\b""")


def scan_config_file(path: Path, rel_path: str, text: str | None, cfg: GuardConfig) -> list[Finding]:
    findings: list[Finding] = []
    name = path.name

    # Committed secret/env files
    if name in {".env", ".env.production", ".env.local"} or path.suffix.lower() in {".pem", ".key"}:
        if "CFG-001" not in cfg.disabled_rules:
            findings.append(
                Finding(
                    rule_id="CFG-001",
                    category="config",
                    severity="HIGH",
                    title="Sensitive Environment or Key File Committed",
                    file_path=rel_path,
                    line=1,
                    message=f"File '{name}' should not be committed to version control.",
                )
            )
        return findings

    if text is None:
        return findings

    if name == "Dockerfile" or name.startswith("Dockerfile."):
        lines = text.splitlines()
        has_non_root_user = False
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.upper().startswith("FROM ") and ":latest" in stripped.lower():
                if "CFG-002" not in cfg.disabled_rules:
                    findings.append(
                        Finding(
                            rule_id="CFG-002",
                            category="container",
                            severity="MEDIUM",
                            title="Unpinned Docker Base Image (:latest)",
                            file_path=rel_path,
                            line=lineno,
                            message="Pin Docker base image to an explicit version tag or digest.",
                        )
                    )
            if stripped.upper().startswith("USER "):
                user_val = stripped.split(None, 1)[1].strip()
                if user_val not in {"root", "0"}:
                    has_non_root_user = True
        if not has_non_root_user and "CFG-003" not in cfg.disabled_rules:
            findings.append(
                Finding(
                    rule_id="CFG-003",
                    category="container",
                    severity="MEDIUM",
                    title="Container Runs as Root User",
                    file_path=rel_path,
                    line=1,
                    message="Add a non-root USER instruction in Dockerfile.",
                )
            )

    for lineno, line in enumerate(text.splitlines(), start=1):
        if "devguard:ignore" in line:
            continue
        if _DEBUG_TRUE_RE.search(line) and "CFG-004" not in cfg.disabled_rules:
            findings.append(
                Finding(
                    rule_id="CFG-004",
                    category="config",
                    severity="MEDIUM",
                    title="Debug Mode Enabled",
                    file_path=rel_path,
                    line=lineno,
                    message="Ensure DEBUG=True is not enabled in production configuration.",
                )
            )
        if _CORS_WILD_RE.search(line) and "CFG-005" not in cfg.disabled_rules:
            findings.append(
                Finding(
                    rule_id="CFG-005",
                    category="config",
                    severity="MEDIUM",
                    title="Wildcard CORS Origin",
                    file_path=rel_path,
                    line=lineno,
                    message="Restrict allow_origins instead of using wildcard '*'.",
                )
            )

    return findings
