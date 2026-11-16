"""Repository traversal and scan orchestration engine."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from devguard.models import Finding, GuardConfig, Severity
from devguard.plugins import load_plugins
from devguard.scanners.config_scan import scan_config_file
from devguard.scanners.deps import scan_dependencies
from devguard.scanners.python_ast import scan_python_ast
from devguard.scanners.secrets import scan_secrets

_MAX_TEXT_BYTES = 1024 * 1024


@dataclass(slots=True)
class ScanResult:
    root: str
    files_scanned: int
    findings: list[Finding]

    def summary(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def has_findings_at_or_above(self, min_severity: Severity) -> bool:
        return any(Severity.from_str(f.severity) >= min_severity for f in self.findings)


def scan_repository(
    root: Path,
    cfg: GuardConfig | None = None,
    plugin_paths: list[Path] | None = None,
) -> ScanResult:
    root = root.resolve()
    config = cfg or GuardConfig.load(root)
    findings: list[Finding] = []
    files_scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if d not in config.exclude_dirs]
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            rel_path = fpath.relative_to(root).as_posix()
            files_scanned += 1

            text: str | None = None
            try:
                if fpath.stat().st_size <= _MAX_TEXT_BYTES:
                    raw = fpath.read_bytes()
                    if b"\x00" not in raw[:2048]:
                        text = raw.decode("utf-8", errors="replace")
            except OSError:
                continue

            findings.extend(scan_config_file(fpath, rel_path, text, config))
            if text is None:
                continue

            findings.extend(scan_secrets(fpath, rel_path, text, config))
            if fpath.suffix == ".py":
                findings.extend(scan_python_ast(rel_path, text, config))
            findings.extend(scan_dependencies(fpath, rel_path, text, config))

    auto_plugins_dir = root / ".devguard_plugins"
    discovered = list(plugin_paths or [])
    if auto_plugins_dir.is_dir():
        discovered.extend(sorted(auto_plugins_dir.glob("*.py")))

    for plugin_fn in load_plugins(discovered):
        findings.extend(plugin_fn(root, config))

    findings.sort(key=lambda f: (-Severity.from_str(f.severity), f.file_path, f.line, f.rule_id))
    return ScanResult(root=str(root), files_scanned=files_scanned, findings=findings)
