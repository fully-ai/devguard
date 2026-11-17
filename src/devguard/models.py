"""Core finding models and configuration loader."""

from __future__ import annotations

import hashlib
import tomllib
from dataclasses import asdict, dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, val: str) -> Severity:
        return cls[val.strip().upper()]


@dataclass(slots=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    file_path: str
    line: int
    message: str
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def fingerprint(self) -> str:
        """Compute a deterministic fingerprint used for baseline matching and SARIF."""
        raw = f"{self.rule_id}|{self.file_path}|{self.line}|{self.title}|{self.message}".encode()
        return hashlib.sha256(raw).hexdigest()[:24]


@dataclass(slots=True)
class GuardConfig:
    exclude_dirs: set[str]
    disabled_rules: set[str]
    entropy_threshold: float = 4.3
    min_secret_length: int = 20

    @classmethod
    def load(cls, root: Path, config_path: Path | None = None) -> GuardConfig:
        default_excludes = {
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "target",
            "dist",
            "build",
            "__pycache__",
        }
        disabled: set[str] = set()
        entropy = 4.3
        min_len = 20

        candidate = config_path or (root / ".devguard.toml")
        if candidate.is_file():
            data = tomllib.loads(candidate.read_text(encoding="utf-8"))
            for d in data.get("exclude_dirs", []):
                default_excludes.add(str(d))
            for r in data.get("disabled_rules", []):
                disabled.add(str(r))
            entropy = float(data.get("entropy_threshold", entropy))
            min_len = int(data.get("min_secret_length", min_len))

        return cls(
            exclude_dirs=default_excludes,
            disabled_rules=disabled,
            entropy_threshold=entropy,
            min_secret_length=min_len,
        )
