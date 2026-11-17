# Changelog

## [0.3.0] - 2026-11-18

### Added
- **SARIF v2.1.0 Reporter**: Added `--format sarif` for GitHub Code Scanning and IDE SARIF viewers.
- **GitHub Actions CI/CD Security Scanner (`CI-001`..`CI-005`)**: Detects mutable branch pins, unpinned third-party actions, unsafe `pull_request_target` PR checkouts, script injection via `${{ github.event.* }}`, and `permissions: write-all`.
- **Baseline & Rule-Specific Suppression**: Added `devguard baseline` subcommand, `--baseline` filtering by finding SHA-256 fingerprint, and `# devguard: ignore RULE_ID` inline annotations.
- **Cross-Platform Runner Scripts**: Added `scripts/{install,dev,test}.{sh,ps1}`.

## [0.2.0] - 2026-11-16

### Added
- Dependency manifest checks for `pyproject.toml` (unpinned dependencies) and `go.mod` (local filesystem `replace` directives).
- CI integration guide (`docs/ci-integration.md`) and expanded unit tests.
- Complete maintainer README with Mermaid diagram, rule reference table, and honest limitation notes.

## [0.1.0] - 2026-11-16

### Added
- Secret scanning (regex signatures + Shannon entropy) with `# devguard:ignore` suppression.
- Python AST security checks (`eval`, `exec`, `os.system`, `subprocess shell=True`, `pickle`, `yaml.load`, weak hashes, `verify=False`).
- Configuration and container checks (committed `.env`/keys, root/unpinned Dockerfile, debug/CORS flags).
- Dependency hygiene checks (`requirements.txt`, `package.json`), Python plugin loader, and JSON/HTML/text reporters.
