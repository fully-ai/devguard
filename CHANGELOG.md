# Changelog

## [0.1.0] - 2026-11-16

### Added
- Secret scanning (regex signatures + Shannon entropy) with `# devguard:ignore` suppression.
- Python AST security checks (`eval`, `exec`, `os.system`, `subprocess shell=True`, `pickle`, `yaml.load`, weak hashes, `verify=False`).
- Configuration and container checks (committed `.env`/keys, root/unpinned Dockerfile, debug/CORS flags).
- Dependency hygiene checks (`requirements.txt`, `package.json`), Python plugin loader, and JSON/HTML/text reporters.
