# Architecture — DevGuard

## Scanner Pipeline

- `src/devguard/engine.py`: Walks repository directories respecting `.devguard.toml` exclusions and runs all enabled scanners plus custom Python plugins.
- `src/devguard/scanners/secrets.py`: Signature matching and Shannon entropy analysis with `# devguard:ignore` line suppression.
- `src/devguard/scanners/python_ast.py`: AST-based detection of `eval`/`exec`, `os.system`, `subprocess(..., shell=True)`, `pickle`, unsafe `yaml.load`, weak hashes, and `verify=False`.
- `src/devguard/scanners/config_scan.py` & `deps.py`: Checks committed `.env`/key files, Dockerfile root/unpinned images, debug/CORS flags, and unpinned/HTTP dependencies.
- `src/devguard/reporters.py`: Renders terminal text, JSON, and standalone HTML reports.
