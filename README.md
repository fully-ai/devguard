# DevGuard

Extensible repository security, secret scanning, Python AST, configuration, and dependency hygiene analyzer.

## Features

- **Secret Detection**: Signature matching (AWS, GitHub, Slack, Stripe, private key PEM headers) plus Shannon entropy analysis on credential assignments.
- **Python AST Security Analysis**: Inspects Python ASTs for `eval`/`exec`, `os.system`, `subprocess(..., shell=True)`, `pickle.load(s)`, unsafe `yaml.load`, MD5/SHA1 hashes, and `verify=False`.
- **Configuration & Container Audits**: Flags committed `.env` / `.pem` / `.key` files, containers running as `root`, `:latest` base images, `DEBUG = True`, and wildcard CORS origins.
- **Dependency Hygiene**: Checks `requirements.txt` and `package.json` for unpinned versions and plain HTTP URLs.
- **Plugin System & Reports**: Load custom Python rule modules (`--plugin` or `.devguard_plugins/`) and export findings to terminal text, JSON, or standalone HTML reports.

## Installation & Usage

```bash
git clone https://github.com/fully-ai/devguard.git
cd devguard
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
devguard scan . --format text --fail-on high
devguard scan . --format html --output report.html
```

## Testing

```bash
ruff check src tests
mypy src
pytest -v
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
