# CI/CD Integration Guide

Add DevGuard to GitHub Actions to block high or critical findings on pull requests and pushes:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  devguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/fully-ai/devguard.git
      - run: devguard scan . --format html --output devguard-report.html --fail-on high
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: devguard-report
          path: devguard-report.html
```
