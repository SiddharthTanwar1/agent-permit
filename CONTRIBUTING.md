# Contributing

Use Python 3.11+. Run `python -m unittest discover -s tests -v` from the repository
root, then `python -m examples.integration`. Build/install with `python -m pip install .`.

For security-boundary changes, add a test demonstrating the denied operation never
reaches a handler. Preserve strict policy validation, fail-closed execution, and
argument-free audit records. Document any expansion of supported types or trust
assumptions. Keep the runtime free of third-party dependencies where practical.

Do not submit real credentials, customer data, or captured production prompts.
Report vulnerabilities according to SECURITY.md.
