# ipcheck collaboration rules

- Python 3.11+, standard library runtime; no local web server and no frontend bundle.
- Browser-side checks (fingerprint, WebRTC, DNS leak) stay delegated to https://ip.net.coffee/claude/; do not add a local UI.
- Keep `LICENSE` and the package license metadata consistent with what is shipped.
- Collect observations and evidence; never claim account safety or infer bans from language, fonts or timezone.
- Unknown, unsupported and skipped checks must remain distinguishable from successful checks.
- Never print, persist, transmit or add fixtures containing real keys, tokens, credentials or raw shell configuration.
- Local identity checks are opt-in. Never modify user configuration, delete credentials or reset identifiers.
- Supported-region data must cite its source and keep `verified_at` / `effective` current.
- Keep Python models and the JSON Schema aligned; run contract tests when they change.
- Validate with `PYTHONPATH=src python3 -m unittest discover -s tests -v`.
- Network tests use synthetic fixtures. Do not contact diagnostic providers during tests.
