# ipcheck collaboration rules

- Python 3.11+, standard library runtime; React / TypeScript / Vite for the local UI.
- Do not run a build or start a development server without explicit user authorization.
- Do not perform automated visual review without explicit user authorization.
- Preserve upstream licenses and update docs/upstream-sources.md for adapted code.
- Collect observations and evidence; never claim account safety or infer bans from language, fonts or timezone.
- Unknown, unsupported and skipped checks must remain distinguishable from successful checks.
- Never print, persist, transmit or add fixtures containing real keys, tokens, credentials or raw shell configuration.
- Local identity checks are opt-in. Never modify user configuration, delete credentials or reset identifiers.
- The local API binds to loopback and checks Host, Origin and a per-process bearer token.
- Keep Python models, the JSON Schema and TypeScript protocol aligned; run contract tests when they change.
- Validate with `PYTHONPATH=src python3 -m unittest discover -s tests -v`, `npm --prefix web run typecheck` and `npm --prefix web run lint`.
- Network tests use synthetic fixtures. Do not contact diagnostic providers during tests.
