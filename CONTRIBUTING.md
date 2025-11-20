# Contributing

Thank you for improving the ADCS Attack & Defence Lab!

## Development Workflow
1. Fork and branch from `main`.
2. Keep changes small and focused; update tests and docs alongside code.
3. Use virtual environments or the provided `.devcontainer` for consistency.
4. Run quality gates locally:
   - `make lint`
   - `make format`
   - `make test`
5. Submit a PR describing ESC coverage, security impact, and manual test steps.

## Code Style
- Python: type hints, dataclasses where appropriate, avoid broad exceptions, add docstrings for public objects.
- PowerShell: prefer verbose logging with actionable messages.
- Documentation: include diagrams, examples, and references to ESC techniques.

## Security
If you discover a security issue, please follow the process in `SECURITY.md`
before opening a public issue. Avoid sharing exploits publicly before a fix is
available.
