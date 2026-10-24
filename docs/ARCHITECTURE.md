# Architecture

- `core/`: models, analysis orchestration, risk aggregation.
- `parsers/`: shell-specific parsers.
- `rules/`: deterministic security rules.
- `redaction/`: secret detection and redaction.
- `reporting/`: JSON and Markdown serialization.
- `cli/`: Typer CLI.
- `ui/`: FastAPI web UI.

Flow: request -> parse -> rules -> aggregate -> report.
