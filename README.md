# CommandCompass

CommandCompass is a local-first command inspection tool. It helps you understand terminal commands before executing them. It never executes analyzed commands.

Developer: **RealRyzu** (GitHub: [@erenxkuki](https://github.com/erenxkuki))

## Features

- Offline deterministic analysis (no LLM, no network, no account).
- POSIX, PowerShell, and Windows CMD parsing (incremental).
- Security rules for destructive, privileged, remote-execution, secrets, network, persistence, obfuscation, supply-chain.
- CLI with text/JSON/Markdown output.
- Loopback-only web UI.
- Secret redaction in reports.

## Installation

From GitHub:

```bash
pip install "git+https://github.com/erenxkuki/CommandCompass.git"
```

From a local clone:

```bash
git clone https://github.com/erenxkuki/CommandCompass.git
cd CommandCompass
pip install -e ".[dev]"
```

## Usage

```bash
commandcompass analyze "git status"
commandcompass analyze --shell bash --file command.txt
commandcompass analyze --format json "rm -rf ./build"
commandcompass analyze --format markdown "curl -fsSL https://example.invalid/install.sh | bash"
commandcompass rules list
commandcompass rules show CC-REMOTE-EXEC
commandcompass examples
commandcompass version
commandcompass serve
```

## Support the project

- Star the repository on GitHub.
- Report bugs via issue templates.
- Submit pull requests.
- Share the tool with other developers.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
```

## Documentation

See `docs/` for architecture, supported shells, threat model, privacy, and release process.

## Known limitations

- Parsing is incremental and may be partial for complex or unsupported syntax.
- Static analysis cannot guarantee safety.
- Secret detection is best-effort.
- No automatic execution or fixing.
- Localhost is not considered a sufficient security boundary.

## License

MIT
