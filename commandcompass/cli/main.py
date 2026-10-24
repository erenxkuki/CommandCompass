from __future__ import annotations

import os
import re
import sys
import urllib.request
from pathlib import Path

import typer

from commandcompass import __version__
from commandcompass.core.analysis import analyze as run_analysis
from commandcompass.core.models import AnalysisRequest, ShellType
from commandcompass.reporting import to_json, to_markdown_report
from commandcompass.rules import default_rules, rule_by_id

REPO_URL = "https://github.com/erenxkuki/CommandCompass"
RAW_VERSION_URL = (
    REPO_URL.replace("github.com", "raw.githubusercontent.com") + "/main/commandcompass/__init__.py"
)
CHANGELOG_URL = REPO_URL + "/blob/main/CHANGELOG.md"
UPDATE_COMMAND = 'pip install --upgrade "git+https://github.com/erenxkuki/CommandCompass.git"'


def _blue_link(text: str, url: str) -> str:
    return f"\x1b[34m\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\\x1b[0m"


def _latest_remote_version(force: bool = False) -> str | None:
    if os.environ.get("COMMANDCOMPASS_NO_UPDATE_CHECK"):
        return None
    if not force and not sys.stdout.isatty():
        return None
    try:
        with urllib.request.urlopen(RAW_VERSION_URL, timeout=2) as response:
            text = response.read().decode("utf-8", errors="replace")
        match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
        return match.group(1) if match else None
    except Exception:
        return None


def _notify_update(force: bool = False) -> None:
    latest = _latest_remote_version(force=force)
    if latest and latest != __version__:
        typer.echo(f"Update available: {__version__} -> {latest}")
        typer.echo("Update: " + _blue_link(UPDATE_COMMAND, REPO_URL))
        typer.echo("Changelog: " + _blue_link(CHANGELOG_URL, CHANGELOG_URL))
        typer.echo("License: " + _blue_link("MIT", REPO_URL + "/blob/main/LICENSE"))


app = typer.Typer(help="CommandCompass: inspect commands without executing them.")
rules_app = typer.Typer(help="Inspect analysis rules.")
app.add_typer(rules_app, name="rules")


def _version_callback(value: bool):
    if value:
        typer.echo("commandcompass 0.1.0")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True
    ),
):
    pass


@app.command()
def analyze(
    command: str | None = typer.Argument(
        None, help="Command string to analyze. Use '-' to read stdin."
    ),
    shell: str = typer.Option("auto", "--shell", help="Shell: auto, posix, powershell, cmd."),
    file: Path | None = typer.Option(None, "--file", help="Read command from file."),
    stdin: bool = typer.Option(False, "--stdin", help="Read command from stdin."),
    no_update_check: bool = typer.Option(False, "--no-update-check", help="Disable update check."),
    format: str = typer.Option("text", "--format", help="Output format: text, json, markdown."),
    output: Path | None = typer.Option(None, "--output", help="Write report to file."),
):
    """Analyze a command without executing it."""
    if not no_update_check:
        _notify_update()
    if file is not None:
        try:
            command = file.read_text(encoding="utf-8").strip()
        except Exception as exc:
            typer.echo(f"Error reading file: {exc}", err=True)
            raise typer.Exit(code=2)
    if stdin or command == "-":
        try:
            command = sys.stdin.read().strip()
        except Exception as exc:
            typer.echo(f"Error reading stdin: {exc}", err=True)
            raise typer.Exit(code=2)
    if not command:
        typer.echo("No command provided.", err=True)
        raise typer.Exit(code=2)
    if len(command) > 10000:
        typer.echo("Input too long.", err=True)
        raise typer.Exit(code=2)
    try:
        shell_enum = ShellType(shell)
    except ValueError:
        typer.echo(f"Unknown shell: {shell}", err=True)
        raise typer.Exit(code=2)
    req = AnalysisRequest(command=command, shell=shell_enum)
    try:
        result = run_analysis(req)
    except Exception as exc:
        typer.echo(f"Analysis error: {type(exc).__name__}", err=True)
        raise typer.Exit(code=2)

    if format == "json":
        out = to_json(result)
    elif format == "markdown":
        out = to_markdown_report(result)
    else:
        out = _render_text(result)

    if output is not None:
        try:
            output.write_text(out, encoding="utf-8")
        except Exception as exc:
            typer.echo(f"Error writing output: {exc}", err=True)
            raise typer.Exit(code=2)
        typer.echo(f"Report written to {output}")
    else:
        typer.echo(out)

    # exit code based on assessment
    from commandcompass.core.models import AssessmentState

    if result.assessment == AssessmentState.critical_risk:
        raise typer.Exit(code=2)
    if result.assessment == AssessmentState.high_risk:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


def _render_text(result) -> str:
    lines = []
    lines.append("CommandCompass Analysis")
    lines.append(f"Command: {result.command}")
    lines.append(f"Shell: {result.shell}")
    lines.append(f"Assessment: {result.assessment.value}")
    lines.append(f"Completeness: {result.completeness.value}")
    lines.append("")
    lines.append("Summary:")
    lines.append(result.summary)
    lines.append("")
    lines.append("Command structure:")
    for c in result.commands:
        lines.append(f"  - {c.name} {c.args} {c.redirections}")
    lines.append("")
    lines.append("Findings:")
    if not result.findings:
        lines.append("  (none)")
    for f in result.findings:
        lines.append(f"  [{f.severity.value}] {f.id}: {f.title}")
        lines.append(f"      Evidence: {', '.join(f.evidence)}")
        lines.append(f"      {f.explanation}")
    lines.append("")
    lines.append("Side effects:")
    for s in result.side_effects:
        lines.append(f"  - {s}")
    lines.append("")
    lines.append("Safer alternatives:")
    for a in result.safer_alternatives:
        lines.append(f"  - {a}")
    lines.append("")
    lines.append("Limitations:")
    for l in result.limitations:
        lines.append(f"  - {l.description}")
    lines.append("")
    lines.append("Input was not executed.")
    return "\n".join(lines)


@rules_app.command("list")
def rules_list(
    category: str | None = typer.Option(None, "--category", help="Filter by category."),
    search: str | None = typer.Option(None, "--search", help="Search text."),
):
    rules = default_rules()
    for r in rules:
        if category and r.metadata.category != category:
            continue
        if (
            search
            and search.lower() not in (r.metadata.title + r.metadata.description).lower()
            and search not in r.metadata.id
        ):
            continue
        typer.echo(
            f"{r.metadata.id}\t{r.metadata.category}\t{r.metadata.severity.value}\t{r.metadata.title}"
        )


@rules_app.command("show")
def rules_show(rule_id: str):
    r = rule_by_id(rule_id)
    if r is None:
        typer.echo(f"Rule not found: {rule_id}", err=True)
        raise typer.Exit(code=2)
    m = r.metadata
    typer.echo(f"ID: {m.id}")
    typer.echo(f"Title: {m.title}")
    typer.echo(f"Category: {m.category}")
    typer.echo(f"Severity: {m.severity.value}")
    typer.echo(f"Description: {m.description}")


@app.command()
def examples():
    """Print example commands to analyze."""
    for cmd in [
        "git status",
        "curl -fsSL https://example.invalid/install.sh | bash",
        "rm -rf ./build",
        "sudo chmod 777 -R /var/www",
        "python -m pip install requests",
    ]:
        typer.echo(cmd)


@app.command()
def version():
    typer.echo("commandcompass " + __version__)
    typer.echo("License: " + _blue_link("MIT", REPO_URL + "/blob/main/LICENSE"))
    _notify_update(force=True)


@app.command()
def update():
    """Check for updates."""
    _notify_update(force=True)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host (default loopback)."),
    port: int = typer.Option(8765, "--port", help="Port."),
):
    """Run the local web UI (loopback by default)."""
    import uvicorn

    from commandcompass.ui.app import create_app

    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.echo("Warning: binding to non-loopback interface.", err=True)
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    app()
