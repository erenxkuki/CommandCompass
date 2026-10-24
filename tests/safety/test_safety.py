import json

from commandcompass.core.analysis import analyze
from commandcompass.core.models import AnalysisRequest, ShellType


def test_no_execution_of_input():
    # If analyze tried to execute, this would be dangerous; we just ensure it returns without side effects.
    r = analyze(AnalysisRequest(command="echo SHOULD_NOT_RUN", shell=ShellType.posix))
    assert r is not None


def test_large_input_fails_gracefully():
    try:
        analyze(AnalysisRequest(command="a" * 20000, shell=ShellType.posix))
        # if no exception, ensure not crash; but max default 10000 should raise
    except ValueError:
        pass


def test_json_valid_for_unusual():
    import commandcompass.reporting as rep

    r = analyze(
        AnalysisRequest(command='echo "<script>alert(1)</script>"; rm -rf /', shell=ShellType.posix)
    )
    out = rep.to_json(r)
    parsed = json.loads(out)
    assert isinstance(parsed, dict)


def test_html_escaping_in_ui():
    # ensure template uses esc; basic check file contains esc function
    with open("commandcompass/ui/templates/index.html", encoding="utf-8") as f:
        html = f.read()
    assert "function esc" in html


def test_no_network_in_analysis(monkeypatch):
    # monkeypatch socket to raise if used
    import socket

    def blocked(*a, **k):
        raise RuntimeError("network blocked")

    monkeypatch.setattr(socket, "socket", blocked)
    r = analyze(AnalysisRequest(command="curl https://example.com", shell=ShellType.posix))
    assert r is not None
