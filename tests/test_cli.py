import json
import subprocess
import sys


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "commandcompass.cli.main", *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_version():
    # use console script
    import shutil

    exe = shutil.which("commandcompass")
    res = subprocess.run([exe, "version"], check=False, capture_output=True, text=True)
    assert res.returncode == 0
    assert "0.1.0" in res.stdout


def test_analyze_json():
    exe = __import__("shutil").which("commandcompass")
    res = subprocess.run(
        [exe, "analyze", "--format", "json", "git status"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["assessment"] == "informational"


def test_rules_list():
    exe = __import__("shutil").which("commandcompass")
    res = subprocess.run([exe, "rules", "list"], check=False, capture_output=True, text=True)
    assert res.returncode == 0
    assert "CC-REMOTE-EXEC" in res.stdout


def test_rules_show():
    exe = __import__("shutil").which("commandcompass")
    res = subprocess.run(
        [exe, "rules", "show", "CC-REMOTE-EXEC"], check=False, capture_output=True, text=True
    )
    assert res.returncode == 0
    assert "Downloaded content executed" in res.stdout


def test_analyze_markdown():
    exe = __import__("shutil").which("commandcompass")
    res = subprocess.run(
        [exe, "analyze", "--format", "markdown", "git status"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "# CommandCompass Analysis Report" in res.stdout


def test_analyze_output_file(tmp_path):
    exe = __import__("shutil").which("commandcompass")
    out = tmp_path / "report.json"
    res = subprocess.run(
        [exe, "analyze", "--format", "json", "--output", str(out), "git status"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert out.exists()
    import json

    json.loads(out.read_text())


def test_analyze_high_risk_exit_code():
    exe = __import__("shutil").which("commandcompass")
    res = subprocess.run(
        [exe, "analyze", "rm -rf ./build"], check=False, capture_output=True, text=True
    )
    assert res.returncode == 1


def test_examples_command():
    exe = __import__("shutil").which("commandcompass")
    res = subprocess.run([exe, "examples"], check=False, capture_output=True, text=True)
    assert res.returncode == 0
    assert "git status" in res.stdout
