from commandcompass.parsers.cmd import CmdParser
from commandcompass.parsers.powershell import PowerShellParser


def test_ps_pipe():
    r = PowerShellParser().parse("Get-Process | Select-Object Name")
    assert len(r.commands) == 2
    assert r.commands[0].name == "Get-Process"


def test_ps_variable():
    r = PowerShellParser().parse("echo $env:PATH")
    assert any("$env:PATH" in v for v in r.env_vars)


def test_ps_redirection():
    r = PowerShellParser().parse("echo hi > out.txt")
    assert r.commands[0].redirections


def test_cmd_pipe():
    r = CmdParser().parse("dir | findstr txt")
    assert len(r.commands) == 2


def test_cmd_redirection():
    r = CmdParser().parse("echo hi > out.txt")
    assert r.commands[0].redirections


def test_cmd_env():
    r = CmdParser().parse("echo %PATH%")
    assert "%PATH%" in r.env_vars


def test_ps_encoded():
    from commandcompass.parsers.powershell import PowerShellParser

    r = PowerShellParser().parse("powershell -EncodedCommand ZQBjAGgAbwA=")
    assert r.commands
    assert r.complete is not None


def test_windows_path():
    from commandcompass.parsers.cmd import CmdParser

    r = CmdParser().parse(r"dir C:\Windows\System32")
    assert r.commands[0].name.lower() == "dir"
    assert any("System32" in a for a in r.commands[0].args)
