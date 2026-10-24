from __future__ import annotations

from commandcompass.core.models import ShellType
from commandcompass.parsers.base import BaseParser
from commandcompass.parsers.cmd import CmdParser
from commandcompass.parsers.posix import PosixParser
from commandcompass.parsers.powershell import PowerShellParser


def detect_shell(command: str) -> ShellType:
    low = command.lower()
    ps_markers = [
        "get-",
        "set-",
        "invoke-",
        "new-",
        "remove-",
        "select-",
        "$env:",
        "write-host",
        "iex",
        "invoke-expression",
        "-eq",
        "-ne",
        "-like",
        "foreach-object",
        "where-object",
    ]
    if any(m in low for m in ps_markers):
        return ShellType.powershell
    # cmd markers
    # weak; default posix unless windows-ish
    if "cmd.exe" in low or "command.com" in low:
        return ShellType.cmd
    return ShellType.posix


def get_parser(shell: ShellType, command: str = "") -> BaseParser:
    if shell == ShellType.auto:
        shell = detect_shell(command)
    if shell == ShellType.powershell:
        return PowerShellParser()
    if shell == ShellType.cmd:
        return CmdParser()
    return PosixParser()
