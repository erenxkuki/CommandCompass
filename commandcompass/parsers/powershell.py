from __future__ import annotations

import re

from commandcompass.core.models import CommandNode, ParserResult, Pipeline, ShellType
from commandcompass.parsers.base import BaseParser


class PowerShellParser(BaseParser):
    shell = ShellType.powershell

    def parse(self, command: str) -> ParserResult:
        result = ParserResult(shell="powershell", raw_command=command)
        # detect substitutions / subexpressions
        for m in re.finditer(r"\$\(([^)]*)\)", command):
            result.substitutions.append(m.group(1))
        # env vars
        for m in re.finditer(r"\$env:[A-Za-z_][A-Za-z0-9_]*", command):
            result.env_vars.append(m.group(0))
        for m in re.finditer(r"\$[A-Za-z_][A-Za-z0-9_]*", command):
            result.env_vars.append(m.group(0))

        # split by statement separators: ; and newlines, but keep pipelines
        # We'll split into statements by ; then parse each as pipeline by |
        statements = [s.strip() for s in re.split(r"[;\n]+", command) if s.strip()]
        for stmt in statements:
            # handle && / || chains
            # split chains
            re.split(r"(\&\&|\|\|)", stmt)
            # reconstruct
            # simpler: split by && or ||
            parts = re.split(r"(\&\&|\|\|)", stmt)
            # parts alternate
            for idx in range(0, len(parts), 2):
                seg = parts[idx].strip()
                if not seg:
                    continue
                if idx > 0:
                    result.chains.append(parts[idx - 1].strip())
                # pipeline split by | (not ||)
                pipe_segments = self._split_pipes(seg)
                pipe_cmds: list[CommandNode] = []
                for ps in pipe_segments:
                    ps = ps.strip()
                    if not ps:
                        continue
                    node = self._parse_command(ps, result)
                    pipe_cmds.append(node)
                if pipe_cmds:
                    result.pipelines.append(Pipeline(commands=pipe_cmds, raw=seg))
        # flatten
        all_cmds: list[CommandNode] = []
        for p in result.pipelines:
            all_cmds.extend(p.commands)
        result.commands = all_cmds
        for c in all_cmds:
            result.redirections.extend(c.redirections)
        # unsupported markers
        if re.search(r"`", command):
            result.notes.append("Backtick string/escape detected")
        if not result.commands and command.strip():
            result.complete = False
            result.confidence = 0.3
        if result.substitutions:
            result.notes.append("Subexpression detected")
        if not result.unsupported:
            result.confidence = 0.75
        return result

    def _split_pipes(self, seg: str) -> list[str]:
        # split on | not ||
        parts = []
        buf = ""
        i = 0
        n = len(seg)
        while i < n:
            if seg[i] == "|" and (i + 1 >= n or seg[i + 1] != "|"):
                parts.append(buf)
                buf = ""
                i += 1
            elif seg[i] == "|" and i + 1 < n and seg[i + 1] == "|":
                # keep as chain? shouldn't happen here
                buf += "||"
                i += 2
            else:
                buf += seg[i]
                i += 1
        parts.append(buf)
        return parts

    def _parse_command(self, text: str, result: ParserResult) -> CommandNode:
        text = text.strip()
        redirections: list[str] = []
        # extract redirections >, >>, 2>, etc.
        # simple: find > or >> tokens
        # We'll parse by shlex-like splitting
        tokens = self._tokenize(text)
        # remove redirections
        words: list[str] = []
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t in (">", ">>", "2>", "2>>", ">", ">>") or re.match(r"^\d+>>?$", t):
                if i + 1 < len(tokens):
                    redirections.append(f"{t} {tokens[i + 1]}")
                    i += 2
                else:
                    redirections.append(t)
                    i += 1
                continue
            # handle 2>&1
            if re.match(r"^\d*>&\d+$", t):
                redirections.append(t)
                i += 1
                continue
            words.append(t)
            i += 1
        env_assignments: list[str] = []
        # env assignment at start? PowerShell uses $env:VAR = value (special). Handle simple NAME=value
        i = 0
        while i < len(words) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[i]):
            env_assignments.append(words[i])
            i += 1
        remaining = words[i:]
        name = remaining[0] if remaining else ""
        args = remaining[1:] if len(remaining) > 1 else []
        return CommandNode(
            name=name,
            args=args,
            raw=text,
            env_assignments=env_assignments,
            redirections=redirections,
        )

    def _tokenize(self, text: str) -> list[str]:
        # split respecting single/double quotes
        tokens: list[str] = []
        buf = ""
        i = 0
        n = len(text)
        quote = None
        while i < n:
            c = text[i]
            if quote:
                buf += c
                if c == quote:
                    quote = None
                i += 1
                continue
            if c in ("'", '"'):
                quote = c
                buf += c
                i += 1
                continue
            if c.isspace():
                if buf:
                    tokens.append(buf)
                    buf = ""
                i += 1
                continue
            buf += c
            i += 1
        if buf:
            tokens.append(buf)
        return tokens
