from __future__ import annotations

import re

from commandcompass.core.models import CommandNode, ParserResult, Pipeline, ShellType
from commandcompass.parsers.base import BaseParser


class CmdParser(BaseParser):
    shell = ShellType.cmd

    def parse(self, command: str) -> ParserResult:
        result = ParserResult(shell="cmd", raw_command=command)
        # env vars %VAR%
        for m in re.finditer(r"%[A-Za-z0-9_]+%", command):
            result.env_vars.append(m.group(0))
        statements = [s.strip() for s in re.split(r"[\n]+", command) if s.strip()]
        # split by & or && at top-level (simple)
        for stmt in statements:
            parts = re.split(r"(&&|&|\|\|)", stmt)
            for idx in range(0, len(parts), 2):
                seg = parts[idx].strip()
                if not seg:
                    continue
                if idx > 0:
                    result.chains.append(parts[idx - 1].strip())
                pipe_segments = seg.split("|")
                pipe_cmds: list[CommandNode] = []
                for ps in pipe_segments:
                    ps = ps.strip()
                    if not ps:
                        continue
                    node = self._parse_command(ps, result)
                    pipe_cmds.append(node)
                if pipe_cmds:
                    result.pipelines.append(Pipeline(commands=pipe_cmds, raw=seg))
        all_cmds: list[CommandNode] = []
        for p in result.pipelines:
            all_cmds.extend(p.commands)
        result.commands = all_cmds
        for c in all_cmds:
            result.redirections.extend(c.redirections)
        if not result.commands and command.strip():
            result.complete = False
            result.confidence = 0.3
        else:
            result.confidence = 0.7
        return result

    def _parse_command(self, text: str, result: ParserResult) -> CommandNode:
        text = text.strip()
        redirections: list[str] = []
        tokens = self._tokenize(text)
        words: list[str] = []
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if re.match(r"^\d*>>?$", t) or t in (">", ">>", "<"):
                if i + 1 < len(tokens):
                    redirections.append(f"{t} {tokens[i + 1]}")
                    i += 2
                else:
                    redirections.append(t)
                    i += 1
                continue
            words.append(t)
            i += 1
        name = words[0] if words else ""
        args = words[1:] if len(words) > 1 else []
        return CommandNode(name=name, args=args, raw=text, redirections=redirections)

    def _tokenize(self, text: str) -> list[str]:
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
            if c in ('"', "'"):
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
