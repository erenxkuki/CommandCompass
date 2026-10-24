from __future__ import annotations

import re
from typing import Any, ClassVar

from commandcompass.core.models import CommandNode, ParserResult, Pipeline, ShellType
from commandcompass.parsers.base import BaseParser


class PosixParser(BaseParser):
    shell = ShellType.posix

    REDIR_OPS: ClassVar[set[str]] = {
        ">",
        ">>",
        "<",
        "<<",
        "<<<",
        "2>",
        "2>>",
        ">&",
        "&>",
        "1>",
        "1>>",
        "2>&1",
        "&>>",
    }

    def parse(self, command: str) -> ParserResult:
        tokens = self._tokenize(command)
        result = ParserResult(shell="posix", raw_command=command)
        # collect substitutions
        for t in tokens:
            if t["type"] == "substitution":
                result.substitutions.append(t["value"])
        # detect env vars
        for t in tokens:
            if t["type"] == "word":
                for m in re.finditer(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", t["value"]):
                    result.env_vars.append(m.group(0))
        # parse structure
        pipelines: list[Pipeline] = []
        current_pipeline_commands: list[CommandNode] = []
        current_cmd: CommandNode | None = None
        current_words: list[str] = []
        current_redirs: list[str] = []
        current_env: list[str] = []

        def flush_cmd():
            nonlocal current_cmd, current_words, current_redirs, current_env
            if current_words or current_env or current_redirs:
                name = ""
                args: list[str] = []
                # determine name
                remaining = list(current_words)
                # env assignments at start
                envs = []
                i = 0
                while i < len(remaining) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", remaining[i]):
                    envs.append(remaining[i])
                    i += 1
                if i < len(remaining):
                    name = remaining[i]
                    args = remaining[i + 1 :]
                node = CommandNode(
                    name=name,
                    args=args,
                    raw=" ".join(current_words + current_redirs),
                    env_assignments=envs + current_env,
                    redirections=list(current_redirs),
                )
                if current_pipeline_commands is not None:
                    current_pipeline_commands.append(node)
                current_words = []
                current_redirs = []
                current_env = []
                current_cmd = None

        def flush_pipeline():
            nonlocal current_pipeline_commands
            if current_pipeline_commands:
                pipelines.append(Pipeline(commands=list(current_pipeline_commands), raw=""))
                current_pipeline_commands = []

        i = 0
        n = len(tokens)
        while i < n:
            t = tokens[i]
            typ = t["type"]
            val = t["value"]
            if typ == "word":
                # redirection pattern?
                if self._is_redirection_word(val) and i + 1 < n and tokens[i + 1]["type"] == "word":
                    current_redirs.append(val + " " + tokens[i + 1]["value"])
                    i += 2
                    continue
                current_words.append(val)
                i += 1
                continue
            if typ == "redir":
                # redir token followed by word
                if i + 1 < n and tokens[i + 1]["type"] == "word":
                    current_redirs.append(val + " " + tokens[i + 1]["value"])
                    i += 2
                else:
                    current_redirs.append(val)
                    i += 1
                continue
            if typ == "op" and val == "|":
                flush_cmd()
                # move to next command in same pipeline
                i += 1
                continue
            if typ == "op" and val in ("||", "&&", ";", "&"):
                flush_cmd()
                flush_pipeline()
                result.chains.append(val)
                i += 1
                continue
            if typ in ("lparen", "rparen"):
                result.unsupported.append("parentheses/grouping")
                result.complete = False
                i += 1
                continue
            if typ == "substitution":
                result.substitutions.append(val)
                current_words.append(f"$({val})")
                i += 1
                continue
            # unknown token type
            i += 1

        flush_cmd()
        flush_pipeline()

        # flatten commands
        all_cmds: list[CommandNode] = []
        for p in pipelines:
            all_cmds.extend(p.commands)
        result.commands = all_cmds
        result.pipelines = pipelines
        # redirections aggregate
        for c in all_cmds:
            result.redirections.extend(c.redirections)
        # unsupported detection
        if not tokens and command.strip():
            result.complete = False
            result.warnings.append("No tokens parsed")
        # check for backticks handled in tokenizer as substitution
        if result.substitutions:
            result.notes.append("Command substitution detected")
            result.confidence = min(result.confidence, 0.8)
        # confidence
        if result.unsupported:
            result.complete = False
            result.confidence = 0.6
        if not result.commands and command.strip():
            result.complete = False
            result.confidence = 0.3
        # wildcards note
        for c in all_cmds:
            for a in c.args:
                if any(ch in a for ch in "*?[]"):
                    result.notes.append(f"Wildcard/path expansion possible in argument: {a}")
        return result

    def _is_redirection_word(self, val: str) -> bool:
        return bool(re.match(r"^\d*>>?$", val)) or val in self.REDIR_OPS

    def _tokenize(self, command: str) -> list[dict[str, Any]]:
        tokens: list[dict[str, Any]] = []
        i = 0
        n = len(command)
        buf = ""
        quoted = False

        def flush_buf():
            nonlocal buf
            if buf != "":
                tokens.append({"type": "word", "value": buf})
                buf = ""

        while i < n:
            c = command[i]
            if c == "\\" and not quoted:
                if i + 1 < n:
                    buf += command[i + 1]
                    i += 2
                    continue
                else:
                    buf += c
                    i += 1
                    continue
            if c == "'":
                # single quote
                j = command.find("'", i + 1)
                if j == -1:
                    # unterminated
                    tokens.append({"type": "word", "value": buf + command[i:]})
                    buf = ""
                    i = n
                    continue
                buf += command[i + 1 : j]
                i = j + 1
                quoted = True
                continue
            if c == '"':
                j = i + 1
                # handle escapes inside
                val = ""
                j = i + 1
                while j < n and command[j] != '"':
                    if command[j] == "\\" and j + 1 < n:
                        val += command[j + 1]
                        j += 2
                    else:
                        val += command[j]
                        j += 1
                buf += val
                i = j + 1
                continue
            if c == "$" and i + 1 < n and command[i + 1] == "(":
                flush_buf()
                # parse matching paren
                depth = 0
                j = i
                # find matching
                k = i + 2
                depth = 1
                while k < n and depth > 0:
                    if command[k] == "(":
                        depth += 1
                    elif command[k] == ")":
                        depth -= 1
                    k += 1
                inner = command[i + 2 : k - 1]
                tokens.append({"type": "substitution", "value": inner})
                i = k
                continue
            if c == "`":
                flush_buf()
                j = command.find("`", i + 1)
                if j == -1:
                    tokens.append({"type": "substitution", "value": command[i + 1 :]})
                    i = n
                else:
                    tokens.append({"type": "substitution", "value": command[i + 1 : j]})
                    i = j + 1
                continue
            if c.isspace():
                flush_buf()
                i += 1
                continue
            # operators
            two = command[i : i + 2]
            three = command[i : i + 3]
            if three in (">>&",):  # rare
                flush_buf()
                tokens.append({"type": "redir", "value": three})
                i += 3
                continue
            if two in ("||", "&&", ">>", "<<", "2>", "&>", ">&"):
                # but '2>' already two; '2>>' three handled? check
                flush_buf()
                if two in ("||", "&&"):
                    tokens.append({"type": "op", "value": two})
                elif two in (">>", "<<", "2>", "&>", ">&"):
                    tokens.append({"type": "redir", "value": two})
                i += 2
                continue
            if c in ("|", ";", "&", "<", ">", "(", ")"):
                # handle 2>> maybe
                if c == ">" and i > 0 and command[i - 1].isdigit():
                    pass
                # check three for 2>>
                if command[i : i + 3] == "2>>":
                    flush_buf()
                    tokens.append({"type": "redir", "value": "2>>"})
                    i += 3
                    continue
                if command[i : i + 2] == "2>":
                    flush_buf()
                    tokens.append({"type": "redir", "value": "2>"})
                    i += 2
                    continue
                flush_buf()
                if c == "|":
                    tokens.append({"type": "op", "value": "|"})
                elif c == ";":
                    tokens.append({"type": "op", "value": ";"})
                elif c == "&":
                    tokens.append({"type": "op", "value": "&"})
                elif c == "<":
                    tokens.append({"type": "redir", "value": "<"})
                elif c == ">":
                    tokens.append({"type": "redir", "value": ">"})
                elif c == "(":
                    tokens.append({"type": "lparen", "value": "("})
                elif c == ")":
                    tokens.append({"type": "rparen", "value": ")"})
                i += 1
                continue
            buf += c
            i += 1

        flush_buf()
        # mark quoted? not needed
        return tokens
