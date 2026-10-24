from __future__ import annotations

from collections.abc import Iterable

from commandcompass.core.models import ParserResult


def command_names(pr: ParserResult) -> list[str]:
    out: list[str] = []
    for c in pr.commands:
        if c.name:
            out.append(c.name.lower())
    return out


def all_text(pr: ParserResult) -> str:
    return " ".join([pr.raw_command] + [c.raw for c in pr.commands])


def has_command(pr: ParserResult, names: Iterable[str]) -> bool:
    names_l = {n.lower() for n in names}
    return any(n in names_l for n in command_names(pr))


def args_of(pr: ParserResult, names: Iterable[str]) -> list[str]:
    names_l = {n.lower() for n in names}
    out: list[str] = []
    for c in pr.commands:
        if c.name.lower() in names_l:
            out.extend(c.args)
    return out


def contains_any(text: str, needles: Iterable[str]) -> bool:
    low = text.lower()
    return any(n.lower() in low for n in needles)


def find_segments(pr: ParserResult, names: Iterable[str]) -> list[str]:
    names_l = {n.lower() for n in names}
    out: list[str] = []
    for c in pr.commands:
        if c.name.lower() in names_l:
            out.append(c.raw or c.name)
    return out
