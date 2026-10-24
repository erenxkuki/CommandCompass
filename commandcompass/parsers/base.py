from __future__ import annotations

from abc import ABC, abstractmethod

from commandcompass.core.models import ParserResult, ShellType


class BaseParser(ABC):
    shell: ShellType

    @abstractmethod
    def parse(self, command: str) -> ParserResult: ...

    def _truncate(self, text: str, limit: int = 200) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + "..."
