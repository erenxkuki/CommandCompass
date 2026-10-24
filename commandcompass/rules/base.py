from __future__ import annotations

from abc import ABC, abstractmethod

from commandcompass.core.models import AnalysisRequest, Finding, ParserResult, RuleMetadata


class Rule(ABC):
    metadata: RuleMetadata

    @abstractmethod
    def evaluate(self, parser_result: ParserResult, request: AnalysisRequest) -> list[Finding]: ...

    def applies(self, parser_result: ParserResult, request: AnalysisRequest) -> bool:
        return True
