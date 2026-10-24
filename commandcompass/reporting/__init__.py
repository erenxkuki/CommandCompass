from __future__ import annotations

import json
from typing import Any

from commandcompass.core.models import AnalysisResult
from commandcompass.reporting.markdown_report import to_markdown


def to_json(result: AnalysisResult, indent: int = 2) -> str:
    data = result.model_dump(mode="json")
    return json.dumps(data, indent=indent, ensure_ascii=False)


def to_dict(result: AnalysisResult) -> dict[str, Any]:
    return result.model_dump(mode="json")


def to_markdown_report(result: AnalysisResult) -> str:
    return to_markdown(result)
