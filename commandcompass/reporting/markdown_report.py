from __future__ import annotations

from commandcompass.core.models import AnalysisResult


def to_markdown(result: AnalysisResult) -> str:
    lines = []
    lines.append("# CommandCompass Analysis Report")
    lines.append("")
    lines.append(f"- **Command:** `{result.command}`")
    lines.append(f"- **Shell:** {result.shell}")
    lines.append(f"- **Assessment:** {result.assessment.value}")
    lines.append(f"- **Completeness:** {result.completeness.value}")
    lines.append("")
    lines.append("## Summary")
    lines.append(result.summary)
    lines.append("")
    lines.append("## Command structure")
    for c in result.commands:
        lines.append(f"- `{c.name}` args: {c.args} redirs: {c.redirections}")
    lines.append("")
    lines.append("## Findings")
    if not result.findings:
        lines.append("No specific findings.")
    for f in result.findings:
        lines.append(f"### {f.id}: {f.title}")
        lines.append(f"- Severity: {f.severity.value}")
        lines.append(f"- Confidence: {f.confidence}")
        lines.append(f"- Evidence: {', '.join(f.evidence)}")
        lines.append(f"- Explanation: {f.explanation}")
        lines.append(f"- Impact: {f.impact}")
        lines.append(f"- Mitigation: {f.mitigation}")
        lines.append("")
    lines.append("## Side effects")
    for s in result.side_effects:
        lines.append(f"- {s}")
    lines.append("")
    lines.append("## Safer alternatives")
    for a in result.safer_alternatives:
        lines.append(f"- {a}")
    lines.append("")
    lines.append("## Limitations")
    for l in result.limitations:
        lines.append(f"- {l.description}")
    lines.append("")
    lines.append("## Missing context")
    for m in result.missing_context:
        lines.append(f"- {m}")
    lines.append("")
    lines.append("## Suggested questions")
    for q in result.suggested_questions:
        lines.append(f"- {q}")
    lines.append("")
    lines.append(
        "> Static analysis is limited and cannot guarantee safety. CommandCompass never executes the input."
    )
    return "\n".join(lines)
