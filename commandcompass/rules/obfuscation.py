from __future__ import annotations

from commandcompass.core.models import (
    AnalysisRequest,
    Finding,
    ParserResult,
    RuleMetadata,
    Severity,
)
from commandcompass.rules import utils as U
from commandcompass.rules.base import Rule


class ObfuscationRule(Rule):
    metadata = RuleMetadata(
        id="CC-OBFUSCATION",
        title="Obfuscation or indirect execution",
        category="obfuscation",
        severity=Severity.high,
        description="Identifies encoded commands, dynamic evaluation, or layered interpretation.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        low = pr.raw_command.lower()
        # dynamic eval/exec
        if U.contains_any(
            low,
            [
                "eval ",
                "exec ",
                "invoke-expression",
                "iex ",
                "bash -c",
                "sh -c",
                "powershell -command",
                "pwsh -command",
            ],
        ):
            out.append(
                Finding(
                    id=self.metadata.id + "-EVAL",
                    title="Dynamic evaluation or nested shell",
                    category="obfuscation",
                    severity=Severity.caution,
                    confidence=0.8,
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command uses dynamic evaluation or a nested shell, which can hide intent.",
                    impact="Static analysis may not reflect actual executed behavior.",
                    caveats=["Often used for legitimate scripting."],
                    mitigation="Expand the command and inspect the resulting script.",
                    assumptions=[],
                    next_steps=["Reconstruct the effective command."],
                )
            )
        # encoded command
        if U.contains_any(
            low,
            [
                "-encodedcommand",
                "-enc ",
                "frombase64string",
                "base64 -d",
                "base64 --decode",
                "atob(",
            ],
        ):
            out.append(
                Finding(
                    id=self.metadata.id + "-ENCODED",
                    title="Encoded command argument",
                    category="obfuscation",
                    severity=Severity.high,
                    confidence=0.85,
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command contains an encoded or decoded payload.",
                    impact="The decoded content could perform arbitrary actions.",
                    caveats=["Encoding may be used for transport convenience."],
                    mitigation="Decode and inspect the payload in a safe environment.",
                    assumptions=[],
                    next_steps=["Decode the payload without executing it."],
                )
            )
        # try decode base64 chunks to see if suspicious? best-effort note only, no execution
        # command substitution
        if pr.substitutions:
            out.append(
                Finding(
                    id=self.metadata.id + "-SUBST",
                    title="Command substitution detected",
                    category="obfuscation",
                    severity=Severity.caution,
                    confidence=0.8,
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command embeds command substitution, so part of its behavior is generated at runtime.",
                    impact="Final behavior depends on runtime output.",
                    caveats=["Common in shell scripting."],
                    mitigation="Resolve substitutions manually and inspect them.",
                    assumptions=[],
                    next_steps=["Evaluate substitutions in an isolated, non-executing way."],
                )
            )
        # multiple pipes
        if len(pr.pipelines) > 0 and sum(len(p.commands) for p in pr.pipelines) >= 4:
            out.append(
                Finding(
                    id=self.metadata.id + "-COMPLEX",
                    title="Complex command composition",
                    category="obfuscation",
                    severity=Severity.caution,
                    confidence=0.6,
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command composes many stages, increasing analysis uncertainty.",
                    impact="Harder to reason about end-to-end behavior.",
                    caveats=["Complexity alone is not malicious."],
                    mitigation="Break into smaller, reviewable steps.",
                    assumptions=[],
                    next_steps=["Simplify and review each stage."],
                )
            )
        return out
