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

DOWNLOADERS = {
    "curl",
    "wget",
    "invoke-webrequest",
    "iwr",
    "irm",
    "invoke-restmethod",
    "certutil",
    "bitsadmin",
    "powershell",
    "pwsh",
}
INTERPRETERS = {
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "powershell",
    "pwsh",
    "cmd",
    "cmd.exe",
}


class DownloadAndExecuteRule(Rule):
    metadata = RuleMetadata(
        id="CC-REMOTE-EXEC",
        title="Downloaded content executed",
        category="remote-execution",
        severity=Severity.critical,
        description="Identifies downloaded content passed directly to an interpreter or shell.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        text = pr.raw_command
        low = text.lower()
        # pipeline: downloader | interpreter
        for p in pr.pipelines:
            names = [c.name.lower() for c in p.commands]
            if any(d in names for d in DOWNLOADERS) and any(i in names for i in INTERPRETERS):
                out.append(
                    Finding(
                        id=self.metadata.id,
                        title=self.metadata.title,
                        severity=Severity.critical,
                        confidence=0.9,
                        category="remote-execution",
                        evidence=[p.raw or text],
                        affected=[p.raw or text],
                        explanation="A download tool and an interpreter appear in the same pipeline, so remote content may be executed as code.",
                        impact="Arbitrary code execution with the user's privileges.",
                        caveats=["HTTPS alone does not establish trust in the downloaded content."],
                        mitigation="Download the script, inspect it, verify checksums/signatures, then run it.",
                        assumptions=[
                            "The pipeline connects output of the downloader to the interpreter."
                        ],
                        next_steps=["Fetch the script to a file and review it; verify publisher."],
                    )
                )
                return out
        # patterns like bash <(curl), eval "$(curl ...)"
        if U.contains_any(low, ["curl", "wget"]) and U.contains_any(
            low, ["eval", "iex", "invoke-expression", "frombase64", "encodedcommand"]
        ):
            out.append(
                Finding(
                    id=self.metadata.id + "-INDIRECT",
                    title=self.metadata.title,
                    severity=Severity.critical,
                    confidence=0.85,
                    category="remote-execution",
                    evidence=[text],
                    affected=[text],
                    explanation="Remote content retrieval is combined with dynamic execution or decoding.",
                    impact="Arbitrary code execution possible.",
                    caveats=["The actual fetched content was not inspected."],
                    mitigation="Separate download and execution; inspect content first.",
                    assumptions=[],
                    next_steps=["Download to a file and inspect."],
                )
            )
        # curl ... | bash already handled; also check raw for pipe to bash
        if (
            "|" in text
            and any(d in low for d in ["curl", "wget", "irm", "iwr"])
            and any(i in low for i in ["bash", "sh", "powershell", "pwsh", "python"])
            and not out
        ):
            # avoid duplicate if already added
            out.append(
                Finding(
                    id=self.metadata.id + "-PIPE",
                    title=self.metadata.title,
                    severity=Severity.critical,
                    confidence=0.85,
                    category="remote-execution",
                    evidence=[text],
                    affected=[text],
                    explanation="Remote content retrieval appears to be piped into a shell or interpreter.",
                    impact="Remote code execution risk.",
                    caveats=["Content not inspected."],
                    mitigation="Download, inspect, verify, then execute.",
                    assumptions=[],
                    next_steps=["Review the script source."],
                )
            )
        return out


class RemoteScriptInvocationRule(Rule):
    metadata = RuleMetadata(
        id="CC-REMOTE-SCRIPT",
        title="Remote script or code launched",
        category="remote-execution",
        severity=Severity.high,
        description="Identifies launching interpreters on remote or temporary scripts.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        text = pr.raw_command.lower()
        if (
            U.contains_any(text, ["http://", "https://"])
            and U.contains_any(text, ["bash ", "sh ", "python ", "powershell ", "pwsh "])
            and not U.contains_any(text, ["curl", "wget", "iwr", "irm"])
        ):
            # already maybe download; mark high if executing URL directly
            out.append(
                Finding(
                    id=self.metadata.id,
                    title=self.metadata.title,
                    severity=Severity.high,
                    confidence=0.7,
                    category="remote-execution",
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="An interpreter appears to be invoked with a remote URL argument.",
                    impact="Remote code may be executed.",
                    caveats=["Some tools fetch and run URLs natively."],
                    mitigation="Download and inspect before execution.",
                    assumptions=[],
                    next_steps=["Verify the URL and content."],
                )
            )
        return out
