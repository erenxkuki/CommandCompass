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


class DataDestructionRule(Rule):
    metadata = RuleMetadata(
        id="CC-DESTRUCTIVE-DATA",
        title="Data destruction utility",
        category="destructive",
        severity=Severity.high,
        description="Identifies utilities that can destroy or truncate data.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        names = {"shred", "srm", "truncate", "dd"}
        segs = U.find_segments(pr, names)
        if segs:
            for s in segs:
                out.append(
                    Finding(
                        id=self.metadata.id,
                        title=self.metadata.title,
                        severity=Severity.high,
                        confidence=0.9,
                        category="destructive",
                        evidence=[s],
                        affected=[s],
                        explanation="The command uses a utility that can destroy or overwrite data.",
                        impact="Data may be permanently lost.",
                        caveats=["May be intended for secure deletion."],
                        mitigation="Verify targets and keep backups.",
                        assumptions=[],
                        next_steps=["Confirm target paths."],
                    )
                )
        return out


class UploadExfiltrationRule(Rule):
    metadata = RuleMetadata(
        id="CC-NETWORK-UPLOAD",
        title="Potential data upload",
        category="network",
        severity=Severity.high,
        description="Identifies commands that may upload data to remote systems.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        text = pr.raw_command.lower()
        triggers = ["curl -t", "curl --upload-file", "scp ", "rsync ", "ftp ", "put "]
        if U.contains_any(text, triggers) or ("curl" in text and "-d @" in text):
            out.append(
                Finding(
                    id=self.metadata.id,
                    title=self.metadata.title,
                    severity=Severity.high,
                    confidence=0.75,
                    category="network",
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command may upload local data to a remote destination.",
                    impact="Sensitive data could be exfiltrated.",
                    caveats=["May be intended deployment or backup."],
                    mitigation="Review destination and payload.",
                    assumptions=[],
                    next_steps=["Confirm remote endpoint and data."],
                )
            )
        return out


class HistoryTamperingRule(Rule):
    metadata = RuleMetadata(
        id="CC-PERSISTENCE-HISTORY",
        title="Shell history tampering",
        category="persistence",
        severity=Severity.caution,
        description="Identifies commands that clear or disable shell history.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        text = pr.raw_command.lower()
        if U.contains_any(
            text, ["history -c", "unset histfile", "histfile=/dev/null", "rm .*history"]
        ):
            out.append(
                Finding(
                    id=self.metadata.id,
                    title=self.metadata.title,
                    severity=Severity.caution,
                    confidence=0.8,
                    category="persistence",
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command may clear or disable shell history.",
                    impact="Activity may be hidden from audit trails.",
                    caveats=["May be privacy-related."],
                    mitigation="Avoid disabling history in shared environments.",
                    assumptions=[],
                    next_steps=["Review intent."],
                )
            )
        return out


class SetuidRule(Rule):
    metadata = RuleMetadata(
        id="CC-PRIV-SETUID",
        title="Setuid or special permission bit",
        category="privilege",
        severity=Severity.high,
        description="Identifies chmod operations setting setuid/setgid/sticky bits.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        text = pr.raw_command.lower()
        if "chmod" in text and U.contains_any(text, ["u+s", "g+s", "+s", "4755", "2755", "1777"]):
            out.append(
                Finding(
                    id=self.metadata.id,
                    title=self.metadata.title,
                    severity=Severity.high,
                    confidence=0.85,
                    category="privilege",
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command sets special permission bits.",
                    impact="Privilege escalation or altered execution behavior may result.",
                    caveats=["May be required for specific tools."],
                    mitigation="Use least privilege and verify binaries.",
                    assumptions=[],
                    next_steps=["Review target executable."],
                )
            )
        return out
