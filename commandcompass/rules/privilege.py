from __future__ import annotations

from typing import ClassVar

from commandcompass.core.models import (
    AnalysisRequest,
    Finding,
    ParserResult,
    RuleMetadata,
    Severity,
)
from commandcompass.rules import utils as U
from commandcompass.rules.base import Rule


class PrivilegeElevationRule(Rule):
    metadata = RuleMetadata(
        id="CC-PRIV-ELEVATION",
        title="Privilege elevation requested",
        category="privilege",
        severity=Severity.caution,
        description="Identifies commands run with elevated privileges.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        names = {"sudo", "su", "doas", "pkexec", "runas"}
        segs = U.find_segments(pr, names)
        if segs or U.contains_any(pr.raw_command, ["sudo ", "runas "]):
            for s in segs or [pr.raw_command]:
                out.append(
                    Finding(
                        id=self.metadata.id,
                        title=self.metadata.title,
                        severity=Severity.caution,
                        confidence=0.95,
                        category="privilege",
                        evidence=[s],
                        affected=[s],
                        explanation="The command requests elevated privileges, expanding potential impact.",
                        impact="Mistakes or malicious content can affect the whole system.",
                        caveats=["Elevation may be required for legitimate tasks."],
                        mitigation="Review the exact command and consider least-privilege alternatives.",
                        assumptions=[],
                        next_steps=["Confirm why elevation is needed."],
                    )
                )
        return out


class PermissionChangeRule(Rule):
    metadata = RuleMetadata(
        id="CC-PRIV-PERM",
        title="Permissions or ownership changed",
        category="privilege",
        severity=Severity.high,
        description="Identifies chmod/chown or permission changes.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        names = {"chmod", "chown", "chgrp", "icacls", "takeown"}
        for c in pr.commands:
            if c.name.lower() not in names:
                continue
            args = " ".join(c.args)
            broad = any(t in args for t in ["777", "666", "-R", "/t", "+s", "a+rwx"])
            sev = Severity.high if broad else Severity.caution
            out.append(
                Finding(
                    id=self.metadata.id,
                    title=self.metadata.title,
                    severity=sev,
                    confidence=0.9,
                    category="privilege",
                    evidence=[c.raw],
                    affected=[c.raw],
                    explanation=f"{c.name} changes file permissions or ownership. Broad/recursive={broad}.",
                    impact="Access control may be weakened or ownership altered.",
                    caveats=["May be intended for deployment or build directories."],
                    mitigation="Use least-privilege modes and avoid recursive changes on system paths.",
                    assumptions=[],
                    next_steps=["Verify target paths and required permissions."],
                )
            )
        return out


class SecuritySensitivePathRule(Rule):
    metadata = RuleMetadata(
        id="CC-PRIV-SENSITIVE-PATH",
        title="Sensitive system path targeted",
        category="privilege",
        severity=Severity.high,
        description="Identifies operations targeting security-sensitive directories.",
    )

    SENSITIVE: ClassVar[list[str]] = [
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/boot",
        "C:\\Windows",
        "C:\\Program Files",
        "/root",
        "system32",
    ]

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        text = pr.raw_command
        hits = [p for p in self.SENSITIVE if p.lower() in text.lower()]
        if hits:
            out.append(
                Finding(
                    id=self.metadata.id,
                    title=self.metadata.title,
                    severity=Severity.high,
                    confidence=0.75,
                    category="privilege",
                    evidence=[text],
                    affected=[text],
                    explanation=f"The command references sensitive system paths: {', '.join(hits)}.",
                    impact="System-wide configuration or binaries could be altered.",
                    caveats=["Reference may be read-only."],
                    mitigation="Avoid modifying system directories; use user-level paths or package managers.",
                    assumptions=[],
                    next_steps=["Confirm whether the path is read or written."],
                )
            )
        return out
