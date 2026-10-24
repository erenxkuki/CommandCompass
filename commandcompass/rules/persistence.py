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


class PersistenceRule(Rule):
    metadata = RuleMetadata(
        id="CC-PERSISTENCE",
        title="Persistence or system modification",
        category="persistence",
        severity=Severity.high,
        description="Identifies operations that create scheduled tasks, modify startup config, or alter services.",
    )

    TRIGGERS: ClassVar[list[str]] = [
        "crontab",
        "systemctl enable",
        "service ",
        "schtasks",
        "reg add",
        "launchctl",
        "update-rc.d",
        "chkconfig",
        "sc create",
        "sc config",
    ]

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        low = pr.raw_command.lower()
        hits = [t for t in self.TRIGGERS if t in low]
        if hits:
            out.append(
                Finding(
                    id=self.metadata.id,
                    title=self.metadata.title,
                    severity=Severity.high,
                    confidence=0.8,
                    category="persistence",
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation=f"Command may establish persistence or modify system services: {', '.join(hits)}.",
                    impact="Changes may survive reboot or affect system-wide behavior.",
                    caveats=["May be legitimate administration."],
                    mitigation="Review the exact task/service and require approval.",
                    assumptions=[],
                    next_steps=["Inspect resulting configuration."],
                )
            )
        # startup file writes
        if U.contains_any(
            low,
            [
                ".bashrc",
                ".profile",
                ".zshrc",
                "bash_profile",
                "powershell profile",
                "currentversion\\run",
            ],
        ):
            out.append(
                Finding(
                    id=self.metadata.id + "-STARTUP",
                    title="Shell or system startup configuration modified",
                    category="persistence",
                    severity=Severity.caution,
                    confidence=0.75,
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command references a shell or system startup file.",
                    impact="Commands may run automatically in future sessions.",
                    caveats=["Could be an append of a PATH entry."],
                    mitigation="Review the modification and prefer explicit, minimal changes.",
                    assumptions=[],
                    next_steps=["Inspect the startup file diff."],
                )
            )
        # firewall
        if U.contains_any(
            low, ["ufw", "iptables", "firewall-cmd", "netsh advfirewall", "set-netfirewallprofile"]
        ):
            out.append(
                Finding(
                    id="CC-SYSTEM-FIREWALL",
                    title="Firewall or security settings modified",
                    category="persistence",
                    severity=Severity.high,
                    confidence=0.8,
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command modifies firewall or security settings.",
                    impact="Network exposure or protection may change.",
                    caveats=["May be intended hardening."],
                    mitigation="Review rules and prefer least-open configuration.",
                    assumptions=[],
                    next_steps=["List resulting firewall rules."],
                )
            )
        return out
