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


class SupplyChainRule(Rule):
    metadata = RuleMetadata(
        id="CC-SUPPLY-CHAIN",
        title="Package or supply-chain concern",
        category="supply-chain",
        severity=Severity.caution,
        description="Identifies package installation or trust-configuration concerns.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        low = pr.raw_command.lower()
        # npm/pip/yarn install
        if U.contains_any(
            low,
            [
                "npm install",
                "npm i ",
                "yarn add",
                "pip install",
                "pnpm add",
                "gem install",
                "cargo install",
                "go install",
            ],
        ):
            # unpinned? heuristic: no version pin
            if (
                not any(ch.isdigit() for ch in low.split()[-1:])
                and "@" not in low
                and "==" not in low
                and "@" not in low
            ):
                pass
            out.append(
                Finding(
                    id=self.metadata.id + "-INSTALL",
                    title="Package installation command",
                    severity=Severity.caution,
                    confidence=0.7,
                    category="supply-chain",
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command installs packages, which may execute install scripts and add dependencies.",
                    impact="Supply-chain compromise or unwanted code execution.",
                    caveats=["Common development workflow."],
                    mitigation="Pin versions, review lockfiles, and disable scripts where appropriate (npm --ignore-scripts).",
                    assumptions=[],
                    next_steps=["Review package source and lockfile."],
                )
            )
        # disable verification / insecure transport
        if U.contains_any(
            low,
            [
                "--no-verify",
                "--skip-gpg",
                "--disable-gpg",
                "--allow-unauthenticated",
                "--trusted-host",
                "npm config set strict-ssl false",
                "pip --trusted-host",
            ],
        ):
            out.append(
                Finding(
                    id=self.metadata.id + "-VERIFY-DISABLED",
                    title="Verification disabled or trust weakened",
                    category="supply-chain",
                    severity=Severity.high,
                    confidence=0.9,
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command disables verification or trusts an unusual host.",
                    impact="Packages or connections may not be authenticated.",
                    caveats=["May be used in internal registries."],
                    mitigation="Re-enable verification and use proper CA/trust configuration.",
                    assumptions=[],
                    next_steps=["Confirm registry authenticity."],
                )
            )
        # insecure transport http for install
        if "http://" in low and U.contains_any(low, ["install", "add"]):
            out.append(
                Finding(
                    id=self.metadata.id + "-HTTP",
                    title="Insecure transport for package operation",
                    category="supply-chain",
                    severity=Severity.high,
                    confidence=0.8,
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="Package operation uses HTTP rather than HTTPS.",
                    impact="Packages could be tampered with in transit.",
                    caveats=["May be an internal registry."],
                    mitigation="Use HTTPS or a trusted internal mirror.",
                    assumptions=[],
                    next_steps=["Verify registry URL."],
                )
            )
        return out
