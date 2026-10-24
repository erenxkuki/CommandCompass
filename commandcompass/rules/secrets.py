from __future__ import annotations

from commandcompass.core.models import (
    AnalysisRequest,
    Finding,
    ParserResult,
    RuleMetadata,
    Severity,
)
from commandcompass.redaction import contains_secret, redact_text
from commandcompass.rules import utils as U
from commandcompass.rules.base import Rule


class SecretExposureRule(Rule):
    metadata = RuleMetadata(
        id="CC-SECRET-EMBEDDED",
        title="Potential secret embedded in command",
        category="secrets",
        severity=Severity.high,
        description="Identifies tokens, passwords, or credentials embedded in command arguments.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        if contains_secret(pr.raw_command):
            out.append(
                Finding(
                    id=self.metadata.id,
                    title=self.metadata.title,
                    severity=Severity.high,
                    confidence=0.8,
                    category="secrets",
                    evidence=[redact_text(pr.raw_command)],
                    affected=[redact_text(pr.raw_command)],
                    explanation="The command appears to contain a credential or token. Secret values are redacted in this report.",
                    impact="Credentials may be exposed in shell history, process listings, or logs.",
                    caveats=["Detection is best-effort and may include false positives."],
                    mitigation="Use environment variables or secret managers; avoid inline secrets.",
                    assumptions=[],
                    next_steps=["Rotate the credential if it was shared; move to a secret store."],
                )
            )
        # env var assignment with sensitive name
        for c in pr.commands:
            for env in c.env_assignments:
                if "=" in env:
                    name = env.split("=", 1)[0].lower()
                    if any(k in name for k in ["password", "secret", "token", "key", "passwd"]):
                        out.append(
                            Finding(
                                id=self.metadata.id + "-ENV",
                                title="Credential passed via environment variable",
                                severity=Severity.caution,
                                confidence=0.7,
                                category="secrets",
                                evidence=[redact_text(env)],
                                affected=[redact_text(env)],
                                explanation="An environment variable with a credential-like name is set inline.",
                                impact="Value may persist in process environment or logs.",
                                caveats=["May be a placeholder."],
                                mitigation="Inject secrets via a secret manager or protected env file.",
                                assumptions=[],
                                next_steps=["Review how the variable is consumed."],
                            )
                        )
        return out


class PrivateKeyPathRule(Rule):
    metadata = RuleMetadata(
        id="CC-SECRET-KEYPATH",
        title="Private key path referenced",
        category="secrets",
        severity=Severity.caution,
        description="Identifies references to private key files.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        if U.contains_any(pr.raw_command, ["id_rsa", "id_ed25519", ".pem", ".key", "privatekey"]):
            out.append(
                Finding(
                    id=self.metadata.id,
                    title=self.metadata.title,
                    severity=Severity.caution,
                    confidence=0.7,
                    category="secrets",
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command references a file that may be a private key.",
                    impact="Private key exposure or misuse could compromise authentication.",
                    caveats=["The file may not exist or may be a public key."],
                    mitigation="Ensure key permissions are restrictive and avoid copying private keys.",
                    assumptions=[],
                    next_steps=["Verify file permissions and necessity."],
                )
            )
        return out
