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


class NetworkActivityRule(Rule):
    metadata = RuleMetadata(
        id="CC-NETWORK-ACTIVITY",
        title="Network activity detected",
        category="network",
        severity=Severity.caution,
        description="Identifies commands that perform outbound network requests.",
    )

    DOWNLOADERS: ClassVar[list[str]] = [
        "curl",
        "wget",
        "invoke-webrequest",
        "iwr",
        "invoke-restmethod",
        "irm",
        "httpx",
        "fetch",
    ]

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        names = U.command_names(pr)
        low = pr.raw_command.lower()
        download_hits = [n for n in names if n in self.DOWNLOADERS]
        other_net = U.contains_any(
            low, ["ssh ", "scp ", "rsync ", "nc ", "netcat", "nmap", "telnet "]
        )
        if download_hits:
            out.append(
                Finding(
                    id=self.metadata.id + "-DOWNLOAD",
                    title="Download tool invoked",
                    severity=Severity.caution,
                    confidence=0.9,
                    category="network",
                    evidence=U.find_segments(pr, download_hits),
                    affected=U.find_segments(pr, download_hits),
                    explanation=f"Download tool(s) invoked: {', '.join(download_hits)}. Data may be retrieved from a remote source.",
                    impact="Remote content or metadata may be fetched; trust depends on source.",
                    caveats=["Not all downloads are malicious."],
                    mitigation="Verify URLs, use HTTPS, and inspect downloaded content.",
                    assumptions=[],
                    next_steps=["Review destination URLs."],
                )
            )
        if other_net:
            out.append(
                Finding(
                    id=self.metadata.id + "-OTHER",
                    title="Network-capable tool invoked",
                    severity=Severity.caution,
                    confidence=0.7,
                    category="network",
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="A tool capable of network communication was invoked.",
                    impact="Data may be transmitted to or from remote systems.",
                    caveats=["May be used for legitimate administration."],
                    mitigation="Confirm endpoints and authentication.",
                    assumptions=[],
                    next_steps=["Review remote host and port."],
                )
            )
        # TLS verification disabling
        if U.contains_any(
            low,
            [
                "-k",
                "--insecure",
                "--no-check-certificate",
                "git_ssl_no_verify",
                "node_tls_reject_unauthorized=0",
            ],
        ):
            out.append(
                Finding(
                    id="CC-NETWORK-TLS-DISABLED",
                    title="TLS/certificate verification weakened",
                    category="network",
                    severity=Severity.high,
                    confidence=0.9,
                    evidence=[pr.raw_command],
                    affected=[pr.raw_command],
                    explanation="The command disables or bypasses TLS certificate validation.",
                    impact="Man-in-the-middle attacks become easier; remote identity is not verified.",
                    caveats=["May be used in controlled test environments."],
                    mitigation="Keep verification enabled; use a trusted CA instead.",
                    assumptions=[],
                    next_steps=["Remove the insecure flag and configure proper trust."],
                )
            )
        return out
