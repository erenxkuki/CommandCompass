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


class RecursiveDeleteRule(Rule):
    metadata = RuleMetadata(
        id="CC-DESTRUCTIVE-DELETE",
        title="Recursive or forceful deletion",
        category="destructive",
        severity=Severity.high,
        description="Identifies commands that may delete files or directories recursively or forcefully.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        del_cmds = {"rm", "del", "erase", "rmdir", "rd", "remove-item", "ri"}
        for c in pr.commands:
            if c.name.lower() not in del_cmds:
                continue
            args = " ".join(c.args).lower()
            recursive = any(
                t in args for t in ["-r", "-rf", "-fr", "-rec", "/s", "-recurse", "--recursive"]
            )
            force = any(t in args for t in ["-f", "-force", "/f", "--force"])
            if not (recursive or force):
                # still deletion
                pass
            # filter flags
            target_args = [a for a in c.args if not a.startswith("-") and not a.startswith("/")]
            sev = Severity.high if (recursive or force) else Severity.caution
            # critical if root/home/wildcard
            joined = " ".join(target_args)
            if recursive and (
                joined in ("", "/", "*", "~", "..") or "*" in joined or joined.startswith("/")
            ):
                sev = Severity.critical
            evidence = [c.raw]
            out.append(
                Finding(
                    id=self.metadata.id,
                    title=self.metadata.title,
                    severity=sev,
                    confidence=0.9,
                    category="destructive",
                    evidence=evidence,
                    affected=[c.raw],
                    explanation=f"The command invokes '{c.name}' which can remove files or directories. "
                    f"Recursive={recursive}, force={force}. Targets: {target_args or '(unspecified/flags only)'}.",
                    impact="Permanent loss of files or directories may occur; recovery may be impossible.",
                    caveats=[
                        "The final target may depend on variables, globs, or working directory not visible here."
                    ],
                    mitigation="List matching paths first (e.g., ls/find) and prefer explicit, narrow targets. Use trash/recycle where available.",
                    assumptions=[
                        "The command's arguments are interpreted according to the selected shell."
                    ],
                    next_steps=[
                        "Verify the exact target paths and current working directory.",
                        "Consider a dry-run or backup.",
                    ],
                )
            )
        return out


class FormatStorageRule(Rule):
    metadata = RuleMetadata(
        id="CC-DESTRUCTIVE-FORMAT",
        title="Storage formatting or partitioning",
        category="destructive",
        severity=Severity.critical,
        description="Identifies commands that format, partition, or wipe storage devices.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        names = {"mkfs", "mkfs.ext4", "fdisk", "parted", "format", "diskpart", "wipefs", "dd"}
        segs = U.find_segments(pr, names)
        if segs or U.contains_any(pr.raw_command, ["mkfs", "diskpart", "format c:", "dd if="]):
            for s in segs or [pr.raw_command]:
                out.append(
                    Finding(
                        id=self.metadata.id,
                        title=self.metadata.title,
                        severity=Severity.critical,
                        confidence=0.85,
                        category="destructive",
                        evidence=[s],
                        affected=[s],
                        explanation="The command appears to format, partition, or raw-write storage, which can destroy data on a device.",
                        impact="Severe data loss or system inaccessibility.",
                        caveats=[
                            "Confirm the exact target device; static analysis cannot determine runtime device resolution."
                        ],
                        mitigation="Double-check device identifiers and prefer vendor tools with confirmation prompts.",
                        assumptions=[],
                        next_steps=["Identify the target device and back up data."],
                    )
                )
        return out


class GitDestructiveRule(Rule):
    metadata = RuleMetadata(
        id="CC-DESTRUCTIVE-GIT",
        title="Git history or working tree destructive operation",
        category="destructive",
        severity=Severity.high,
        description="Identifies git commands that discard local changes or rewrite history.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        text = pr.raw_command.lower()
        triggers = [
            "reset --hard",
            "clean -fd",
            "clean -fdx",
            "push --force",
            "push -f",
            "checkout -- .",
            "restore .",
            "branch -D",
        ]
        for t in triggers:
            if t in text:
                out.append(
                    Finding(
                        id=self.metadata.id + "-" + t.replace(" ", "_").upper().replace("-", ""),
                        title=self.metadata.title,
                        severity=Severity.high,
                        confidence=0.9,
                        category="destructive",
                        evidence=[pr.raw_command],
                        affected=[pr.raw_command],
                        explanation=f"Git operation '{t}' can discard uncommitted changes or rewrite shared history.",
                        impact="Loss of local work or disruption for collaborators.",
                        caveats=["Scope depends on repository state and arguments."],
                        mitigation="Use 'git status' and 'git stash' first; prefer --force-with-lease.",
                        assumptions=[],
                        next_steps=["Review git status and stash or branch before proceeding."],
                    )
                )
        return out


class OverwriteRedirectionRule(Rule):
    metadata = RuleMetadata(
        id="CC-DESTRUCTIVE-OVERWRITE",
        title="Output redirection may overwrite files",
        category="destructive",
        severity=Severity.caution,
        description="Identifies output redirections that can overwrite existing files.",
    )

    def evaluate(self, pr: ParserResult, req: AnalysisRequest) -> list[Finding]:
        out: list[Finding] = []
        for r in pr.redirections:
            if ">" in r and ">>" not in r:
                out.append(
                    Finding(
                        id=self.metadata.id,
                        title=self.metadata.title,
                        severity=Severity.caution,
                        confidence=0.8,
                        category="destructive",
                        evidence=[r],
                        affected=[r],
                        explanation=f"Redirection '{r}' writes output and may overwrite an existing file.",
                        impact="Existing file content may be replaced.",
                        caveats=["If the target does not exist, it will be created."],
                        mitigation="Use append (>>) or write to a new path; back up the target first.",
                        assumptions=[],
                        next_steps=["Confirm the redirection target."],
                    )
                )
        return out
