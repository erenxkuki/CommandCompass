from __future__ import annotations

import uuid

from commandcompass.core.models import (
    AnalysisLimitation,
    AnalysisRequest,
    AnalysisResult,
    AssessmentState,
    Completeness,
    Finding,
    Severity,
    ShellType,
)
from commandcompass.parsers import get_parser
from commandcompass.redaction import redact_text
from commandcompass.rules import default_rules

MAX_INPUT = 10000


def analyze(request: AnalysisRequest) -> AnalysisResult:
    command = request.command or ""
    if len(command) > request.max_input_length:
        raise ValueError(f"Input exceeds maximum length of {request.max_input_length}")

    shell_enum = request.shell
    if shell_enum == ShellType.auto:
        from commandcompass.parsers import detect_shell

        shell_enum = detect_shell(command)

    parser = get_parser(shell_enum, command)
    parser_result = parser.parse(command)

    findings: list[Finding] = []
    for rule in default_rules():
        try:
            findings.extend(rule.evaluate(parser_result, request))
        except Exception as exc:  # structured; do not swallow silently
            findings.append(
                Finding(
                    id="CC-ENGINE-ERROR",
                    title="Analysis rule error",
                    severity=Severity.caution,
                    confidence=0.5,
                    category="engine",
                    evidence=[],
                    explanation=f"A rule raised an error: {type(exc).__name__}",
                    impact="Part of the analysis may be incomplete.",
                    caveats=[str(exc)],
                    mitigation="Report the issue.",
                    assumptions=[],
                    next_steps=[],
                )
            )

    # de-duplicate findings by id+evidence
    deduped: list[Finding] = []
    seen = set()
    for f in findings:
        key = (f.id, tuple(f.evidence))
        if key in seen:
            continue
        seen.add(key)
        # redact evidence
        f.evidence = [redact_text(e) for e in f.evidence]
        f.affected = [redact_text(e) for e in f.affected]
        deduped.append(f)
    findings = deduped

    # redact raw command text in parser result before exposure
    parser_result.raw_command = redact_text(parser_result.raw_command)
    for c in parser_result.commands:
        c.raw = redact_text(c.raw)
        c.args = [redact_text(a) for a in c.args]
        c.env_assignments = [redact_text(e) for e in c.env_assignments]
        c.redirections = [redact_text(r) for r in c.redirections]
    for p in parser_result.pipelines:
        for c in p.commands:
            c.raw = redact_text(c.raw)
            c.args = [redact_text(a) for a in c.args]
    parser_result.substitutions = [redact_text(s) for s in parser_result.substitutions]
    parser_result.env_vars = [redact_text(v) for v in parser_result.env_vars]
    parser_result.redirections = [redact_text(r) for r in parser_result.redirections]
    # side effects / affected resources
    side_effects = _side_effects(parser_result, findings)
    affected_resources = _affected_resources(parser_result)

    # assessment
    assessment, _completeness = _aggregate(parser_result, findings)

    # safer alternatives
    alternatives = _safer_alternatives(parser_result, findings)

    # limitations
    limitations = [
        AnalysisLimitation(
            description="Static analysis cannot guarantee the absence of harmful behavior."
        ),
        AnalysisLimitation(
            description="The tool does not execute the command; runtime behavior may differ."
        ),
    ]
    if parser_result.unsupported:
        limitations.append(
            AnalysisLimitation(
                description="Unsupported syntax encountered: "
                + ", ".join(parser_result.unsupported)
            )
        )
    if not parser_result.complete:
        limitations.append(
            AnalysisLimitation(description="Parsing was partial; results may be incomplete.")
        )
    if parser_result.substitutions:
        limitations.append(
            AnalysisLimitation(
                description="Command substitution or dynamic content may change behavior at runtime."
            )
        )

    missing_context = _missing_context(parser_result)
    questions = _suggested_questions(parser_result, findings)

    summary = _summary(command, assessment, findings, parser_result)

    result = AnalysisResult(
        request_id=str(uuid.uuid4()),
        command=redact_text(command),
        raw_command_length=len(command),
        shell=parser_result.shell,
        assessment=assessment,
        completeness=Completeness.complete
        if parser_result.complete and not parser_result.unsupported
        else Completeness.partial,
        summary=summary,
        commands=parser_result.commands,
        findings=findings,
        side_effects=side_effects,
        affected_resources=affected_resources,
        safer_alternatives=alternatives,
        limitations=limitations,
        missing_context=missing_context,
        suggested_questions=questions,
        parser=parser_result,
        redacted=True,
        metadata={"shell_input": shell_enum.value},
    )
    return result


def _aggregate(pr, findings):
    if not pr.complete or pr.unsupported:
        base_unknown = True
    else:
        base_unknown = False
    max_sev = None
    for f in findings:
        if max_sev is None or _sev_rank(f.severity) > _sev_rank(max_sev):
            max_sev = f.severity
    if max_sev is None:
        if base_unknown:
            return AssessmentState.unknown, Completeness.partial
        return AssessmentState.informational, Completeness.complete
    # map severity to assessment
    if max_sev.value == "critical":
        assessment = AssessmentState.critical_risk
    elif max_sev.value == "high":
        assessment = AssessmentState.high_risk
    elif max_sev.value == "caution":
        assessment = AssessmentState.caution
    else:
        assessment = AssessmentState.informational
    if base_unknown and assessment in (AssessmentState.informational,):
        assessment = AssessmentState.unknown
    completeness = (
        Completeness.complete if (pr.complete and not pr.unsupported) else Completeness.partial
    )
    return assessment, completeness


def _sev_rank(s):
    from commandcompass.core.models import Severity

    order = {Severity.informational: 0, Severity.caution: 1, Severity.high: 2, Severity.critical: 3}
    return order.get(s, 0)


def _side_effects(pr, findings):
    effects = []
    names = [c.name.lower() for c in pr.commands]
    if any(n in names for n in ["rm", "del", "rmdir"]):
        effects.append("May delete files or directories.")
    if pr.redirections:
        effects.append("May write or overwrite files via redirection.")
    if any(">" in r for r in pr.redirections):
        pass
    if any(n in names for n in ["curl", "wget"]):
        effects.append("May download data from a network location.")
    if pr.chains:
        effects.append("Conditional or sequential execution between commands.")
    if any(n in names for n in ["chmod", "chown"]):
        effects.append("May change file permissions or ownership.")
    # from findings
    for f in findings:
        if f.category in ("persistence",):
            effects.append(f.title)
    # dedup
    seen = set()
    out = []
    for e in effects:
        if e in seen:
            continue
        seen.add(e)
        out.append(e)
    return out


def _affected_resources(pr):
    res = []
    for c in pr.commands:
        res.append(c.name)
        for a in c.args:
            if "/" in a or "\\" in a or a.startswith("."):
                res.append(a)
    # dedup
    seen = set()
    out = []
    for r in res:
        if r in seen:
            continue
        seen.add(r)
        out.append(r)
    return out[:50]


def _safer_alternatives(pr, findings):
    alts = []
    text = pr.raw_command.lower()
    if "curl" in text and "|" in text and "bash" in text:
        alts.append(
            "Download the script to a file, inspect it, verify its source/checksum, then execute it explicitly."
        )
    if any("rm" == c.name.lower() for c in pr.commands):
        alts.append(
            "List the matched paths first (ls/find) and consider a dry run or trash instead of permanent deletion."
        )
    if "git reset --hard" in text:
        alts.append(
            "Use 'git stash' or create a branch before discarding changes; inspect with 'git diff'."
        )
    if any(f.id.startswith("CC-NETWORK-TLS") for f in findings):
        alts.append("Keep TLS verification enabled and configure a trusted CA.")
    if not alts:
        alts.append("If unsure, run the command in an isolated environment or container first.")
    return alts


def _missing_context(pr):
    missing = []
    if pr.substitutions or pr.env_vars:
        missing.append("Values of variables or substitutions are not known.")
    if any("*" in a or "?" in a for c in pr.commands for a in c.args):
        missing.append("Wildcard expansion targets are not known.")
    if not pr.complete:
        missing.append("Some syntax was not fully parsed.")
    missing.append("Current working directory, user, and environment are not known.")
    return missing


def _suggested_questions(pr, findings):
    qs = [
        "What is the current working directory?",
        "Who will run this command and with what privileges?",
        "Are all URLs, packages, and scripts trusted?",
    ]
    if any(f.category == "secrets" for f in findings):
        qs.append("Can the secret be provided through a safer mechanism?")
    if any(f.category == "destructive" for f in findings):
        qs.append("Is there a backup or rollback plan?")
    return qs


def _summary(command, assessment, findings, pr):
    if assessment == AssessmentState.unknown:
        return "The command could not be fully analyzed; treat it with caution and review manually."
    if not findings:
        return "No specific high-impact findings were detected, but static analysis cannot guarantee safety."
    cats = sorted({f.category for f in findings})
    return f"Analysis identified {len(findings)} finding(s) across: {', '.join(cats)}. Overall: {assessment.value}."
