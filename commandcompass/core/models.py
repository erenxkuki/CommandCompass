from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ShellType(str, Enum):
    auto = "auto"
    posix = "posix"
    powershell = "powershell"
    cmd = "cmd"


class Severity(str, Enum):
    informational = "informational"
    caution = "caution"
    high = "high"
    critical = "critical"


class AssessmentState(str, Enum):
    informational = "informational"
    caution = "caution"
    high_risk = "high_risk"
    critical_risk = "critical_risk"
    unknown = "unknown"


class Completeness(str, Enum):
    complete = "complete"
    partial = "partial"


class CommandNode(BaseModel):
    name: str
    args: list[str] = Field(default_factory=list)
    raw: str = ""
    position: int = 0
    kind: str = "command"
    env_assignments: list[str] = Field(default_factory=list)
    redirections: list[str] = Field(default_factory=list)


class Pipeline(BaseModel):
    commands: list[CommandNode] = Field(default_factory=list)
    raw: str = ""


class Chain(BaseModel):
    operator: str
    left: Chain | None = None
    right: Chain | None = None
    raw: str = ""


class ParserResult(BaseModel):
    shell: str
    raw_command: str
    commands: list[CommandNode] = Field(default_factory=list)
    pipelines: list[Pipeline] = Field(default_factory=list)
    chains: list[str] = Field(default_factory=list)
    redirections: list[str] = Field(default_factory=list)
    substitutions: list[str] = Field(default_factory=list)
    env_vars: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    unsupported: list[str] = Field(default_factory=list)
    complete: bool = True
    confidence: float = 1.0
    notes: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: float = 1.0
    category: str
    evidence: list[str] = Field(default_factory=list)
    affected: list[str] = Field(default_factory=list)
    explanation: str
    impact: str
    caveats: list[str] = Field(default_factory=list)
    mitigation: str
    assumptions: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class AnalysisLimitation(BaseModel):
    description: str
    severity: str = "info"


class AnalysisResult(BaseModel):
    request_id: str = ""
    command: str  # redacted form for display
    raw_command_length: int = 0
    shell: str
    assessment: AssessmentState
    completeness: Completeness
    summary: str
    commands: list[CommandNode] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)
    affected_resources: list[str] = Field(default_factory=list)
    safer_alternatives: list[str] = Field(default_factory=list)
    limitations: list[AnalysisLimitation] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)
    suggested_questions: list[str] = Field(default_factory=list)
    parser: ParserResult
    redacted: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuleMetadata(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    references: list[str] = Field(default_factory=list)


class AnalysisRequest(BaseModel):
    command: str
    shell: ShellType = ShellType.auto
    max_input_length: int = 10000
