"""Data models shared by the scanner, reports, CLI and web UI."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import List


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]

    @property
    def label(self) -> str:
        return self.name.capitalize()


# Points each severity adds to the 0-100 risk score.
SEVERITY_POINTS = {
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 10,
    Severity.HIGH: 25,
    Severity.CRITICAL: 45,
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    file: str
    line: int = 0
    evidence: str = ""
    advice: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class ScanResult:
    root: str
    files_scanned: List[str] = field(default_factory=list)
    agent_files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        return min(100, sum(SEVERITY_POINTS[f.severity] for f in self.findings))

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def verdict(self) -> str:
        if self.max_severity >= Severity.CRITICAL or self.risk_score >= 70:
            return "DANGEROUS"
        if self.max_severity >= Severity.MEDIUM:
            return "REVIEW"
        return "LOOKS SAFE"

    def counts(self) -> dict:
        out = {s.name: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.name] += 1
        return out

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, f.file, f.line))

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "max_severity": self.max_severity.name,
            "counts": self.counts(),
            "agent_files": self.agent_files,
            "files_scanned": len(self.files_scanned),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
