from dataclasses import dataclass, field
from enum import Enum


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityFinding:
    finding_id: str
    category: str
    severity: FindingSeverity
    title: str
    description: str
    remediation: str
    standards_mapped: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    passed: bool
    findings: list[SecurityFinding] = field(default_factory=list)
    total_scanned: int = 0
    critical_count: int = 0
