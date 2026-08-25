"""Shared types: findings, severities, and the scan context.

Kept dependency-free and import-light so every check module can pull these in
without dragging the HTTP layer along — which matters for testing checks in
isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so findings sort worst-first and exit codes can threshold on it.

    INFO is not a problem — it is context the operator asked for (the detected
    version, the enumerated plugin list). It never affects the exit code.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_name(cls, name: str) -> Severity:
        return cls[name.strip().upper()]


@dataclass
class Finding:
    """One thing the scan observed.

    `check` is the stable id (e.g. "user-enum"), used for allowlisting and for
    the JSON consumer. `evidence` is what was actually seen — a URL, a header, a
    version string — never a guess. `remediation` is the one concrete next step.
    """

    check: str
    title: str
    severity: Severity
    detail: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity.label,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass
class Target:
    """A normalised scan target: a base URL and the operator's assertions."""

    base_url: str          # scheme://host[:port], no trailing slash
    host: str

    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"
