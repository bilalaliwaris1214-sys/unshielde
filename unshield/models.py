"""Shared result types for every Unshield analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional

# Score thresholds (0-100). Tune these using your own test data.
SUSPICIOUS_AT = 25
PHISHING_AT = 60


@dataclass
class Finding:
    """One reason that raised (or explained) the risk score."""
    code: str          # machine readable id, e.g. "ip_host"
    message: str       # human readable explanation
    weight: int        # points added to the risk score
    evidence: str = ""  # the exact text/URL part that triggered it


@dataclass
class Result:
    kind: str                      # "url" | "text" | "email" | "qr"
    target: str                    # what was analysed (shortened for display)
    findings: List[Finding] = field(default_factory=list)
    children: List["Result"] = field(default_factory=list)  # e.g. URLs inside an email
    error: Optional[str] = None

    @property
    def own_score(self) -> int:
        return min(100, sum(f.weight for f in self.findings))

    @property
    def score(self) -> int:
        """Own score, raised to the worst child score (one bad link taints the message)."""
        child_max = max((c.score for c in self.children), default=0)
        return min(100, max(self.own_score, child_max))

    @property
    def verdict(self) -> str:
        if self.score >= PHISHING_AT:
            return "PHISHING"
        if self.score >= SUSPICIOUS_AT:
            return "SUSPICIOUS"
        return "LIKELY SAFE"

    def add(self, code: str, message: str, weight: int, evidence: str = "") -> None:
        # never report the same rule twice for the same evidence
        for f in self.findings:
            if f.code == code and f.evidence == evidence:
                return
        self.findings.append(Finding(code, message, weight, evidence))

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "target": self.target,
            "score": self.score,
            "verdict": self.verdict,
            "error": self.error,
            "findings": [asdict(f) for f in sorted(self.findings, key=lambda x: -x.weight)],
            "children": [c.to_dict() for c in self.children],
        }
